import express, { type Request, type Response, type NextFunction } from 'express';
import pino from 'pino';
import { v4 as uuidv4 } from 'uuid';
import { Queue, Worker, type Job } from 'bullmq';
import http from 'node:http';
import pg from 'pg';
import Redis from 'ioredis';
import { InternetMode, JobStatus } from '@scanboy/shared';
import { loadConfig, type DynamicAnalysisConfig } from './config.js';
import { Detonator, type DetonationRequest, type DetonationResult } from './detonation/detonator.js';
import { DockerSandboxExecutor, type DetonationReport } from './docker-sandbox/index.js';

// ── Job payload type ────────────────────────────────────────────────────────

interface DynamicAnalysisJobData {
  readonly submissionId: string;
  readonly samplePath: string;
  readonly fileName: string;
  readonly mimeType: string;
  readonly sha256: string;
  readonly os: string;
  readonly osVersion: string;
  readonly architecture: string;
  readonly baseImage: string;
  readonly internetMode: InternetMode;
  readonly durationSeconds: number;
  readonly provider: string;
}

interface JobStatusResponse {
  readonly jobId: string;
  readonly status: string;
  readonly progress: number;
  readonly result: DetonationResult | null;
  readonly failedReason: string | null;
}

// ── Docker sandbox analysis request type ────────────────────────────────────

interface DockerAnalyzeRequestBody {
  readonly submissionId: string;
  readonly storagePath: string;
  readonly sha256: string;
  readonly filename?: string;
  readonly timeoutSeconds?: number;
  readonly internetAccess?: boolean;
  readonly captureNetwork?: boolean;
}

// ── Sandbox client (HTTP adapter to sandbox-manager) ────────────────────────

function createSandboxClient(cfg: DynamicAnalysisConfig['sandboxManager']) {
  async function request<T>(
    method: string,
    path: string,
    body?: unknown,
  ): Promise<T> {
    const url = new URL(path, cfg.baseUrl);

    return new Promise<T>((resolve, reject) => {
      const options: http.RequestOptions = {
        hostname: url.hostname,
        port: url.port,
        path: url.pathname,
        method,
        headers: { 'Content-Type': 'application/json' },
        timeout: cfg.timeoutMs,
      };

      const req = http.request(options, (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (chunk: Buffer) => chunks.push(chunk));
        res.on('end', () => {
          const raw = Buffer.concat(chunks).toString('utf-8');
          const statusCode = res.statusCode ?? 0;
          if (statusCode >= 200 && statusCode < 300) {
            try {
              const parsed = JSON.parse(raw) as { data: T };
              resolve(parsed.data);
            } catch {
              resolve(null as T);
            }
          } else {
            reject(new Error(`Sandbox manager error ${statusCode}: ${raw}`));
          }
        });
      });

      req.on('error', reject);
      req.on('timeout', () => {
        req.destroy();
        reject(new Error(`Sandbox manager request timed out: ${method} ${path}`));
      });

      if (body !== undefined) {
        req.write(JSON.stringify(body));
      }
      req.end();
    });
  }

  return {
    async provision(params: {
      name: string;
      provider: string;
      os: string;
      osVersion: string;
      architecture: string;
      baseImage: string;
      internetMode: InternetMode;
      maxExecutionSeconds: number;
    }): Promise<{ instanceId: string; provider: string }> {
      return request<{ instanceId: string; provider: string }>(
        'POST',
        '/sandboxes/provision',
        params,
      );
    },

    async destroy(instanceId: string): Promise<void> {
      await request<null>('POST', `/sandboxes/${instanceId}/destroy`);
    },

    async executeCommand(
      instanceId: string,
      command: string,
    ): Promise<{ exitCode: number; stdout: string; stderr: string; durationMs: number }> {
      return request<{
        exitCode: number;
        stdout: string;
        stderr: string;
        durationMs: number;
      }>('POST', `/sandboxes/${instanceId}/execute`, { command });
    },

    async uploadFile(
      instanceId: string,
      localPath: string,
      remotePath: string,
    ): Promise<void> {
      await request<null>('POST', `/sandboxes/${instanceId}/upload`, {
        localPath,
        remotePath,
      });
    },

    async captureScreenshot(instanceId: string): Promise<Buffer> {
      const result = await request<{ data: string }>(
        'POST',
        `/sandboxes/${instanceId}/screenshot`,
      );
      return Buffer.from(result.data, 'base64');
    },

    async getNetworkCapture(instanceId: string): Promise<Buffer> {
      const result = await request<{ data: string }>(
        'POST',
        `/sandboxes/${instanceId}/network-capture`,
      );
      return Buffer.from(result.data, 'base64');
    },

    async getMemoryDump(instanceId: string): Promise<Buffer> {
      const result = await request<{ data: string }>(
        'POST',
        `/sandboxes/${instanceId}/memory-dump`,
      );
      return Buffer.from(result.data, 'base64');
    },
  };
}

// ── Main ────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const config = loadConfig();

  const logger = pino({
    level: config.logLevel,
    transport:
      config.nodeEnv === 'development'
        ? { target: 'pino-pretty', options: { colorize: true } }
        : undefined,
  });

  // Redis connection config for BullMQ
  const redisConnection = {
    host: config.redis.host,
    port: config.redis.port,
    password: config.redis.password,
    maxRetriesPerRequest: null,
  } as const;

  // Initialize sandbox client and detonator
  const sandboxClient = createSandboxClient(config.sandboxManager);
  const detonator = new Detonator(config.detonation, sandboxClient, logger);

  // Initialize Docker sandbox executor (direct Docker-based detonation)
  const dockerExecutor = new DockerSandboxExecutor();

  // PostgreSQL pool for storing results
  const pgPool = new pg.Pool({
    host: config.postgres.host,
    port: config.postgres.port,
    database: config.postgres.database,
    user: config.postgres.user,
    password: config.postgres.password,
    max: config.postgres.poolMax,
  });

  // Redis client for fetching samples stored in Redis
  const redisClient = new Redis({
    host: config.redis.host,
    port: config.redis.port,
    password: config.redis.password,
    maxRetriesPerRequest: 3,
    lazyConnect: true,
  });

  // Connect Redis lazily — singleton promise prevents double-connect race
  let redisConnectPromise: Promise<Redis> | null = null;
  function getRedisClient(): Promise<Redis> {
    if (!redisConnectPromise) {
      redisConnectPromise = redisClient.connect().then(() => redisClient);
    }
    return redisConnectPromise;
  }

  // ── BullMQ Queue ──────────────────────────────────────────────────────

  const dynamicAnalysisQueue = new Queue<DynamicAnalysisJobData>('dynamic-analysis', {
    connection: redisConnection,
    defaultJobOptions: {
      attempts: config.queue.maxRetries,
      backoff: {
        type: 'exponential',
        delay: config.queue.retryDelayMs,
      },
      removeOnComplete: { count: 1000 },
      removeOnFail: { count: 5000 },
    },
  });

  // ── BullMQ Worker ─────────────────────────────────────────────────────

  const worker = new Worker<DynamicAnalysisJobData, DetonationResult>(
    'dynamic-analysis',
    async (job: Job<DynamicAnalysisJobData>): Promise<DetonationResult> => {
      logger.info(
        {
          jobId: job.id,
          submissionId: job.data.submissionId,
          fileName: job.data.fileName,
        },
        'Processing dynamic analysis job',
      );

      await job.updateProgress(10);

      const request: DetonationRequest = {
        submissionId: job.data.submissionId,
        samplePath: job.data.samplePath,
        fileName: job.data.fileName,
        mimeType: job.data.mimeType,
        sha256: job.data.sha256,
        os: job.data.os,
        osVersion: job.data.osVersion,
        architecture: job.data.architecture,
        baseImage: job.data.baseImage,
        internetMode: job.data.internetMode,
        durationSeconds: Math.min(
          job.data.durationSeconds,
          config.detonation.maxDurationSeconds,
        ),
        provider: job.data.provider,
      };

      await job.updateProgress(20);

      const result = await detonator.detonate(request);

      await job.updateProgress(100);

      logger.info(
        {
          jobId: job.id,
          submissionId: job.data.submissionId,
          durationMs: result.durationMs,
          processEvents: result.processEvents.length,
          fileEvents: result.fileEvents.length,
          networkEvents: result.networkEvents.length,
          evasionAttempts: result.evasionDetection.attempts.length,
        },
        'Dynamic analysis job completed',
      );

      return result;
    },
    {
      connection: redisConnection,
      concurrency: config.queue.concurrency,
      limiter: {
        max: config.queue.concurrency,
        duration: 1000,
      },
    },
  );

  worker.on('failed', (job, err) => {
    logger.error(
      {
        jobId: job?.id,
        submissionId: job?.data.submissionId,
        error: err.message,
      },
      'Dynamic analysis job failed',
    );
  });

  worker.on('error', (err) => {
    logger.error({ error: err.message }, 'Worker error');
  });

  // ── Express app ─────────────────────────────────────────────────────────

  const app = express();
  app.use(express.json());

  // Request ID middleware
  app.use((_req: Request, res: Response, next: NextFunction) => {
    const requestId = uuidv4();
    res.setHeader('X-Request-Id', requestId);
    next();
  });

  // Internal API key auth for all routes except /health
  const INTERNAL_KEY = process.env['INTERNAL_API_KEY'];
  if (INTERNAL_KEY) {
    app.use((req: Request, res: Response, next: NextFunction) => {
      if (req.path === '/health') return next();
      if (req.headers['x-internal-api-key'] !== INTERNAL_KEY) {
        res.status(401).json({ success: false, error: 'Unauthorized' });
        return;
      }
      next();
    });
  }

  // ── Routes ──────────────────────────────────────────────────────────────

  // POST /analyze - Submit a sample for dynamic analysis
  app.post('/analyze', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const body = req.body as DynamicAnalysisJobData;

      if (!body.submissionId || !body.samplePath || !body.fileName) {
        res.status(400).json({
          success: false,
          data: null,
          error: {
            code: 'INVALID_REQUEST',
            message: 'Missing required fields: submissionId, samplePath, fileName',
          },
          requestId: res.getHeader('X-Request-Id') as string,
          timestamp: new Date().toISOString(),
        });
        return;
      }

      const jobData: DynamicAnalysisJobData = {
        submissionId: body.submissionId,
        samplePath: body.samplePath,
        fileName: body.fileName,
        mimeType: body.mimeType ?? 'application/octet-stream',
        sha256: body.sha256 ?? '',
        os: body.os ?? 'windows-10',
        osVersion: body.osVersion ?? '10.0',
        architecture: body.architecture ?? 'x86_64',
        baseImage: body.baseImage ?? 'windows-10-analyst',
        internetMode: body.internetMode ?? InternetMode.Disabled,
        durationSeconds: body.durationSeconds ?? config.detonation.defaultDurationSeconds,
        provider: body.provider ?? 'qemu',
      };

      const jobName = `detonate-${body.submissionId}` as string;
      const job = await dynamicAnalysisQueue.add(
        jobName,
        jobData,
        { priority: 1 },
      );

      res.status(202).json({
        success: true,
        data: {
          jobId: job.id,
          submissionId: body.submissionId,
          status: JobStatus.Queued,
        },
        error: null,
        requestId: res.getHeader('X-Request-Id') as string,
        timestamp: new Date().toISOString(),
      });
    } catch (err) {
      next(err);
    }
  });

  // POST /analyze/docker — Direct Docker sandbox detonation (synchronous)
  app.post('/analyze/docker', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const body = req.body as DockerAnalyzeRequestBody;

      if (!body.submissionId || !body.storagePath || !body.sha256) {
        res.status(400).json({
          success: false,
          data: null,
          error: {
            code: 'INVALID_REQUEST',
            message: 'Missing required fields: submissionId, storagePath, sha256',
          },
          requestId: res.getHeader('X-Request-Id') as string,
          timestamp: new Date().toISOString(),
        });
        return;
      }

      // Validate submissionId format to prevent injection in container names,
      // Redis keys, and filesystem paths
      if (!/^[a-f0-9\-]{36}$/.test(body.submissionId)) {
        res.status(400).json({
          success: false,
          data: null,
          error: {
            code: 'INVALID_REQUEST',
            message: 'Invalid submissionId format',
          },
          requestId: res.getHeader('X-Request-Id') as string,
          timestamp: new Date().toISOString(),
        });
        return;
      }

      // Validate sha256 format
      if (!/^[a-f0-9]{64}$/.test(body.sha256)) {
        res.status(400).json({
          success: false,
          data: null,
          error: {
            code: 'INVALID_REQUEST',
            message: 'Invalid sha256 format',
          },
          requestId: res.getHeader('X-Request-Id') as string,
          timestamp: new Date().toISOString(),
        });
        return;
      }

      logger.info(
        { submissionId: body.submissionId, sha256: body.sha256 },
        'Starting Docker sandbox analysis',
      );

      // Fetch the file buffer
      let fileBuffer: Buffer;

      if (body.storagePath.startsWith('redis:')) {
        // Fetch from Redis: storagePath format is "redis:<key>"
        const redisKey = body.storagePath.slice('redis:'.length);

        // Validate Redis key: must match expected submission key pattern
        // to prevent accessing arbitrary Redis keys (IDOR via crafted storagePath).
        // The API gateway stores files at "scanboy:file:<uuid>".
        if (!/^scanboy:file:[a-f0-9\-]{36}$/.test(redisKey)) {
          res.status(400).json({
            success: false,
            data: null,
            error: {
              code: 'INVALID_STORAGE_PATH',
              message: 'Invalid Redis storage path format',
            },
            requestId: res.getHeader('X-Request-Id') as string,
            timestamp: new Date().toISOString(),
          });
          return;
        }

        const redis = await getRedisClient();
        const rawData = await redis.get(redisKey);
        const data = rawData ? Buffer.from(rawData, 'base64') : null;
        if (!data) {
          res.status(404).json({
            success: false,
            data: null,
            error: {
              code: 'SAMPLE_NOT_FOUND',
              message: 'Sample not found in Redis',
            },
            requestId: res.getHeader('X-Request-Id') as string,
            timestamp: new Date().toISOString(),
          });
          return;
        }
        fileBuffer = data;
      } else {
        // Read from filesystem — validate path to prevent path traversal
        const { readFile } = await import('node:fs/promises');
        const { resolve, normalize } = await import('node:path');

        // Restrict to allowed storage directories only
        const ALLOWED_STORAGE_DIRS = [
          '/data/scanboy/uploads',
          '/tmp/scanboy',
          process.env['SCANBOY_STORAGE_DIR'] ?? '/data/scanboy/storage',
        ];
        const normalizedPath = resolve(normalize(body.storagePath));
        const isAllowed = ALLOWED_STORAGE_DIRS.some(dir => normalizedPath.startsWith(dir + '/'));

        if (!isAllowed) {
          logger.warn({ storagePath: body.storagePath, normalizedPath }, 'Path traversal attempt blocked');
          res.status(400).json({
            success: false,
            data: null,
            error: {
              code: 'INVALID_STORAGE_PATH',
              message: 'Storage path is outside allowed directories',
            },
            requestId: res.getHeader('X-Request-Id') as string,
            timestamp: new Date().toISOString(),
          });
          return;
        }

        try {
          fileBuffer = await readFile(normalizedPath);
        } catch {
          res.status(404).json({
            success: false,
            data: null,
            error: {
              code: 'SAMPLE_NOT_FOUND',
              message: 'Sample not found at storage path',
            },
            requestId: res.getHeader('X-Request-Id') as string,
            timestamp: new Date().toISOString(),
          });
          return;
        }
      }

      // Execute in Docker sandbox
      const report: DetonationReport = await dockerExecutor.execute(
        body.submissionId,
        fileBuffer,
        body.filename ?? 'sample',
        {
          timeoutSeconds: body.timeoutSeconds,
          internetAccess: body.internetAccess,
          captureNetwork: body.captureNetwork,
        },
      );

      // Store results in PostgreSQL
      try {
        const sanitizeJson = (obj: unknown): string =>
          JSON.stringify(obj).replace(/\\u0000/g, '');

        await pgPool.query(
          `INSERT INTO dynamic_analysis_results (
            submission_id, processes, file_activity, registry_activity, network_activity,
            memory_activity, duration_seconds
          ) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
          [
            body.submissionId,
            sanitizeJson(report.processActivity),
            sanitizeJson(report.fileActivity),
            sanitizeJson((report as unknown as Record<string, unknown>)['wineRegistryChanges'] ?? {}),
            sanitizeJson(report.networkActivity),
            sanitizeJson({ suspiciousIndicators: report.suspiciousIndicators, riskScore: report.riskScore, droppedFiles: report.droppedFiles, extractedFiles: (report as unknown as Record<string, unknown>)['extractedFiles'], deepAnalysis: (report as unknown as Record<string, unknown>)['deepAnalysis'], yaraPatternMatches: (report as unknown as Record<string, unknown>)['yaraPatternMatches'], yaraPatternOutput: (report as unknown as Record<string, unknown>)['yaraPatternOutput'], yaraBinaryMatches: (report as unknown as Record<string, unknown>)['yaraBinaryMatches'], containerSbom: (report as unknown as Record<string, unknown>)['containerSbom'] }),
            Math.round((report.executionDuration ?? 0) / 1000),
          ],
        );
      } catch (dbErr) {
        logger.warn({ err: dbErr, submissionId: body.submissionId }, 'Failed to store analysis results in PostgreSQL');
      }

      // Store PCAP in Redis for download (1 hour TTL)
      const pcap = (report as unknown as Record<string, unknown>)['pcapBase64'] as string | undefined;
      if (pcap && pcap.length > 20) {
        try {
          const redis = await getRedisClient();
          await redis.set(`scanboy:pcap:${body.submissionId}`, pcap, 'EX', 3600);
          logger.info({ submissionId: body.submissionId, pcapSize: pcap.length }, 'PCAP stored in Redis');
        } catch { /* non-fatal */ }
      }

      logger.info(
        {
          submissionId: body.submissionId,
          riskScore: report.riskScore,
          duration: report.executionDuration,
          processes: report.processActivity.processes.length,
          filesCreated: report.fileActivity.created.length,
          connections: report.networkActivity.connections.length,
          indicators: report.suspiciousIndicators.length,
        },
        'Docker sandbox analysis completed',
      );

      res.json({
        success: true,
        data: {
          report,
          riskScore: report.riskScore,
          submissionId: body.submissionId,
        },
        error: null,
        requestId: res.getHeader('X-Request-Id') as string,
        timestamp: new Date().toISOString(),
      });
    } catch (err) {
      next(err);
    }
  });

  // GET /jobs/:jobId - Get job status and results
  app.get('/jobs/:jobId', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { jobId } = req.params;
      const job = await dynamicAnalysisQueue.getJob(jobId as string);

      if (!job) {
        res.status(404).json({
          success: false,
          data: null,
          error: {
            code: 'NOT_FOUND',
            message: `Job not found: ${jobId as string}`,
          },
          requestId: res.getHeader('X-Request-Id') as string,
          timestamp: new Date().toISOString(),
        });
        return;
      }

      const state = await job.getState();
      const progress = typeof job.progress === 'number' ? job.progress : 0;

      const response: JobStatusResponse = {
        jobId: job.id ?? '',
        status: state,
        progress,
        result: state === 'completed' ? (job.returnvalue as DetonationResult) : null,
        failedReason: job.failedReason ?? null,
      };

      res.json({
        success: true,
        data: response,
        error: null,
        requestId: res.getHeader('X-Request-Id') as string,
        timestamp: new Date().toISOString(),
      });
    } catch (err) {
      next(err);
    }
  });

  // GET /queue/stats - Get queue statistics
  app.get('/queue/stats', async (_req: Request, res: Response, next: NextFunction) => {
    try {
      const [waiting, active, completed, failed, delayed] = await Promise.all([
        dynamicAnalysisQueue.getWaitingCount(),
        dynamicAnalysisQueue.getActiveCount(),
        dynamicAnalysisQueue.getCompletedCount(),
        dynamicAnalysisQueue.getFailedCount(),
        dynamicAnalysisQueue.getDelayedCount(),
      ]);

      res.json({
        success: true,
        data: {
          queue: 'dynamic-analysis',
          counts: { waiting, active, completed, failed, delayed },
          workerConcurrency: config.queue.concurrency,
        },
        error: null,
        requestId: res.getHeader('X-Request-Id') as string,
        timestamp: new Date().toISOString(),
      });
    } catch (err) {
      next(err);
    }
  });

  // GET /health
  app.get('/health', async (_req: Request, res: Response) => {
    const [waiting, active] = await Promise.all([
      dynamicAnalysisQueue.getWaitingCount(),
      dynamicAnalysisQueue.getActiveCount(),
    ]);

    res.json({
      status: 'healthy',
      service: 'dynamic-analysis',
      timestamp: new Date().toISOString(),
      queue: {
        waiting,
        active,
        concurrency: config.queue.concurrency,
      },
    });
  });

  // ── Error handler ───────────────────────────────────────────────────────

  app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
    // Sanitize error logging — avoid logging file contents or credentials
    const safeMessage = err.message?.slice(0, 500) ?? 'Unknown error';
    logger.error({ err: safeMessage }, 'Unhandled error');

    // Never expose internal error details to clients, even in development,
    // as they may contain file paths, Redis keys, or DB connection strings.
    res.status(500).json({
      success: false,
      data: null,
      error: {
        code: 'INTERNAL_ERROR',
        message: 'Internal server error',
      },
      requestId: res.getHeader('X-Request-Id') as string,
      timestamp: new Date().toISOString(),
    });
  });

  // ── Start server ────────────────────────────────────────────────────────

  const server = app.listen(config.port, config.host, () => {
    logger.info(
      {
        port: config.port,
        host: config.host,
        env: config.nodeEnv,
        workerConcurrency: config.queue.concurrency,
      },
      'FraudVault Dynamic Analysis Engine is running',
    );
  });

  // ── Graceful shutdown ───────────────────────────────────────────────────

  const shutdown = async (signal: string) => {
    logger.info({ signal }, 'Received shutdown signal, closing gracefully...');

    server.close(async () => {
      await worker.close();
      await dynamicAnalysisQueue.close();
      await pgPool.end();
      if (redisConnectPromise) {
        redisClient.disconnect();
      }
      logger.info('All connections closed. Goodbye.');
      process.exit(0);
    });

    setTimeout(() => {
      logger.error('Graceful shutdown timed out, forcing exit');
      process.exit(1);
    }, 15_000);
  };

  process.on('SIGTERM', () => void shutdown('SIGTERM'));
  process.on('SIGINT', () => void shutdown('SIGINT'));
}

main().catch((err) => {
  console.error('Fatal startup error:', err);
  process.exit(1);
});
