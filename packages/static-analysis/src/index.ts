import express from 'express';
import * as dns from 'node:dns/promises';
import pino from 'pino';
import pg from 'pg';
import Redis from 'ioredis';
import { Worker, type Job, type ConnectionOptions } from 'bullmq';
import { v4 as uuidv4 } from 'uuid';
import {
  QUEUE_NAMES,
  type StaticAnalysisResult,
  type SectionInfo,
  type ExtractedString,
  type CertificateInfo,
  type IOC,
  IOCType,
  JobStatus,
} from '@scanboy/shared';

import { loadConfig, type StaticAnalysisConfig } from './config.js';
import { extractMetadata } from './analyzers/metadata.js';
import { extractStrings } from './analyzers/strings.js';
import { analyzeEntropy } from './analyzers/entropy.js';
import { analyzePE } from './analyzers/pe.js';
import { analyzeELF } from './analyzers/elf.js';
import { analyzeOffice } from './analyzers/office.js';
import { analyzePDF } from './analyzers/pdf.js';
import { analyzeScript } from './analyzers/script.js';

const { Pool } = pg;

// ── Job data shape (matches what the orchestrator enqueues) ──────────────────

interface StaticAnalysisJobData {
  submissionId: string;
  sha256: string;
  storagePath: string;
  userId: string;
}

// ── Run all analyzers and compose the StaticAnalysisResult ───────────────────

async function runAnalysis(
  filePath: string,
  submissionId: string,
  config: StaticAnalysisConfig,
  logger: pino.Logger,
): Promise<StaticAnalysisResult> {
  logger.info({ submissionId, filePath }, 'Starting static analysis');

  // Run all analyzers in parallel where possible.
  const [metadata, strings, entropy, pe, elf, office, pdf, script] = await Promise.all([
    extractMetadata(filePath),
    extractStrings(filePath, config.analysis.minStringLength, config.analysis.maxStrings),
    analyzeEntropy(filePath, config.analysis.highEntropyThreshold),
    analyzePE(filePath),
    analyzeELF(filePath),
    analyzeOffice(filePath),
    analyzePDF(filePath),
    analyzeScript(filePath),
  ]);

  logger.info(
    {
      submissionId,
      fileSize: metadata.fileSize,
      mimeType: metadata.mimeType,
      isPE: pe.isPE,
      isELF: elf.isELF,
      isOffice: office.isOfficeDocument,
      isPDF: pdf.isPDF,
      isScript: script.isScript,
      overallEntropy: entropy.overallEntropy,
    },
    'All analyzers completed',
  );

  // ── Determine dominant file type label ─────────────────────
  let fileType = metadata.mimeType;
  let magic = metadata.fileTypeLabel;

  if (pe.isPE) {
    fileType = pe.header?.is64Bit ? 'PE32+ executable' : 'PE32 executable';
    magic = `${fileType} (${pe.header?.subsystem ?? 'unknown'})`;
  } else if (elf.isELF) {
    fileType = `ELF ${String(elf.header?.elfClass ?? '')} ${elf.header?.machine ?? ''}`;
    magic = `${fileType} (${elf.header?.type ?? 'unknown'})`;
  } else if (office.isOfficeDocument) {
    fileType = office.format === 'ole' ? 'OLE Compound Document' : 'OOXML Office Document';
    magic = `${fileType} (macros: ${String(office.hasMacros)})`;
  } else if (pdf.isPDF) {
    fileType = `PDF ${pdf.version ?? ''}`;
    magic = `PDF document v${pdf.version ?? 'unknown'}`;
  } else if (script.isScript) {
    fileType = `Script (${script.language})`;
    magic = `${script.language} script`;
  }

  // ── Packer detection ───────────────────────────────────────
  let packerName: string | null = null;
  if (entropy.isPacked) {
    // Heuristic: check PE section names for known packers.
    if (pe.isPE) {
      const sectionNames = pe.sections.map((s) => s.name.toLowerCase());
      if (sectionNames.includes('upx0') || sectionNames.includes('upx1')) {
        packerName = 'UPX';
      } else if (sectionNames.includes('.aspack')) {
        packerName = 'ASPack';
      } else if (sectionNames.includes('.nsp0') || sectionNames.includes('.nsp1')) {
        packerName = 'NsPack';
      } else if (sectionNames.includes('.themida')) {
        packerName = 'Themida';
      } else if (sectionNames.includes('.vmp0') || sectionNames.includes('.vmp1')) {
        packerName = 'VMProtect';
      } else {
        packerName = 'Unknown packer (high entropy)';
      }
    } else {
      packerName = 'Possible packing/encryption detected';
    }
  }

  // ── Build section info ─────────────────────────────────────
  let sections: SectionInfo[] = [];
  if (pe.isPE) {
    sections = pe.sections.map((s) => ({
      name: s.name,
      virtualSize: s.virtualSize,
      rawSize: s.rawSize,
      entropy: s.entropy,
      md5: s.md5,
    }));
  } else if (elf.isELF) {
    sections = elf.sections
      .filter((s) => s.size > 0 && s.typeRaw !== 0)
      .map((s) => ({
        name: s.name,
        virtualSize: s.size,
        rawSize: s.size,
        entropy: s.entropy,
        md5: '', // ELF parser does not hash sections individually
      }));
  } else {
    sections = entropy.sections.map((s) => ({
      name: s.name,
      virtualSize: s.size,
      rawSize: s.size,
      entropy: s.entropy,
      md5: '',
    }));
  }

  // ── Build extracted strings (first 500 for the result) ─────
  const extractedStrings: ExtractedString[] = strings.strings
    .slice(0, 500)
    .map((s) => ({
      value: s.value,
      encoding: s.encoding,
      offset: s.offset,
      category: s.category,
    }));

  // ── Build import/export lists ──────────────────────────────
  let imports: string[] = [];
  let exports: string[] = [];
  if (pe.isPE) {
    imports = pe.importedFunctions;
    exports = pe.exportedFunctions;
  } else if (elf.isELF) {
    imports = elf.symbols
      .filter((s) => s.section === 'UND' && s.name.length > 0)
      .map((s) => s.name);
    exports = elf.symbols
      .filter((s) => s.section !== 'UND' && s.binding !== 'STB_LOCAL')
      .map((s) => s.name);
  }

  // ── Build certificate info ─────────────────────────────────
  const certificates: CertificateInfo[] = [];
  if (pe.certificate?.hasCertificate) {
    certificates.push({
      subject: 'Authenticode signature present',
      issuer: '',
      serial: '',
      validFrom: '',
      validTo: '',
      isValid: false, // We do not verify the chain here
    });
  }

  // ── Extract IOCs from strings ──────────────────────────────
  const iocs: IOC[] = [];
  const now = new Date().toISOString();

  const TRUSTED_DOMAIN_PATTERNS = [
    /digicert\.com$/i, /globalsign\.com$/i, /verisign\.com$/i, /symantec\.com$/i,
    /letsencrypt\.org$/i, /comodo\.com$/i, /sectigo\.com$/i, /entrust\.net$/i,
    /microsoft\.com$/i, /windows\.com$/i, /windowsupdate\.com$/i, /office\.com$/i,
    /google\.com$/i, /googleapis\.com$/i, /gstatic\.com$/i, /android\.com$/i,
    /apple\.com$/i, /icloud\.com$/i, /mozilla\.org$/i, /mozilla\.com$/i,
    /cisco\.com$/i, /webex\.com$/i, /adobe\.com$/i,
    /github\.com$/i, /githubusercontent\.com$/i,
    /cloudflare\.com$/i, /akamai\.net$/i, /amazonaws\.com$/i,
    /w3\.org$/i, /xmlsoap\.org$/i, /openxmlformats\.org$/i,
  ];
  function isTrustedDomain(urlOrDomain: string): boolean {
    try {
      const host = urlOrDomain.includes('://') ? new URL(urlOrDomain).hostname : urlOrDomain;
      return TRUSTED_DOMAIN_PATTERNS.some(p => p.test(host));
    } catch { return false; }
  }

  // DNS-resolve all domains and URL hostnames — discard NXDOMAIN before creating IOCs
  const resolvedDomainSet = new Set<string>();
  const allHostnames = [...strings.domains.map(d => d.toLowerCase())];
  for (const u of strings.urls) {
    try { allHostnames.push(new URL(u).hostname.toLowerCase()); } catch { /* skip */ }
  }
  await Promise.allSettled(
    [...new Set(allHostnames)].map(async (d) => {
      try { await dns.resolve(d); resolvedDomainSet.add(d); } catch { /* NXDOMAIN */ }
    }),
  );

  for (const url of strings.urls) {
    let host: string;
    try { host = new URL(url).hostname.toLowerCase(); } catch { continue; }
    if (!resolvedDomainSet.has(host)) continue;
    const trusted = isTrustedDomain(url);
    iocs.push({
      id: uuidv4(),
      submissionId,
      type: IOCType.URL,
      value: url,
      context: trusted ? 'Known infrastructure (certificate/vendor)' : 'Extracted from file strings',
      confidence: trusted ? 0.1 : 0.6,
      source: 'static_analysis',
      firstSeenAt: now,
      createdAt: now,
    });
  }

  for (const ip of strings.ipv4Addresses) {
    // Skip private/loopback/bogus IPs
    if (ip.startsWith('127.') || ip.startsWith('0.') ||
        ip.startsWith('10.') || ip.startsWith('192.168.') ||
        ip.startsWith('169.254.') || /^172\.(1[6-9]|2\d|3[01])\./.test(ip)) {
      continue;
    }
    // Skip IPs with low first octet (1-9) — almost always version numbers (e.g. 6.0.0.0, 1.0.0.0)
    const firstOctet = parseInt(ip.split('.')[0] ?? '', 10);
    if (firstOctet >= 1 && firstOctet <= 9) continue;
    // Skip IPs where all octets except the first are zero — version patterns like X.0.0.0
    const octets = ip.split('.');
    if (octets[1] === '0' && octets[2] === '0' && octets[3] === '0') continue;
    iocs.push({
      id: uuidv4(),
      submissionId,
      type: IOCType.IPv4,
      value: ip,
      context: 'Extracted from file strings',
      confidence: 0.5,
      source: 'static_analysis',
      firstSeenAt: now,
      createdAt: now,
    });
  }

  for (const email of strings.emailAddresses) {
    // Skip garbage matches — require 3+ char local part, 4+ char domain
    const atIdx = email.indexOf('@');
    if (atIdx < 3 || email.length - atIdx < 5) continue;
    iocs.push({
      id: uuidv4(),
      submissionId,
      type: IOCType.Email,
      value: email,
      context: 'Extracted from file strings',
      confidence: 0.4,
      source: 'static_analysis',
      firstSeenAt: now,
      createdAt: now,
    });
  }

  for (const domain of strings.domains) {
    if (!resolvedDomainSet.has(domain.toLowerCase())) continue;
    const trusted = isTrustedDomain(domain);
    iocs.push({
      id: uuidv4(),
      submissionId,
      type: IOCType.Domain,
      value: domain,
      context: trusted ? 'Known infrastructure (certificate/vendor)' : 'Extracted from file strings',
      confidence: trusted ? 0.1 : 0.4,
      source: 'static_analysis',
      firstSeenAt: now,
      createdAt: now,
    });
  }

  for (const path of strings.filePaths) {
    iocs.push({
      id: uuidv4(),
      submissionId,
      type: IOCType.FilePath,
      value: path,
      context: 'Extracted from file strings',
      confidence: 0.3,
      source: 'static_analysis',
      firstSeenAt: now,
      createdAt: now,
    });
  }

  for (const regKey of strings.registryKeys) {
    iocs.push({
      id: uuidv4(),
      submissionId,
      type: IOCType.RegistryKey,
      value: regKey,
      context: 'Extracted from file strings',
      confidence: 0.4,
      source: 'static_analysis',
      firstSeenAt: now,
      createdAt: now,
    });
  }

  // Cap IOCs.
  const cappedIocs = iocs.slice(0, 1000);

  // ── Assemble the result ────────────────────────────────────
  const result: StaticAnalysisResult & { versionInfo?: Record<string, string> | null; suspiciousImports?: unknown[] } = {
    submissionId,
    fileType,
    magic,
    entropy: entropy.overallEntropy,
    isPacked: entropy.isPacked,
    packerName,
    imports,
    exports,
    sections,
    strings: extractedStrings,
    certificates,
    iocs: cappedIocs,
    attackTechniques: [], // Populated by the detection engine downstream
  };

  if (pe.isPE) {
    result.versionInfo = pe.versionInfo as Record<string, string> | null;
    result.suspiciousImports = pe.suspiciousImports;
  }

  return result;
}

// ── Express server ───────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const config = loadConfig();

  const logger = pino({
    level: config.logLevel,
    transport:
      config.nodeEnv === 'development'
        ? { target: 'pino-pretty', options: { colorize: true } }
        : undefined,
  });

  // ── PostgreSQL ──────────────────────────────────────────────
  const pool = new Pool({
    host: config.postgres.host,
    port: config.postgres.port,
    database: config.postgres.database,
    user: config.postgres.user,
    password: config.postgres.password,
    max: config.postgres.poolMax,
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 5_000,
  });

  pool.on('error', (err) => {
    logger.error({ err }, 'Unexpected PostgreSQL pool error');
  });

  try {
    await pool.query('SELECT 1');
    logger.info('PostgreSQL connection established');
  } catch (err) {
    logger.fatal({ err }, 'Failed to connect to PostgreSQL');
    process.exit(1);
  }

  // ── Redis ───────────────────────────────────────────────────
  const redisConnection: ConnectionOptions = {
    host: config.redis.host,
    port: config.redis.port,
    password: config.redis.password,
    maxRetriesPerRequest: null,
  };

  const redis = new Redis({
    host: config.redis.host,
    port: config.redis.port,
    password: config.redis.password,
    maxRetriesPerRequest: 3,
    retryStrategy(times: number) {
      return Math.min(times * 200, 5_000);
    },
  });

  redis.on('error', (err) => {
    logger.error({ err }, 'Redis client error');
  });

  // ── BullMQ Worker ──────────────────────────────────────────
  const worker = new Worker<StaticAnalysisJobData>(
    QUEUE_NAMES.STATIC_ANALYSIS,
    async (job: Job<StaticAnalysisJobData>) => {
      const { submissionId, storagePath } = job.data;
      const jobLogger = logger.child({ submissionId, jobId: job.id });

      jobLogger.info('Processing static analysis job');

      // Update job status in DB.
      await pool.query(
        `UPDATE analysis_jobs SET status = $1, started_at = NOW(), updated_at = NOW()
         WHERE submission_id = $2 AND job_type = 'static_analysis' AND status != 'cancelled'`,
        [JobStatus.Running, submissionId],
      );

      try {
        const result = await runAnalysis(storagePath, submissionId, config, jobLogger);

        // Store results in the database.
        await pool.query(
          `UPDATE analysis_jobs
           SET status = $1, result = $2, completed_at = NOW(), updated_at = NOW()
           WHERE submission_id = $3 AND job_type = 'static_analysis'`,
          [JobStatus.Completed, JSON.stringify(result), submissionId],
        );

        // Publish results to Redis for the orchestrator to pick up.
        await redis.publish(
          'static-analysis:completed',
          JSON.stringify({
            submissionId,
            status: 'completed',
            result,
          }),
        );

        jobLogger.info('Static analysis completed successfully');
        return result;
      } catch (err) {
        jobLogger.error({ err }, 'Static analysis failed');

        await pool.query(
          `UPDATE analysis_jobs
           SET status = $1, error_message = $2, completed_at = NOW(), updated_at = NOW()
           WHERE submission_id = $3 AND job_type = 'static_analysis'`,
          [JobStatus.Failed, err instanceof Error ? err.message : 'Unknown error', submissionId],
        );

        await redis.publish(
          'static-analysis:completed',
          JSON.stringify({
            submissionId,
            status: 'failed',
            error: err instanceof Error ? err.message : 'Unknown error',
          }),
        );

        throw err;
      }
    },
    {
      connection: redisConnection,
      concurrency: config.worker.concurrency,
      limiter: {
        max: config.worker.concurrency * 2,
        duration: 1_000,
      },
    },
  );

  worker.on('failed', (job, err) => {
    logger.error(
      { jobId: job?.id, submissionId: job?.data.submissionId, err },
      'Worker job failed',
    );
  });

  worker.on('completed', (job) => {
    logger.info(
      { jobId: job.id, submissionId: job.data.submissionId },
      'Worker job completed',
    );
  });

  logger.info(
    { queue: QUEUE_NAMES.STATIC_ANALYSIS, concurrency: config.worker.concurrency },
    'BullMQ worker started',
  );

  // ── Express app ──────────────────────────────────────────────
  const app = express();
  app.use(express.json({ limit: '1mb' }));

  const INTERNAL_KEY = process.env['INTERNAL_API_KEY'];
  if (INTERNAL_KEY) {
    app.use((req: express.Request, res: express.Response, next: express.NextFunction) => {
      if (req.path === '/health') return next();
      if (req.headers['x-internal-api-key'] !== INTERNAL_KEY) {
        res.status(401).json({ error: 'Unauthorized' });
        return;
      }
      next();
    });
  }

  // Health check.
  app.get('/health', (_req, res) => {
    res.json({
      status: 'ok',
      service: 'static-analysis',
      timestamp: new Date().toISOString(),
      worker: {
        running: worker.isRunning(),
      },
    });
  });

  // POST /analyze - direct analysis trigger (used by orchestrator or testing).
  app.post('/analyze', async (req, res) => {
    const { submission_id, submissionId: altSubId, artifact_path, storagePath, sha256 } = req.body as {
      submission_id?: string;
      submissionId?: string;
      artifact_path?: string;
      storagePath?: string;
      sha256?: string;
    };

    const subId = submission_id ?? altSubId;
    const artPath = artifact_path ?? storagePath;

    if (!subId || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(subId)) {
      res.status(400).json({
        success: false,
        error: { code: 'INVALID_INPUT', message: 'submission_id must be a valid UUID' },
      });
      return;
    }

    const requestId = uuidv4();
    const reqLogger = logger.child({ requestId, submissionId: subId });
    reqLogger.info({ artPath, sha256 }, 'Direct analysis request received');

    // If storagePath starts with "redis:", fetch file from Redis and write to temp
    let resolvedPath = artPath ?? '';
    if (!resolvedPath.startsWith('redis:')) {
      const { resolve, normalize } = await import('node:path');
      const normalizedPath = resolve(normalize(resolvedPath));
      const ALLOWED_PREFIXES = ['/tmp/scanboy-', '/tmp/scanboy/'];
      if (!ALLOWED_PREFIXES.some(p => normalizedPath.startsWith(p))) {
        res.status(403).json({
          success: false,
          error: { code: 'PATH_NOT_ALLOWED', message: 'Artifact path is outside allowed directories' },
        });
        return;
      }
      resolvedPath = normalizedPath;
    }
    if (resolvedPath.startsWith('redis:')) {
      const redisKey = resolvedPath.slice(6);
      const REDIS_FILE_KEY_RE = /^scanboy:file:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
      if (!REDIS_FILE_KEY_RE.test(redisKey)) {
        res.status(403).json({
          success: false,
          error: { code: 'INVALID_REDIS_KEY', message: 'Redis key must match scanboy:file:<uuid> pattern' },
        });
        return;
      }
      reqLogger.info({ redisKey }, 'Fetching file from Redis');
      const base64Data = await redis.get(redisKey);
      if (!base64Data) {
        res.status(404).json({ success: false, error: { code: 'FILE_NOT_FOUND', message: 'File not found in Redis' } });
        return;
      }
      const tmpDir = `/tmp/scanboy-${subId}`;
      const fs = await import('node:fs/promises');
      await fs.mkdir(tmpDir, { recursive: true });
      resolvedPath = `${tmpDir}/sample`;
      await fs.writeFile(resolvedPath, Buffer.from(base64Data, 'base64'));
      reqLogger.info({ resolvedPath, size: base64Data.length }, 'File written to temp path');
    }

    try {
      const result = await runAnalysis(resolvedPath, subId, config, reqLogger);

      // Publish to Redis.
      await redis.publish(
        'static-analysis:completed',
        JSON.stringify({
          submissionId: subId,
          status: 'completed',
          result,
        }),
      );

      res.json({
        success: true,
        data: result,
        error: null,
        requestId,
        timestamp: new Date().toISOString(),
      });
    } catch (err) {
      reqLogger.error({ err }, 'Analysis failed');
      res.status(500).json({
        success: false,
        data: null,
        error: {
          code: 'ANALYSIS_FAILED',
          message: err instanceof Error ? err.message : 'Unknown error',
        },
        requestId,
        timestamp: new Date().toISOString(),
      });
    } finally {
      if (resolvedPath.startsWith('/tmp/scanboy-')) {
        const fs = await import('node:fs/promises');
        await fs.rm(resolvedPath.replace(/\/sample$/, ''), { recursive: true, force: true }).catch(() => {});
      }
    }
  });

  // ── Start server ──────────────────────────────────────────────
  const server = app.listen(config.port, config.host, () => {
    logger.info(
      { port: config.port, host: config.host, env: config.nodeEnv },
      'FraudVault Static Analysis Engine is running',
    );
  });

  // ── Graceful shutdown ─────────────────────────────────────────
  const shutdown = async (signal: string) => {
    logger.info({ signal }, 'Received shutdown signal, closing gracefully...');

    // Stop accepting new HTTP requests.
    server.close();

    // Close the BullMQ worker (waits for running jobs to finish).
    await worker.close();

    // Close Redis and PostgreSQL.
    await redis.quit();
    await pool.end();

    logger.info('Static Analysis Engine shut down cleanly');
    process.exit(0);
  };

  // Force exit after 30 seconds if graceful shutdown stalls.
  const forceExit = () => {
    setTimeout(() => {
      logger.error('Graceful shutdown timed out, forcing exit');
      process.exit(1);
    }, 30_000);
  };

  process.on('SIGTERM', () => { forceExit(); void shutdown('SIGTERM'); });
  process.on('SIGINT', () => { forceExit(); void shutdown('SIGINT'); });
}

main().catch((err) => {
  console.error('Fatal startup error:', err);
  process.exit(1);
});
