import express, { type Request, type Response, type NextFunction } from 'express';
import pino from 'pino';
import { v4 as uuidv4 } from 'uuid';
import { InternetMode, SandboxStatus } from '@scanboy/shared';
import { loadConfig } from './config.js';
import { QemuProvider } from './providers/qemu.js';
import { DockerProvider } from './providers/docker.js';
import type { SandboxProvider, SandboxConfig } from './providers/base.js';
import { PoolManager } from './services/poolManager.js';
import { NetworkIsolationService } from './services/networkIsolation.js';

// ── Request body types ──────────────────────────────────────────────────────

interface ProvisionRequestBody {
  readonly name: string;
  readonly provider: 'qemu' | 'docker';
  readonly os: string;
  readonly osVersion: string;
  readonly architecture: string;
  readonly memoryMb?: number;
  readonly cpuCores?: number;
  readonly baseImage: string;
  readonly internetMode?: InternetMode;
  readonly maxExecutionSeconds?: number;
}

interface SnapshotRequestBody {
  readonly label?: string;
}

interface RestoreRequestBody {
  readonly snapshotId: string;
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

  // Initialize providers
  const qemuProvider = new QemuProvider(config.qemu);
  const dockerProvider = new DockerProvider(config.docker);
  const providers = new Map<string, SandboxProvider>([
    ['qemu', qemuProvider],
    ['docker', dockerProvider],
  ]);

  // Initialize pool manager
  const poolManager = new PoolManager(config.pool, logger);
  poolManager.start();

  // Initialize network isolation
  const networkIsolation = new NetworkIsolationService(logger);
  await networkIsolation.initialize();

  // ── Express app ─────────────────────────────────────────────────────────

  const app = express();
  app.use(express.json());

  // Request ID middleware
  app.use((_req: Request, res: Response, next: NextFunction) => {
    const requestId = uuidv4();
    res.setHeader('X-Request-Id', requestId);
    next();
  });

  const INTERNAL_KEY = process.env['INTERNAL_API_KEY'];
  app.use((req: Request, res: Response, next: NextFunction) => {
    if (req.path === '/health') return next();
    if (!INTERNAL_KEY || req.headers['x-internal-api-key'] !== INTERNAL_KEY) {
      res.status(401).json({
        success: false,
        data: null,
        error: { code: 'UNAUTHORIZED', message: 'Invalid or missing API key' },
        requestId: res.getHeader('X-Request-Id') as string,
        timestamp: new Date().toISOString(),
      });
      return;
    }
    next();
  });

  // ── Routes ──────────────────────────────────────────────────────────────

  // GET /sandboxes - List sandbox environments
  app.get('/sandboxes', (_req: Request, res: Response) => {
    const instances = poolManager.listInstances();
    const stats = poolManager.getStats();

    res.json({
      success: true,
      data: {
        instances,
        stats,
      },
      error: null,
      requestId: res.getHeader('X-Request-Id') as string,
      timestamp: new Date().toISOString(),
    });
  });

  // POST /sandboxes/provision - Provision a new sandbox
  app.post('/sandboxes/provision', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const body = req.body as ProvisionRequestBody;

      if (!body.name || !body.provider || !body.os || !body.baseImage) {
        res.status(400).json({
          success: false,
          data: null,
          error: {
            code: 'INVALID_REQUEST',
            message: 'Missing required fields: name, provider, os, baseImage',
          },
          requestId: res.getHeader('X-Request-Id') as string,
          timestamp: new Date().toISOString(),
        });
        return;
      }

      const SAFE_FIELD_RE = /^[a-zA-Z0-9][a-zA-Z0-9._\-]{0,127}$/;
      if (!SAFE_FIELD_RE.test(body.name) || !SAFE_FIELD_RE.test(body.os) ||
          (body.architecture && !SAFE_FIELD_RE.test(body.architecture))) {
        res.status(400).json({
          success: false,
          data: null,
          error: {
            code: 'INVALID_REQUEST',
            message: 'name, os, and architecture must be alphanumeric (max 128 chars)',
          },
          requestId: res.getHeader('X-Request-Id') as string,
          timestamp: new Date().toISOString(),
        });
        return;
      }

      if (!/^[a-zA-Z0-9][a-zA-Z0-9._\-/:]{0,255}$/.test(body.baseImage) || /\.\./.test(body.baseImage)) {
        res.status(400).json({
          success: false,
          data: null,
          error: {
            code: 'INVALID_REQUEST',
            message: 'Invalid baseImage: must be alphanumeric with ._-/: only, no path traversal',
          },
          requestId: res.getHeader('X-Request-Id') as string,
          timestamp: new Date().toISOString(),
        });
        return;
      }

      if (typeof body.provider !== 'string' || !['qemu', 'docker'].includes(body.provider)) {
        res.status(400).json({
          success: false,
          data: null,
          error: {
            code: 'INVALID_PROVIDER',
            message: 'Supported providers: qemu, docker',
          },
          requestId: res.getHeader('X-Request-Id') as string,
          timestamp: new Date().toISOString(),
        });
        return;
      }
      const provider = providers.get(body.provider);
      if (!provider) {
        res.status(400).json({
          success: false,
          data: null,
          error: {
            code: 'INVALID_PROVIDER',
            message: 'Supported providers: qemu, docker',
          },
          requestId: res.getHeader('X-Request-Id') as string,
          timestamp: new Date().toISOString(),
        });
        return;
      }

      const MAX_MEMORY_MB = 8192;
      const MAX_CPU_CORES = 4;

      const sandboxConfig: SandboxConfig = {
        name: body.name,
        os: body.os,
        osVersion: body.osVersion ?? '',
        architecture: body.architecture ?? 'x86_64',
        memoryMb: Math.min(body.memoryMb ?? config.qemu.defaultMemoryMb, MAX_MEMORY_MB),
        cpuCores: Math.min(body.cpuCores ?? config.qemu.defaultCpuCores, MAX_CPU_CORES),
        baseImage: body.baseImage,
        internetMode: body.internetMode ?? InternetMode.Disabled,
        maxExecutionSeconds: Math.min(body.maxExecutionSeconds ?? 300, 600),
      };

      const requesterId = uuidv4();
      const result = await poolManager.checkout(provider, sandboxConfig, requesterId);

      // Apply network isolation
      if (result.instance.ipAddress) {
        await networkIsolation.applyPolicy({
          instanceId: result.instance.instanceId,
          tapInterface: `tap-${result.instance.instanceId.slice(0, 8)}`,
          internetMode: sandboxConfig.internetMode,
          allowedDnsServers: ['8.8.8.8', '8.8.4.4'],
          allowedHosts: [],
        });
      }

      res.status(201).json({
        success: true,
        data: {
          instanceId: result.instance.instanceId,
          provider: result.instance.provider,
          status: result.instance.status,
          ipAddress: result.instance.ipAddress,
          createdAt: result.instance.createdAt,
        },
        error: null,
        requestId: res.getHeader('X-Request-Id') as string,
        timestamp: new Date().toISOString(),
      });
    } catch (err) {
      next(err);
    }
  });

  // POST /sandboxes/:id/destroy - Destroy a sandbox
  app.post('/sandboxes/:id/destroy', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { id } = req.params;

      // Remove network isolation rules
      await networkIsolation.removePolicy(id as string);

      // Destroy the pool instance
      await poolManager.destroyPoolInstance(id as string);

      res.json({
        success: true,
        data: { instanceId: id, status: SandboxStatus.Offline },
        error: null,
        requestId: res.getHeader('X-Request-Id') as string,
        timestamp: new Date().toISOString(),
      });
    } catch (err) {
      next(err);
    }
  });

  // GET /sandboxes/:id/status - Get sandbox status
  app.get('/sandboxes/:id/status', (_req: Request, res: Response) => {
    const { id } = _req.params;
    const instances = poolManager.listInstances();
    const instance = instances.find((i) => i.instanceId === id);

    if (!instance) {
      res.status(404).json({
        success: false,
        data: null,
        error: {
          code: 'NOT_FOUND',
          message: `Sandbox not found: ${id as string}`,
        },
        requestId: res.getHeader('X-Request-Id') as string,
        timestamp: new Date().toISOString(),
      });
      return;
    }

    res.json({
      success: true,
      data: instance,
      error: null,
      requestId: res.getHeader('X-Request-Id') as string,
      timestamp: new Date().toISOString(),
    });
  });

  // POST /sandboxes/:id/snapshot - Create snapshot
  app.post('/sandboxes/:id/snapshot', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { id } = req.params;
      const _snapshotBody = req.body as SnapshotRequestBody;
      void _snapshotBody;
      const instances = poolManager.listInstances();
      const instance = instances.find((i) => i.instanceId === id);

      if (!instance) {
        res.status(404).json({
          success: false,
          data: null,
          error: {
            code: 'NOT_FOUND',
            message: `Sandbox not found: ${id as string}`,
          },
          requestId: res.getHeader('X-Request-Id') as string,
          timestamp: new Date().toISOString(),
        });
        return;
      }

      const provider = providers.get(instance.provider);
      if (!provider) {
        res.status(500).json({
          success: false,
          data: null,
          error: {
            code: 'PROVIDER_ERROR',
            message: `Provider not found: ${instance.provider}`,
          },
          requestId: res.getHeader('X-Request-Id') as string,
          timestamp: new Date().toISOString(),
        });
        return;
      }

      const snapshotId = await provider.snapshot(id as string);

      res.status(201).json({
        success: true,
        data: { instanceId: id, snapshotId },
        error: null,
        requestId: res.getHeader('X-Request-Id') as string,
        timestamp: new Date().toISOString(),
      });
    } catch (err) {
      next(err);
    }
  });

  // POST /sandboxes/:id/restore - Restore from snapshot
  app.post('/sandboxes/:id/restore', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { id } = req.params;
      const body = req.body as RestoreRequestBody;

      if (!body.snapshotId) {
        res.status(400).json({
          success: false,
          data: null,
          error: {
            code: 'INVALID_REQUEST',
            message: 'Missing required field: snapshotId',
          },
          requestId: res.getHeader('X-Request-Id') as string,
          timestamp: new Date().toISOString(),
        });
        return;
      }

      const instances = poolManager.listInstances();
      const instance = instances.find((i) => i.instanceId === id);

      if (!instance) {
        res.status(404).json({
          success: false,
          data: null,
          error: {
            code: 'NOT_FOUND',
            message: `Sandbox not found: ${id as string}`,
          },
          requestId: res.getHeader('X-Request-Id') as string,
          timestamp: new Date().toISOString(),
        });
        return;
      }

      const provider = providers.get(instance.provider);
      if (!provider) {
        res.status(500).json({
          success: false,
          data: null,
          error: {
            code: 'PROVIDER_ERROR',
            message: `Provider not found: ${instance.provider}`,
          },
          requestId: res.getHeader('X-Request-Id') as string,
          timestamp: new Date().toISOString(),
        });
        return;
      }

      await provider.restore(id as string, body.snapshotId);

      res.json({
        success: true,
        data: { instanceId: id, snapshotId: body.snapshotId, status: SandboxStatus.Running },
        error: null,
        requestId: res.getHeader('X-Request-Id') as string,
        timestamp: new Date().toISOString(),
      });
    } catch (err) {
      next(err);
    }
  });

  // GET /health
  app.get('/health', (_req: Request, res: Response) => {
    const stats = poolManager.getStats();

    res.json({
      status: 'healthy',
      service: 'sandbox-manager',
      timestamp: new Date().toISOString(),
      pool: stats,
    });
  });

  // ── Error handler ───────────────────────────────────────────────────────

  app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
    logger.error({ err: err.message, stack: err.stack }, 'Unhandled error');

    res.status(500).json({
      success: false,
      data: null,
      error: {
        code: 'INTERNAL_ERROR',
        message: config.nodeEnv === 'development' ? err.message : 'Internal server error',
      },
      requestId: res.getHeader('X-Request-Id') as string,
      timestamp: new Date().toISOString(),
    });
  });

  // ── Start server ────────────────────────────────────────────────────────

  const server = app.listen(config.port, config.host, () => {
    logger.info(
      { port: config.port, host: config.host, env: config.nodeEnv },
      'FraudVault Sandbox Manager is running',
    );
  });

  // ── Graceful shutdown ───────────────────────────────────────────────────

  const shutdown = async (signal: string) => {
    logger.info({ signal }, 'Received shutdown signal, closing gracefully...');

    server.close(async () => {
      await poolManager.stop();
      await networkIsolation.flushAll();
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
