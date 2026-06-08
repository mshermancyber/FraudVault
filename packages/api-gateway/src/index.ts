import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import pino from 'pino';
import { loadConfig } from './config.js';
import { getPool, closePool } from './db.js';
import { getRedis, closeRedis } from './redis.js';
import { createRateLimiter } from './middleware/rateLimiter.js';
import { createRequestLogger } from './middleware/requestLogger.js';
import { createErrorHandler } from './middleware/errorHandler.js';
import { createRoutes } from './routes/index.js';

async function main(): Promise<void> {
  const config = loadConfig();

  const logger = pino({
    level: config.logLevel,
    transport:
      config.nodeEnv === 'development'
        ? { target: 'pino-pretty', options: { colorize: true } }
        : undefined,
  });

  const app = express();
  const pool = getPool(config);
  const redis = getRedis(config);

  // ── Global middleware ────────────────────────────────────
  app.set('trust proxy', 1);
  app.use(helmet());
  app.use(
    cors({
      origin: config.corsOrigins,
      credentials: true,
      maxAge: 86400,
    }),
  );
  app.use(express.json({ limit: '1mb' }));
  app.use(createRequestLogger(logger));
  app.use(createRateLimiter(config));

  // ── Health check (root-level for Docker/LB probes) ──────
  app.get('/health', (_req, res) => {
    res.json({ status: 'ok' });
  });

  // ── Routes ───────────────────────────────────────────────
  app.use('/api/v1', createRoutes(pool, redis, config));

  // ── Error handling ───────────────────────────────────────
  app.use(createErrorHandler(logger));

  // ── Start server ─────────────────────────────────────────
  const server = app.listen(config.port, config.host, () => {
    logger.info(
      { port: config.port, host: config.host, env: config.nodeEnv },
      'FraudVault API Gateway is running',
    );
  });

  // ── Graceful shutdown ────────────────────────────────────
  const shutdown = async (signal: string) => {
    logger.info({ signal }, 'Received shutdown signal, closing gracefully...');

    server.close(async () => {
      await closeRedis();
      await closePool();
      logger.info('All connections closed. Goodbye.');
      process.exit(0);
    });

    // Force exit after 10 seconds.
    setTimeout(() => {
      logger.error('Graceful shutdown timed out, forcing exit');
      process.exit(1);
    }, 10_000);
  };

  process.on('SIGTERM', () => void shutdown('SIGTERM'));
  process.on('SIGINT', () => void shutdown('SIGINT'));
}

main().catch((err) => {
  console.error('Fatal startup error:', err);
  process.exit(1);
});
