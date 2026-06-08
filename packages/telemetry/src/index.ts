import express from 'express';
import pino from 'pino';
import { loadConfig } from './config.js';
import { registry } from './metrics.js';
import { checkAllHealth } from './healthCheck.js';

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
  app.use(express.json({ limit: '256kb' }));

  const INTERNAL_KEY = process.env['INTERNAL_API_KEY'];
  if (INTERNAL_KEY) {
    app.use((req, res, next) => {
      if (req.path === '/health') return next();
      if (req.headers['x-internal-api-key'] !== INTERNAL_KEY) {
        res.status(401).json({ error: 'Unauthorized' });
        return;
      }
      next();
    });
  }

  // ── Routes ─────────────────────────────────────────────────────────────

  app.get('/metrics', async (_req, res) => {
    try {
      const metrics = await registry.metrics();
      res.setHeader('Content-Type', registry.contentType);
      res.send(metrics);
    } catch (err) {
      logger.error({ err }, 'Failed to collect metrics');
      res.status(500).send('Failed to collect metrics');
    }
  });

  app.get('/health', async (_req, res) => {
    try {
      const health = await checkAllHealth(config);

      const statusCode = health.status === 'healthy' ? 200 : health.status === 'degraded' ? 200 : 503;

      res.status(statusCode).json({
        status: health.status,
        service: 'telemetry',
        components: health.components,
        timestamp: health.timestamp,
      });
    } catch (err) {
      logger.error({ err }, 'Health check failed');
      res.status(503).json({
        status: 'unhealthy',
        service: 'telemetry',
        components: [],
        timestamp: new Date().toISOString(),
      });
    }
  });

  // ── Start server ───────────────────────────────────────────────────────

  const server = app.listen(config.port, config.host, () => {
    logger.info(
      { port: config.port, host: config.host, env: config.nodeEnv },
      'FraudVault Telemetry Service is running',
    );
  });

  // ── Graceful shutdown ──────────────────────────────────────────────────

  const shutdown = async (signal: string) => {
    logger.info({ signal }, 'Received shutdown signal, closing gracefully...');

    server.close(() => {
      logger.info('Server closed. Goodbye.');
      process.exit(0);
    });

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
