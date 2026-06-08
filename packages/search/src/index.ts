import express from 'express';
import pino from 'pino';
import { loadConfig } from './config.js';
import {
  getElasticsearchClient,
  closeElasticsearch,
  ensureIndexes,
} from './elasticsearch.js';
import { SearchService } from './services/searchService.js';
import { CorrelationService } from './services/correlationService.js';
import { HuntingService } from './services/huntingService.js';

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
  app.use(express.json({ limit: '1mb' }));

  const es = getElasticsearchClient(config);

  // Ensure indexes exist
  try {
    await ensureIndexes(es);
    logger.info('Elasticsearch indexes verified');
  } catch (err) {
    logger.warn({ err }, 'Failed to verify Elasticsearch indexes (will retry on demand)');
  }

  const INTERNAL_KEY = process.env['INTERNAL_API_KEY'];
  if (INTERNAL_KEY) {
    app.use((req, res, next) => {
      if (req.path === '/health') return next();
      if (req.headers['x-internal-api-key'] !== INTERNAL_KEY) {
        res.status(401).json({ success: false, error: 'Unauthorized' });
        return;
      }
      next();
    });
  }

  const searchService = new SearchService(es);
  const correlationService = new CorrelationService(es);
  const huntingService = new HuntingService(es);

  // ── Routes ─────────────────────────────────────────────────────────────

  app.get('/health', async (_req, res) => {
    try {
      await es.ping();
      res.json({ status: 'healthy', service: 'search', timestamp: new Date().toISOString() });
    } catch {
      res.status(503).json({
        status: 'unhealthy',
        service: 'search',
        timestamp: new Date().toISOString(),
      });
    }
  });

  app.get('/search', async (req, res) => {
    try {
      const filters = {
        query: req.query['q'] as string | undefined,
        md5: req.query['md5'] as string | undefined,
        sha1: req.query['sha1'] as string | undefined,
        sha256: req.query['sha256'] as string | undefined,
        domain: req.query['domain'] as string | undefined,
        url: req.query['url'] as string | undefined,
        ip: req.query['ip'] as string | undefined,
        fileName: req.query['fileName'] as string | undefined,
        malwareFamily: req.query['malwareFamily'] as string | undefined,
        attackTechnique: req.query['attackTechnique'] as string | undefined,
        registryKey: req.query['registryKey'] as string | undefined,
        threatLevel: req.query['threatLevel'] as string | undefined,
        status: req.query['status'] as string | undefined,
        tag: req.query['tag'] as string | undefined,
        dateFrom: req.query['dateFrom'] as string | undefined,
        dateTo: req.query['dateTo'] as string | undefined,
        page: Math.max(1, parseInt(req.query['page'] as string, 10) || 1),
        pageSize: Math.min(100, Math.max(1, parseInt(req.query['pageSize'] as string, 10) || 20)),
      };

      const result = await searchService.search(filters);

      res.json({
        success: true,
        data: result,
        error: null,
        requestId: req.headers['x-request-id'] ?? crypto.randomUUID(),
        timestamp: new Date().toISOString(),
      });
    } catch (err) {
      logger.error({ err }, 'Search failed');
      res.status(500).json({
        success: false,
        data: null,
        error: { code: 'SEARCH_ERROR', message: 'Search query failed' },
        requestId: req.headers['x-request-id'] ?? crypto.randomUUID(),
        timestamp: new Date().toISOString(),
      });
    }
  });

  app.get('/correlate/:id', async (req, res) => {
    try {
      const submissionId = req.params['id']!;
      const result = await correlationService.correlate(submissionId);

      res.json({
        success: true,
        data: result,
        error: null,
        requestId: req.headers['x-request-id'] ?? crypto.randomUUID(),
        timestamp: new Date().toISOString(),
      });
    } catch (err) {
      logger.error({ err, submissionId: req.params['id'] }, 'Correlation failed');
      res.status(500).json({
        success: false,
        data: null,
        error: { code: 'CORRELATION_ERROR', message: 'Correlation query failed' },
        requestId: req.headers['x-request-id'] ?? crypto.randomUUID(),
        timestamp: new Date().toISOString(),
      });
    }
  });

  app.get('/hunt', async (req, res) => {
    try {
      const rawIndicators = req.query['indicators'] as string | undefined;
      const rawTypes = req.query['indicatorTypes'] as string | undefined;

      const huntQuery = {
        indicators: rawIndicators ? rawIndicators.split(',').map((s) => s.trim()) : undefined,
        indicatorTypes: rawTypes ? rawTypes.split(',').map((s) => s.trim()) : undefined,
        campaignThreshold: req.query['campaignThreshold']
          ? parseInt(req.query['campaignThreshold'] as string, 10)
          : undefined,
        dateFrom: req.query['dateFrom'] as string | undefined,
        dateTo: req.query['dateTo'] as string | undefined,
        limit: req.query['limit'] ? parseInt(req.query['limit'] as string, 10) : undefined,
      };

      const result = await huntingService.hunt(huntQuery);

      res.json({
        success: true,
        data: result,
        error: null,
        requestId: req.headers['x-request-id'] ?? crypto.randomUUID(),
        timestamp: new Date().toISOString(),
      });
    } catch (err) {
      logger.error({ err }, 'Threat hunting failed');
      res.status(500).json({
        success: false,
        data: null,
        error: { code: 'HUNT_ERROR', message: 'Threat hunting query failed' },
        requestId: req.headers['x-request-id'] ?? crypto.randomUUID(),
        timestamp: new Date().toISOString(),
      });
    }
  });

  // ── Start server ───────────────────────────────────────────────────────

  const server = app.listen(config.port, config.host, () => {
    logger.info(
      { port: config.port, host: config.host, env: config.nodeEnv },
      'FraudVault Search Service is running',
    );
  });

  // ── Graceful shutdown ──────────────────────────────────────────────────

  const shutdown = async (signal: string) => {
    logger.info({ signal }, 'Received shutdown signal, closing gracefully...');

    server.close(async () => {
      await closeElasticsearch();
      logger.info('All connections closed. Goodbye.');
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
