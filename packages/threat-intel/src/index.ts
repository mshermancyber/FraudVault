import express from 'express';
import { Pool } from 'pg';
import { Worker, Queue } from 'bullmq';
import pino from 'pino';
import pinoHttp from 'pino-http';
import { QUEUE_NAMES } from '@scanboy/shared';
import { config } from './config.js';
import { EnrichmentService } from './services/enrichment.js';
import { ReputationService } from './services/reputation.js';

// ── Logger ──────────────────────────────────────────────────────────────────
const log = pino({ name: 'threat-intel', level: process.env['LOG_LEVEL'] ?? 'info' });

// ── PostgreSQL ──────────────────────────────────────────────────────────────
const db = new Pool({
  host: config.database.host,
  port: config.database.port,
  database: config.database.name,
  user: config.database.user,
  password: config.database.password,
  max: config.database.maxConnections,
});

// ── Redis / BullMQ ──────────────────────────────────────────────────────────
const redisOpts = {
  host: config.redis.host,
  port: config.redis.port,
  password: config.redis.password || undefined,
  maxRetriesPerRequest: null as null, // required by BullMQ
};

const threatIntelQueue = new Queue(QUEUE_NAMES.THREAT_INTEL, { connection: redisOpts });

// ── Services ────────────────────────────────────────────────────────────────
const enrichmentService = new EnrichmentService(db, log);
const reputationService = new ReputationService(db, log);

// ── BullMQ Worker ───────────────────────────────────────────────────────────
const worker = new Worker(
  QUEUE_NAMES.THREAT_INTEL,
  async (job) => {
    const { submissionId, hash, url, ip, domain } = job.data as {
      submissionId: string;
      hash?: string;
      url?: string;
      ip?: string;
      domain?: string;
    };

    log.info({ jobId: job.id, submissionId }, 'Processing threat-intel job');

    try {
      // Run the appropriate enrichment based on available data
      const verdicts = [];

      if (hash) {
        const verdict = await enrichmentService.enrichByHash(hash, submissionId);
        verdicts.push(verdict);
      }
      if (url) {
        const verdict = await enrichmentService.enrichByUrl(url, submissionId);
        verdicts.push(verdict);
      }
      if (ip) {
        const verdict = await enrichmentService.enrichByIp(ip, submissionId);
        verdicts.push(verdict);
      }
      if (domain) {
        const verdict = await enrichmentService.enrichByDomain(domain, submissionId);
        verdicts.push(verdict);
      }

      // Calculate final reputation score
      const reputation = await reputationService.scoreSubmission(submissionId);

      // Update submission status in database
      await db.query(
        `UPDATE submissions SET threat_level = $1, threat_score = $2, updated_at = NOW() WHERE id = $3`,
        [reputation.threatLevel, reputation.score, submissionId],
      );

      log.info({ submissionId, score: reputation.score, level: reputation.threatLevel }, 'Threat intel processing complete');

      return { verdicts, reputation };
    } catch (err: unknown) {
      log.error({ jobId: job.id, submissionId, err }, 'Threat-intel job failed');
      throw err;
    }
  },
  {
    connection: redisOpts,
    concurrency: config.workerConcurrency,
  },
);

worker.on('failed', (job, err) => {
  log.error({ jobId: job?.id, err }, 'Worker job failed');
});

worker.on('completed', (job) => {
  log.info({ jobId: job.id }, 'Worker job completed');
});

// ── Express App ─────────────────────────────────────────────────────────────
const app = express();
app.use(express.json());
app.use(pinoHttp({ logger: log }));

const INTERNAL_KEY = process.env['INTERNAL_API_KEY'];
app.use((req, res, next) => {
  if (req.path === '/health' || req.path === '/ready') return next();
  if (!INTERNAL_KEY || req.headers['x-internal-api-key'] !== INTERNAL_KEY) {
    res.status(401).json({ error: 'Unauthorized' });
    return;
  }
  next();
});

// Health check
app.get('/health', (_req, res) => {
  res.json({ status: 'ok', service: 'threat-intel', timestamp: new Date().toISOString() });
});

// Readiness probe
app.get('/ready', async (_req, res) => {
  try {
    await db.query('SELECT 1');
    await threatIntelQueue.getJobCounts();
    res.json({ status: 'ready' });
  } catch {
    res.status(503).json({ status: 'not ready' });
  }
});

// List configured providers
app.get('/api/v1/providers', (_req, res) => {
  const providers = enrichmentService.getConfiguredProviders().map((p) => ({
    name: p.name,
    configured: true,
  }));
  res.json({ data: providers });
});

// Enqueue a threat intel lookup
app.post('/api/v1/enrich', async (req, res) => {
  const { submissionId, hash, url, ip, domain } = req.body as {
    submissionId: string;
    hash?: string;
    url?: string;
    ip?: string;
    domain?: string;
  };

  if (!submissionId || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(submissionId)) {
    res.status(400).json({ error: 'submissionId must be a valid UUID' });
    return;
  }

  if (hash && !/^[a-fA-F0-9]{32,64}$/.test(hash)) {
    res.status(400).json({ error: 'hash must be a valid hex hash (32-64 characters)' });
    return;
  }
  if (ip && !/^(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)$/.test(ip)) {
    res.status(400).json({ error: 'ip must be a valid IPv4 address' });
    return;
  }
  if (domain && !/^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$/.test(domain)) {
    res.status(400).json({ error: 'domain must be a valid domain name' });
    return;
  }
  if (url) {
    try {
      const parsed = new URL(url);
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') throw new Error('bad protocol');
      const h = parsed.hostname;
      if (h === 'localhost' || h === '0.0.0.0' || h.startsWith('[') ||
          h.startsWith('127.') || h.startsWith('10.') || h.startsWith('192.168.') ||
          h.startsWith('169.254.') || /^172\.(1[6-9]|2\d|3[01])\./.test(h)) {
        res.status(400).json({ error: 'url must not target internal/private addresses' });
        return;
      }
    } catch {
      res.status(400).json({ error: 'url must be a valid HTTP(S) URL' });
      return;
    }
  }

  const job = await threatIntelQueue.add('enrich', { submissionId, hash, url, ip, domain }, {
    attempts: 3,
    backoff: { type: 'exponential', delay: 5000 },
  });

  res.status(202).json({ jobId: job.id, submissionId });
});

// Synchronous enrichment (for on-demand lookups)
app.post('/api/v1/enrich/sync', async (req, res) => {
  const { submissionId, hash, url, ip, domain } = req.body as {
    submissionId: string;
    hash?: string;
    url?: string;
    ip?: string;
    domain?: string;
  };

  if (!submissionId || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(submissionId)) {
    res.status(400).json({ error: 'submissionId must be a valid UUID' });
    return;
  }

  if (hash && !/^[a-fA-F0-9]{32,64}$/.test(hash)) {
    res.status(400).json({ error: 'hash must be a valid hex hash (32-64 characters)' });
    return;
  }
  if (ip && !/^(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)$/.test(ip)) {
    res.status(400).json({ error: 'ip must be a valid IPv4 address' });
    return;
  }
  if (domain && !/^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$/.test(domain)) {
    res.status(400).json({ error: 'domain must be a valid domain name' });
    return;
  }
  if (url) {
    try {
      const parsed = new URL(url);
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') throw new Error('bad protocol');
      const h = parsed.hostname;
      if (h === 'localhost' || h === '0.0.0.0' || h.startsWith('[') ||
          h.startsWith('127.') || h.startsWith('10.') || h.startsWith('192.168.') ||
          h.startsWith('169.254.') || /^172\.(1[6-9]|2\d|3[01])\./.test(h)) {
        res.status(400).json({ error: 'url must not target internal/private addresses' });
        return;
      }
    } catch {
      res.status(400).json({ error: 'url must be a valid HTTP(S) URL' });
      return;
    }
  }

  try {
    const verdicts = [];
    if (hash) verdicts.push(await enrichmentService.enrichByHash(hash, submissionId));
    if (url) verdicts.push(await enrichmentService.enrichByUrl(url, submissionId));
    if (ip) verdicts.push(await enrichmentService.enrichByIp(ip, submissionId));
    if (domain) verdicts.push(await enrichmentService.enrichByDomain(domain, submissionId));

    const reputation = await reputationService.scoreSubmission(submissionId);
    res.json({ verdicts, reputation });
  } catch (err: unknown) {
    log.error({ err }, 'Synchronous enrichment failed');
    res.status(500).json({ error: 'Enrichment failed' });
  }
});

// Get reputation score for a submission
app.get('/api/v1/reputation/:submissionId', async (req, res) => {
  const submissionId = req.params['submissionId']!;
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(submissionId)) {
    res.status(400).json({ error: 'submissionId must be a valid UUID' });
    return;
  }
  try {
    const score = await reputationService.scoreSubmission(submissionId);
    res.json({ data: score });
  } catch (err: unknown) {
    log.error({ err }, 'Reputation scoring failed');
    res.status(500).json({ error: 'Scoring failed' });
  }
});

// Get reputation score for an arbitrary indicator
app.get('/api/v1/reputation/indicator/:value', async (req, res) => {
  const value = req.params['value']!;
  if (!/^[a-fA-F0-9]{32,64}$/.test(value)) {
    res.status(400).json({ error: 'Indicator must be a valid hash (32-64 hex characters)' });
    return;
  }
  try {
    const score = await reputationService.scoreIndicator(value);
    res.json({ data: score });
  } catch (err: unknown) {
    log.error({ err }, 'Indicator reputation scoring failed');
    res.status(500).json({ error: 'Scoring failed' });
  }
});

// ── Start ───────────────────────────────────────────────────────────────────
app.listen(config.port, config.host, () => {
  log.info({ port: config.port, host: config.host }, 'Threat-intel service started');
  log.info(
    { providers: enrichmentService.getConfiguredProviders().map((p) => p.name) },
    'Configured providers',
  );
});

// ── Graceful shutdown ───────────────────────────────────────────────────────
async function shutdown(): Promise<void> {
  log.info('Shutting down threat-intel service');
  await worker.close();
  await threatIntelQueue.close();
  await db.end();
  process.exit(0);
}

process.on('SIGTERM', () => void shutdown());
process.on('SIGINT', () => void shutdown());
