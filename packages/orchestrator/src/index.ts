import pino from 'pino';
import Redis from 'ioredis';
import { SubmissionStatus } from '@scanboy/shared';
import { loadConfig, type OrchestratorConfig } from './config.js';
import { getPool, closePool } from './db.js';
import {
  getQueues,
  closeQueues,
  enqueueSubmissionIntake,
  type SubmissionIntakeJobData,
} from './queue.js';
import { createAnalysisWorker } from './workers/analysisWorker.js';

// ── Redis Pub/Sub Channel ────────────────────────────────────────────────────

const SUBMISSION_CHANNEL = 'scanboy:submissions:new';

interface NewSubmissionMessage {
  submissionId: string;
  sha256: string;
  storagePath: string;
  userId: string;
  priority?: number;
}

// ── Service Entry Point ──────────────────────────────────────────────────────

async function main(): Promise<void> {
  const config = loadConfig();

  const logger = pino({
    level: config.logLevel,
    transport:
      config.nodeEnv === 'development'
        ? { target: 'pino-pretty', options: { colorize: true } }
        : undefined,
  });

  logger.info({ nodeEnv: config.nodeEnv }, 'FraudVault Orchestrator starting');

  // ── PostgreSQL ──────────────────────────────────────────────────────────

  const pool = getPool(config);

  try {
    await pool.query('SELECT 1');
    logger.info('PostgreSQL connection established');
  } catch (err) {
    logger.fatal({ err }, 'Failed to connect to PostgreSQL');
    process.exit(1);
  }

  // ── Redis connections ───────────────────────────────────────────────────
  // We need two connections: one for subscribing (blocked in subscribe
  // mode) and one general-purpose client passed into the workflow for
  // publishing status events.

  const redisOptions = {
    host: config.redis.host,
    port: config.redis.port,
    password: config.redis.password,
    maxRetriesPerRequest: null as number | null, // required by BullMQ
    enableReadyCheck: true,
    retryStrategy: (times: number) => Math.min(times * 200, 5_000),
  };

  const redisSubscriber = new Redis(redisOptions);
  const redisPublisher = new Redis(redisOptions);

  redisSubscriber.on('error', (err) => {
    logger.error({ err }, 'Redis subscriber error');
  });
  redisPublisher.on('error', (err) => {
    logger.error({ err }, 'Redis publisher error');
  });

  try {
    await redisPublisher.ping();
    logger.info('Redis connection established');
  } catch (err) {
    logger.fatal({ err }, 'Failed to connect to Redis');
    process.exit(1);
  }

  // ── Initialize queues ───────────────────────────────────────────────────

  const queues = getQueues(config);
  logger.info(
    { queues: Object.keys(queues) },
    'BullMQ queues initialized',
  );

  // ── Start workers ───────────────────────────────────────────────────────

  const worker = createAnalysisWorker({
    config,
    pool,
    logger: logger.child({ component: 'analysis-worker' }),
  });

  // ── Listen for new submissions via Redis pub/sub ────────────────────────

  await redisSubscriber.subscribe(SUBMISSION_CHANNEL);
  logger.info({ channel: SUBMISSION_CHANNEL }, 'Listening for new submissions');

  redisSubscriber.on('message', (channel: string, rawMessage: string) => {
    if (channel !== SUBMISSION_CHANNEL) return;

    void handleNewSubmission(config, pool, logger, rawMessage);
  });

  logger.info('FraudVault Orchestrator is running');

  // ── Startup recovery: re-enqueue any submissions stuck in 'submitted' ──
  void recoverStuckSubmissions(config, pool, redisPublisher, logger);

  // ── Periodic sweep: catch orphaned submissions every 5 minutes ──────────
  const sweepInterval = setInterval(() => {
    void recoverStuckSubmissions(config, pool, redisPublisher, logger);
  }, 5 * 60_000);

  // ── Graceful shutdown ───────────────────────────────────────────────────

  let shuttingDown = false;

  const shutdown = async (signal: string): Promise<void> => {
    if (shuttingDown) return;
    shuttingDown = true;
    logger.info({ signal }, 'Received shutdown signal -- draining');

    const SHUTDOWN_TIMEOUT_MS = 30_000;
    const timer = setTimeout(() => {
      logger.error('Graceful shutdown timed out -- forcing exit');
      process.exit(1);
    }, SHUTDOWN_TIMEOUT_MS);

    try {
      // 0. Stop sweep timer.
      clearInterval(sweepInterval);

      // 1. Stop accepting new pub/sub messages.
      await redisSubscriber.unsubscribe(SUBMISSION_CHANNEL);

      // 2. Drain the worker (finish in-progress jobs).
      await worker.close();

      // 3. Close queues and connections.
      await closeQueues();
      await redisSubscriber.quit();
      await redisPublisher.quit();
      await closePool();

      clearTimeout(timer);
      logger.info('Orchestrator shut down cleanly');
      process.exit(0);
    } catch (err) {
      clearTimeout(timer);
      logger.error({ err }, 'Error during shutdown');
      process.exit(1);
    }
  };

  process.on('SIGTERM', () => void shutdown('SIGTERM'));
  process.on('SIGINT', () => void shutdown('SIGINT'));

  // Catch unhandled rejections to avoid silent failures.
  process.on('unhandledRejection', (reason) => {
    logger.fatal({ reason }, 'Unhandled promise rejection');
    void shutdown('unhandledRejection');
  });
}

// ── Pub/Sub Message Handler ──────────────────────────────────────────────────

async function handleNewSubmission(
  config: OrchestratorConfig,
  pool: ReturnType<typeof getPool>,
  logger: pino.Logger,
  rawMessage: string,
): Promise<void> {
  let parsed: NewSubmissionMessage;
  try {
    parsed = JSON.parse(rawMessage) as NewSubmissionMessage;
  } catch {
    logger.warn({ rawMessage }, 'Ignoring malformed submission message');
    return;
  }

  const { submissionId, sha256, storagePath, userId, priority } = parsed;
  const rawOptions = (parsed as unknown as Record<string, unknown>)['options'] as Record<string, unknown> | undefined;
  const options: Record<string, unknown> = {};
  if (rawOptions?.['analysisWorkflow'] === 'container') options['analysisWorkflow'] = 'container';

  if (!submissionId || !sha256 || !storagePath || !userId) {
    logger.warn({ parsed }, 'Ignoring submission message with missing fields');
    return;
  }

  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(submissionId)) {
    logger.warn({ submissionId: String(submissionId).slice(0, 50) }, 'Ignoring submission with invalid ID format');
    return;
  }

  if (!/^redis:scanboy:file:[a-f0-9-]{36}$/.test(storagePath)) {
    logger.warn({ storagePath: String(storagePath).slice(0, 80) }, 'Ignoring submission with invalid storagePath format');
    return;
  }

  if (!/^[a-f0-9]{64}$/i.test(sha256)) {
    logger.warn({ sha256: String(sha256).slice(0, 80) }, 'Ignoring submission with invalid sha256 format');
    return;
  }

  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(userId)) {
    logger.warn({ userId: String(userId).slice(0, 50) }, 'Ignoring submission with invalid userId format');
    return;
  }

  logger.info({ submissionId, sha256 }, 'New submission received via pub/sub');

  try {
    // Mark the submission as queued.
    await pool.query(
      `UPDATE submissions SET status = $1, updated_at = NOW() WHERE id = $2`,
      [SubmissionStatus.Queued, submissionId],
    );

    // Enqueue the job.
    const jobData = {
      submissionId,
      sha256,
      storagePath,
      userId,
      options,
    } as unknown as SubmissionIntakeJobData;

    const jobId = await enqueueSubmissionIntake(config, jobData, priority ?? 0);
    logger.info({ submissionId, jobId }, 'Submission enqueued for analysis');
  } catch (err) {
    logger.error({ submissionId, err }, 'Failed to enqueue submission');
  }
}

// ── Startup / periodic recovery ──────────────────────────────────────────────

async function recoverStuckSubmissions(
  config: OrchestratorConfig,
  pool: ReturnType<typeof getPool>,
  redis: Redis,
  logger: pino.Logger,
): Promise<void> {
  try {
    // Find submissions stuck in 'submitted' for more than 15 seconds
    const { rows } = await pool.query(
      `SELECT id, sha256, user_id
       FROM submissions
       WHERE status = 'submitted'
         AND created_at < NOW() - INTERVAL '15 seconds'
       ORDER BY created_at ASC
       LIMIT 20`,
    );

    if (rows.length === 0) return;

    logger.info({ count: rows.length }, 'Found stuck submissions — recovering');

    for (const row of rows) {
      const submissionId = row['id'] as string;
      const sha256 = row['sha256'] as string;
      const userId = row['user_id'] as string;
      const storagePath = `redis:scanboy:file:${submissionId}`;

      // Verify the file still exists in Redis before re-enqueuing
      const exists = await redis.exists(`scanboy:file:${submissionId}`);
      if (!exists) {
        logger.warn({ submissionId }, 'Stuck submission has no file in Redis — marking failed');
        await pool.query(
          `UPDATE submissions SET status = 'closed', updated_at = NOW() WHERE id = $1 AND status = 'submitted'`,
          [submissionId],
        );
        continue;
      }

      try {
        await pool.query(
          `UPDATE submissions SET status = $1, updated_at = NOW() WHERE id = $2 AND status = 'submitted'`,
          [SubmissionStatus.Queued, submissionId],
        );
        const jobData = { submissionId, sha256, storagePath, userId } as unknown as SubmissionIntakeJobData;
        const jobId = await enqueueSubmissionIntake(config, jobData, 0);
        logger.info({ submissionId, jobId }, 'Recovered stuck submission');
      } catch (err) {
        logger.error({ submissionId, err }, 'Failed to recover submission');
      }
    }
  } catch (err) {
    logger.error({ err }, 'Stuck submission recovery sweep failed');
  }
}

// ── Bootstrap ────────────────────────────────────────────────────────────────

main().catch((err: unknown) => {
  // eslint-disable-next-line no-console
  console.error('Fatal startup error:', err);
  process.exit(1);
});
