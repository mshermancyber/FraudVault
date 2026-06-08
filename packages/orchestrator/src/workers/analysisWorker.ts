import { Worker, type Job, type ConnectionOptions } from 'bullmq';
import type pg from 'pg';
import type { Logger } from 'pino';
import type { OrchestratorConfig } from '../config.js';
import { ORCHESTRATOR_QUEUE_NAMES, type SubmissionIntakeJobData } from '../queue.js';
import { runSubmissionWorkflow, type WorkflowContext } from '../workflows/submissionWorkflow.js';

// ── DB Helpers ───────────────────────────────────────────────────────────────

async function markJobRunning(pool: pg.Pool, submissionId: string): Promise<void> {
  await pool.query(
    `UPDATE analysis_jobs
     SET status = 'running', started_at = NOW()
     WHERE submission_id = $1 AND status = 'pending'`,
    [submissionId],
  );
}

async function markJobFailed(
  pool: pg.Pool,
  submissionId: string,
  errorMessage: string,
): Promise<void> {
  await pool.query(
    `UPDATE analysis_jobs
     SET status = 'failed', error_message = $1, completed_at = NOW()
     WHERE submission_id = $2 AND status = 'running'`,
    [errorMessage, submissionId],
  );
}

// ── Worker Factory ───────────────────────────────────────────────────────────

export interface AnalysisWorkerDeps {
  config: OrchestratorConfig;
  pool: pg.Pool;
  logger: Logger;
}

/**
 * Processes a single submission-intake job:
 *   1. Updates the DB job row to "running".
 *   2. Reports BullMQ progress at each pipeline stage.
 *   3. Delegates to the submission workflow.
 *   4. Marks the DB job as failed on unrecoverable errors.
 */
async function processJob(
  job: Job<SubmissionIntakeJobData>,
  deps: AnalysisWorkerDeps,
): Promise<void> {
  const { pool, logger: parentLogger } = deps;
  const { submissionId, sha256, storagePath } = job.data;

  const logger = parentLogger.child({
    jobId: job.id,
    submissionId,
    sha256,
    attempt: job.attemptsMade + 1,
  });

  logger.info('Starting submission intake processing');

  // Report initial progress.
  await job.updateProgress(0);

  try {
    // Mark all queued jobs for this submission as running.
    await markJobRunning(pool, submissionId);
    await job.updateProgress(5);

    // Build the workflow context.
    const options = (job.data as unknown as Record<string, unknown>)['options'] as Record<string, unknown> | undefined;
    const ctx: WorkflowContext = {
      submissionId,
      sha256,
      storagePath,
      pool,
      logger,
      analysisWorkflow: options?.['analysisWorkflow'] === 'container' ? 'container' : 'default',
    };

    await job.updateProgress(10);

    // Run the full analysis pipeline.
    await runSubmissionWorkflow(ctx);

    await job.updateProgress(100);
    logger.info('Submission intake processing completed successfully');
  } catch (err: unknown) {
    const errorMessage = err instanceof Error ? err.message : 'Unknown processing error';
    logger.error({ err }, 'Submission intake processing failed');

    // Persist the failure into the DB so the API can surface it.
    await markJobFailed(pool, submissionId, errorMessage).catch((dbErr: unknown) => {
      logger.error({ dbErr }, 'Failed to mark analysis job as failed in DB');
    });

    // Re-throw so BullMQ can handle retries.
    throw err;
  }
}

/**
 * Creates and returns a BullMQ Worker that processes jobs from the
 * submission-intake queue. The caller owns the lifecycle -- call
 * `worker.close()` during graceful shutdown.
 */
export function createAnalysisWorker(deps: AnalysisWorkerDeps): Worker<SubmissionIntakeJobData> {
  const { config, logger } = deps;

  const connection: ConnectionOptions = {
    host: config.redis.host,
    port: config.redis.port,
    password: config.redis.password,
  };

  const worker = new Worker<SubmissionIntakeJobData>(
    ORCHESTRATOR_QUEUE_NAMES.SUBMISSION_INTAKE,
    async (job) => processJob(job, deps),
    {
      connection,
      concurrency: config.worker.concurrency,
      lockDuration: config.worker.analysisTimeoutSeconds * 1_000,
      // Stall-check interval: half the lock duration, capped at 30 s.
      stalledInterval: Math.min(30_000, config.worker.analysisTimeoutSeconds * 500),
      removeOnComplete: { count: 10_000 },
      removeOnFail: { count: 50_000 },
    },
  );

  // ── Worker event handlers ────────────────────────────────────────────────

  worker.on('completed', (job) => {
    logger.info(
      { jobId: job.id, submissionId: job.data.submissionId },
      'Job completed',
    );
  });

  worker.on('failed', (job, err) => {
    if (job) {
      logger.error(
        {
          jobId: job.id,
          submissionId: job.data.submissionId,
          attempt: job.attemptsMade,
          maxAttempts: job.opts.attempts ?? config.worker.maxRetries,
          err,
        },
        'Job failed',
      );
    } else {
      logger.error({ err }, 'Job failed (job reference unavailable)');
    }
  });

  worker.on('stalled', (jobId) => {
    logger.warn({ jobId }, 'Job stalled -- will be retried');
  });

  worker.on('error', (err) => {
    logger.error({ err }, 'Worker error');
  });

  logger.info(
    {
      queue: ORCHESTRATOR_QUEUE_NAMES.SUBMISSION_INTAKE,
      concurrency: config.worker.concurrency,
    },
    'Analysis worker started',
  );

  return worker;
}
