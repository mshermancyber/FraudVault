import { Router, type Request, type Response, type NextFunction } from 'express';
import { z } from 'zod';
import { validate } from '../middleware/validation.js';
import type Redis from 'ioredis';
import { createAuthMiddleware } from '../middleware/auth.js';
import { AppError } from '../middleware/errorHandler.js';
import type { AppConfig } from '../config.js';
import type pg from 'pg';

function safeParseJson(val: unknown): unknown {
  if (typeof val === 'string') { try { return JSON.parse(val); } catch { return null; } }
  return val ?? null;
}

const submissionIdParam = z.object({
  submissionId: z.string().uuid(),
});

const jobIdParam = z.object({
  submissionId: z.string().uuid(),
  jobId: z.string().uuid(),
});

export function createAnalysisRouter(pool: pg.Pool, config: AppConfig, redis?: Redis): Router {
  const router = Router();
  const auth = createAuthMiddleware(config, redis);

  router.use(auth);

  // List all analysis jobs for a submission.
  router.get(
    '/submissions/:submissionId/jobs',
    validate({ params: submissionIdParam }),
    async (req: Request, res: Response, next: NextFunction) => {
      try {
        const { submissionId } = req.params as unknown as z.infer<typeof submissionIdParam>;

        // Verify the user owns this submission before returning its jobs.
        const ownerCheck = await pool.query(
          `SELECT id FROM submissions WHERE id = $1 AND user_id = $2`,
          [submissionId, req.user!.sub],
        );
        if (ownerCheck.rows.length === 0) {
          throw new AppError(404, 'NOT_FOUND', 'Submission not found');
        }

        const result = await pool.query(
          `SELECT * FROM analysis_jobs WHERE submission_id = $1 ORDER BY created_at ASC`,
          [submissionId],
        );

        res.status(200).json({
          success: true,
          data: result.rows,
          error: null,
          requestId: res.getHeader('x-request-id') as string,
          timestamp: new Date().toISOString(),
        });
      } catch (err) {
        next(err);
      }
    },
  );

  // Get a specific analysis job.
  router.get(
    '/submissions/:submissionId/jobs/:jobId',
    validate({ params: jobIdParam }),
    async (req: Request, res: Response, next: NextFunction) => {
      try {
        const { submissionId, jobId } = req.params as unknown as z.infer<typeof jobIdParam>;

        // Verify ownership.
        const ownerCheck = await pool.query(
          `SELECT id FROM submissions WHERE id = $1 AND user_id = $2`,
          [submissionId, req.user!.sub],
        );
        if (ownerCheck.rows.length === 0) {
          throw new AppError(404, 'NOT_FOUND', 'Submission not found');
        }

        const result = await pool.query(
          `SELECT * FROM analysis_jobs WHERE id = $1 AND submission_id = $2`,
          [jobId, submissionId],
        );

        if (result.rows.length === 0) {
          throw new AppError(404, 'NOT_FOUND', 'Analysis job not found');
        }

        res.status(200).json({
          success: true,
          data: result.rows[0],
          error: null,
          requestId: res.getHeader('x-request-id') as string,
          timestamp: new Date().toISOString(),
        });
      } catch (err) {
        next(err);
      }
    },
  );

  // Cancel an analysis job.
  router.post(
    '/submissions/:submissionId/jobs/:jobId/cancel',
    validate({ params: jobIdParam }),
    async (req: Request, res: Response, next: NextFunction) => {
      try {
        const { submissionId, jobId } = req.params as unknown as z.infer<typeof jobIdParam>;

        // Verify ownership.
        const ownerCheck = await pool.query(
          `SELECT id FROM submissions WHERE id = $1 AND user_id = $2`,
          [submissionId, req.user!.sub],
        );
        if (ownerCheck.rows.length === 0) {
          throw new AppError(404, 'NOT_FOUND', 'Submission not found');
        }

        const result = await pool.query(
          `UPDATE analysis_jobs
           SET status = 'cancelled', updated_at = NOW()
           WHERE id = $1 AND submission_id = $2 AND status IN ('queued', 'running')
           RETURNING *`,
          [jobId, submissionId],
        );

        if (result.rows.length === 0) {
          throw new AppError(404, 'NOT_FOUND', 'Job not found or not cancellable');
        }

        res.status(200).json({
          success: true,
          data: result.rows[0],
          error: null,
          requestId: res.getHeader('x-request-id') as string,
          timestamp: new Date().toISOString(),
        });
      } catch (err) {
        next(err);
      }
    },
  );

  // Get the final analysis report for a submission.
  router.get(
    '/submissions/:submissionId/report',
    validate({ params: submissionIdParam }),
    async (req: Request, res: Response, next: NextFunction) => {
      try {
        const { submissionId } = req.params as unknown as z.infer<typeof submissionIdParam>;

        // Verify ownership.
        const ownerCheck = await pool.query(
          `SELECT id FROM submissions WHERE id = $1 AND user_id = $2`,
          [submissionId, req.user!.sub],
        );
        if (ownerCheck.rows.length === 0) {
          throw new AppError(404, 'NOT_FOUND', 'Submission not found');
        }

        const result = await pool.query(
          `SELECT * FROM analysis_reports WHERE submission_id = $1`,
          [submissionId],
        );

        if (result.rows.length === 0) {
          throw new AppError(404, 'NOT_FOUND', 'Report not yet available');
        }

        res.status(200).json({
          success: true,
          data: result.rows[0],
          error: null,
          requestId: res.getHeader('x-request-id') as string,
          timestamp: new Date().toISOString(),
        });
      } catch (err) {
        next(err);
      }
    },
  );

  // Get detection results (Sigma rules, scoring breakdown, etc.) for a submission.
  router.get(
    '/:submissionId/detection-results',
    validate({ params: submissionIdParam }),
    async (req: Request, res: Response, next: NextFunction) => {
      try {
        const { submissionId } = req.params as unknown as z.infer<typeof submissionIdParam>;

        // Verify ownership.
        const ownerCheck = await pool.query(
          `SELECT id FROM submissions WHERE id = $1 AND user_id = $2`,
          [submissionId, req.user!.sub],
        );
        if (ownerCheck.rows.length === 0) {
          throw new AppError(404, 'NOT_FOUND', 'Submission not found');
        }

        const result = await pool.query(
          `SELECT score_breakdown, sigma_rules, suricata_rules, snort_rules, yara_recommendations, created_at
           FROM detection_results WHERE submission_id = $1`,
          [submissionId],
        );

        if (result.rows.length === 0) {
          res.status(404).json({
            success: false,
            data: null,
            error: { code: 'NOT_FOUND', message: 'Detection results not found for this submission' },
            requestId: res.getHeader('x-request-id') as string,
            timestamp: new Date().toISOString(),
          });
          return;
        }

        const row = result.rows[0] as Record<string, unknown>;
        res.status(200).json({
          success: true,
          data: {
            scoreBreakdown: safeParseJson(row['score_breakdown']),
            sigmaRules: safeParseJson(row['sigma_rules']),
            suricataRules: safeParseJson(row['suricata_rules']),
            snortRules: safeParseJson(row['snort_rules']),
            yaraRecommendations: safeParseJson(row['yara_recommendations']),
            createdAt: row['created_at'],
          },
          error: null,
          requestId: res.getHeader('x-request-id') as string,
          timestamp: new Date().toISOString(),
        });
      } catch (err) {
        next(err);
      }
    },
  );

  return router;
}
