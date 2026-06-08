import { Router, type Request, type Response, type NextFunction } from 'express';
import { z } from 'zod';
import multer from 'multer';
import type Redis from 'ioredis';
import { MAX_FILE_SIZE_BYTES, MAX_TAGS_PER_SUBMISSION } from '@scanboy/shared';
import { validate } from '../middleware/validation.js';
import { createAuthMiddleware } from '../middleware/auth.js';
import type { SubmissionService } from '../services/submissionService.js';
import type { AppConfig } from '../config.js';

const listQuerySchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  pageSize: z.coerce.number().int().min(1).max(100).default(25),
  status: z.enum(['pending', 'processing', 'completed', 'failed', 'error']).optional(),
  threatLevel: z.enum(['critical', 'high', 'medium', 'low', 'informational']).optional(),
  sortBy: z.enum(['submittedAt', 'threatScore', 'fileName']).default('submittedAt'),
  sortOrder: z.enum(['asc', 'desc']).default('desc'),
});

const idParamSchema = z.object({
  id: z.string().uuid(),
});

const updateTagsSchema = z.object({
  tags: z.array(z.string().min(1).max(50)).max(MAX_TAGS_PER_SUBMISSION),
});

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_FILE_SIZE_BYTES },
});

const urlSubmissionSchema = z.object({
  type: z.literal('url'),
  url: z.string().url().refine(
    (url) => {
      try {
        const parsed = new URL(url);
        // Only allow http and https schemes to prevent file://, ftp://, etc.
        return parsed.protocol === 'http:' || parsed.protocol === 'https:';
      } catch {
        return false;
      }
    },
    { message: 'Only http and https URLs are allowed' },
  ),
});

export function createSubmissionsRouter(
  submissionService: SubmissionService,
  config: AppConfig,
  redis?: Redis,
): Router {
  const router = Router();
  const auth = createAuthMiddleware(config, redis);

  // All submission routes require authentication.
  router.use(auth);

  // List submissions (paginated).
  router.get(
    '/',
    validate({ query: listQuerySchema }),
    async (req: Request, res: Response, next: NextFunction) => {
      try {
        const query = req.query as unknown as z.infer<typeof listQuerySchema>;
        const userId = req.user!.sub;
        const result = await submissionService.list(userId, query);

        res.status(200).json({
          success: true,
          data: {
            items: result.data,
            total: result.total,
            page: result.page,
            pageSize: result.pageSize,
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

  // Get a single submission by ID.
  router.get(
    '/:id',
    validate({ params: idParamSchema }),
    async (req: Request, res: Response, next: NextFunction) => {
      try {
        const { id } = req.params as unknown as z.infer<typeof idParamSchema>;
        const submission = await submissionService.getById(id, req.user!.sub);

        res.status(200).json({
          success: true,
          data: submission,
          error: null,
          requestId: res.getHeader('x-request-id') as string,
          timestamp: new Date().toISOString(),
        });
      } catch (err) {
        next(err);
      }
    },
  );

  // Upload a new file for analysis.
  router.post(
    '/upload',
    upload.single('file'),
    async (req: Request, res: Response, next: NextFunction) => {
      try {
        if (!req.file) {
          res.status(400).json({
            success: false,
            data: null,
            error: { code: 'VALIDATION_ERROR', message: 'File is required' },
            requestId: res.getHeader('x-request-id') as string,
            timestamp: new Date().toISOString(),
          });
          return;
        }

        // Parse analysis options from the request body
        const body = req.body as Record<string, unknown>;
        const rawNetworkMode = body['networkMode'] as string | undefined;
        const rawTimeout = body['timeout'] as string | number | undefined;

        const validNetworkModes = ['isolated', 'simulated', 'controlled'];
        const validTimeouts = [30, 60, 120, 300];

        const networkMode = rawNetworkMode && validNetworkModes.includes(rawNetworkMode)
          ? rawNetworkMode
          : undefined;
        const timeout = rawTimeout
          ? (validTimeouts.includes(Number(rawTimeout)) ? Number(rawTimeout) : undefined)
          : undefined;

        const submissionType = String(body['type'] ?? 'file');
        const options = (networkMode || timeout || submissionType === 'container')
          ? { networkMode, timeout, analysisWorkflow: submissionType === 'container' ? 'container' as const : 'default' as const }
          : undefined;

        // Validate tags from multipart body (not covered by Zod since multer runs first).
        let tags: string[] | undefined;
        const rawTags = body['tags'];
        if (Array.isArray(rawTags)) {
          tags = rawTags
            .filter((t): t is string => typeof t === 'string' && t.length > 0 && t.length <= 50)
            .slice(0, MAX_TAGS_PER_SUBMISSION);
        }

        const submission = await submissionService.create(
          req.user!.sub,
          req.file,
          tags,
          options,
        );

        res.status(201).json({
          success: true,
          data: submission,
          error: null,
          requestId: res.getHeader('x-request-id') as string,
          timestamp: new Date().toISOString(),
        });
      } catch (err) {
        next(err);
      }
    },
  );

  // Update tags on a submission.
  router.patch(
    '/:id/tags',
    validate({ params: idParamSchema, body: updateTagsSchema }),
    async (req: Request, res: Response, next: NextFunction) => {
      try {
        const { id } = req.params as unknown as z.infer<typeof idParamSchema>;
        const { tags } = req.body as z.infer<typeof updateTagsSchema>;
        const submission = await submissionService.updateTags(id, req.user!.sub, tags);

        res.status(200).json({
          success: true,
          data: submission,
          error: null,
          requestId: res.getHeader('x-request-id') as string,
          timestamp: new Date().toISOString(),
        });
      } catch (err) {
        next(err);
      }
    },
  );

  // Submit a URL for analysis.
  router.post(
    '/',
    validate({ body: urlSubmissionSchema }),
    async (req: Request, res: Response, next: NextFunction) => {
      try {
        const { url } = req.body as z.infer<typeof urlSubmissionSchema>;
        const submission = await submissionService.createUrlSubmission(
          req.user!.sub,
          url,
        );

        res.status(201).json({
          success: true,
          data: submission,
          error: null,
          requestId: res.getHeader('x-request-id') as string,
          timestamp: new Date().toISOString(),
        });
      } catch (err) {
        next(err);
      }
    },
  );

  // Download PCAP for a submission.
  router.get(
    '/:id/pcap',
    validate({ params: idParamSchema }),
    async (req: Request, res: Response, next: NextFunction) => {
      try {
        const { id } = req.params as unknown as z.infer<typeof idParamSchema>;

        // Verify ownership before serving PCAP data.
        await submissionService.getById(id, req.user!.sub);

        if (!redis) {
          res.status(503).json({
            success: false,
            data: null,
            error: { code: 'SERVICE_UNAVAILABLE', message: 'PCAP download is not available' },
            requestId: res.getHeader('x-request-id') as string,
            timestamp: new Date().toISOString(),
          });
          return;
        }

        const pcapBase64 = await redis.get(`scanboy:pcap:${id}`);
        if (!pcapBase64) {
          res.status(404).json({
            success: false,
            data: null,
            error: { code: 'NOT_FOUND', message: 'No PCAP data found for this submission (may have expired or no network traffic was captured)' },
            requestId: res.getHeader('x-request-id') as string,
            timestamp: new Date().toISOString(),
          });
          return;
        }

        const pcapBuffer = Buffer.from(pcapBase64, 'base64');
        res.setHeader('Content-Type', 'application/vnd.tcpdump.pcap');
        res.setHeader('Content-Disposition', `attachment; filename="scanboy-capture-${id}.pcap"`);
        res.setHeader('Content-Length', pcapBuffer.length.toString());
        res.send(pcapBuffer);
      } catch (err) {
        next(err);
      }
    },
  );

  // Delete a submission.
  router.delete(
    '/:id',
    validate({ params: idParamSchema }),
    async (req: Request, res: Response, next: NextFunction) => {
      try {
        const { id } = req.params as unknown as z.infer<typeof idParamSchema>;
        await submissionService.delete(id, req.user!.sub);

        res.status(204).send();
      } catch (err) {
        next(err);
      }
    },
  );

  return router;
}
