import { Router, type Request, type Response, type NextFunction } from 'express';
import { z } from 'zod';
import { validate } from '../middleware/validation.js';
import { createAuthRateLimiter } from '../middleware/rateLimiter.js';
import type { AuthService } from '../services/authService.js';

const loginSchema = z.object({
  email: z.string().email().max(255),
  password: z.string().min(8).max(128),
});

const refreshSchema = z.object({
  refreshToken: z.string().min(1),
});

const mfaVerifySchema = z.object({
  token: z.string().length(6).regex(/^\d+$/),
  mfaSessionId: z.string().uuid(),
});

export function createAuthRouter(authService: AuthService): Router {
  const router = Router();
  const authLimiter = createAuthRateLimiter();

  router.post(
    '/login',
    authLimiter,
    validate({ body: loginSchema }),
    async (req: Request, res: Response, next: NextFunction) => {
      try {
        const { email, password } = req.body as z.infer<typeof loginSchema>;
        const result = await authService.login(email, password);

        res.status(200).json({
          success: true,
          data: result,
          error: null,
          requestId: res.getHeader('x-request-id') as string,
          timestamp: new Date().toISOString(),
        });
      } catch (err) {
        next(err);
      }
    },
  );

  router.post(
    '/refresh',
    authLimiter,
    validate({ body: refreshSchema }),
    async (req: Request, res: Response, next: NextFunction) => {
      try {
        const { refreshToken } = req.body as z.infer<typeof refreshSchema>;
        const result = await authService.refresh(refreshToken);

        res.status(200).json({
          success: true,
          data: result,
          error: null,
          requestId: res.getHeader('x-request-id') as string,
          timestamp: new Date().toISOString(),
        });
      } catch (err) {
        next(err);
      }
    },
  );

  router.post('/logout', authLimiter, async (req: Request, res: Response, next: NextFunction) => {
    try {
      const authHeader = req.headers.authorization;
      if (authHeader?.startsWith('Bearer ')) {
        await authService.logout(authHeader.slice(7));
      }
      const { refreshToken } = (req.body ?? {}) as { refreshToken?: string };
      if (refreshToken) {
        await authService.revokeRefreshToken(refreshToken);
      }

      res.status(200).json({
        success: true,
        data: { message: 'Logged out successfully' },
        error: null,
        requestId: res.getHeader('x-request-id') as string,
        timestamp: new Date().toISOString(),
      });
    } catch (err) {
      next(err);
    }
  });

  router.post(
    '/mfa/verify',
    authLimiter,
    validate({ body: mfaVerifySchema }),
    async (req: Request, res: Response, next: NextFunction) => {
      try {
        const { token, mfaSessionId } = req.body as z.infer<typeof mfaVerifySchema>;
        const result = await authService.verifyMfa(mfaSessionId, token);

        res.status(200).json({
          success: true,
          data: result,
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
