import { Router, type Request, type Response, type NextFunction } from 'express';
import { z } from 'zod';
import { UserRole } from '@scanboy/shared';
import { validate } from '../middleware/validation.js';
import type Redis from 'ioredis';
import { createAuthMiddleware } from '../middleware/auth.js';
import { requireRole } from '../middleware/rbac.js';
import type { UserService } from '../services/userService.js';
import type { AppConfig } from '../config.js';

const listUsersQuery = z.object({
  page: z.coerce.number().int().min(1).default(1),
  pageSize: z.coerce.number().int().min(1).max(100).default(25),
  role: z.nativeEnum(UserRole).optional(),
});

const userIdParam = z.object({
  id: z.string().uuid(),
});

const createUserSchema = z.object({
  email: z.string().email().max(255),
  displayName: z.string().min(1).max(100),
  password: z.string().min(12).max(128),
  role: z.nativeEnum(UserRole).default(UserRole.Viewer),
});

const updateUserSchema = z.object({
  displayName: z.string().min(1).max(100).optional(),
  role: z.nativeEnum(UserRole).optional(),
  mfaEnabled: z.boolean().optional(),
});

export function createAdminRouter(userService: UserService, config: AppConfig, redis?: Redis): Router {
  const router = Router();
  const auth = createAuthMiddleware(config, redis);

  // All admin routes require authentication + Admin role.
  router.use(auth, requireRole(UserRole.Admin));

  // List all users.
  router.get(
    '/users',
    validate({ query: listUsersQuery }),
    async (req: Request, res: Response, next: NextFunction) => {
      try {
        const query = req.query as unknown as z.infer<typeof listUsersQuery>;
        const result = await userService.list(query);

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

  // Get user by ID.
  router.get(
    '/users/:id',
    validate({ params: userIdParam }),
    async (req: Request, res: Response, next: NextFunction) => {
      try {
        const { id } = req.params as unknown as z.infer<typeof userIdParam>;
        const user = await userService.getById(id);

        res.status(200).json({
          success: true,
          data: user,
          error: null,
          requestId: res.getHeader('x-request-id') as string,
          timestamp: new Date().toISOString(),
        });
      } catch (err) {
        next(err);
      }
    },
  );

  // Create a new user.
  router.post(
    '/users',
    validate({ body: createUserSchema }),
    async (req: Request, res: Response, next: NextFunction) => {
      try {
        const data = req.body as z.infer<typeof createUserSchema>;

        // Prevent privilege escalation: only SuperAdmin can create SuperAdmin or Admin users.
        if (
          (data.role === UserRole.SuperAdmin || data.role === UserRole.Admin) &&
          req.user!.role !== UserRole.SuperAdmin
        ) {
          res.status(403).json({
            success: false,
            data: null,
            error: { code: 'FORBIDDEN', message: 'Only SuperAdmin can assign Admin or SuperAdmin roles' },
            requestId: res.getHeader('x-request-id') as string,
            timestamp: new Date().toISOString(),
          });
          return;
        }

        const user = await userService.create(data);

        res.status(201).json({
          success: true,
          data: user,
          error: null,
          requestId: res.getHeader('x-request-id') as string,
          timestamp: new Date().toISOString(),
        });
      } catch (err) {
        next(err);
      }
    },
  );

  // Update an existing user.
  router.patch(
    '/users/:id',
    validate({ params: userIdParam, body: updateUserSchema }),
    async (req: Request, res: Response, next: NextFunction) => {
      try {
        const { id } = req.params as unknown as z.infer<typeof userIdParam>;
        const data = req.body as z.infer<typeof updateUserSchema>;

        // Prevent privilege escalation via role update.
        if (
          data.role !== undefined &&
          (data.role === UserRole.SuperAdmin || data.role === UserRole.Admin) &&
          req.user!.role !== UserRole.SuperAdmin
        ) {
          res.status(403).json({
            success: false,
            data: null,
            error: { code: 'FORBIDDEN', message: 'Only SuperAdmin can assign Admin or SuperAdmin roles' },
            requestId: res.getHeader('x-request-id') as string,
            timestamp: new Date().toISOString(),
          });
          return;
        }

        // Prevent admin from modifying users at or above their own role level.
        const ROLE_RANK: Record<string, number> = { viewer: 0, analyst: 1, admin: 2, super_admin: 3 };
        const targetUser = await userService.getById(id);
        const targetRank = ROLE_RANK[targetUser.role] ?? 0;
        const requesterRank = ROLE_RANK[req.user!.role] ?? 0;
        if (targetRank >= requesterRank && req.user!.role !== UserRole.SuperAdmin) {
          res.status(403).json({
            success: false,
            data: null,
            error: { code: 'FORBIDDEN', message: 'Cannot modify a user with equal or higher role' },
            requestId: res.getHeader('x-request-id') as string,
            timestamp: new Date().toISOString(),
          });
          return;
        }

        const user = await userService.update(id, data);

        // Invalidate existing tokens so the user must re-authenticate with new role/state.
        if (redis && (data.role !== undefined || data.mfaEnabled !== undefined)) {
          await redis.set(
            `session:user_invalidated:${id}`,
            String(Math.floor(Date.now() / 1000)),
            'EX', 7 * 24 * 60 * 60,
          );
        }

        res.status(200).json({
          success: true,
          data: user,
          error: null,
          requestId: res.getHeader('x-request-id') as string,
          timestamp: new Date().toISOString(),
        });
      } catch (err) {
        next(err);
      }
    },
  );

  // Delete a user.
  router.delete(
    '/users/:id',
    requireRole(UserRole.SuperAdmin),
    validate({ params: userIdParam }),
    async (req: Request, res: Response, next: NextFunction) => {
      try {
        const { id } = req.params as unknown as z.infer<typeof userIdParam>;

        // Prevent self-deletion.
        if (id === req.user!.sub) {
          res.status(400).json({
            success: false,
            data: null,
            error: { code: 'BAD_REQUEST', message: 'Cannot delete your own account' },
            requestId: res.getHeader('x-request-id') as string,
            timestamp: new Date().toISOString(),
          });
          return;
        }

        // Prevent deleting the last SuperAdmin.
        const targetUser = await userService.getById(id);
        if (targetUser.role === 'super_admin') {
          const countResult = await userService.countByRole('super_admin' as UserRole);
          if (countResult <= 1) {
            res.status(400).json({
              success: false,
              data: null,
              error: { code: 'BAD_REQUEST', message: 'Cannot delete the last SuperAdmin account' },
              requestId: res.getHeader('x-request-id') as string,
              timestamp: new Date().toISOString(),
            });
            return;
          }
        }

        await userService.delete(id);

        // Invalidate all existing tokens for the deleted user.
        if (redis) {
          await redis.set(
            `session:user_invalidated:${id}`,
            String(Math.floor(Date.now() / 1000)),
            'EX', 7 * 24 * 60 * 60,
          );
        }

        res.status(204).send();
      } catch (err) {
        next(err);
      }
    },
  );

  return router;
}
