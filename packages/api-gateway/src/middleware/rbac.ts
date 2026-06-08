import type { Request, Response, NextFunction } from 'express';
import { UserRole } from '@scanboy/shared';

/**
 * Role hierarchy: higher index = more privileged.
 */
const ROLE_HIERARCHY: ReadonlyArray<UserRole> = [
  UserRole.Viewer,
  UserRole.Analyst,
  UserRole.Admin,
  UserRole.SuperAdmin,
];

function roleIndex(role: UserRole): number {
  return ROLE_HIERARCHY.indexOf(role);
}

/**
 * Middleware factory that restricts access to users with a minimum role level.
 * Must be placed after the auth middleware so that `req.user` is populated.
 */
export function requireRole(minimumRole: UserRole) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const user = req.user;

    if (!user) {
      res.status(401).json({
        success: false,
        data: null,
        error: { code: 'UNAUTHORIZED', message: 'Authentication required' },
        requestId: res.getHeader('x-request-id') as string,
        timestamp: new Date().toISOString(),
      });
      return;
    }

    if (roleIndex(user.role) < roleIndex(minimumRole)) {
      res.status(403).json({
        success: false,
        data: null,
        error: {
          code: 'FORBIDDEN',
          message: `Minimum role required: ${minimumRole}`,
        },
        requestId: res.getHeader('x-request-id') as string,
        timestamp: new Date().toISOString(),
      });
      return;
    }

    next();
  };
}
