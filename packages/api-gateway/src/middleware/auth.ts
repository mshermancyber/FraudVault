import type { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { createHash } from 'node:crypto';
import type Redis from 'ioredis';
import type { UserRole } from '@scanboy/shared';
import { REDIS_KEY_PREFIXES } from '@scanboy/shared';
import type { AppConfig } from '../config.js';

function tokenHash(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

export interface JwtPayload {
  sub: string;
  email: string;
  role: UserRole;
  type?: string;
  iat: number;
  exp: number;
}

declare global {
  namespace Express {
    interface Request {
      user?: JwtPayload;
    }
  }
}

/**
 * Creates JWT authentication middleware.
 * Extracts and verifies the Bearer token from the Authorization header.
 * Checks the Redis revocation list so that logged-out tokens are rejected.
 */
export function createAuthMiddleware(config: AppConfig, redis?: Redis) {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      res.status(401).json({
        success: false,
        data: null,
        error: { code: 'UNAUTHORIZED', message: 'Missing or invalid authorization header' },
        requestId: res.getHeader('x-request-id') as string,
        timestamp: new Date().toISOString(),
      });
      return;
    }

    const token = authHeader.slice(7);

    try {
      const decoded = jwt.verify(token, config.jwt.secret, {
        algorithms: ['HS256'],
      }) as JwtPayload;

      if (decoded.type === 'refresh') {
        res.status(401).json({
          success: false,
          data: null,
          error: { code: 'UNAUTHORIZED', message: 'Refresh tokens cannot be used for authentication' },
          requestId: res.getHeader('x-request-id') as string,
          timestamp: new Date().toISOString(),
        });
        return;
      }

      // Check if the token has been revoked (e.g., via logout).
      if (redis) {
        const isRevoked = await redis.get(`${REDIS_KEY_PREFIXES.SESSION}revoked:${tokenHash(token)}`);
        if (isRevoked) {
          res.status(401).json({
            success: false,
            data: null,
            error: { code: 'UNAUTHORIZED', message: 'Token has been revoked' },
            requestId: res.getHeader('x-request-id') as string,
            timestamp: new Date().toISOString(),
          });
          return;
        }

        // Check if the user has been modified (role change, disabled) since this token was issued.
        const invalidatedAt = await redis.get(`${REDIS_KEY_PREFIXES.SESSION}user_invalidated:${decoded.sub}`);
        if (invalidatedAt && decoded.iat < parseInt(invalidatedAt, 10)) {
          res.status(401).json({
            success: false,
            data: null,
            error: { code: 'UNAUTHORIZED', message: 'User account has been modified. Please log in again.' },
            requestId: res.getHeader('x-request-id') as string,
            timestamp: new Date().toISOString(),
          });
          return;
        }
      }

      req.user = decoded;
      next();
    } catch (err) {
      const message =
        err instanceof jwt.TokenExpiredError
          ? 'Token has expired'
          : 'Invalid token';

      res.status(401).json({
        success: false,
        data: null,
        error: { code: 'UNAUTHORIZED', message },
        requestId: res.getHeader('x-request-id') as string,
        timestamp: new Date().toISOString(),
      });
    }
  };
}
