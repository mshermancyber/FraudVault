import { Router, type Request, type Response } from 'express';
import type pg from 'pg';
import type Redis from 'ioredis';

export function createHealthRouter(pool: pg.Pool, redis: Redis): Router {
  const router = Router();

  router.get('/', async (_req: Request, res: Response) => {
    const checks: Record<string, 'ok' | 'degraded' | 'down'> = {};

    try {
      await pool.query('SELECT 1');
      checks['postgres'] = 'ok';
    } catch {
      checks['postgres'] = 'down';
    }

    try {
      await redis.ping();
      checks['redis'] = 'ok';
    } catch {
      checks['redis'] = 'down';
    }

    const allHealthy = Object.values(checks).every((v) => v === 'ok');

    res.status(allHealthy ? 200 : 503).json({
      success: true,
      data: {
        status: allHealthy ? 'healthy' : 'degraded',
        checks,
        timestamp: new Date().toISOString(),
      },
      error: null,
      requestId: res.getHeader('x-request-id') as string,
      timestamp: new Date().toISOString(),
    });
  });

  return router;
}
