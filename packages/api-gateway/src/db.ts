import pg from 'pg';
import type { AppConfig } from './config.js';

const { Pool } = pg;

let pool: pg.Pool | null = null;

/**
 * Initializes and returns a PostgreSQL connection pool.
 * Reuses the same pool if called multiple times.
 */
export function getPool(config: AppConfig): pg.Pool {
  if (!pool) {
    pool = new Pool({
      host: config.postgres.host,
      port: config.postgres.port,
      database: config.postgres.database,
      user: config.postgres.user,
      password: config.postgres.password,
      max: config.postgres.poolMax,
      idleTimeoutMillis: 30_000,
      connectionTimeoutMillis: 5_000,
    });

    pool.on('error', (err) => {
      console.error('Unexpected PostgreSQL pool error:', err);
    });
  }

  return pool;
}

/**
 * Gracefully shuts down the connection pool.
 */
export async function closePool(): Promise<void> {
  if (pool) {
    await pool.end();
    pool = null;
  }
}
