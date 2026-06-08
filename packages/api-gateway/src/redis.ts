import Redis from 'ioredis';
import type { AppConfig } from './config.js';

let client: Redis | null = null;

/**
 * Initializes and returns a Redis client. Reuses the same client across calls.
 */
export function getRedis(config: AppConfig): Redis {
  if (!client) {
    client = new Redis({
      host: config.redis.host,
      port: config.redis.port,
      password: config.redis.password,
      maxRetriesPerRequest: 3,
      retryStrategy(times: number) {
        const delay = Math.min(times * 200, 5_000);
        return delay;
      },
    });

    client.on('error', (err) => {
      console.error('Redis client error:', err);
    });
  }

  return client;
}

/**
 * Gracefully disconnects from Redis.
 */
export async function closeRedis(): Promise<void> {
  if (client) {
    await client.quit();
    client = null;
  }
}
