import type { TelemetryConfig } from './config.js';

// ── Types ──────────────────────────────────────────────────────────────────

export interface ComponentHealth {
  name: string;
  status: 'healthy' | 'unhealthy' | 'degraded';
  latencyMs: number;
  message: string | null;
  checkedAt: string;
}

export interface AggregateHealth {
  status: 'healthy' | 'unhealthy' | 'degraded';
  components: ComponentHealth[];
  timestamp: string;
}

// ── Health Check Functions ─────────────────────────────────────────────────

async function checkPostgres(config: TelemetryConfig): Promise<ComponentHealth> {
  const start = Date.now();
  try {
    // Dynamic import to avoid requiring pg as a hard dependency
    const pg = await import('pg');
    const client = new pg.default.Client({
      host: config.postgres.host,
      port: config.postgres.port,
      database: config.postgres.database,
      user: config.postgres.user,
      password: config.postgres.password,
      connectionTimeoutMillis: config.healthCheck.timeoutMs,
    });

    await client.connect();
    await client.query('SELECT 1');
    await client.end();

    return {
      name: 'postgresql',
      status: 'healthy',
      latencyMs: Date.now() - start,
      message: null,
      checkedAt: new Date().toISOString(),
    };
  } catch (err) {
    return {
      name: 'postgresql',
      status: 'unhealthy',
      latencyMs: Date.now() - start,
      message: err instanceof Error ? err.message : 'Unknown error',
      checkedAt: new Date().toISOString(),
    };
  }
}

async function checkRedis(config: TelemetryConfig): Promise<ComponentHealth> {
  const start = Date.now();
  try {
    const { Redis } = await import('ioredis');
    const client = new Redis({
      host: config.redis.host,
      port: config.redis.port,
      password: config.redis.password,
      connectTimeout: config.healthCheck.timeoutMs,
      maxRetriesPerRequest: 1,
      retryStrategy: () => null, // Don't retry during health check
    });

    await client.ping();
    await client.quit();

    return {
      name: 'redis',
      status: 'healthy',
      latencyMs: Date.now() - start,
      message: null,
      checkedAt: new Date().toISOString(),
    };
  } catch (err) {
    return {
      name: 'redis',
      status: 'unhealthy',
      latencyMs: Date.now() - start,
      message: err instanceof Error ? err.message : 'Unknown error',
      checkedAt: new Date().toISOString(),
    };
  }
}

async function checkElasticsearch(config: TelemetryConfig): Promise<ComponentHealth> {
  const start = Date.now();
  try {
    const url = new URL('/_cluster/health', config.elasticsearch.node);
    const headers: Record<string, string> = {};

    if (config.elasticsearch.username && config.elasticsearch.password) {
      const creds = Buffer.from(
        `${config.elasticsearch.username}:${config.elasticsearch.password}`,
      ).toString('base64');
      headers['Authorization'] = `Basic ${creds}`;
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), config.healthCheck.timeoutMs);

    try {
      const response = await fetch(url.toString(), {
        headers,
        signal: controller.signal,
      });

      if (!response.ok) {
        return {
          name: 'elasticsearch',
          status: 'unhealthy',
          latencyMs: Date.now() - start,
          message: `HTTP ${response.status}: ${response.statusText}`,
          checkedAt: new Date().toISOString(),
        };
      }

      const body = (await response.json()) as { status?: string };
      const esStatus = body.status;

      return {
        name: 'elasticsearch',
        status: esStatus === 'green' ? 'healthy' : esStatus === 'yellow' ? 'degraded' : 'unhealthy',
        latencyMs: Date.now() - start,
        message: esStatus === 'green' ? null : `Cluster status: ${esStatus ?? 'unknown'}`,
        checkedAt: new Date().toISOString(),
      };
    } finally {
      clearTimeout(timeout);
    }
  } catch (err) {
    return {
      name: 'elasticsearch',
      status: 'unhealthy',
      latencyMs: Date.now() - start,
      message: err instanceof Error ? err.message : 'Unknown error',
      checkedAt: new Date().toISOString(),
    };
  }
}

async function checkMinio(config: TelemetryConfig): Promise<ComponentHealth> {
  const start = Date.now();
  try {
    const protocol = config.minio.port === 443 ? 'https' : 'http';
    const url = `${protocol}://${config.minio.endpoint}:${config.minio.port}/minio/health/live`;

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), config.healthCheck.timeoutMs);

    try {
      const response = await fetch(url, { signal: controller.signal });

      return {
        name: 'minio',
        status: response.ok ? 'healthy' : 'unhealthy',
        latencyMs: Date.now() - start,
        message: response.ok ? null : `HTTP ${response.status}: ${response.statusText}`,
        checkedAt: new Date().toISOString(),
      };
    } finally {
      clearTimeout(timeout);
    }
  } catch (err) {
    return {
      name: 'minio',
      status: 'unhealthy',
      latencyMs: Date.now() - start,
      message: err instanceof Error ? err.message : 'Unknown error',
      checkedAt: new Date().toISOString(),
    };
  }
}

// ── Aggregate Health Check ─────────────────────────────────────────────────

export async function checkAllHealth(config: TelemetryConfig): Promise<AggregateHealth> {
  const components = await Promise.all([
    checkPostgres(config),
    checkRedis(config),
    checkElasticsearch(config),
    checkMinio(config),
  ]);

  const hasUnhealthy = components.some((c) => c.status === 'unhealthy');
  const hasDegraded = components.some((c) => c.status === 'degraded');

  let status: AggregateHealth['status'];
  if (hasUnhealthy) {
    status = 'unhealthy';
  } else if (hasDegraded) {
    status = 'degraded';
  } else {
    status = 'healthy';
  }

  return {
    status,
    components,
    timestamp: new Date().toISOString(),
  };
}
