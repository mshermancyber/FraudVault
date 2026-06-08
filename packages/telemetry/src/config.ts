function optionalEnv(name: string, fallback: string): string {
  return process.env[name] ?? fallback;
}

function optionalIntEnv(name: string, fallback: number): number {
  const raw = process.env[name];
  if (!raw) return fallback;
  const parsed = parseInt(raw, 10);
  if (Number.isNaN(parsed)) {
    throw new Error(`Environment variable ${name} must be an integer, got: ${raw}`);
  }
  return parsed;
}

export interface TelemetryConfig {
  readonly nodeEnv: string;
  readonly port: number;
  readonly host: string;
  readonly logLevel: string;

  readonly redis: {
    readonly host: string;
    readonly port: number;
    readonly password: string | undefined;
  };

  readonly postgres: {
    readonly host: string;
    readonly port: number;
    readonly database: string;
    readonly user: string;
    readonly password: string | undefined;
  };

  readonly elasticsearch: {
    readonly node: string;
    readonly username: string | undefined;
    readonly password: string | undefined;
  };

  readonly minio: {
    readonly endpoint: string;
    readonly port: number;
    readonly accessKey: string | undefined;
    readonly secretKey: string | undefined;
  };

  readonly healthCheck: {
    readonly intervalSeconds: number;
    readonly timeoutMs: number;
  };
}

export function loadConfig(): TelemetryConfig {
  return {
    nodeEnv: optionalEnv('NODE_ENV', 'development'),
    port: optionalIntEnv('TELEMETRY_PORT', 3007),
    host: optionalEnv('TELEMETRY_HOST', '0.0.0.0'),
    logLevel: optionalEnv('LOG_LEVEL', 'info'),

    redis: {
      host: optionalEnv('REDIS_HOST', 'localhost'),
      port: optionalIntEnv('REDIS_PORT', 6379),
      password: process.env['REDIS_PASSWORD'],
    },

    postgres: {
      host: optionalEnv('POSTGRES_HOST', 'localhost'),
      port: optionalIntEnv('POSTGRES_PORT', 5432),
      database: optionalEnv('POSTGRES_DB', 'scanboy'),
      user: optionalEnv('POSTGRES_USER', 'scanboy'),
      password: process.env['POSTGRES_PASSWORD'],
    },

    elasticsearch: {
      node: optionalEnv('ELASTICSEARCH_NODE', 'http://localhost:9200'),
      username: process.env['ELASTICSEARCH_USERNAME'],
      password: process.env['ELASTICSEARCH_PASSWORD'],
    },

    minio: {
      endpoint: optionalEnv('MINIO_ENDPOINT', 'localhost'),
      port: optionalIntEnv('MINIO_PORT', 9000),
      accessKey: process.env['MINIO_ACCESS_KEY'],
      secretKey: process.env['MINIO_SECRET_KEY'],
    },

    healthCheck: {
      intervalSeconds: optionalIntEnv('HEALTH_CHECK_INTERVAL_SECONDS', 30),
      timeoutMs: optionalIntEnv('HEALTH_CHECK_TIMEOUT_MS', 5_000),
    },
  };
}
