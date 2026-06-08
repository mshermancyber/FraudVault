function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value;
}

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

export interface OrchestratorConfig {
  readonly nodeEnv: string;
  readonly logLevel: string;

  readonly postgres: {
    readonly host: string;
    readonly port: number;
    readonly database: string;
    readonly user: string;
    readonly password: string;
    readonly poolMax: number;
  };

  readonly redis: {
    readonly host: string;
    readonly port: number;
    readonly password: string | undefined;
  };

  readonly worker: {
    readonly concurrency: number;
    readonly analysisTimeoutSeconds: number;
    readonly maxRetries: number;
  };
}

export function loadConfig(): OrchestratorConfig {
  return {
    nodeEnv: optionalEnv('NODE_ENV', 'development'),
    logLevel: optionalEnv('LOG_LEVEL', 'info'),

    postgres: {
      host: optionalEnv('POSTGRES_HOST', 'localhost'),
      port: optionalIntEnv('POSTGRES_PORT', 5432),
      database: optionalEnv('POSTGRES_DB', 'scanboy'),
      user: optionalEnv('POSTGRES_USER', 'scanboy'),
      password: requireEnv('POSTGRES_PASSWORD'),
      poolMax: optionalIntEnv('POSTGRES_POOL_MAX', 10),
    },

    redis: {
      host: optionalEnv('REDIS_HOST', 'localhost'),
      port: optionalIntEnv('REDIS_PORT', 6379),
      password: process.env['REDIS_PASSWORD'],
    },

    worker: {
      concurrency: optionalIntEnv('WORKER_CONCURRENCY', 5),
      analysisTimeoutSeconds: optionalIntEnv('SANDBOX_TIMEOUT_SECONDS', 300),
      maxRetries: optionalIntEnv('WORKER_MAX_RETRIES', 3),
    },
  };
}
