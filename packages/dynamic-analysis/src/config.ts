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

export interface DynamicAnalysisConfig {
  readonly nodeEnv: string;
  readonly port: number;
  readonly host: string;
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

  readonly sandboxManager: {
    readonly baseUrl: string;
    readonly timeoutMs: number;
  };

  readonly detonation: {
    readonly defaultDurationSeconds: number;
    readonly maxDurationSeconds: number;
    readonly screenshotIntervalSeconds: number;
    readonly monitorPollIntervalMs: number;
    readonly artifactStoragePath: string;
    readonly maxSampleSizeBytes: number;
  };

  readonly queue: {
    readonly concurrency: number;
    readonly maxRetries: number;
    readonly retryDelayMs: number;
  };
}

export function loadConfig(): DynamicAnalysisConfig {
  return {
    nodeEnv: optionalEnv('NODE_ENV', 'development'),
    port: optionalIntEnv('DYNAMIC_ANALYSIS_PORT', 3009),
    host: optionalEnv('DYNAMIC_ANALYSIS_HOST', '0.0.0.0'),
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

    sandboxManager: {
      baseUrl: optionalEnv('SANDBOX_MANAGER_URL', 'http://localhost:3008'),
      timeoutMs: optionalIntEnv('SANDBOX_MANAGER_TIMEOUT_MS', 30_000),
    },

    detonation: {
      defaultDurationSeconds: optionalIntEnv('DETONATION_DEFAULT_DURATION_S', 120),
      maxDurationSeconds: optionalIntEnv('DETONATION_MAX_DURATION_S', 600),
      screenshotIntervalSeconds: optionalIntEnv('SCREENSHOT_INTERVAL_S', 10),
      monitorPollIntervalMs: optionalIntEnv('MONITOR_POLL_INTERVAL_MS', 2000),
      artifactStoragePath: optionalEnv('ARTIFACT_STORAGE_PATH', '/var/lib/scanboy/artifacts'),
      maxSampleSizeBytes: optionalIntEnv('MAX_SAMPLE_SIZE_BYTES', 100 * 1024 * 1024),
    },

    queue: {
      concurrency: optionalIntEnv('QUEUE_CONCURRENCY', 4),
      maxRetries: optionalIntEnv('QUEUE_MAX_RETRIES', 2),
      retryDelayMs: optionalIntEnv('QUEUE_RETRY_DELAY_MS', 5000),
    },
  };
}
