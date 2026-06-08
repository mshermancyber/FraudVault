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

export interface StaticAnalysisConfig {
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

  readonly worker: {
    readonly concurrency: number;
    readonly analysisTimeoutSeconds: number;
    readonly maxRetries: number;
  };

  readonly analysis: {
    /** Minimum length for extracted ASCII strings. */
    readonly minStringLength: number;
    /** Maximum number of strings to extract per file. */
    readonly maxStrings: number;
    /** Entropy threshold above which a section is flagged as packed/encrypted. */
    readonly highEntropyThreshold: number;
    /** Maximum file size to attempt full analysis (in bytes). */
    readonly maxFileSizeBytes: number;
  };
}

export function loadConfig(): StaticAnalysisConfig {
  return {
    nodeEnv: optionalEnv('NODE_ENV', 'development'),
    port: optionalIntEnv('STATIC_ANALYSIS_PORT', 3002),
    host: optionalEnv('STATIC_ANALYSIS_HOST', '0.0.0.0'),
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
      concurrency: optionalIntEnv('WORKER_CONCURRENCY', 3),
      analysisTimeoutSeconds: optionalIntEnv('ANALYSIS_TIMEOUT_SECONDS', 120),
      maxRetries: optionalIntEnv('WORKER_MAX_RETRIES', 2),
    },

    analysis: {
      minStringLength: optionalIntEnv('MIN_STRING_LENGTH', 4),
      maxStrings: optionalIntEnv('MAX_STRINGS', 10_000),
      highEntropyThreshold: parseFloat(optionalEnv('HIGH_ENTROPY_THRESHOLD', '7.0')),
      maxFileSizeBytes: optionalIntEnv('MAX_FILE_SIZE_BYTES', 256 * 1024 * 1024),
    },
  };
}
