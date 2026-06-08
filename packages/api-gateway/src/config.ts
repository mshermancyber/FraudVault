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

export interface AppConfig {
  readonly nodeEnv: string;
  readonly port: number;
  readonly host: string;
  readonly corsOrigins: string[];
  readonly logLevel: string;

  readonly jwt: {
    readonly secret: string;
    readonly refreshSecret: string;
    readonly expiry: string;
    readonly refreshExpiry: string;
  };
  readonly bcryptRounds: number;

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

  readonly rateLimit: {
    readonly windowMs: number;
    readonly maxRequests: number;
  };
}

export function loadConfig(): AppConfig {
  return {
    nodeEnv: optionalEnv('NODE_ENV', 'development'),
    port: optionalIntEnv('API_PORT', 3000),
    host: optionalEnv('API_HOST', '0.0.0.0'),
    corsOrigins: optionalEnv('CORS_ORIGINS', 'http://localhost:5173').split(','),
    logLevel: optionalEnv('LOG_LEVEL', 'info'),

    jwt: {
      secret: requireEnv('JWT_SECRET'),
      refreshSecret: requireEnv('JWT_REFRESH_SECRET'),
      expiry: optionalEnv('JWT_EXPIRY', '15m'),
      refreshExpiry: optionalEnv('JWT_REFRESH_EXPIRY', '7d'),
    },
    bcryptRounds: optionalIntEnv('BCRYPT_ROUNDS', 12),

    postgres: {
      host: optionalEnv('POSTGRES_HOST', 'localhost'),
      port: optionalIntEnv('POSTGRES_PORT', 5432),
      database: optionalEnv('POSTGRES_DB', 'scanboy'),
      user: optionalEnv('POSTGRES_USER', 'scanboy'),
      password: requireEnv('POSTGRES_PASSWORD'),
      poolMax: optionalIntEnv('POSTGRES_POOL_MAX', 20),
    },

    redis: {
      host: optionalEnv('REDIS_HOST', 'localhost'),
      port: optionalIntEnv('REDIS_PORT', 6379),
      password: process.env['REDIS_PASSWORD'],
    },

    rateLimit: {
      windowMs: optionalIntEnv('RATE_LIMIT_WINDOW_MS', 900_000),
      maxRequests: optionalIntEnv('RATE_LIMIT_MAX_REQUESTS', 100),
    },
  };
}
