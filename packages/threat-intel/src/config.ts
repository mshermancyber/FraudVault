export interface ThreatIntelConfig {
  port: number;
  host: string;
  database: {
    host: string;
    port: number;
    name: string;
    user: string;
    password: string;
    maxConnections: number;
  };
  redis: {
    host: string;
    port: number;
    password: string;
  };
  providers: {
    virustotal: {
      apiKey: string;
      rateLimit: number; // requests per minute
    };
    malwarebazaar: {
      enabled: boolean;
    };
    otx: {
      apiKey: string;
    };
    abuseipdb: {
      apiKey: string;
    };
    urlhaus: {
      enabled: boolean;
    };
  };
  cacheTtlSeconds: number;
  requestTimeoutMs: number;
  workerConcurrency: number;
}

function env(key: string, fallback: string): string {
  return process.env[key] ?? fallback;
}

function envInt(key: string, fallback: number): number {
  const val = process.env[key];
  if (val === undefined) return fallback;
  const parsed = parseInt(val, 10);
  return Number.isNaN(parsed) ? fallback : parsed;
}

export const config: ThreatIntelConfig = {
  port: envInt('PORT', 3003),
  host: env('HOST', '0.0.0.0'),
  database: {
    host: env('POSTGRES_HOST', env('DB_HOST', 'localhost')),
    port: envInt('POSTGRES_PORT', envInt('DB_PORT', 5432)),
    name: env('POSTGRES_DB', env('DB_NAME', 'scanboy')),
    user: env('POSTGRES_USER', env('DB_USER', 'scanboy')),
    password: env('POSTGRES_PASSWORD', env('DB_PASSWORD', '')),
    maxConnections: envInt('DB_MAX_CONNECTIONS', 10),
  },
  redis: {
    host: env('REDIS_HOST', 'localhost'),
    port: envInt('REDIS_PORT', 6379),
    password: env('REDIS_PASSWORD', ''),
  },
  providers: {
    virustotal: {
      apiKey: env('VIRUSTOTAL_API_KEY', ''),
      rateLimit: envInt('VIRUSTOTAL_RATE_LIMIT', 4),
    },
    malwarebazaar: {
      enabled: env('MALWAREBAZAAR_ENABLED', 'true') === 'true',
    },
    otx: {
      apiKey: env('OTX_API_KEY', ''),
    },
    abuseipdb: {
      apiKey: env('ABUSEIPDB_API_KEY', ''),
    },
    urlhaus: {
      enabled: env('URLHAUS_ENABLED', 'true') === 'true',
    },
  },
  cacheTtlSeconds: envInt('CACHE_TTL_SECONDS', 3600),
  requestTimeoutMs: envInt('REQUEST_TIMEOUT_MS', 30000),
  workerConcurrency: envInt('WORKER_CONCURRENCY', 3),
};
