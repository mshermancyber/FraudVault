export interface DetectionEngineConfig {
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
  workerConcurrency: number;
  /** Base SID for generated Suricata/Snort rules. */
  suricataBaseSid: number;
  snortBaseSid: number;
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

export const config: DetectionEngineConfig = {
  port: envInt('PORT', 3004),
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
  workerConcurrency: envInt('WORKER_CONCURRENCY', 3),
  suricataBaseSid: envInt('SURICATA_BASE_SID', 9000000),
  snortBaseSid: envInt('SNORT_BASE_SID', 8000000),
};
