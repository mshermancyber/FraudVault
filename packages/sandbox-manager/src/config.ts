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

export interface SandboxManagerConfig {
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

  readonly qemu: {
    readonly binaryPath: string;
    readonly imagesDir: string;
    readonly snapshotsDir: string;
    readonly bridgeInterface: string;
    readonly vncBasePort: number;
    readonly monitorBasePort: number;
    readonly defaultMemoryMb: number;
    readonly defaultCpuCores: number;
  };

  readonly docker: {
    readonly socketPath: string;
    readonly networkName: string;
    readonly defaultMemoryMb: number;
    readonly defaultCpuShares: number;
    readonly registryPrefix: string;
  };

  readonly pool: {
    readonly minReady: number;
    readonly maxTotal: number;
    readonly provisionTimeoutMs: number;
    readonly sessionTimeoutMs: number;
    readonly cleanupIntervalMs: number;
  };
}

export function loadConfig(): SandboxManagerConfig {
  return {
    nodeEnv: optionalEnv('NODE_ENV', 'development'),
    port: optionalIntEnv('SANDBOX_MANAGER_PORT', 3008),
    host: optionalEnv('SANDBOX_MANAGER_HOST', '0.0.0.0'),
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

    qemu: {
      binaryPath: optionalEnv('QEMU_BINARY', 'qemu-system-x86_64'),
      imagesDir: optionalEnv('QEMU_IMAGES_DIR', '/var/lib/scanboy/images'),
      snapshotsDir: optionalEnv('QEMU_SNAPSHOTS_DIR', '/var/lib/scanboy/snapshots'),
      bridgeInterface: optionalEnv('QEMU_BRIDGE', 'sbr0'),
      vncBasePort: optionalIntEnv('QEMU_VNC_BASE_PORT', 5900),
      monitorBasePort: optionalIntEnv('QEMU_MONITOR_BASE_PORT', 4444),
      defaultMemoryMb: optionalIntEnv('QEMU_DEFAULT_MEMORY_MB', 2048),
      defaultCpuCores: optionalIntEnv('QEMU_DEFAULT_CPU_CORES', 2),
    },

    docker: {
      socketPath: optionalEnv('DOCKER_SOCKET', '/var/run/docker.sock'),
      networkName: optionalEnv('DOCKER_NETWORK', 'scanboy-sandbox'),
      defaultMemoryMb: optionalIntEnv('DOCKER_DEFAULT_MEMORY_MB', 512),
      defaultCpuShares: optionalIntEnv('DOCKER_DEFAULT_CPU_SHARES', 512),
      registryPrefix: optionalEnv('DOCKER_REGISTRY_PREFIX', 'scanboy'),
    },

    pool: {
      minReady: optionalIntEnv('POOL_MIN_READY', 2),
      maxTotal: optionalIntEnv('POOL_MAX_TOTAL', 10),
      provisionTimeoutMs: optionalIntEnv('POOL_PROVISION_TIMEOUT_MS', 120_000),
      sessionTimeoutMs: optionalIntEnv('POOL_SESSION_TIMEOUT_MS', 600_000),
      cleanupIntervalMs: optionalIntEnv('POOL_CLEANUP_INTERVAL_MS', 30_000),
    },
  };
}
