import pino from 'pino';
import { SandboxStatus } from '@scanboy/shared';
import type { SandboxProvider, SandboxConfig, SandboxInstance } from '../providers/base.js';
import type { SandboxManagerConfig } from '../config.js';

// ── Pool types ──────────────────────────────────────────────────────────────

interface PoolEntry {
  readonly instance: SandboxInstance;
  readonly provider: SandboxProvider;
  readonly config: SandboxConfig;
  checkedOutAt: string | null;
  checkedOutBy: string | null;
  readonly createdAt: string;
}

interface CheckoutResult {
  readonly instance: SandboxInstance;
  readonly provider: SandboxProvider;
}

interface PoolStats {
  readonly totalInstances: number;
  readonly availableInstances: number;
  readonly checkedOutInstances: number;
  readonly queuedRequests: number;
}

interface QueuedRequest {
  readonly id: string;
  readonly config: SandboxConfig;
  readonly provider: SandboxProvider;
  readonly queuedAt: string;
  resolve: (result: CheckoutResult) => void;
  reject: (err: Error) => void;
}

// ── Pool manager ────────────────────────────────────────────────────────────

export class PoolManager {
  private readonly pool = new Map<string, PoolEntry>();
  private readonly waitQueue: QueuedRequest[] = [];
  private cleanupTimer: ReturnType<typeof setInterval> | null = null;
  private replenishTimer: ReturnType<typeof setInterval> | null = null;

  constructor(
    private readonly cfg: SandboxManagerConfig['pool'],
    private readonly logger: pino.Logger,
  ) {}

  /**
   * Start pool maintenance loops.
   */
  start(): void {
    this.cleanupTimer = setInterval(
      () => void this.cleanupExpiredSessions(),
      this.cfg.cleanupIntervalMs,
    );

    this.replenishTimer = setInterval(
      () => void this.replenishPool(),
      this.cfg.cleanupIntervalMs,
    );

    this.logger.info(
      {
        minReady: this.cfg.minReady,
        maxTotal: this.cfg.maxTotal,
        sessionTimeoutMs: this.cfg.sessionTimeoutMs,
      },
      'Sandbox pool manager started',
    );
  }

  /**
   * Stop pool maintenance and destroy all instances.
   */
  async stop(): Promise<void> {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }
    if (this.replenishTimer) {
      clearInterval(this.replenishTimer);
      this.replenishTimer = null;
    }

    // Reject all queued requests
    for (const queued of this.waitQueue) {
      queued.reject(new Error('Pool manager is shutting down'));
    }
    this.waitQueue.length = 0;

    // Destroy all pool instances
    const destroyPromises = [...this.pool.values()].map(async (entry) => {
      try {
        await entry.provider.destroy(entry.instance.instanceId);
      } catch (err) {
        this.logger.warn(
          { instanceId: entry.instance.instanceId, err },
          'Failed to destroy instance during shutdown',
        );
      }
    });

    await Promise.allSettled(destroyPromises);
    this.pool.clear();

    this.logger.info('Sandbox pool manager stopped');
  }

  /**
   * Pre-provision sandboxes into the pool for fast checkout.
   */
  async warmPool(
    provider: SandboxProvider,
    config: SandboxConfig,
    count: number,
  ): Promise<void> {
    const toProvision = Math.min(
      count,
      this.cfg.maxTotal - this.pool.size,
    );

    this.logger.info(
      { count: toProvision, provider: provider.providerName },
      'Warming sandbox pool',
    );

    const results = await Promise.allSettled(
      Array.from({ length: toProvision }, () =>
        this.provisionToPool(provider, config),
      ),
    );

    const succeeded = results.filter((r) => r.status === 'fulfilled').length;
    const failed = results.filter((r) => r.status === 'rejected').length;

    this.logger.info(
      { succeeded, failed },
      'Pool warming complete',
    );
  }

  /**
   * Check out a sandbox instance for use. If none available and pool is full,
   * the request is queued until an instance becomes available.
   */
  async checkout(
    provider: SandboxProvider,
    config: SandboxConfig,
    requesterId: string,
  ): Promise<CheckoutResult> {
    // Try to find an available instance matching the config
    const available = this.findAvailableInstance(config);
    if (available) {
      available.checkedOutAt = new Date().toISOString();
      available.checkedOutBy = requesterId;

      this.logger.info(
        {
          instanceId: available.instance.instanceId,
          requesterId,
        },
        'Sandbox checked out from pool',
      );

      return {
        instance: available.instance,
        provider: available.provider,
      };
    }

    // If pool is not full, provision a new instance
    if (this.pool.size < this.cfg.maxTotal) {
      const entry = await this.provisionToPool(provider, config);
      entry.checkedOutAt = new Date().toISOString();
      entry.checkedOutBy = requesterId;

      this.logger.info(
        {
          instanceId: entry.instance.instanceId,
          requesterId,
        },
        'New sandbox provisioned and checked out',
      );

      return {
        instance: entry.instance,
        provider: entry.provider,
      };
    }

    // Pool is exhausted -- queue the request
    this.logger.info(
      { requesterId, queueDepth: this.waitQueue.length + 1 },
      'Pool exhausted, queueing checkout request',
    );

    return new Promise<CheckoutResult>((resolve, reject) => {
      const timeoutHandle = setTimeout(() => {
        const idx = this.waitQueue.findIndex(
          (q) => q.id === requesterId,
        );
        if (idx !== -1) {
          this.waitQueue.splice(idx, 1);
        }
        reject(
          new Error(
            `Sandbox provisioning timed out after ${this.cfg.provisionTimeoutMs}ms`,
          ),
        );
      }, this.cfg.provisionTimeoutMs);

      this.waitQueue.push({
        id: requesterId,
        config,
        provider,
        queuedAt: new Date().toISOString(),
        resolve: (result) => {
          clearTimeout(timeoutHandle);
          resolve(result);
        },
        reject: (err) => {
          clearTimeout(timeoutHandle);
          reject(err);
        },
      });
    });
  }

  /**
   * Return a sandbox instance to the pool, making it available for reuse
   * or destroying it if it is in an error state.
   */
  async returnToPool(instanceId: string): Promise<void> {
    const entry = this.pool.get(instanceId);
    if (!entry) {
      this.logger.warn(
        { instanceId },
        'Attempted to return unknown instance to pool',
      );
      return;
    }

    const status = await entry.provider.getStatus(instanceId);

    if (status === SandboxStatus.Error || status === SandboxStatus.Offline) {
      // Instance is unhealthy, destroy it
      this.logger.info(
        { instanceId, status },
        'Destroying unhealthy instance on return',
      );
      await this.destroyPoolInstance(instanceId);
      return;
    }

    // Reset the instance to clean state via snapshot restore
    try {
      await entry.provider.restore(instanceId, 'clean-base');
      entry.checkedOutAt = null;
      entry.checkedOutBy = null;

      this.logger.info({ instanceId }, 'Sandbox returned to pool');

      // Serve queued requests
      this.serveQueuedRequest(entry);
    } catch (err) {
      this.logger.warn(
        { instanceId, err },
        'Failed to restore instance, destroying',
      );
      await this.destroyPoolInstance(instanceId);
    }
  }

  /**
   * Forcibly destroy and remove a sandbox from the pool.
   */
  async destroyPoolInstance(instanceId: string): Promise<void> {
    const entry = this.pool.get(instanceId);
    if (!entry) return;

    try {
      await entry.provider.destroy(instanceId);
    } catch (err) {
      this.logger.warn({ instanceId, err }, 'Error destroying pool instance');
    }

    this.pool.delete(instanceId);
  }

  /**
   * Get current pool statistics.
   */
  getStats(): PoolStats {
    let available = 0;
    let checkedOut = 0;

    for (const entry of this.pool.values()) {
      if (entry.checkedOutAt) {
        checkedOut++;
      } else {
        available++;
      }
    }

    return {
      totalInstances: this.pool.size,
      availableInstances: available,
      checkedOutInstances: checkedOut,
      queuedRequests: this.waitQueue.length,
    };
  }

  /**
   * Get all tracked instances.
   */
  listInstances(): ReadonlyArray<{
    readonly instanceId: string;
    readonly provider: string;
    readonly status: SandboxStatus;
    readonly checkedOutAt: string | null;
    readonly checkedOutBy: string | null;
    readonly createdAt: string;
  }> {
    return [...this.pool.values()].map((entry) => ({
      instanceId: entry.instance.instanceId,
      provider: entry.provider.providerName,
      status: entry.instance.status,
      checkedOutAt: entry.checkedOutAt,
      checkedOutBy: entry.checkedOutBy,
      createdAt: entry.createdAt,
    }));
  }

  // ── Private helpers ─────────────────────────────────────────────────────────

  private async provisionToPool(
    provider: SandboxProvider,
    config: SandboxConfig,
  ): Promise<PoolEntry> {
    const instance = await provider.provision(config);

    const entry: PoolEntry = {
      instance,
      provider,
      config,
      checkedOutAt: null,
      checkedOutBy: null,
      createdAt: new Date().toISOString(),
    };

    this.pool.set(instance.instanceId, entry);
    return entry;
  }

  private findAvailableInstance(config: SandboxConfig): PoolEntry | undefined {
    for (const entry of this.pool.values()) {
      if (
        !entry.checkedOutAt &&
        entry.config.os === config.os &&
        entry.config.architecture === config.architecture &&
        entry.instance.status === SandboxStatus.Running
      ) {
        return entry;
      }
    }
    return undefined;
  }

  private serveQueuedRequest(entry: PoolEntry): void {
    // Find a queued request that matches this instance's config
    const idx = this.waitQueue.findIndex(
      (q) =>
        q.config.os === entry.config.os &&
        q.config.architecture === entry.config.architecture,
    );

    if (idx !== -1) {
      const queued = this.waitQueue.splice(idx, 1)[0];
      if (queued) {
        entry.checkedOutAt = new Date().toISOString();
        entry.checkedOutBy = queued.id;

        this.logger.info(
          { instanceId: entry.instance.instanceId, requesterId: queued.id },
          'Serving queued checkout request',
        );

        queued.resolve({
          instance: entry.instance,
          provider: entry.provider,
        });
      }
    }
  }

  private async cleanupExpiredSessions(): Promise<void> {
    const now = Date.now();

    for (const [instanceId, entry] of this.pool) {
      if (!entry.checkedOutAt) continue;

      const checkedOutTime = new Date(entry.checkedOutAt).getTime();
      const elapsed = now - checkedOutTime;

      if (elapsed > this.cfg.sessionTimeoutMs) {
        this.logger.warn(
          {
            instanceId,
            checkedOutBy: entry.checkedOutBy,
            elapsedMs: elapsed,
          },
          'Sandbox session timed out, destroying',
        );
        await this.destroyPoolInstance(instanceId);
      }
    }
  }

  private async replenishPool(): Promise<void> {
    // Count available (not checked out) instances
    let available = 0;
    let lastProvider: SandboxProvider | null = null;
    let lastConfig: SandboxConfig | null = null;

    for (const entry of this.pool.values()) {
      if (!entry.checkedOutAt) {
        available++;
      }
      lastProvider = entry.provider;
      lastConfig = entry.config;
    }

    // If we have a reference config and we're below the minimum, top up
    if (
      available < this.cfg.minReady &&
      this.pool.size < this.cfg.maxTotal &&
      lastProvider &&
      lastConfig
    ) {
      const toProvision = Math.min(
        this.cfg.minReady - available,
        this.cfg.maxTotal - this.pool.size,
      );

      this.logger.info(
        { available, minReady: this.cfg.minReady, toProvision },
        'Replenishing sandbox pool',
      );

      for (let i = 0; i < toProvision; i++) {
        try {
          await this.provisionToPool(lastProvider, lastConfig);
        } catch (err) {
          this.logger.error({ err }, 'Failed to replenish pool instance');
        }
      }
    }
  }
}
