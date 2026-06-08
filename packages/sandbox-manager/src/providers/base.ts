import { type SandboxStatus, type InternetMode } from '@scanboy/shared';

// ── Provider-level types ────────────────────────────────────────────────────

export interface SandboxConfig {
  /** Human-readable name for the sandbox instance. */
  readonly name: string;
  /** Operating system identifier (e.g. "windows-10", "ubuntu-22.04"). */
  readonly os: string;
  /** OS version string. */
  readonly osVersion: string;
  /** CPU architecture ("x86_64" | "aarch64"). */
  readonly architecture: string;
  /** Memory allocation in megabytes. */
  readonly memoryMb: number;
  /** Number of virtual CPUs. */
  readonly cpuCores: number;
  /** Disk image or base image to start from. */
  readonly baseImage: string;
  /** Network connectivity mode for the sandbox. */
  readonly internetMode: InternetMode;
  /** Maximum execution duration in seconds. */
  readonly maxExecutionSeconds: number;
}

export interface SandboxInstance {
  /** Provider-assigned instance identifier. */
  readonly instanceId: string;
  /** Provider type that created this instance ("qemu" | "docker"). */
  readonly provider: string;
  /** Current sandbox status. */
  readonly status: SandboxStatus;
  /** IP address assigned to the sandbox (if any). */
  readonly ipAddress: string | null;
  /** Port mappings (host -> guest). */
  readonly portMappings: ReadonlyMap<number, number>;
  /** ISO 8601 timestamp when the instance was created. */
  readonly createdAt: string;
  /** Original configuration used to provision the instance. */
  readonly config: SandboxConfig;
}

export interface CommandResult {
  /** Process exit code. */
  readonly exitCode: number;
  /** Standard output content. */
  readonly stdout: string;
  /** Standard error content. */
  readonly stderr: string;
  /** Execution duration in milliseconds. */
  readonly durationMs: number;
}

// ── Abstract provider ───────────────────────────────────────────────────────

export abstract class SandboxProvider {
  abstract readonly providerName: string;

  /**
   * Provision a new sandbox instance from the given configuration.
   */
  abstract provision(config: SandboxConfig): Promise<SandboxInstance>;

  /**
   * Destroy a sandbox instance and release all resources.
   */
  abstract destroy(instanceId: string): Promise<void>;

  /**
   * Create a point-in-time snapshot of the sandbox.
   * Returns a snapshot identifier.
   */
  abstract snapshot(instanceId: string): Promise<string>;

  /**
   * Restore a sandbox to a previous snapshot state.
   */
  abstract restore(instanceId: string, snapshotId: string): Promise<void>;

  /**
   * Get the current status of a sandbox instance.
   */
  abstract getStatus(instanceId: string): Promise<SandboxStatus>;

  /**
   * Execute a command inside the sandbox guest.
   */
  abstract executeCommand(instanceId: string, command: string): Promise<CommandResult>;

  /**
   * Upload a file from the host into the sandbox guest.
   */
  abstract uploadFile(
    instanceId: string,
    localPath: string,
    remotePath: string,
  ): Promise<void>;

  /**
   * Download a file from the sandbox guest to host memory.
   */
  abstract downloadFile(instanceId: string, remotePath: string): Promise<Buffer>;

  /**
   * Capture a screenshot of the sandbox display.
   */
  abstract captureScreenshot(instanceId: string): Promise<Buffer>;

  /**
   * Retrieve a PCAP network capture from the sandbox.
   */
  abstract getNetworkCapture(instanceId: string): Promise<Buffer>;

  /**
   * Dump the sandbox guest memory.
   */
  abstract getMemoryDump(instanceId: string): Promise<Buffer>;
}
