// ── Docker Sandbox Detonation Types ─────────────────────────────────────────

/** Network mode for sandbox execution. */
export type NetworkMode = 'isolated' | 'simulated' | 'controlled';

/** Options for controlling how a sample is executed in the sandbox. */
export interface ExecutionOptions {
  /** Maximum execution time in seconds before the container is killed. */
  readonly timeoutSeconds?: number;
  /** Whether the container should have outbound internet access. */
  readonly internetAccess?: boolean;
  /** Whether to capture network traffic (tcpdump). */
  readonly captureNetwork?: boolean;
  /** Network simulation mode: 'isolated' (no network), 'simulated' (FakeNet), 'controlled' (real internet). */
  readonly networkMode?: NetworkMode;
  /** URL to detonate (for URL submission type). */
  readonly targetUrl?: string;
}

/** Resolved version of ExecutionOptions with all defaults applied. */
export interface ResolvedExecutionOptions {
  readonly timeoutSeconds: number;
  readonly internetAccess: boolean;
  readonly captureNetwork: boolean;
  readonly networkMode: NetworkMode;
  readonly targetUrl: string | null;
}

// ── Process activity types ──────────────────────────────────────────────────

export interface SyscallEvent {
  readonly pid: number;
  readonly syscall: string;
  readonly args: readonly string[];
  readonly returnValue: string;
  readonly timestamp: string;
}

export interface ProcessInfo {
  readonly pid: number;
  readonly parentPid: number;
  readonly name: string;
  readonly commandLine: string;
  readonly user: string;
  readonly startTime: string;
}

export interface ProcessTree {
  readonly root: ProcessTreeNode;
  readonly totalProcesses: number;
  readonly maxDepth: number;
}

export interface ProcessTreeNode {
  readonly pid: number;
  readonly name: string;
  readonly commandLine: string;
  readonly children: ProcessTreeNode[];
}

export interface ProcessActivity {
  readonly syscalls: readonly SyscallEvent[];
  readonly fileOperations: readonly FileOperation[];
  readonly networkOperations: readonly NetworkOperation[];
  readonly processCreations: readonly ProcessCreation[];
}

export interface FileOperation {
  readonly syscall: string;
  readonly path: string;
  readonly newPath: string | null;
  readonly flags: string;
  readonly pid: number;
  readonly timestamp: string;
}

export interface NetworkOperation {
  readonly syscall: string;
  readonly family: string;
  readonly address: string;
  readonly port: number;
  readonly pid: number;
  readonly timestamp: string;
}

export interface ProcessCreation {
  readonly parentPid: number;
  readonly childPid: number;
  readonly syscall: string;
  readonly executable: string;
  readonly args: readonly string[];
  readonly timestamp: string;
}

// ── File activity types ─────────────────────────────────────────────────────

export interface FileActivity {
  readonly created: readonly FileChangeEvent[];
  readonly modified: readonly FileChangeEvent[];
  readonly deleted: readonly FileChangeEvent[];
  readonly moved: readonly FileMoveEvent[];
}

export interface FileChangeEvent {
  readonly path: string;
  readonly timestamp: string;
}

export interface FileMoveEvent {
  readonly fromPath: string;
  readonly toPath: string;
  readonly timestamp: string;
}

// ── Network activity types ──────────────────────────────────────────────────

export interface NetworkActivity {
  readonly connections: readonly ConnectionInfo[];
  readonly dnsQueries: readonly DnsQuery[];
  readonly httpRequests: readonly HttpRequest[];
}

export interface ConnectionInfo {
  readonly protocol: 'tcp' | 'udp';
  readonly sourceAddress: string;
  readonly sourcePort: number;
  readonly destinationAddress: string;
  readonly destinationPort: number;
  readonly timestamp: string;
}

export interface DnsQuery {
  readonly domain: string;
  readonly queryType: string;
  readonly responseAddress: string | null;
  readonly timestamp: string;
}

export interface HttpRequest {
  readonly method: string;
  readonly url: string;
  readonly host: string;
  readonly userAgent: string | null;
  readonly statusCode: number | null;
  readonly timestamp: string;
}

// ── Report types ────────────────────────────────────────────────────────────

export interface DroppedFile {
  readonly path: string;
  readonly size: number;
  readonly sha256: string | null;
  readonly mimeType: string | null;
  readonly isSuspiciousLocation: boolean;
}

export type SuspiciousIndicatorSeverity = 'low' | 'medium' | 'high' | 'critical';

export interface SuspiciousIndicator {
  readonly category: string;
  readonly description: string;
  readonly severity: SuspiciousIndicatorSeverity;
  readonly evidence: string;
}

export interface DetonationReport {
  readonly submissionId: string;
  readonly executionDuration: number;
  readonly exitCode: number | null;
  readonly timedOut: boolean;
  readonly sampleType: string;
  readonly processActivity: {
    readonly processes: readonly ProcessInfo[];
    readonly tree: ProcessTree | null;
    readonly execveProcesses?: readonly {
      readonly pid: number;
      readonly parentPid: number;
      readonly name: string;
      readonly commandLine: string;
      readonly startTime: string;
    }[];
  };
  readonly fileActivity: {
    readonly created: readonly FileChangeEvent[];
    readonly modified: readonly FileChangeEvent[];
    readonly deleted: readonly FileChangeEvent[];
  };
  readonly networkActivity: NetworkActivity;
  readonly droppedFiles: readonly DroppedFile[];
  readonly suspiciousIndicators: readonly SuspiciousIndicator[];
  readonly riskScore: number;
  /** Static analysis results for files extracted from archives or dropped during execution. */
  readonly extractedFiles?: readonly Record<string, unknown>[];
  /** Parsed strace output with DNS, HTTP, external IP, and execve data. */
  readonly straceAnalysis?: Record<string, unknown>;
  /** Wine registry diffs (system and user) captured before/after execution. */
  readonly wineRegistryChanges?: Record<string, unknown>;
  /** IOC-like strings extracted from process memory after execution (best-effort). */
  readonly memoryStrings?: readonly string[];
  /** Base64-encoded PCAP data captured during execution. */
  readonly pcapBase64?: string;
}

/** Result returned from the raw docker execution step. */
export interface DockerExecutionInfo {
  readonly exitCode: number | null;
  readonly timedOut: boolean;
  readonly executionDuration: number;
  readonly straceOutput: string;
  readonly inotifyOutput: string;
  readonly tcpdumpOutput: string;
  readonly psOutput: string;
  readonly droppedFilesOutput: string;
  readonly sampleType: string;
}
