// ── Multi-Stage Payload Tracking ────────────────────────────────────────────
//
// Tracks multi-stage malware execution chains by monitoring:
// - Files created/dropped by the initial process
// - Network downloads (curl/wget observed in strace)
// - New executables launched after being dropped
//
// This builds a full "kill chain" showing how the malware evolves through stages.

// ── Types ───────────────────────────────────────────────────────────────────

export type PayloadStageType = 'initial' | 'downloaded' | 'dropped' | 'decoded' | 'injected';

export interface PayloadStage {
  stage: number;
  type: PayloadStageType;
  path: string;
  sha256: string;
  size: number;
  fileType: string;
  source: string;
  timestamp: string;
}

export interface MultiStageReport {
  stages: PayloadStage[];
  killChain: string[];
  finalPayload: PayloadStage | null;
  totalStages: number;
  hasNetworkStage: boolean;
  hasDecodingStage: boolean;
}

// ── Input Types (from sandbox monitoring) ───────────────────────────────────

export interface FileCreateEvent {
  path: string;
  pid: number;
  timestamp: string;
  size: number;
  sha256: string;
  fileType: string;
}

export interface NetworkDownloadEvent {
  url: string;
  destinationPath: string;
  pid: number;
  timestamp: string;
  size: number;
  sha256: string;
  fileType: string;
  tool: string;
}

export interface ProcessExecEvent {
  executable: string;
  args: string[];
  pid: number;
  parentPid: number;
  timestamp: string;
}

export interface StraceEntry {
  pid: number;
  syscall: string;
  args: string[];
  returnValue: string;
  timestamp: string;
}

// ── Tracker Implementation ──────────────────────────────────────────────────

/**
 * Analyze strace output, file events, and process tree to build a multi-stage
 * payload execution chain.
 */
export function buildMultiStageReport(opts: {
  initialSample: {
    path: string;
    sha256: string;
    size: number;
    fileType: string;
  };
  fileCreates: FileCreateEvent[];
  networkDownloads: NetworkDownloadEvent[];
  processExecs: ProcessExecEvent[];
  straceEntries: StraceEntry[];
  startTime: string;
}): MultiStageReport {
  const { initialSample, fileCreates, networkDownloads, processExecs, straceEntries, startTime } = opts;

  const stages: PayloadStage[] = [];
  const killChain: string[] = [];

  // Stage 0: Initial sample
  const stage0: PayloadStage = {
    stage: 0,
    type: 'initial',
    path: initialSample.path,
    sha256: initialSample.sha256,
    size: initialSample.size,
    fileType: initialSample.fileType,
    source: 'user submission',
    timestamp: startTime,
  };
  stages.push(stage0);
  killChain.push(`[Stage 0] Initial sample executed: ${initialSample.fileType} (${formatSize(initialSample.size)})`);

  // Track which PIDs are descendants of the initial process
  const initialPid = processExecs.length > 0 ? processExecs[0]?.pid ?? 1 : 1;
  const descendantPids = buildDescendantSet(processExecs, initialPid);

  // Stage detection: Files dropped by the process tree
  const droppedFiles = fileCreates.filter(fc => {
    // Only files created by our process tree
    if (!descendantPids.has(fc.pid)) return false;
    // Only executable-looking files or scripts
    return isExecutableType(fc.fileType) || isScriptType(fc.path);
  });

  let stageCounter = 1;

  for (const dropped of droppedFiles) {
    const stage: PayloadStage = {
      stage: stageCounter,
      type: 'dropped',
      path: dropped.path,
      sha256: dropped.sha256,
      size: dropped.size,
      fileType: dropped.fileType,
      source: `PID ${dropped.pid} (process tree)`,
      timestamp: dropped.timestamp,
    };
    stages.push(stage);
    killChain.push(
      `[Stage ${stageCounter}] Dropped file: ${basename(dropped.path)} (${dropped.fileType}, ${formatSize(dropped.size)}) by PID ${dropped.pid}`,
    );
    stageCounter++;
  }

  // Stage detection: Network downloads
  for (const download of networkDownloads) {
    if (!descendantPids.has(download.pid)) continue;

    const stage: PayloadStage = {
      stage: stageCounter,
      type: 'downloaded',
      path: download.destinationPath,
      sha256: download.sha256,
      size: download.size,
      fileType: download.fileType,
      source: `Downloaded from ${download.url} via ${download.tool}`,
      timestamp: download.timestamp,
    };
    stages.push(stage);
    killChain.push(
      `[Stage ${stageCounter}] Downloaded payload: ${download.url} -> ${basename(download.destinationPath)} (${download.fileType}, ${formatSize(download.size)})`,
    );
    stageCounter++;
  }

  // Stage detection: Decoded/unpacked payloads (detected via execve of recently-created files)
  const recentlyCreatedPaths = new Set(fileCreates.map(fc => fc.path));
  const decodedExecutions = processExecs.filter(pe => {
    return recentlyCreatedPaths.has(pe.executable) && pe.pid !== initialPid;
  });

  for (const exec of decodedExecutions) {
    // Find the corresponding file create event
    const fileCreate = fileCreates.find(fc => fc.path === exec.executable);
    if (!fileCreate) continue;

    // Check if this file was already captured as a dropped file
    const alreadyCaptured = stages.some(s => s.path === exec.executable && s.type === 'dropped');
    if (alreadyCaptured) {
      // Update kill chain to note it was executed
      killChain.push(
        `[Execution] Dropped file executed: ${basename(exec.executable)} (PID ${exec.pid})`,
      );
      continue;
    }

    const stage: PayloadStage = {
      stage: stageCounter,
      type: 'decoded',
      path: exec.executable,
      sha256: fileCreate.sha256,
      size: fileCreate.size,
      fileType: fileCreate.fileType,
      source: `Decoded/unpacked and executed by PID ${exec.parentPid}`,
      timestamp: exec.timestamp,
    };
    stages.push(stage);
    killChain.push(
      `[Stage ${stageCounter}] Decoded payload executed: ${basename(exec.executable)} (PID ${exec.pid})`,
    );
    stageCounter++;
  }

  // Detect injection patterns from strace (ptrace, process_vm_writev, memfd_create)
  const injectionEvents = detectInjectionFromStrace(straceEntries, descendantPids);
  for (const injection of injectionEvents) {
    const stage: PayloadStage = {
      stage: stageCounter,
      type: 'injected',
      path: injection.targetProcess,
      sha256: '',
      size: 0,
      fileType: 'memory-injected',
      source: `Injected by PID ${injection.sourcePid} via ${injection.method}`,
      timestamp: injection.timestamp,
    };
    stages.push(stage);
    killChain.push(
      `[Stage ${stageCounter}] Process injection: PID ${injection.sourcePid} -> ${injection.targetProcess} via ${injection.method}`,
    );
    stageCounter++;
  }

  // Determine final payload (last stage that is an executable type)
  const executableStages = stages.filter(
    s => s.type !== 'initial' && (isExecutableType(s.fileType) || s.type === 'injected'),
  );
  const finalPayload = executableStages.length > 0
    ? executableStages[executableStages.length - 1] ?? null
    : null;

  return {
    stages,
    killChain,
    finalPayload,
    totalStages: stages.length,
    hasNetworkStage: stages.some(s => s.type === 'downloaded'),
    hasDecodingStage: stages.some(s => s.type === 'decoded'),
  };
}

// ── Strace Analysis Helpers ─────────────────────────────────────────────────

interface InjectionEvent {
  sourcePid: number;
  targetProcess: string;
  method: string;
  timestamp: string;
}

function detectInjectionFromStrace(
  entries: StraceEntry[],
  descendantPids: Set<number>,
): InjectionEvent[] {
  const injections: InjectionEvent[] = [];

  for (const entry of entries) {
    if (!descendantPids.has(entry.pid)) continue;

    // ptrace(PTRACE_ATTACH, ...) - classic process injection
    if (entry.syscall === 'ptrace' && entry.args[0]?.includes('ATTACH')) {
      const targetPid = parseInt(entry.args[1] ?? '0', 10);
      injections.push({
        sourcePid: entry.pid,
        targetProcess: `PID ${targetPid}`,
        method: 'ptrace',
        timestamp: entry.timestamp,
      });
    }

    // process_vm_writev - direct memory write to another process
    if (entry.syscall === 'process_vm_writev') {
      const targetPid = parseInt(entry.args[0] ?? '0', 10);
      if (targetPid !== entry.pid) {
        injections.push({
          sourcePid: entry.pid,
          targetProcess: `PID ${targetPid}`,
          method: 'process_vm_writev',
          timestamp: entry.timestamp,
        });
      }
    }

    // memfd_create - anonymous in-memory file execution (fileless malware)
    if (entry.syscall === 'memfd_create') {
      injections.push({
        sourcePid: entry.pid,
        targetProcess: `memfd (anonymous)`,
        method: 'memfd_create',
        timestamp: entry.timestamp,
      });
    }
  }

  return injections;
}

/**
 * Parse strace output to extract network download events.
 * Looks for curl/wget execve calls and correlates with file creation.
 */
export function extractNetworkDownloads(
  processExecs: ProcessExecEvent[],
  fileCreates: FileCreateEvent[],
): NetworkDownloadEvent[] {
  const downloads: NetworkDownloadEvent[] = [];

  for (const exec of processExecs) {
    const execName = basename(exec.executable).toLowerCase();
    if (execName !== 'curl' && execName !== 'wget' && execName !== 'fetch') continue;

    // Extract URL from args
    const url = extractUrlFromArgs(exec.args, execName);
    if (!url) continue;

    // Determine output file
    const outputPath = extractOutputPath(exec.args, execName);

    // Find corresponding file create event (closest in time after this exec)
    const execTime = new Date(exec.timestamp).getTime();
    const matchingFile = fileCreates.find(fc => {
      const fcTime = new Date(fc.timestamp).getTime();
      if (outputPath && fc.path === outputPath) return true;
      return fcTime >= execTime && fcTime - execTime < 30000 && fc.pid === exec.pid;
    });

    downloads.push({
      url,
      destinationPath: matchingFile?.path ?? outputPath ?? '/tmp/unknown',
      pid: exec.pid,
      timestamp: exec.timestamp,
      size: matchingFile?.size ?? 0,
      sha256: matchingFile?.sha256 ?? '',
      fileType: matchingFile?.fileType ?? 'unknown',
      tool: execName,
    });
  }

  return downloads;
}

// ── Utility Functions ───────────────────────────────────────────────────────

function buildDescendantSet(execs: ProcessExecEvent[], rootPid: number): Set<number> {
  const descendants = new Set<number>([rootPid]);
  let changed = true;

  while (changed) {
    changed = false;
    for (const exec of execs) {
      if (descendants.has(exec.parentPid) && !descendants.has(exec.pid)) {
        descendants.add(exec.pid);
        changed = true;
      }
    }
  }

  return descendants;
}

function isExecutableType(fileType: string): boolean {
  const lower = fileType.toLowerCase();
  return (
    lower.includes('elf') ||
    lower.includes('pe') ||
    lower.includes('executable') ||
    lower.includes('mach-o') ||
    lower.includes('dex')
  );
}

function isScriptType(path: string): boolean {
  const ext = path.split('.').pop()?.toLowerCase() ?? '';
  return ['sh', 'bash', 'py', 'pl', 'rb', 'ps1', 'bat', 'cmd', 'vbs', 'js'].includes(ext);
}

function basename(path: string): string {
  return path.split('/').pop() ?? path;
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function extractUrlFromArgs(args: string[], _ : string): string | null {
  // curl: URL is typically the last non-flag argument or after -L
  // wget: URL is typically the last argument
  for (let i = args.length - 1; i >= 0; i--) {
    const arg = args[i] ?? '';
    if (arg.startsWith('http://') || arg.startsWith('https://') || arg.startsWith('ftp://')) {
      return arg;
    }
  }

  // Check for --url flag
  for (let i = 0; i < args.length - 1; i++) {
    if (args[i] === '--url' || args[i] === '-u') {
      const nextArg = args[i + 1] ?? '';
      if (nextArg.startsWith('http')) return nextArg;
    }
  }

  return null;
}

function extractOutputPath(args: string[], tool: string): string | null {
  for (let i = 0; i < args.length - 1; i++) {
    const arg = args[i] ?? '';
    if (tool === 'curl' && (arg === '-o' || arg === '--output')) {
      return args[i + 1] ?? null;
    }
    if (tool === 'wget' && (arg === '-O' || arg === '--output-document')) {
      return args[i + 1] ?? null;
    }
  }
  return null;
}
