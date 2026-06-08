// ── Detonation report builder & behavioral risk scorer ──────────────────────

import type {
  DetonationReport,
  DockerExecutionInfo,
  ProcessActivity,
  FileActivity,
  NetworkActivity,
  ProcessInfo,
  ProcessTree,
  DroppedFile,
  SuspiciousIndicator,
  FileChangeEvent,
} from './types.js';

// ── Sandbox infrastructure exclusion ────────────────────────────────────────

const SANDBOX_INFRA_PATTERNS = [
  /\/tmp\/scanboy-exec/,
  /\/tmp\/scanboy-logs\//,
  /scanboy-deep/,
  /scanboy-yara/,
  /scanboy-config/,
  /scanboy-wine/,
  /scanboy-rules\.yar/,
  /scanboy-fakenet/,
  /scanboy-analyze/,
];

export function isSandboxInfra(path: string): boolean {
  return SANDBOX_INFRA_PATTERNS.some(p => p.test(path));
}

// ── Suspicious location sets ────────────────────────────────────────────────

const SENSITIVE_LINUX_DIRS = new Set([
  '/etc/cron.d',
  '/etc/cron.daily',
  '/etc/cron.hourly',
  '/etc/cron.weekly',
  '/etc/cron.monthly',
  '/etc/init.d',
  '/etc/systemd/system',
  '/usr/local/bin',
  '/usr/bin',
  '/usr/sbin',
  '/root/.ssh',
  '/home/sandbox/.ssh',
  '/etc/ld.so.preload',
  '/etc/ld.so.conf.d',
]);

const SYSTEM_CONFIG_PATHS = new Set([
  '/etc/passwd',
  '/etc/shadow',
  '/etc/sudoers',
  '/etc/hosts',
  '/etc/resolv.conf',
  '/etc/ld.so.preload',
  '/etc/environment',
  '/etc/profile',
  '/etc/bashrc',
  '/etc/crontab',
]);

const KNOWN_BAD_DOMAIN_PATTERNS: readonly RegExp[] = [
  /\.onion$/i,
  /\.bit$/i,
  /\.i2p$/i,
  /^[a-z0-9]{30,}\.\w+$/i,           // DGA-like: very long random subdomains
  /pastebin\.\w+$/i,
  /paste\.ee$/i,
  /raw\.githubusercontent\.com$/i,
  /transfer\.sh$/i,
  /ngrok\.\w+$/i,
  /\.duckdns\.org$/i,
  /\.no-ip\.\w+$/i,
  /\.dynu\.com$/i,
];

// ── Build the full report ───────────────────────────────────────────────────

export interface BuildReportInput {
  readonly submissionId: string;
  readonly processData: ProcessActivity;
  readonly fileData: FileActivity;
  readonly networkData: NetworkActivity;
  readonly execInfo: DockerExecutionInfo;
  readonly processInfo: {
    readonly processes: readonly ProcessInfo[];
    readonly tree: ProcessTree | null;
  };
}

/**
 * Assemble all parsed behavioral data into a single DetonationReport.
 */
export function buildReport(input: BuildReportInput): DetonationReport {
  const {
    submissionId,
    processData,
    fileData,
    networkData,
    execInfo,
    processInfo,
  } = input;

  // Build dropped files list from file creates that are not in standard temp/log dirs
  const droppedFiles = identifyDroppedFiles(fileData.created, execInfo.droppedFilesOutput);

  // Start with empty indicators, then run all checks
  const suspiciousIndicators: SuspiciousIndicator[] = [];

  // Check file activity
  detectFileIndicators(fileData, suspiciousIndicators);

  // Check network activity
  detectNetworkIndicators(networkData, suspiciousIndicators);

  // Check process activity
  detectProcessIndicators(processData, processInfo, suspiciousIndicators);

  // Check for sample execution patterns
  detectExecutionPatterns(processData, fileData, networkData, suspiciousIndicators);

  const report: DetonationReport = {
    submissionId,
    executionDuration: execInfo.executionDuration,
    exitCode: execInfo.exitCode,
    timedOut: execInfo.timedOut,
    sampleType: execInfo.sampleType,
    processActivity: {
      processes: [...processInfo.processes],
      tree: processInfo.tree,
      execveProcesses: processData.processCreations
        .filter(pc => pc.syscall === 'execve' && pc.executable)
        .map(pc => ({
          pid: pc.childPid,
          parentPid: pc.parentPid,
          name: pc.executable.split('/').pop() ?? pc.executable,
          commandLine: [pc.executable, ...pc.args].join(' '),
          startTime: pc.timestamp,
        })),
    },
    fileActivity: {
      created: [...fileData.created],
      modified: [...fileData.modified],
      deleted: [...fileData.deleted],
    },
    networkActivity: networkData,
    droppedFiles,
    suspiciousIndicators,
    riskScore: 0,
  };

  // Compute risk score from the indicators
  const riskScore = scoreBehavior(report);

  // Return with final score
  return { ...report, riskScore };
}

// ── Risk scoring ────────────────────────────────────────────────────────────

/**
 * Compute a 0-100 behavioral risk score based on the detonation report.
 */
export function scoreBehavior(report: DetonationReport): number {
  let score = 0;

  // ── Structural signals ───────────────────────────────────────
  // File drops in sensitive locations (excluding sandbox infra)
  const realDrops = report.droppedFiles.filter(f => !isSandboxInfra(f.path));
  for (const file of realDrops) {
    if (file.isSuspiciousLocation) score += 10;
  }

  const externalConnections = report.networkActivity.connections.filter(
    (c) => !isLocalAddress(c.destinationAddress),
  );
  if (externalConnections.length > 0) score += 15;

  if (report.processActivity.tree && report.processActivity.tree.maxDepth >= 3) score += 10;
  if (report.processActivity.processes.length > 10) score += 5;

  const systemFileModifications = report.fileActivity.modified.filter((f) =>
    isSystemConfigPath(f.path),
  );
  if (systemFileModifications.length > 0) score += 20;

  const suspiciousDns = report.networkActivity.dnsQueries.filter((q) =>
    KNOWN_BAD_DOMAIN_PATTERNS.some((pattern) => pattern.test(q.domain)),
  );
  if (suspiciousDns.length > 0) score += 15;

  const hasNetworkAndDrops = externalConnections.length > 0 && realDrops.length > 0;
  if (hasNetworkAndDrops) score += 25;

  if (report.fileActivity.deleted.length > 5) score += 5;

  // ── Indicator scoring ──
  // Per-indicator weights are the primary score driver since structural signals
  // (network, filesystem) are limited in --network none / --read-only jails.
  // Dedup: same category only counts highest severity, additional same-category entries halved.
  const weights: Record<string, number> = { critical: 25, high: 15, medium: 6, low: 2 };
  const categoryMaxSeverity = new Map<string, number>();
  const severityRank: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };

  // First pass: find highest severity per category
  for (const ind of report.suspiciousIndicators) {
    if (isSandboxInfra(ind.evidence)) continue;
    const cat = ind.category;
    const rank = severityRank[ind.severity] ?? 0;
    categoryMaxSeverity.set(cat, Math.max(categoryMaxSeverity.get(cat) ?? 0, rank));
  }

  // Second pass: score — first of each category gets full weight, duplicates halved
  const categorySeen = new Map<string, number>();
  const categoryTotals = new Map<string, number>();

  for (const ind of report.suspiciousIndicators) {
    if (isSandboxInfra(ind.evidence)) continue;
    const cat = ind.category;
    const seen = categorySeen.get(cat) ?? 0;
    categorySeen.set(cat, seen + 1);
    const w = weights[ind.severity] ?? 3;
    const effectiveW = seen === 0 ? w : Math.round(w * 0.3); // diminishing returns
    const current = categoryTotals.get(cat) ?? 0;
    categoryTotals.set(cat, current + effectiveW);
  }
  for (const catScore of categoryTotals.values()) score += catScore;

  // ── Category-based score floors ──
  const categories = new Set(report.suspiciousIndicators.map(i => i.category));
  if (categories.has('ransomware'))       score = Math.max(score, 65);
  if (categories.has('c2_communication')) score = Math.max(score, 45);
  if (categories.has('reverse_shell'))    score = Math.max(score, 60);
  if (categories.has('staged_payload'))   score = Math.max(score, 55);
  if (categories.has('persistence'))      score = Math.max(score, 40);

  return Math.min(100, Math.max(0, score));
}

// ── Indicator detection ─────────────────────────────────────────────────────

function detectFileIndicators(
  fileData: FileActivity,
  indicators: SuspiciousIndicator[],
): void {
  // Files created in sensitive directories
  for (const fileEvent of fileData.created) {
    if (isSandboxInfra(fileEvent.path)) continue;

    if (isInSensitiveDir(fileEvent.path)) {
      indicators.push({
        category: 'persistence',
        description: `File created in sensitive directory: ${fileEvent.path}`,
        severity: 'high',
        evidence: `CREATE ${fileEvent.path} at ${fileEvent.timestamp}`,
      });
    }

    // Executable files dropped
    if (isExecutablePath(fileEvent.path)) {
      indicators.push({
        category: 'dropper',
        description: `Executable file dropped: ${fileEvent.path}`,
        severity: 'medium',
        evidence: `CREATE ${fileEvent.path}`,
      });
    }
  }

  // System config file modifications
  for (const fileEvent of fileData.modified) {
    if (isSystemConfigPath(fileEvent.path)) {
      indicators.push({
        category: 'system_modification',
        description: `System configuration file modified: ${fileEvent.path}`,
        severity: 'critical',
        evidence: `MODIFY ${fileEvent.path} at ${fileEvent.timestamp}`,
      });
    }
  }

  // Mass file deletion (anti-forensics)
  if (fileData.deleted.length > 10) {
    indicators.push({
      category: 'anti_forensics',
      description: `Mass file deletion detected: ${fileData.deleted.length} files deleted`,
      severity: 'medium',
      evidence: fileData.deleted.slice(0, 5).map((f) => f.path).join(', '),
    });
  }

  // Cron job creation
  const cronFiles = fileData.created.filter(
    (f) => f.path.includes('/cron') || f.path.includes('crontab'),
  );
  if (cronFiles.length > 0) {
    indicators.push({
      category: 'persistence',
      description: 'Cron job created for persistence',
      severity: 'high',
      evidence: cronFiles.map((f) => f.path).join(', '),
    });
  }

  // SSH key manipulation
  const sshFiles = fileData.created.filter((f) => f.path.includes('.ssh/'));
  if (sshFiles.length > 0) {
    indicators.push({
      category: 'lateral_movement',
      description: 'SSH key files created or modified',
      severity: 'high',
      evidence: sshFiles.map((f) => f.path).join(', '),
    });
  }
}

function detectNetworkIndicators(
  networkData: NetworkActivity,
  indicators: SuspiciousIndicator[],
): void {
  // External connections
  const externalConns = networkData.connections.filter(
    (c) => !isLocalAddress(c.destinationAddress),
  );

  for (const conn of externalConns) {
    // Check for suspicious ports
    if (isSuspiciousPort(conn.destinationPort)) {
      indicators.push({
        category: 'c2_communication',
        description: `Connection to suspicious port: ${conn.destinationAddress}:${conn.destinationPort}`,
        severity: 'high',
        evidence: `${conn.protocol.toUpperCase()} ${conn.sourceAddress}:${conn.sourcePort} -> ${conn.destinationAddress}:${conn.destinationPort}`,
      });
    }
  }

  // DNS to suspicious domains
  for (const query of networkData.dnsQueries) {
    for (const pattern of KNOWN_BAD_DOMAIN_PATTERNS) {
      if (pattern.test(query.domain)) {
        indicators.push({
          category: 'c2_communication',
          description: `DNS query to suspicious domain: ${query.domain}`,
          severity: 'high',
          evidence: `DNS ${query.queryType} ${query.domain}`,
        });
        break;
      }
    }
  }

  // High volume of unique DNS queries (potential DGA)
  const uniqueDomains = new Set(networkData.dnsQueries.map((q) => q.domain));
  if (uniqueDomains.size > 20) {
    indicators.push({
      category: 'dga',
      description: `High volume of unique DNS queries: ${uniqueDomains.size} unique domains`,
      severity: 'high',
      evidence: [...uniqueDomains].slice(0, 10).join(', '),
    });
  }

  // HTTP requests to external hosts
  for (const req of networkData.httpRequests) {
    if (!isLocalAddress(req.host)) {
      indicators.push({
        category: 'data_exfiltration',
        description: `HTTP ${req.method} to external host: ${req.host}${req.url}`,
        severity: 'medium',
        evidence: `${req.method} ${req.host}${req.url}`,
      });
    }
  }
}

function detectProcessIndicators(
  processData: ProcessActivity,
  processInfo: { readonly processes: readonly ProcessInfo[]; readonly tree: ProcessTree | null },
  indicators: SuspiciousIndicator[],
): void {
  // Process creation via execve
  for (const creation of processData.processCreations) {
    if (creation.syscall === 'execve') {
      const exe = creation.executable.toLowerCase();

      // Suspicious executables
      if (exe.includes('wget') || exe.includes('curl') || exe.includes('fetch')) {
        indicators.push({
          category: 'download',
          description: `Download tool invoked: ${creation.executable}`,
          severity: 'medium',
          evidence: `execve("${creation.executable}", [${creation.args.join(', ')}])`,
        });
      }

      // Shell spawning (potential reverse shell)
      if (
        (exe.endsWith('/sh') || exe.endsWith('/bash') || exe.endsWith('/dash') || exe.endsWith('/zsh')) &&
        creation.args.some((a) => a.includes('-i') || a.includes('/dev/tcp') || a.includes('exec '))
      ) {
        indicators.push({
          category: 'reverse_shell',
          description: 'Potential reverse shell detected',
          severity: 'critical',
          evidence: `execve("${creation.executable}", [${creation.args.join(', ')}])`,
        });
      }

      // Privilege escalation attempts
      if (exe.includes('sudo') || exe.includes('su ') || exe.includes('pkexec') || exe.includes('doas')) {
        indicators.push({
          category: 'privilege_escalation',
          description: `Privilege escalation attempt: ${creation.executable}`,
          severity: 'high',
          evidence: `execve("${creation.executable}", [${creation.args.join(', ')}])`,
        });
      }

      // Compiler usage (building tools on target)
      if (exe.includes('gcc') || exe.includes('g++') || exe.includes('make') || exe.includes('cc')) {
        indicators.push({
          category: 'compilation',
          description: `Compiler invoked on target: ${creation.executable}`,
          severity: 'medium',
          evidence: `execve("${creation.executable}", [${creation.args.join(', ')}])`,
        });
      }
    }
  }

  // Deep process tree (indicator of process hollowing or injection chains)
  if (processInfo.tree && processInfo.tree.maxDepth >= 4) {
    indicators.push({
      category: 'process_injection',
      description: `Deep process tree detected: depth ${processInfo.tree.maxDepth}`,
      severity: 'medium',
      evidence: `${processInfo.tree.totalProcesses} total processes, max depth ${processInfo.tree.maxDepth}`,
    });
  }
}

function detectExecutionPatterns(
  processData: ProcessActivity,
  fileData: FileActivity,
  networkData: NetworkActivity,
  indicators: SuspiciousIndicator[],
): void {
  // Pattern: network connection followed by file drop followed by execution
  const hasExternalNetwork = networkData.connections.some(
    (c) => !isLocalAddress(c.destinationAddress),
  );
  const hasDroppedExecutable = fileData.created.some((f) => isExecutablePath(f.path));
  const hasChildExecution = processData.processCreations.length > 1;

  if (hasExternalNetwork && hasDroppedExecutable && hasChildExecution) {
    indicators.push({
      category: 'staged_payload',
      description: 'Staged payload pattern: network download, file drop, and execution detected',
      severity: 'critical',
      evidence: 'Network connections, file drops, and process creation observed in sequence',
    });
  }

  // Pattern: self-deletion (process deletes its own executable)
  const deletedPaths = new Set(fileData.deleted.map((f) => f.path));
  const createdPaths = new Set(fileData.created.map((f) => f.path));
  const selfDeleteCandidates = [...deletedPaths].filter((p) => p.includes('/home/sandbox/'));
  if (selfDeleteCandidates.length > 0) {
    indicators.push({
      category: 'anti_forensics',
      description: 'Sample may have deleted itself from disk',
      severity: 'medium',
      evidence: selfDeleteCandidates.join(', '),
    });
  }

  // Pattern: creating files with execution permissions
  const execCreatedInTemp = fileData.created.filter(
    (f) => (f.path.startsWith('/tmp/') || f.path.startsWith('/dev/shm/')) && isExecutablePath(f.path) && !isSandboxInfra(f.path),
  );
  if (execCreatedInTemp.length > 0) {
    indicators.push({
      category: 'dropper',
      description: `Executable files created in temporary directories: ${execCreatedInTemp.length}`,
      severity: 'high',
      evidence: execCreatedInTemp.map((f) => f.path).join(', '),
    });
  }

  // Avoid unused-variable lint error for createdPaths
  void createdPaths;
}

// ── Dropped file identification ─────────────────────────────────────────────

function identifyDroppedFiles(
  created: readonly FileChangeEvent[],
  droppedFilesOutput: string,
): DroppedFile[] {
  const dropped: DroppedFile[] = [];

  // Parse the dropped files output (from `find /home/sandbox /tmp -newer ...`)
  // Each line: /path/to/file SIZE SHA256 MIME
  // Or just file paths if the richer format is not available
  if (droppedFilesOutput.trim()) {
    const lines = droppedFilesOutput.trim().split('\n');
    for (const rawLine of lines) {
      const line = rawLine.trim();
      if (line === '') continue;

      try {
        // Try parsing "path|size|sha256|mime" format from our custom find script
        const parts = line.split('|');
        if (parts.length >= 2) {
          const filePath = parts[0] ?? '';
          const size = parseInt(parts[1] ?? '0', 10);
          const sha256 = parts[2] ?? null;
          const mimeType = parts[3] ?? null;

          dropped.push({
            path: filePath,
            size: Number.isNaN(size) ? 0 : size,
            sha256: sha256 && sha256 !== '' ? sha256 : null,
            mimeType: mimeType && mimeType !== '' ? mimeType : null,
            isSuspiciousLocation: isInSensitiveDir(filePath),
          });
        } else {
          // Just a path
          dropped.push({
            path: line,
            size: 0,
            sha256: null,
            mimeType: null,
            isSuspiciousLocation: isInSensitiveDir(line),
          });
        }
      } catch {
        continue;
      }
    }
  }

  // Also add any created files from inotify that are not already tracked
  const droppedPaths = new Set(dropped.map((d) => d.path));
  for (const fileEvent of created) {
    if (!droppedPaths.has(fileEvent.path) && !isLogFile(fileEvent.path)) {
      dropped.push({
        path: fileEvent.path,
        size: 0,
        sha256: null,
        mimeType: null,
        isSuspiciousLocation: isInSensitiveDir(fileEvent.path),
      });
    }
  }

  return dropped;
}

// ── Helper functions ────────────────────────────────────────────────────────

function isLocalAddress(addr: string): boolean {
  if (
    addr === '' ||
    addr === '127.0.0.1' ||
    addr === '::1' ||
    addr === '0.0.0.0' ||
    addr.startsWith('10.') ||
    addr.startsWith('192.168.')
  ) return true;
  const octets = addr.split('.');
  if (octets.length === 4 && octets[0] === '172') {
    const second = parseInt(octets[1]!, 10);
    if (second >= 16 && second <= 31) return true;
  }
  return false;
}

function isInSensitiveDir(filePath: string): boolean {
  for (const dir of SENSITIVE_LINUX_DIRS) {
    if (filePath.startsWith(dir)) return true;
  }
  return false;
}

function isSystemConfigPath(filePath: string): boolean {
  return SYSTEM_CONFIG_PATHS.has(filePath);
}

function isExecutablePath(filePath: string): boolean {
  const lower = filePath.toLowerCase();
  return (
    lower.endsWith('.sh') ||
    lower.endsWith('.py') ||
    lower.endsWith('.pl') ||
    lower.endsWith('.rb') ||
    lower.endsWith('.exe') ||
    lower.endsWith('.elf') ||
    lower.endsWith('.bin') ||
    lower.endsWith('.so') ||
    lower.endsWith('.dll') ||
    // Check for files in bin directories
    lower.includes('/bin/') ||
    lower.includes('/sbin/')
  );
}

function isLogFile(filePath: string): boolean {
  return (
    filePath.includes('/scanboy-logs/') ||
    filePath.endsWith('.log') ||
    filePath.endsWith('.pcap')
  );
}

function isSuspiciousPort(port: number): boolean {
  const suspiciousPorts = new Set([
    4444, 5555, 6666, 7777, 8888, 9999,   // Common backdoor ports
    1337, 31337,                            // Elite/hacker ports
    3389,                                    // RDP
    445, 139,                                // SMB
    1080, 8080, 3128,                       // Proxy ports
    6667, 6697,                              // IRC
  ]);
  return suspiciousPorts.has(port);
}
