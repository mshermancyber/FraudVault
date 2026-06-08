// ── Timeline Builder — merges all monitoring data into a unified timeline ────
//
// Takes strace events, inotify events, network events, and process events from
// the detonation run and produces a single chronologically-ordered timeline.
// Also identifies "key moments" — significant behavioral transitions.

import type {
  SyscallEvent,
  FileOperation,
  NetworkOperation,
  ProcessCreation,
  FileChangeEvent,
  ConnectionInfo,
  DnsQuery,
  HttpRequest,
  ProcessInfo,
} from './types.js';

// ── Types ──────────────────────────────────────────────────────────────────────

export type EventSeverity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export type EventCategory =
  | 'process'
  | 'file'
  | 'network'
  | 'registry'
  | 'service'
  | 'credential'
  | 'evasion'
  | 'persistence'
  | 'discovery';

export interface TimelineEvent {
  readonly timestamp: number;
  readonly type: string;
  readonly category: EventCategory;
  readonly description: string;
  readonly details: Record<string, string | number | boolean | null>;
  readonly severity: EventSeverity;
}

export interface KeyMoment {
  readonly event: TimelineEvent;
  readonly label: string;
  readonly reason: string;
}

export interface Timeline {
  readonly events: readonly TimelineEvent[];
  readonly keyMoments: readonly KeyMoment[];
  readonly startTime: number;
  readonly endTime: number;
  readonly totalEvents: number;
  readonly eventCountByCategory: Record<string, number>;
  readonly highestSeverity: EventSeverity;
}

// ── Input types ────────────────────────────────────────────────────────────────

export interface TimelineInput {
  readonly straceEvents: readonly SyscallEvent[];
  readonly fileOperations: readonly FileOperation[];
  readonly networkOperations: readonly NetworkOperation[];
  readonly processCreations: readonly ProcessCreation[];
  readonly fileChanges: {
    readonly created: readonly FileChangeEvent[];
    readonly modified: readonly FileChangeEvent[];
    readonly deleted: readonly FileChangeEvent[];
  };
  readonly connections: readonly ConnectionInfo[];
  readonly dnsQueries: readonly DnsQuery[];
  readonly httpRequests: readonly HttpRequest[];
  readonly processes: readonly ProcessInfo[];
  readonly executionStartTime: number;
}

// ── Severity classification ────────────────────────────────────────────────────

const CRITICAL_SYSCALLS = new Set(['execve', 'ptrace', 'init_module']);
const HIGH_SYSCALLS = new Set(['clone', 'clone3', 'fork', 'vfork', 'unlink', 'unlinkat']);
const MEDIUM_SYSCALLS = new Set(['connect', 'sendto', 'bind', 'chmod', 'fchmod', 'fchmodat']);

const SUSPICIOUS_PATHS = [
  /\/etc\/shadow/,
  /\/etc\/passwd/,
  /\/etc\/sudoers/,
  /\.ssh\/authorized_keys/,
  /\.ssh\/id_/,
  /\/proc\/\d+\/mem/,
  /\/dev\/mem/,
  /\/boot\//,
  /crontab/,
  /\.bashrc/,
  /\.profile/,
  /\/etc\/ld\.so\.preload/,
  /\/etc\/init\.d\//,
  /\/etc\/systemd\//,
];

const CREDENTIAL_PATHS = [
  /\/etc\/shadow/,
  /\.ssh\//,
  /\.gnupg\//,
  /wallet/i,
  /credential/i,
  /password/i,
  /\.keystore/,
  /\.mozilla\/.*logins\.json/,
  /\.config\/chromium.*Login Data/,
];

const SERVICE_COMMANDS = [
  /systemctl\s+(stop|disable|mask)/,
  /service\s+\S+\s+stop/,
  /net\s+stop/i,
  /sc\s+(stop|delete|config)/i,
  /taskkill/i,
];

// ── Helper functions ───────────────────────────────────────────────────────────

function parseTimestamp(ts: string, baseTime: number): number {
  if (!ts) return baseTime;

  // strace format: epoch seconds with microseconds (e.g., "1717344000.123456")
  const epochMatch = /^(\d{10,})\.(\d+)$/.exec(ts);
  if (epochMatch) {
    return parseFloat(ts) * 1000; // convert to ms
  }

  // ISO format
  const isoTime = Date.parse(ts);
  if (!isNaN(isoTime)) {
    return isoTime;
  }

  // Relative seconds (e.g., "0.123456" or "12.345678")
  const relativeMatch = /^(\d+)\.(\d+)$/.exec(ts);
  if (relativeMatch) {
    return baseTime + parseFloat(ts) * 1000;
  }

  return baseTime;
}

function classifySyscallSeverity(syscall: string, args: readonly string[]): EventSeverity {
  if (CRITICAL_SYSCALLS.has(syscall)) return 'critical';
  if (HIGH_SYSCALLS.has(syscall)) return 'high';
  if (MEDIUM_SYSCALLS.has(syscall)) return 'medium';

  // Check if file operations target suspicious paths
  const pathArg = args[0] || args[1] || '';
  for (const pattern of SUSPICIOUS_PATHS) {
    if (pattern.test(pathArg)) return 'high';
  }

  return 'info';
}

function classifyFileEventSeverity(path: string, operation: string): EventSeverity {
  for (const pattern of CREDENTIAL_PATHS) {
    if (pattern.test(path)) return 'critical';
  }
  for (const pattern of SUSPICIOUS_PATHS) {
    if (pattern.test(path)) return 'high';
  }
  if (operation === 'deleted') return 'medium';
  if (/\.(exe|dll|so|sh|py|pl|rb)$/i.test(path)) return 'medium';
  return 'low';
}

function classifyNetworkSeverity(port: number, address: string): EventSeverity {
  // Known C2 / suspicious ports
  if (port === 4444 || port === 5555 || port === 1337 || port === 31337) return 'critical';
  if (port === 445 || port === 139 || port === 3389) return 'high';
  if (port === 8080 || port === 8443 || port === 9090) return 'medium';

  // Non-routable addresses are less suspicious (internal)
  if (address.startsWith('127.') || address.startsWith('10.') ||
      address.startsWith('192.168.') || address.startsWith('172.')) {
    return 'low';
  }

  // External connections are at least medium
  if (port === 80 || port === 443) return 'low';
  return 'medium';
}

function categorizeSyscall(syscall: string, args: readonly string[]): EventCategory {
  switch (syscall) {
    case 'execve':
      return 'process';
    case 'clone':
    case 'clone3':
    case 'fork':
    case 'vfork':
      return 'process';
    case 'connect':
    case 'sendto':
    case 'bind':
    case 'socket':
      return 'network';
    case 'open':
    case 'openat':
    case 'creat':
    case 'write':
    case 'pwrite64':
    case 'unlink':
    case 'unlinkat':
    case 'rename':
    case 'renameat':
    case 'renameat2':
    case 'chmod':
    case 'fchmod':
    case 'fchmodat':
    case 'mkdir':
    case 'mkdirat':
    case 'symlink':
    case 'symlinkat':
    case 'link':
    case 'linkat':
      return 'file';
    default:
      break;
  }

  // Check args for credential access
  const pathArg = args[0] || args[1] || '';
  for (const pattern of CREDENTIAL_PATHS) {
    if (pattern.test(pathArg)) return 'credential';
  }

  return 'file';
}

function describeSyscall(syscall: string, args: readonly string[]): string {
  const firstArg = args[0] || '';
  const secondArg = args[1] || '';

  switch (syscall) {
    case 'execve':
      return `Executed: ${firstArg}`;
    case 'clone':
    case 'clone3':
    case 'fork':
    case 'vfork':
      return `Created child process via ${syscall}`;
    case 'connect':
      return `Connected to ${firstArg}`;
    case 'open':
    case 'openat':
      return `Opened file: ${secondArg || firstArg}`;
    case 'unlink':
    case 'unlinkat':
      return `Deleted file: ${firstArg}`;
    case 'rename':
    case 'renameat':
    case 'renameat2':
      return `Renamed: ${firstArg} -> ${secondArg}`;
    case 'chmod':
    case 'fchmod':
    case 'fchmodat':
      return `Changed permissions: ${firstArg}`;
    case 'mkdir':
    case 'mkdirat':
      return `Created directory: ${firstArg}`;
    case 'symlink':
    case 'symlinkat':
      return `Created symlink: ${firstArg} -> ${secondArg}`;
    case 'write':
    case 'pwrite64':
      return `Wrote to fd ${firstArg}`;
    case 'sendto':
      return `Sent data to ${secondArg || firstArg}`;
    case 'bind':
      return `Bound to ${firstArg}`;
    default:
      return `${syscall}(${args.slice(0, 2).join(', ')})`;
  }
}

// ── Severity ordering ──────────────────────────────────────────────────────────

const SEVERITY_ORDER: Record<EventSeverity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

function maxSeverity(a: EventSeverity, b: EventSeverity): EventSeverity {
  return SEVERITY_ORDER[a] >= SEVERITY_ORDER[b] ? a : b;
}

// ── Main builder ───────────────────────────────────────────────────────────────

/**
 * Builds a unified timeline from all monitoring data sources collected during
 * sandbox execution.
 */
export function buildTimeline(input: TimelineInput): Timeline {
  const events: TimelineEvent[] = [];
  const baseTime = input.executionStartTime;

  // 1. Process strace syscall events
  for (const evt of input.straceEvents) {
    const timestamp = parseTimestamp(evt.timestamp, baseTime);
    const severity = classifySyscallSeverity(evt.syscall, evt.args);
    const category = categorizeSyscall(evt.syscall, evt.args);
    const description = describeSyscall(evt.syscall, evt.args);

    events.push({
      timestamp,
      type: `syscall:${evt.syscall}`,
      category,
      description,
      details: {
        pid: evt.pid,
        syscall: evt.syscall,
        returnValue: evt.returnValue,
        args: evt.args.join(', '),
      },
      severity,
    });
  }

  // 2. Process file operations from strace
  for (const op of input.fileOperations) {
    const timestamp = parseTimestamp(op.timestamp, baseTime);
    const severity = classifyFileEventSeverity(op.path, op.syscall);
    events.push({
      timestamp,
      type: `file:${op.syscall}`,
      category: 'file',
      description: `${op.syscall}: ${op.path}${op.newPath ? ' -> ' + op.newPath : ''}`,
      details: {
        path: op.path,
        newPath: op.newPath,
        flags: op.flags,
        pid: op.pid,
      },
      severity,
    });
  }

  // 3. Process network operations from strace
  for (const netOp of input.networkOperations) {
    const timestamp = parseTimestamp(netOp.timestamp, baseTime);
    const severity = classifyNetworkSeverity(netOp.port, netOp.address);
    events.push({
      timestamp,
      type: `network:${netOp.syscall}`,
      category: 'network',
      description: `${netOp.syscall} to ${netOp.address}:${netOp.port} (${netOp.family})`,
      details: {
        syscall: netOp.syscall,
        family: netOp.family,
        address: netOp.address,
        port: netOp.port,
        pid: netOp.pid,
      },
      severity,
    });
  }

  // 4. Process creation events
  for (const proc of input.processCreations) {
    const timestamp = parseTimestamp(proc.timestamp, baseTime);
    const isServiceCmd = SERVICE_COMMANDS.some(re => re.test(proc.executable + ' ' + proc.args.join(' ')));
    const severity: EventSeverity = isServiceCmd ? 'critical' : 'high';
    const category: EventCategory = isServiceCmd ? 'service' : 'process';

    events.push({
      timestamp,
      type: 'process:create',
      category,
      description: `Process created: ${proc.executable} ${proc.args.slice(0, 3).join(' ')}`,
      details: {
        parentPid: proc.parentPid,
        childPid: proc.childPid,
        executable: proc.executable,
        args: proc.args.join(' '),
        syscall: proc.syscall,
      },
      severity,
    });
  }

  // 4b. Process listing (from ps output) — records observed processes
  for (const proc of input.processes) {
    const timestamp = parseTimestamp(proc.startTime, baseTime);
    events.push({
      timestamp,
      type: 'process:observed',
      category: 'process',
      description: `Process observed: [${proc.pid}] ${proc.name} (${proc.commandLine})`,
      details: {
        pid: proc.pid,
        parentPid: proc.parentPid,
        name: proc.name,
        commandLine: proc.commandLine,
        user: proc.user,
      },
      severity: 'info',
    });
  }

  // 5. inotify file change events
  for (const file of input.fileChanges.created) {
    const timestamp = parseTimestamp(file.timestamp, baseTime);
    const severity = classifyFileEventSeverity(file.path, 'created');
    events.push({
      timestamp,
      type: 'file:created',
      category: 'file',
      description: `File created: ${file.path}`,
      details: { path: file.path },
      severity,
    });
  }

  for (const file of input.fileChanges.modified) {
    const timestamp = parseTimestamp(file.timestamp, baseTime);
    events.push({
      timestamp,
      type: 'file:modified',
      category: 'file',
      description: `File modified: ${file.path}`,
      details: { path: file.path },
      severity: 'info',
    });
  }

  for (const file of input.fileChanges.deleted) {
    const timestamp = parseTimestamp(file.timestamp, baseTime);
    const severity = classifyFileEventSeverity(file.path, 'deleted');
    events.push({
      timestamp,
      type: 'file:deleted',
      category: 'file',
      description: `File deleted: ${file.path}`,
      details: { path: file.path },
      severity,
    });
  }

  // 6. Network connections from tcpdump
  for (const conn of input.connections) {
    const timestamp = parseTimestamp(conn.timestamp, baseTime);
    const severity = classifyNetworkSeverity(conn.destinationPort, conn.destinationAddress);
    events.push({
      timestamp,
      type: `network:${conn.protocol}`,
      category: 'network',
      description: `${conn.protocol.toUpperCase()} ${conn.sourceAddress}:${conn.sourcePort} -> ${conn.destinationAddress}:${conn.destinationPort}`,
      details: {
        protocol: conn.protocol,
        sourceAddress: conn.sourceAddress,
        sourcePort: conn.sourcePort,
        destinationAddress: conn.destinationAddress,
        destinationPort: conn.destinationPort,
      },
      severity,
    });
  }

  // 7. DNS queries
  for (const dns of input.dnsQueries) {
    const timestamp = parseTimestamp(dns.timestamp, baseTime);
    events.push({
      timestamp,
      type: 'network:dns',
      category: 'network',
      description: `DNS ${dns.queryType} query: ${dns.domain}${dns.responseAddress ? ' -> ' + dns.responseAddress : ''}`,
      details: {
        domain: dns.domain,
        queryType: dns.queryType,
        responseAddress: dns.responseAddress,
      },
      severity: 'low',
    });
  }

  // 8. HTTP requests
  for (const http of input.httpRequests) {
    const timestamp = parseTimestamp(http.timestamp, baseTime);
    events.push({
      timestamp,
      type: 'network:http',
      category: 'network',
      description: `HTTP ${http.method} ${http.url} (Host: ${http.host})`,
      details: {
        method: http.method,
        url: http.url,
        host: http.host,
        userAgent: http.userAgent,
        statusCode: http.statusCode,
      },
      severity: 'medium',
    });
  }

  // Sort all events chronologically
  events.sort((a, b) => a.timestamp - b.timestamp);

  // Identify key moments
  const keyMoments = identifyKeyMoments(events);

  // Compute summary statistics
  const eventCountByCategory: Record<string, number> = {};
  let highestSeverity: EventSeverity = 'info';

  for (const event of events) {
    eventCountByCategory[event.category] = (eventCountByCategory[event.category] || 0) + 1;
    highestSeverity = maxSeverity(highestSeverity, event.severity);
  }

  const startTime = events.length > 0 ? events[0]!.timestamp : baseTime;
  const endTime = events.length > 0 ? events[events.length - 1]!.timestamp : baseTime;

  return {
    events,
    keyMoments,
    startTime,
    endTime,
    totalEvents: events.length,
    eventCountByCategory,
    highestSeverity,
  };
}

// ── Key moment identification ──────────────────────────────────────────────────

function identifyKeyMoments(events: readonly TimelineEvent[]): KeyMoment[] {
  const moments: KeyMoment[] = [];
  const seen = new Set<string>();

  for (const event of events) {
    // First process execution
    if (!seen.has('first_process') && event.type === 'process:create') {
      seen.add('first_process');
      moments.push({
        event,
        label: 'First Process Created',
        reason: 'The sample spawned its first child process',
      });
    }

    // First execve (actual binary execution)
    if (!seen.has('first_execve') && event.type === 'syscall:execve') {
      seen.add('first_execve');
      moments.push({
        event,
        label: 'First Execution',
        reason: 'First binary execution via execve syscall',
      });
    }

    // First network connection
    if (!seen.has('first_network') &&
        (event.type === 'network:connect' || event.type === 'network:tcp' || event.type === 'network:udp') &&
        event.category === 'network') {
      seen.add('first_network');
      moments.push({
        event,
        label: 'First Network Connection',
        reason: 'The sample initiated its first outbound network connection',
      });
    }

    // First DNS query
    if (!seen.has('first_dns') && event.type === 'network:dns') {
      seen.add('first_dns');
      moments.push({
        event,
        label: 'First DNS Query',
        reason: 'The sample performed its first DNS resolution',
      });
    }

    // First file drop
    if (!seen.has('first_file_drop') && event.type === 'file:created') {
      seen.add('first_file_drop');
      moments.push({
        event,
        label: 'First File Drop',
        reason: 'The sample created its first file on disk',
      });
    }

    // First file deletion
    if (!seen.has('first_deletion') &&
        (event.type === 'file:deleted' || event.type === 'file:unlink' || event.type === 'syscall:unlink' || event.type === 'syscall:unlinkat')) {
      seen.add('first_deletion');
      moments.push({
        event,
        label: 'First File Deletion',
        reason: 'The sample deleted a file (possible evidence removal or self-deletion)',
      });
    }

    // Registry modification (Wine)
    if (!seen.has('first_registry') && event.description.toLowerCase().includes('regsetvalue')) {
      seen.add('first_registry');
      moments.push({
        event,
        label: 'First Registry Modification',
        reason: 'The sample modified the Windows registry (via Wine)',
      });
    }

    // Service manipulation
    if (!seen.has('first_service_stop') && event.category === 'service') {
      seen.add('first_service_stop');
      moments.push({
        event,
        label: 'Service Manipulation Detected',
        reason: 'The sample attempted to stop or disable a system service',
      });
    }

    // Credential access
    if (!seen.has('first_credential') && event.category === 'credential') {
      seen.add('first_credential');
      moments.push({
        event,
        label: 'Credential Access Attempt',
        reason: 'The sample accessed a file containing credentials or keys',
      });
    }

    // Critical severity event
    if (!seen.has('first_critical') && event.severity === 'critical') {
      seen.add('first_critical');
      moments.push({
        event,
        label: 'Critical Activity Detected',
        reason: `Critical severity event: ${event.description}`,
      });
    }

    // HTTP callback (possible C2)
    if (!seen.has('first_http') && event.type === 'network:http') {
      seen.add('first_http');
      moments.push({
        event,
        label: 'First HTTP Request',
        reason: 'The sample made its first HTTP request (possible C2 communication)',
      });
    }

    // Permission change (privilege escalation indicator)
    if (!seen.has('first_chmod') &&
        (event.type === 'syscall:chmod' || event.type === 'syscall:fchmod' || event.type === 'syscall:fchmodat' || event.type === 'file:chmod')) {
      seen.add('first_chmod');
      moments.push({
        event,
        label: 'Permission Change',
        reason: 'The sample changed file permissions (possible privilege escalation prep)',
      });
    }
  }

  // Sort key moments chronologically
  moments.sort((a, b) => a.event.timestamp - b.event.timestamp);

  return moments;
}
