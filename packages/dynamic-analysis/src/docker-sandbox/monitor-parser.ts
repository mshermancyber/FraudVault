// ── Strace / inotifywait / tcpdump output parsers ───────────────────────────
//
// These parsers are intentionally defensive — strace output in particular is
// messy, with truncated lines, multi-line arguments, and signals interspersed.
// Every regex match is wrapped in try/catch so a single bad line never crashes
// the whole parse.

import type {
  ProcessActivity,
  SyscallEvent,
  FileOperation,
  NetworkOperation,
  ProcessCreation,
  FileActivity,
  FileChangeEvent,
  FileMoveEvent,
  NetworkActivity,
  ConnectionInfo,
  DnsQuery,
  HttpRequest,
  ProcessInfo,
  ProcessTree,
  ProcessTreeNode,
} from './types.js';

// ── Strace parsing ──────────────────────────────────────────────────────────

/**
 * Regex for strace lines in multiple formats:
 *   [pid 12345] 1717344000.123456 openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 3  (stderr -f)
 *   [pid 12345] 03:49:10 execve("/usr/bin/wine", ...) = 0                       (stderr -f -t)
 *   90    03:55:09 execve("/bin/bash", ...) = 0                                  (-o file -f -t)
 *   1717344000.123456 openat(...) = 3                                            (single process)
 */
const STRACE_LINE_RE =
  /^(?:\[pid\s+(\d+)\]\s+|(\d+)\s+)?(?:(\d[\d:.]+)\s+)?(\w+)\(([^)]*)\)\s*=\s*(.+)$/;

/** Subset of syscalls we actually care about for behavioral analysis. */
const TRACKED_SYSCALLS = new Set([
  'open', 'openat', 'creat',
  'connect', 'socket', 'bind', 'sendto',
  'execve', 'clone', 'clone3', 'fork', 'vfork',
  'write', 'pwrite64',
  'unlink', 'unlinkat', 'rename', 'renameat', 'renameat2',
  'chmod', 'fchmod', 'fchmodat',
  'mkdir', 'mkdirat',
  'symlink', 'symlinkat', 'link', 'linkat',
]);

/**
 * Parse strace output into structured process activity.
 *
 * @param output - Raw strace -f output (possibly multi-megabyte).
 * @returns Structured process activity extracted from the trace.
 */
export function parseStraceOutput(output: string): ProcessActivity {
  const syscalls: SyscallEvent[] = [];
  const fileOperations: FileOperation[] = [];
  const networkOperations: NetworkOperation[] = [];
  const processCreations: ProcessCreation[] = [];

  const lines = output.split('\n');

  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (line === '' || line.startsWith('---') || line.startsWith('+++')) {
      // Signal lines (--- SIGCHLD ---) and exit lines (+++ exited with 0 +++)
      continue;
    }

    try {
      const match = STRACE_LINE_RE.exec(line);
      if (!match) continue;

      const pid = match[1] ? parseInt(match[1], 10) : match[2] ? parseInt(match[2], 10) : 0;
      const timestamp = match[3] ?? '';
      const syscall = match[4] ?? '';
      const argsRaw = match[5] ?? '';
      const returnValue = (match[6] ?? '').trim();

      if (!TRACKED_SYSCALLS.has(syscall)) continue;

      const args = parseStraceArgs(argsRaw);

      syscalls.push({
        pid,
        syscall,
        args,
        returnValue,
        timestamp,
      });

      // Classify the syscall
      if (isFileCreationSyscall(syscall)) {
        const path = extractPath(syscall, args);
        if (path) {
          const flags = args.length > 1 ? (args[1] ?? '') : '';
          fileOperations.push({
            syscall,
            path,
            newPath: null,
            flags,
            pid,
            timestamp,
          });
        }
      } else if (isRenameSyscall(syscall)) {
        const oldPath = extractQuotedArg(args, 0);
        const newPath = extractQuotedArg(args, 1);
        if (oldPath) {
          fileOperations.push({
            syscall,
            path: oldPath,
            newPath: newPath ?? null,
            flags: '',
            pid,
            timestamp,
          });
        }
      } else if (isDeleteSyscall(syscall)) {
        const path = extractPath(syscall, args);
        if (path) {
          fileOperations.push({
            syscall,
            path,
            newPath: null,
            flags: 'DELETE',
            pid,
            timestamp,
          });
        }
      } else if (syscall === 'chmod' || syscall === 'fchmod' || syscall === 'fchmodat') {
        const path = extractPath(syscall, args);
        if (path) {
          fileOperations.push({
            syscall,
            path,
            newPath: null,
            flags: args.length > 1 ? (args[1] ?? '') : '',
            pid,
            timestamp,
          });
        }
      } else if (syscall === 'mkdir' || syscall === 'mkdirat') {
        const path = extractPath(syscall, args);
        if (path) {
          fileOperations.push({
            syscall,
            path,
            newPath: null,
            flags: 'DIRECTORY',
            pid,
            timestamp,
          });
        }
      } else if (syscall === 'connect') {
        const netInfo = parseConnectArgs(argsRaw);
        if (netInfo) {
          networkOperations.push({
            syscall,
            family: netInfo.family,
            address: netInfo.address,
            port: netInfo.port,
            pid,
            timestamp,
          });
        }
      } else if (syscall === 'socket') {
        const family = extractSocketFamily(args);
        if (family === 'AF_INET' || family === 'AF_INET6') {
          networkOperations.push({
            syscall,
            family,
            address: '',
            port: 0,
            pid,
            timestamp,
          });
        }
      } else if (syscall === 'execve') {
        const executable = extractQuotedArg(args, 0) ?? '';
        const execArgs = extractExecveArgs(argsRaw);
        processCreations.push({
          parentPid: pid,
          childPid: pid, // execve replaces current process
          syscall,
          executable,
          args: execArgs,
          timestamp,
        });
      } else if (syscall === 'clone' || syscall === 'clone3' || syscall === 'fork' || syscall === 'vfork') {
        const childPid = parseInt(returnValue, 10);
        if (!Number.isNaN(childPid) && childPid > 0) {
          processCreations.push({
            parentPid: pid,
            childPid,
            syscall,
            executable: '',
            args: [],
            timestamp,
          });
        }
      }
    } catch {
      // Malformed line — skip silently
      continue;
    }
  }

  return {
    syscalls,
    fileOperations,
    networkOperations,
    processCreations,
  };
}

// ── inotifywait parsing ─────────────────────────────────────────────────────

/**
 * inotifywait output format (our invocation uses):
 *   --format "%T %w%f %e" --timefmt "%s"
 * So each line looks like:
 *   1717344000 /home/sandbox/somefile CREATE
 *   1717344001 /tmp/dropped.exe MODIFY
 *   1717344002 /home/sandbox/old.txt MOVED_FROM
 *   1717344002 /home/sandbox/new.txt MOVED_TO
 */
const INOTIFY_LINE_RE = /^(\d+)\s+(\S+)\s+(.+)$/;

/**
 * Parse inotifywait monitoring output.
 *
 * @param output - Raw inotifywait output.
 * @returns Structured file activity.
 */
export function parseInotifyOutput(output: string): FileActivity {
  const created: FileChangeEvent[] = [];
  const modified: FileChangeEvent[] = [];
  const deleted: FileChangeEvent[] = [];
  const moved: FileMoveEvent[] = [];

  // Track MOVED_FROM events to pair with MOVED_TO
  let pendingMoveFrom: { path: string; timestamp: string } | null = null;

  const lines = output.split('\n');

  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (line === '') continue;

    try {
      const match = INOTIFY_LINE_RE.exec(line);
      if (!match) continue;

      const epochStr = match[1] ?? '0';
      const filePath = match[2] ?? '';
      const eventsStr = match[3] ?? '';

      const timestamp = new Date(parseInt(epochStr, 10) * 1000).toISOString();
      const events = eventsStr.split(',').map((e) => e.trim());

      for (const event of events) {
        switch (event) {
          case 'CREATE':
            created.push({ path: filePath, timestamp });
            break;
          case 'MODIFY':
            modified.push({ path: filePath, timestamp });
            break;
          case 'DELETE':
            deleted.push({ path: filePath, timestamp });
            break;
          case 'MOVED_FROM':
            pendingMoveFrom = { path: filePath, timestamp };
            break;
          case 'MOVED_TO':
            if (pendingMoveFrom) {
              moved.push({
                fromPath: pendingMoveFrom.path,
                toPath: filePath,
                timestamp,
              });
              pendingMoveFrom = null;
            } else {
              // MOVED_TO without a preceding MOVED_FROM — treat as a create
              created.push({ path: filePath, timestamp });
            }
            break;
          case 'ATTRIB':
            modified.push({ path: filePath, timestamp });
            break;
          // OPEN, ACCESS, CLOSE_WRITE, CLOSE_NOWRITE, etc. — too noisy, skip
          default:
            break;
        }
      }
    } catch {
      continue;
    }
  }

  return { created, modified, deleted, moved };
}

// ── tcpdump parsing ─────────────────────────────────────────────────────────

/**
 * Parse tcpdump text (-nn -q) output into structured network activity.
 *
 * Typical tcpdump -nn -q lines:
 *   14:30:01.123456 IP 10.0.0.2.44556 > 93.184.216.34.80: tcp 0
 *   14:30:01.234567 IP 10.0.0.2.33445 > 8.8.8.8.53: UDP, length 42
 *   14:30:01.345678 IP 10.0.0.2.44556 > 93.184.216.34.80: HTTP: GET / HTTP/1.1
 *
 * We also handle the verbose DNS decode lines:
 *   14:30:01.234567 IP 10.0.0.2.33445 > 8.8.8.8.53: 12345+ A? evil.com. (25)
 *   14:30:01.345678 IP 8.8.8.8.53 > 10.0.0.2.33445: 12345 1/0/0 A 93.184.216.34 (49)
 */

const TCPDUMP_IP_LINE_RE =
  /^(\S+)\s+IP\s+(\d+\.\d+\.\d+\.\d+)\.(\d+)\s+>\s+(\d+\.\d+\.\d+\.\d+)\.(\d+):\s+(.*)$/;

/** DNS query pattern: "12345+ A? domain.com. (len)" */
const DNS_QUERY_RE = /^\d+\+?\s+(A|AAAA|MX|CNAME|TXT|NS|PTR|SRV|SOA)\?\s+(\S+?)\.?\s+\(/;

/** DNS response pattern: "12345 1/0/0 A 1.2.3.4 (len)" */
const DNS_RESPONSE_RE = /^\d+\s+\d+\/\d+\/\d+\s+(A|AAAA)\s+(\S+)/;

/** HTTP request pattern */
const HTTP_METHOD_RE = /^HTTP:\s+(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(\S+)\s+HTTP/;

export function parseNetworkCapture(pcapSummary: string): NetworkActivity {
  const connections: ConnectionInfo[] = [];
  const dnsQueries: DnsQuery[] = [];
  const httpRequests: HttpRequest[] = [];

  // Track seen connections to avoid duplicates (src:port -> dst:port)
  const seenConnections = new Set<string>();

  const lines = pcapSummary.split('\n');

  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (line === '') continue;

    try {
      const match = TCPDUMP_IP_LINE_RE.exec(line);
      if (!match) continue;

      const timestamp = match[1] ?? '';
      const srcAddr = match[2] ?? '';
      const srcPort = parseInt(match[3] ?? '0', 10);
      const dstAddr = match[4] ?? '';
      const dstPort = parseInt(match[5] ?? '0', 10);
      const payload = match[6] ?? '';

      // Check for DNS queries (typically port 53)
      if (dstPort === 53 || srcPort === 53) {
        const dnsQueryMatch = DNS_QUERY_RE.exec(payload);
        if (dnsQueryMatch) {
          dnsQueries.push({
            domain: dnsQueryMatch[2] ?? '',
            queryType: dnsQueryMatch[1] ?? 'A',
            responseAddress: null,
            timestamp,
          });
          continue;
        }

        const dnsResponseMatch = DNS_RESPONSE_RE.exec(payload);
        if (dnsResponseMatch) {
          // Find the corresponding query and update it (best-effort)
          const responseAddr = dnsResponseMatch[2] ?? '';
          const lastQuery = dnsQueries.length > 0 ? dnsQueries[dnsQueries.length - 1] : undefined;
          if (lastQuery && lastQuery.responseAddress === null) {
            // Replace last query with updated version
            const updatedQuery: DnsQuery = {
              domain: lastQuery.domain,
              queryType: lastQuery.queryType,
              responseAddress: responseAddr,
              timestamp: lastQuery.timestamp,
            };
            dnsQueries[dnsQueries.length - 1] = updatedQuery;
          }
          continue;
        }
      }

      // Check for HTTP
      const httpMatch = HTTP_METHOD_RE.exec(payload);
      if (httpMatch) {
        httpRequests.push({
          method: httpMatch[1] ?? 'GET',
          url: httpMatch[2] ?? '/',
          host: dstAddr,
          userAgent: null,
          statusCode: null,
          timestamp,
        });
      }

      // Record unique TCP/UDP connections
      const protocol: 'tcp' | 'udp' = payload.toLowerCase().includes('udp') ? 'udp' : 'tcp';
      const connKey = `${srcAddr}:${srcPort}->${dstAddr}:${dstPort}`;
      if (!seenConnections.has(connKey)) {
        seenConnections.add(connKey);
        connections.push({
          protocol,
          sourceAddress: srcAddr,
          sourcePort: srcPort,
          destinationAddress: dstAddr,
          destinationPort: dstPort,
          timestamp,
        });
      }
    } catch {
      continue;
    }
  }

  return { connections, dnsQueries, httpRequests };
}

// ── ps output parsing ───────────────────────────────────────────────────────

/**
 * Parse `ps auxf --no-headers` or `ps -eo pid,ppid,user,comm,args --no-headers`
 * output to build a process tree.
 *
 * We use `ps -eo pid,ppid,user,comm,args --no-headers` format:
 *   1     0 root     bash     /bin/bash
 *   42    1 sandbox  python3  python3 /home/sandbox/sample.py
 */
const PS_LINE_RE = /^\s*(\d+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(.*)$/;

export function parseProcInfo(output: string): {
  processes: ProcessInfo[];
  tree: ProcessTree | null;
} {
  const processes: ProcessInfo[] = [];
  const lines = output.split('\n');

  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (line === '') continue;

    try {
      const match = PS_LINE_RE.exec(line);
      if (!match) continue;

      const pid = parseInt(match[1] ?? '0', 10);
      const ppid = parseInt(match[2] ?? '0', 10);
      const user = match[3] ?? '';
      const name = match[4] ?? '';
      const commandLine = match[5] ?? '';

      processes.push({
        pid,
        parentPid: ppid,
        name,
        commandLine,
        user,
        startTime: new Date().toISOString(),
      });
    } catch {
      continue;
    }
  }

  // Build tree
  const tree = buildProcessTree(processes);
  return { processes, tree };
}

function buildProcessTree(processes: readonly ProcessInfo[]): ProcessTree | null {
  if (processes.length === 0) return null;

  const nodeMap = new Map<number, ProcessTreeNode & { children: ProcessTreeNode[] }>();

  // Create nodes
  for (const proc of processes) {
    nodeMap.set(proc.pid, {
      pid: proc.pid,
      name: proc.name,
      commandLine: proc.commandLine,
      children: [],
    });
  }

  // Link children to parents
  let rootNode: ProcessTreeNode | undefined;
  for (const proc of processes) {
    const node = nodeMap.get(proc.pid);
    if (!node) continue;

    const parent = nodeMap.get(proc.parentPid);
    if (parent && parent !== node) {
      parent.children.push(node);
    } else {
      // No parent found (or parent is self) — this is a root
      if (!rootNode) {
        rootNode = node;
      }
    }
  }

  if (!rootNode) {
    // Fallback: use the first process as root
    const firstProc = processes[0];
    if (!firstProc) return null;
    rootNode = nodeMap.get(firstProc.pid) ?? {
      pid: firstProc.pid,
      name: firstProc.name,
      commandLine: firstProc.commandLine,
      children: [],
    };
  }

  const maxDepth = computeTreeDepth(rootNode, 0);

  return {
    root: rootNode,
    totalProcesses: processes.length,
    maxDepth,
  };
}

function computeTreeDepth(node: ProcessTreeNode, currentDepth: number): number {
  if (node.children.length === 0) return currentDepth;
  let max = currentDepth;
  for (const child of node.children) {
    const d = computeTreeDepth(child, currentDepth + 1);
    if (d > max) max = d;
  }
  return max;
}

// ── Strace helper functions ─────────────────────────────────────────────────

function parseStraceArgs(argsRaw: string): string[] {
  // Strace args are comma-separated, but may contain nested structures.
  // We do a simple split that respects quoted strings and braces.
  const args: string[] = [];
  let current = '';
  let depth = 0;
  let inString = false;
  let escape = false;

  for (const ch of argsRaw) {
    if (escape) {
      current += ch;
      escape = false;
      continue;
    }

    if (ch === '\\') {
      current += ch;
      escape = true;
      continue;
    }

    if (ch === '"') {
      inString = !inString;
      current += ch;
      continue;
    }

    if (inString) {
      current += ch;
      continue;
    }

    if (ch === '{' || ch === '[') {
      depth++;
      current += ch;
      continue;
    }

    if (ch === '}' || ch === ']') {
      depth--;
      current += ch;
      continue;
    }

    if (ch === ',' && depth === 0) {
      args.push(current.trim());
      current = '';
      continue;
    }

    current += ch;
  }

  if (current.trim() !== '') {
    args.push(current.trim());
  }

  return args;
}

function extractQuotedArg(args: readonly string[], index: number): string | undefined {
  const arg = args[index];
  if (!arg) return undefined;
  // Strip surrounding quotes
  const trimmed = arg.trim();
  if (trimmed.startsWith('"') && trimmed.endsWith('"')) {
    return trimmed.slice(1, -1);
  }
  return trimmed;
}

function extractPath(syscall: string, args: readonly string[]): string | null {
  // openat(AT_FDCWD, "/path", flags) — path is second arg
  // open("/path", flags) — path is first arg
  // unlink("/path") — path is first arg
  // unlinkat(AT_FDCWD, "/path", flags) — path is second arg
  // mkdir("/path", mode) — path is first arg
  // mkdirat(AT_FDCWD, "/path", mode) — path is second arg
  // chmod("/path", mode) — path is first arg
  // fchmodat(AT_FDCWD, "/path", mode, flags) — path is second arg

  if (syscall.endsWith('at') || syscall === 'openat' || syscall === 'mkdirat' || syscall === 'fchmodat' || syscall === 'unlinkat' || syscall === 'renameat' || syscall === 'renameat2' || syscall === 'linkat' || syscall === 'symlinkat') {
    return extractQuotedArg(args, 1) ?? null;
  }
  return extractQuotedArg(args, 0) ?? null;
}

function isFileCreationSyscall(syscall: string): boolean {
  return ['open', 'openat', 'creat', 'write', 'pwrite64', 'symlink', 'symlinkat', 'link', 'linkat'].includes(syscall);
}

function isRenameSyscall(syscall: string): boolean {
  return ['rename', 'renameat', 'renameat2'].includes(syscall);
}

function isDeleteSyscall(syscall: string): boolean {
  return ['unlink', 'unlinkat'].includes(syscall);
}

function extractSocketFamily(args: readonly string[]): string {
  const first = args[0] ?? '';
  if (first.includes('AF_INET6')) return 'AF_INET6';
  if (first.includes('AF_INET')) return 'AF_INET';
  if (first.includes('AF_UNIX')) return 'AF_UNIX';
  return first;
}

/**
 * Parse a connect() syscall's struct sockaddr argument to extract IP and port.
 * Example args string:
 *   3, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("93.184.216.34")}, 16
 */
function parseConnectArgs(argsRaw: string): { family: string; address: string; port: number } | null {
  // Check for AF_INET
  if (!argsRaw.includes('AF_INET')) return null;

  const family = argsRaw.includes('AF_INET6') ? 'AF_INET6' : 'AF_INET';

  // Extract port: sin_port=htons(80)
  const portMatch = /sin_port=htons\((\d+)\)/.exec(argsRaw);
  const port = portMatch ? parseInt(portMatch[1] ?? '0', 10) : 0;

  // Extract address: sin_addr=inet_addr("1.2.3.4")
  const addrMatch = /inet_addr\("([^"]+)"\)/.exec(argsRaw);
  const address = addrMatch ? (addrMatch[1] ?? '') : '';

  // Also try sin6_addr for IPv6
  if (!addrMatch) {
    const addr6Match = /sin6_addr=([^,}]+)/.exec(argsRaw);
    const address6 = addr6Match ? (addr6Match[1] ?? '').trim() : '';
    if (address6) {
      return { family, address: address6, port };
    }
  }

  if (!address && port === 0) return null;
  return { family, address, port };
}

function extractExecveArgs(argsRaw: string): string[] {
  // execve("/bin/sh", ["sh", "-c", "echo hello"], ...) — extract the array
  const arrayMatch = /\[([^\]]*)\]/.exec(argsRaw);
  if (!arrayMatch) return [];

  const inner = arrayMatch[1] ?? '';
  return inner
    .split(',')
    .map((s) => s.trim().replace(/^"|"$/g, ''))
    .filter((s) => s !== '');
}
