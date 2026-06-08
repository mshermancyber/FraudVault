// ── Runtime Deep Extraction ─────────────────────────────────────────────────
//
// Returns bash/Python scripts for deep runtime behavior extraction during
// sandbox execution. All functions return strings (scripts) that can be
// injected into the sandbox container via docker exec.

// ── Interfaces ─────────────────────────────────────────────────────────────

export interface RwxTransition {
  readonly pid: number;
  readonly address: string;
  readonly oldProt: string;
  readonly newProt: string;
}

export interface ProcRead {
  readonly pid: number;
  readonly path: string;
}

export interface DirectoryScan {
  readonly pid: number;
  readonly path: string;
}

export interface InotifyWatch {
  readonly pid: number;
  readonly path: string;
}

export interface NamedPipe {
  readonly pid: number;
  readonly path: string;
}

export interface UnixSocket {
  readonly pid: number;
  readonly path: string;
}

export interface SignalEvent {
  readonly pid: number;
  readonly signal: string;
  readonly action: string;
}

export interface EnhancedStraceResult {
  readonly rwxTransitions: RwxTransition[];
  readonly procReads: ProcRead[];
  readonly directoryScans: DirectoryScan[];
  readonly inotifyWatches: InotifyWatch[];
  readonly namedPipes: NamedPipe[];
  readonly unixSockets: UnixSocket[];
  readonly signalEvents: SignalEvent[];
}

export interface WineLoadDllEntry {
  readonly module: string;
  readonly path: string;
  readonly loadOrder: string;
}

export interface WineNtdllCall {
  readonly function: string;
  readonly args: string;
  readonly returnValue: string;
}

export interface WineEnhancedConfig {
  readonly envVars: Record<string, string>;
  readonly setupCommands: string[];
}

// ── Strace Deep Extraction ─────────────────────────────────────────────────

/** Existing syscalls traced by the executor's strace command. */
const EXISTING_SYSCALLS = [
  'open', 'openat', 'creat',
  'connect', 'socket', 'bind', 'sendto',
  'execve', 'clone', 'clone3', 'fork', 'vfork',
  'write', 'pwrite64',
  'unlink', 'unlinkat', 'rename', 'renameat', 'renameat2',
  'chmod', 'fchmod', 'fchmodat',
  'mkdir', 'mkdirat',
  'symlink', 'link',
] as const;

/** Additional syscalls for deep extraction. */
const ENHANCED_SYSCALLS = [
  'mmap', 'mprotect', 'ioctl',
  'sendmsg', 'recvmsg',
  'inotify_add_watch', 'inotify_init',
  'getdents64',
  'pipe2', 'mkfifo',
  // bind is already in EXISTING_SYSCALLS — included for AF_UNIX detection
] as const;

/**
 * Returns the strace command string with enhanced syscall tracing.
 * Includes all existing syscalls plus deep extraction syscalls.
 *
 * @param stracePath - Strace log output path (default: /tmp/scanboy-logs/strace-deep.log)
 * @param timeoutSeconds - Execution timeout in seconds
 * @param scriptPath - Path to the script to execute
 */
export function getEnhancedStraceCommand(
  stracePath = '/tmp/scanboy-logs/strace-deep.log',
  timeoutSeconds = 120,
  scriptPath = '/tmp/scanboy-exec.sh',
): string {
  const allSyscalls = [...EXISTING_SYSCALLS, ...ENHANCED_SYSCALLS];
  const traceSpec = allSyscalls.join(',');
  return [
    `timeout ${timeoutSeconds}`,
    `strace -f -t -o ${stracePath}`,
    `-e trace=${traceSpec}`,
    `-e signal=all`,
    `/bin/bash ${scriptPath}`,
  ].join(' ');
}

// ── Strace line regex ──────────────────────────────────────────────────────
// Matches lines like:
//   [pid 12345] 12:34:56 mprotect(0x7f..., 4096, PROT_READ|PROT_EXEC) = 0
//   12:34:56 mmap(NULL, 8192, PROT_READ|PROT_WRITE, ...) = 0x7f...
const STRACE_LINE_RE =
  /^(?:\[pid\s+(\d+)\]\s+)?(?:\d+:\d+:\d+\s+)?(\w+)\(([^)]*)\)\s*=\s*(.+)$/;

// Signal lines like:
//   [pid 12345] --- SIGCHLD {si_signo=SIGCHLD, ...} ---
const SIGNAL_LINE_RE =
  /^(?:\[pid\s+(\d+)\]\s+)?---\s+(\w+)\s+\{([^}]*)\}\s+---$/;

/**
 * Parse enhanced strace output for deep behavioral indicators.
 */
export function parseEnhancedStraceOutput(output: string): EnhancedStraceResult {
  const rwxTransitions: RwxTransition[] = [];
  const procReads: ProcRead[] = [];
  const directoryScans: DirectoryScan[] = [];
  const inotifyWatches: InotifyWatch[] = [];
  const namedPipes: NamedPipe[] = [];
  const unixSockets: UnixSocket[] = [];
  const signalEvents: SignalEvent[] = [];

  const lines = output.split('\n');

  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (line === '') continue;

    try {
      // Check for signal lines first
      const sigMatch = SIGNAL_LINE_RE.exec(line);
      if (sigMatch) {
        const pid = sigMatch[1] ? parseInt(sigMatch[1], 10) : 0;
        const signal = sigMatch[2] ?? '';
        const details = sigMatch[3] ?? '';
        // Extract action from si_code if present
        const codeMatch = /si_code=(\w+)/.exec(details);
        signalEvents.push({
          pid,
          signal,
          action: codeMatch ? codeMatch[1] ?? '' : 'delivered',
        });
        continue;
      }

      const match = STRACE_LINE_RE.exec(line);
      if (!match) continue;

      const pid = match[1] ? parseInt(match[1], 10) : 0;
      const syscall = match[2] ?? '';
      const argsRaw = match[3] ?? '';
      const retVal = (match[4] ?? '').trim();

      // Skip failed calls (return -1) for most checks
      const failed = retVal.startsWith('-1');

      // ── mprotect: detect RWX transitions (W+X or RWX) ───────────
      if (syscall === 'mprotect' && !failed) {
        parseMprotect(pid, argsRaw, rwxTransitions);
      }

      // ── /proc and /sys reads ─────────────────────────────────────
      if ((syscall === 'open' || syscall === 'openat') && !failed) {
        const pathStr = extractFirstQuotedArg(argsRaw);
        if (pathStr && (pathStr.startsWith('/proc/') || pathStr.startsWith('/sys/'))) {
          procReads.push({ pid, path: pathStr });
        }
      }

      // ── getdents64: directory scanning ───────────────────────────
      if (syscall === 'getdents64' && !failed) {
        // The first arg is the fd number — we track which directory this
        // corresponds to via preceding openat. For simplicity we just
        // record that the process performed directory enumeration.
        // We'll try to extract the fd from the line.
        const fdStr = argsRaw.split(',')[0]?.trim();
        if (fdStr !== undefined) {
          directoryScans.push({ pid, path: `fd:${fdStr}` });
        }
      }

      // ── inotify_add_watch: filesystem monitoring ─────────────────
      if (syscall === 'inotify_add_watch' && !failed) {
        const watchPath = extractFirstQuotedArg(argsRaw);
        if (watchPath) {
          inotifyWatches.push({ pid, path: watchPath });
        }
      }

      // ── mkfifo / pipe2: named pipes ──────────────────────────────
      if (syscall === 'mkfifo' && !failed) {
        const pipePath = extractFirstQuotedArg(argsRaw);
        if (pipePath) {
          namedPipes.push({ pid, path: pipePath });
        }
      }
      if (syscall === 'pipe2' && !failed) {
        namedPipes.push({ pid, path: `pipe2(${argsRaw})` });
      }

      // ── bind with AF_UNIX: Unix domain sockets ───────────────────
      if (syscall === 'bind' && !failed) {
        parseUnixBind(pid, argsRaw, unixSockets);
      }

      // ── connect with AF_UNIX ─────────────────────────────────────
      if (syscall === 'connect' && !failed) {
        parseUnixConnect(pid, argsRaw, unixSockets);
      }
    } catch {
      // Defensive: skip malformed lines
    }
  }

  // De-duplicate directory scans by pid+path
  const uniqueDirScans = deduplicateByKey(directoryScans, (s) => `${s.pid}:${s.path}`);

  return {
    rwxTransitions,
    procReads,
    directoryScans: uniqueDirScans,
    inotifyWatches,
    namedPipes,
    unixSockets,
    signalEvents,
  };
}

// ── Strace helper parsers ──────────────────────────────────────────────────

function parseMprotect(
  pid: number,
  argsRaw: string,
  results: RwxTransition[],
): void {
  // mprotect(0x7f1234, 4096, PROT_READ|PROT_WRITE|PROT_EXEC) = 0
  const parts = argsRaw.split(',');
  if (parts.length < 3) return;
  const address = (parts[0] ?? '').trim();
  const protStr = (parts[2] ?? '').trim();

  // Check for W+X (PROT_WRITE + PROT_EXEC) which indicates code injection
  const hasWrite = protStr.includes('PROT_WRITE');
  const hasExec = protStr.includes('PROT_EXEC');
  if (hasWrite || hasExec) {
    // Determine old protection — strace doesn't show it, so we infer
    // "changed to" from the new prot flags
    results.push({
      pid,
      address,
      oldProt: 'unknown',
      newProt: protStr,
    });
  }
}

function parseUnixBind(
  pid: number,
  argsRaw: string,
  results: UnixSocket[],
): void {
  // bind(3, {sa_family=AF_UNIX, sun_path="/tmp/sock"}, 110)
  if (!argsRaw.includes('AF_UNIX')) return;
  const pathMatch = /sun_path="([^"]*)"/.exec(argsRaw);
  if (pathMatch) {
    results.push({ pid, path: pathMatch[1] ?? '' });
  } else {
    // Abstract socket (starts with \0)
    const abstractMatch = /sun_path=@(\S+)/.exec(argsRaw);
    results.push({ pid, path: abstractMatch ? `@${abstractMatch[1] ?? ''}` : '@abstract' });
  }
}

function parseUnixConnect(
  pid: number,
  argsRaw: string,
  results: UnixSocket[],
): void {
  if (!argsRaw.includes('AF_UNIX')) return;
  const pathMatch = /sun_path="([^"]*)"/.exec(argsRaw);
  if (pathMatch) {
    results.push({ pid, path: pathMatch[1] ?? '' });
  }
}

function extractFirstQuotedArg(argsRaw: string): string | null {
  // For openat: AT_FDCWD, "/etc/passwd", O_RDONLY
  // For open: "/etc/passwd", O_RDONLY
  const match = /"([^"]*)"/.exec(argsRaw);
  return match ? (match[1] ?? null) : null;
}

function deduplicateByKey<T>(items: T[], keyFn: (item: T) => string): T[] {
  const seen = new Set<string>();
  const result: T[] = [];
  for (const item of items) {
    const key = keyFn(item);
    if (!seen.has(key)) {
      seen.add(key);
      result.push(item);
    }
  }
  return result;
}

// ── /proc Deep Extraction ──────────────────────────────────────────────────

/**
 * Returns a bash script that captures deep /proc data at two timepoints
 * during execution (T=2s and T=timeout-2s).
 *
 * @param targetPidFile - File containing the PID of the monitored process
 * @param timeoutSeconds - Total execution timeout
 */
export function getProcExtractionScript(
  targetPidFile = '/tmp/scanboy-logs/target.pid',
  timeoutSeconds = 120,
): string {
  const secondSnapshot = Math.max(timeoutSeconds - 2, 3);

  return `#!/bin/bash
set -u

PID_FILE="${targetPidFile}"
TIMEOUT=${timeoutSeconds}
SECOND_SNAP=${secondSnapshot}
LOG_DIR="/tmp/scanboy-logs/proc-deep"
mkdir -p "\$LOG_DIR"

# Wait for PID file
for i in $(seq 1 10); do
  [ -f "\$PID_FILE" ] && break
  sleep 0.2
done

if [ ! -f "\$PID_FILE" ]; then
  echo '{"error": "no pid file found"}' >&1
  exit 1
fi

TARGET_PID=\$(cat "\$PID_FILE")

capture_snapshot() {
  local SNAP_NAME="\$1"
  local PID="\$2"
  local OUT="\$LOG_DIR/\${SNAP_NAME}.json"

  # Resolve all descendant PIDs
  local ALL_PIDS
  ALL_PIDS=\$(ps --ppid "\$PID" -o pid= 2>/dev/null | tr '\\n' ' ')
  ALL_PIDS="\$PID \$ALL_PIDS"

  local MAPS=""
  local FDS="[]"
  local STATUS=""
  local CMDLINE=""
  local EXE=""
  local ENVIRON=""

  for P in \$ALL_PIDS; do
    P=\$(echo "\$P" | tr -d ' ')
    [ -z "\$P" ] && continue
    [ ! -d "/proc/\$P" ] && continue

    # /proc/pid/maps — capture executable regions
    if [ -r "/proc/\$P/maps" ]; then
      local M
      M=\$(grep ' r-xp\\| rwxp' "/proc/\$P/maps" 2>/dev/null | head -200 || true)
      MAPS="\${MAPS}\n--- PID \$P ---\n\${M}"
    fi

    # /proc/pid/fd — enumerate open file descriptors
    if [ -d "/proc/\$P/fd" ]; then
      local FD_LIST
      FD_LIST=\$(ls -la "/proc/\$P/fd/" 2>/dev/null | tail -n +2 | head -200 || true)
      FDS="\${FDS}\n--- PID \$P ---\n\${FD_LIST}"
    fi

    # /proc/pid/status — key fields
    if [ -r "/proc/\$P/status" ]; then
      local S
      S=\$(grep -E '^(VmPeak|VmSize|Threads|TracerPid|Seccomp|NoNewPrivs):' "/proc/\$P/status" 2>/dev/null || true)
      STATUS="\${STATUS}\n--- PID \$P ---\n\${S}"
    fi

    # /proc/pid/cmdline vs /proc/pid/exe — masquerading detection
    if [ -r "/proc/\$P/cmdline" ]; then
      CMDLINE="\${CMDLINE}\n--- PID \$P ---\n\$(cat -v /proc/\$P/cmdline 2>/dev/null || true)"
    fi
    if [ -L "/proc/\$P/exe" ]; then
      EXE="\${EXE}\n--- PID \$P ---\n\$(readlink /proc/\$P/exe 2>/dev/null || true)"
    fi

    # /proc/pid/environ
    if [ -r "/proc/\$P/environ" ]; then
      ENVIRON="\${ENVIRON}\n--- PID \$P ---\n\$(cat -v /proc/\$P/environ 2>/dev/null | tr '\\0' '\\n' | head -100 || true)"
    fi
  done

  # /dev/shm contents
  local SHM_CONTENTS
  SHM_CONTENTS=\$(ls -la /dev/shm/ 2>/dev/null || echo "empty")

  # cgroup memory/CPU
  local CGROUP_MEM=""
  local CGROUP_CPU=""
  if [ -f "/sys/fs/cgroup/memory/memory.usage_in_bytes" ]; then
    CGROUP_MEM=\$(cat /sys/fs/cgroup/memory/memory.usage_in_bytes 2>/dev/null || echo "0")
  elif [ -f "/sys/fs/cgroup/memory.current" ]; then
    CGROUP_MEM=\$(cat /sys/fs/cgroup/memory.current 2>/dev/null || echo "0")
  fi
  if [ -f "/sys/fs/cgroup/cpu/cpuacct.usage" ]; then
    CGROUP_CPU=\$(cat /sys/fs/cgroup/cpu/cpuacct.usage 2>/dev/null || echo "0")
  elif [ -f "/sys/fs/cgroup/cpu.stat" ]; then
    CGROUP_CPU=\$(cat /sys/fs/cgroup/cpu.stat 2>/dev/null || echo "")
  fi

  # Entropy pool level
  local ENTROPY
  ENTROPY=\$(cat /proc/sys/kernel/random/entropy_avail 2>/dev/null || echo "unknown")

  # Output JSON (using printf to handle escaping)
  python3 -c "
import json, sys
data = {
    'snapshot': '\${SNAP_NAME}',
    'pids': '\${ALL_PIDS}'.split(),
    'maps': '''$(echo -e "\$MAPS")''',
    'fds': '''$(echo -e "\$FDS")''',
    'status': '''$(echo -e "\$STATUS")''',
    'cmdline': '''$(echo -e "\$CMDLINE")''',
    'exe': '''$(echo -e "\$EXE")''',
    'environ': '''$(echo -e "\$ENVIRON")''',
    'shm_contents': '''$SHM_CONTENTS''',
    'cgroup_memory': '\${CGROUP_MEM}',
    'cgroup_cpu': '\${CGROUP_CPU}',
    'entropy_avail': '\${ENTROPY}',
}
json.dump(data, sys.stdout)
print()
" 2>/dev/null || echo '{"error": "json serialization failed for '\$SNAP_NAME'"}'
}

# First snapshot at T=2s
sleep 2
capture_snapshot "t_early" "\$TARGET_PID"

# Second snapshot at T=timeout-2s (if timeout > 4s)
if [ "\$TIMEOUT" -gt 4 ]; then
  WAIT_TIME=\$(( SECOND_SNAP - 2 ))
  sleep "\$WAIT_TIME"
  capture_snapshot "t_late" "\$TARGET_PID"
fi
`;
}

// ── Wine Deep Extraction ───────────────────────────────────────────────────

/**
 * Returns environment variables and setup commands for enhanced Wine tracing.
 */
export function getWineEnhancedConfig(): WineEnhancedConfig {
  return {
    envVars: {
      WINEDEBUG: '+loaddll,+ntdll',
      WINEPREFIX: '/home/sandbox/.wine',
      WINEARCH: 'win64',
      // Suppress GUI dialogs
      DISPLAY: '',
      WINEDLLOVERRIDES: 'mscoree=d;mshtml=d',
    },
    setupCommands: [
      // Initialize wine prefix if needed (silent, no GUI)
      'wineboot --init 2>/dev/null || true',
      // Pre-execution filesystem snapshot
      'find /home/sandbox/.wine/drive_c -type f 2>/dev/null | sort > /tmp/scanboy-logs/wine-fs-before.txt',
    ],
  };
}

/**
 * Parse Wine +loaddll debug output to extract DLL loading events.
 *
 * Wine loaddll trace lines look like:
 *   0024:trace:loaddll:load_dll Loaded L"C:\\windows\\system32\\ntdll.dll" ...
 *   0024:trace:loaddll:load_builtin_dll loaded L"kernelbase" as builtin
 */
export function parseWineLoadDllOutput(output: string): WineLoadDllEntry[] {
  const entries: WineLoadDllEntry[] = [];

  const lines = output.split('\n');

  // Matches Wine loaddll trace messages
  const loadDllRe = /trace:loaddll:\w+\s+.*?[Ll]"([^"]+)"/;
  const loadOrderRe = /as\s+(builtin|native|disabled)/;

  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line.includes('trace:loaddll:')) continue;

    try {
      const dllMatch = loadDllRe.exec(line);
      if (!dllMatch) continue;

      const fullPath = dllMatch[1] ?? '';
      const orderMatch = loadOrderRe.exec(line);
      const loadOrder = orderMatch ? (orderMatch[1] ?? 'unknown') : 'unknown';

      // Extract module name from path
      const pathParts = fullPath.split(/[/\\]/);
      const module = pathParts[pathParts.length - 1] ?? fullPath;

      entries.push({
        module,
        path: fullPath,
        loadOrder,
      });
    } catch {
      // Skip malformed lines
    }
  }

  return entries;
}

/**
 * Parse Wine +ntdll debug output to extract NT native API calls.
 *
 * Wine ntdll trace lines look like:
 *   0024:trace:ntdll:NtCreateFile (0x..., ..., "\\??\\C:\\file.txt", ...)
 *   0024:trace:ntdll:NtQueryInformationProcess (0x..., ProcessBasicInformation)
 */
export function parseWineNtdllOutput(output: string): WineNtdllCall[] {
  const calls: WineNtdllCall[] = [];

  const lines = output.split('\n');

  // Matches Wine ntdll trace with function name and arguments
  const ntdllRe = /trace:ntdll:(\w+)\s*\(([^)]*)\)(?:\s*(?:ret|=)\s*(.+))?/;

  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line.includes('trace:ntdll:')) continue;

    try {
      const match = ntdllRe.exec(line);
      if (!match) continue;

      calls.push({
        function: match[1] ?? '',
        args: match[2] ?? '',
        returnValue: match[3] ?? '',
      });
    } catch {
      // Skip malformed lines
    }
  }

  return calls;
}

/**
 * Returns a bash script that diffs the Wine drive_c filesystem before/after
 * execution to find created, modified, or deleted files.
 */
export function getWineDriveCDiffScript(): string {
  return `#!/bin/bash
set -u

BEFORE="/tmp/scanboy-logs/wine-fs-before.txt"
AFTER="/tmp/scanboy-logs/wine-fs-after.txt"

# Post-execution snapshot
find /home/sandbox/.wine/drive_c -type f 2>/dev/null | sort > "\$AFTER"

if [ ! -f "\$BEFORE" ]; then
  echo '{"error": "pre-execution snapshot not found"}'
  exit 1
fi

# Compute diffs
CREATED=\$(comm -13 "\$BEFORE" "\$AFTER" 2>/dev/null || true)
DELETED=\$(comm -23 "\$BEFORE" "\$AFTER" 2>/dev/null || true)

# For created files, compute hashes
CREATED_JSON="[]"
if [ -n "\$CREATED" ]; then
  CREATED_JSON=\$(echo "\$CREATED" | while IFS= read -r f; do
    SIZE=\$(stat -c '%s' "\$f" 2>/dev/null || echo "0")
    HASH=\$(sha256sum "\$f" 2>/dev/null | cut -d' ' -f1 || echo "unknown")
    printf '{"path":"%s","size":%s,"sha256":"%s"}\\n' "\$f" "\$SIZE" "\$HASH"
  done | python3 -c "
import sys, json
items = []
for line in sys.stdin:
    line = line.strip()
    if line:
        try:
            items.append(json.loads(line))
        except Exception:
            pass
json.dump(items, sys.stdout)
" 2>/dev/null || echo "[]")
fi

DELETED_JSON="[]"
if [ -n "\$DELETED" ]; then
  DELETED_JSON=\$(echo "\$DELETED" | python3 -c "
import sys, json
items = [line.strip() for line in sys.stdin if line.strip()]
json.dump(items, sys.stdout)
" 2>/dev/null || echo "[]")
fi

# Wine exit code -> NTSTATUS mapping
WINE_EXIT=\${WINE_EXIT_CODE:-0}
NTSTATUS="STATUS_SUCCESS"
case "\$WINE_EXIT" in
  0) NTSTATUS="STATUS_SUCCESS" ;;
  1) NTSTATUS="STATUS_UNSUCCESSFUL" ;;
  3) NTSTATUS="STATUS_INVALID_INFO_CLASS" ;;
  5) NTSTATUS="STATUS_ACCESS_DENIED" ;;
  128) NTSTATUS="STATUS_ABANDONED_WAIT_0" ;;
  255) NTSTATUS="STATUS_FATAL_APP_EXIT" ;;
  -1073741819) NTSTATUS="STATUS_ACCESS_VIOLATION" ;;
  -1073741795) NTSTATUS="STATUS_ILLEGAL_INSTRUCTION" ;;
  -1073741676) NTSTATUS="STATUS_INTEGER_DIVIDE_BY_ZERO" ;;
  -1073741571) NTSTATUS="STATUS_STACK_OVERFLOW" ;;
  -1073741515) NTSTATUS="STATUS_DLL_NOT_FOUND" ;;
  -1073741511) NTSTATUS="STATUS_ENTRYPOINT_NOT_FOUND" ;;
  *) NTSTATUS="STATUS_UNKNOWN_0x\$(printf '%08x' "\$WINE_EXIT" 2>/dev/null || echo 'unknown')" ;;
esac

python3 -c "
import json, sys
data = {
    'created_files': \$CREATED_JSON,
    'deleted_files': \$DELETED_JSON,
    'wine_exit_code': \$WINE_EXIT,
    'ntstatus': '\$NTSTATUS',
}
json.dump(data, sys.stdout)
print()
" 2>/dev/null || echo '{"error": "json output failed"}'
`;
}

// ── Network PCAP Deep Extraction ───────────────────────────────────────────

/**
 * Returns a Python3 script that reads a raw pcap file (libpcap format) and
 * extracts deep network indicators. Uses only struct.unpack — no external
 * libraries needed.
 *
 * @param pcapPath - Path to the pcap file inside the container
 */
export function getDeepPcapAnalysisScript(
  pcapPath = '/tmp/scanboy-logs/capture.pcap',
): string {
  return `#!/usr/bin/env python3
"""Deep PCAP analysis — extracts behavioral network indicators from raw pcap."""

import struct
import hashlib
import json
import sys
from collections import defaultdict

PCAP_PATH = "${pcapPath}"

# ── PCAP global header ──────────────────────────────────────────────────────
# magic_number (4), version_major (2), version_minor (2), thiszone (4),
# sigfigs (4), snaplen (4), network (4) = 24 bytes
PCAP_GLOBAL_HDR_FMT = '<IHHiIII'
PCAP_GLOBAL_HDR_SIZE = 24

# ── PCAP per-packet header ──────────────────────────────────────────────────
# ts_sec (4), ts_usec (4), incl_len (4), orig_len (4) = 16 bytes
PCAP_PKT_HDR_FMT = '<IIII'
PCAP_PKT_HDR_SIZE = 16

# ── Ethernet ────────────────────────────────────────────────────────────────
ETH_HDR_SIZE = 14
ETHERTYPE_IP = 0x0800
ETHERTYPE_ARP = 0x0806

# ── IP ──────────────────────────────────────────────────────────────────────
IPPROTO_ICMP = 1
IPPROTO_TCP = 6
IPPROTO_UDP = 17

# ── Results containers ──────────────────────────────────────────────────────
tcp_syns: list = []
tls_ja3_hashes: list = []
tls_snis: list = []
icmp_packets: list = []
dns_queries: list = []
dns_timestamps: list = []
udp_payload_sizes: list = []
arp_requests: list = []


def ip_to_str(packed_ip: bytes) -> str:
    """Convert 4-byte packed IP to dotted-quad string."""
    return ".".join(str(b) for b in packed_ip)


def parse_dns_name(data: bytes, offset: int) -> tuple:
    """Parse a DNS name from wire format, handling compression pointers."""
    parts: list = []
    original_offset = offset
    jumped = False
    max_jumps = 20
    jumps = 0

    while offset < len(data):
        if jumps > max_jumps:
            break
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:
            # Compression pointer
            if offset + 1 >= len(data):
                break
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                original_offset = offset + 2
            offset = pointer
            jumped = True
            jumps += 1
            continue
        offset += 1
        if offset + length > len(data):
            break
        parts.append(data[offset:offset + length].decode("ascii", errors="replace"))
        offset += length

    name = ".".join(parts)
    final_offset = original_offset if jumped else offset
    return name, final_offset


def compute_ja3(
    tls_version: int,
    cipher_suites: list,
    extensions: list,
    elliptic_curves: list,
    ec_point_formats: list,
) -> str:
    """Compute JA3 hash from TLS ClientHello fields."""
    # JA3 format: TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
    # GREASE values are filtered out
    grease_values = {
        0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
        0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
    }

    def filter_grease(values: list) -> list:
        return [v for v in values if v not in grease_values]

    filtered_ciphers = filter_grease(cipher_suites)
    filtered_extensions = filter_grease(extensions)
    filtered_curves = filter_grease(elliptic_curves)
    filtered_formats = filter_grease(ec_point_formats)

    ja3_str = ",".join([
        str(tls_version),
        "-".join(str(c) for c in filtered_ciphers),
        "-".join(str(e) for e in filtered_extensions),
        "-".join(str(c) for c in filtered_curves),
        "-".join(str(f) for f in filtered_formats),
    ])

    return hashlib.md5(ja3_str.encode()).hexdigest()


def parse_tls_client_hello(data: bytes, offset: int) -> None:
    """Parse TLS ClientHello from a TCP payload."""
    if offset + 5 > len(data):
        return

    # TLS record header: content_type (1), version (2), length (2)
    content_type = data[offset]
    if content_type != 0x16:  # Handshake
        return

    record_version = struct.unpack_from(">H", data, offset + 1)[0]
    record_length = struct.unpack_from(">H", data, offset + 3)[0]
    pos = offset + 5

    if pos + 4 > len(data):
        return

    # Handshake header: type (1), length (3)
    handshake_type = data[pos]
    if handshake_type != 0x01:  # ClientHello
        return

    hs_length = (data[pos + 1] << 16) | (data[pos + 2] << 8) | data[pos + 3]
    pos += 4

    _ = record_version  # used for ja3 below
    _ = hs_length
    _ = record_length

    if pos + 2 > len(data):
        return

    # Client version
    client_version = struct.unpack_from(">H", data, pos)[0]
    pos += 2

    # Random (32 bytes)
    pos += 32
    if pos >= len(data):
        return

    # Session ID
    session_id_len = data[pos]
    pos += 1 + session_id_len
    if pos + 2 > len(data):
        return

    # Cipher suites
    cipher_suites_len = struct.unpack_from(">H", data, pos)[0]
    pos += 2
    cipher_suites: list = []
    cs_end = pos + cipher_suites_len
    while pos + 1 < cs_end and pos + 1 < len(data):
        cs = struct.unpack_from(">H", data, pos)[0]
        cipher_suites.append(cs)
        pos += 2

    if pos >= len(data):
        return

    # Compression methods
    comp_len = data[pos]
    pos += 1 + comp_len

    # Extensions
    extensions: list = []
    elliptic_curves: list = []
    ec_point_formats: list = []
    sni: str = ""

    if pos + 2 <= len(data):
        ext_total_len = struct.unpack_from(">H", data, pos)[0]
        pos += 2
        ext_end = pos + ext_total_len

        while pos + 4 <= ext_end and pos + 4 <= len(data):
            ext_type = struct.unpack_from(">H", data, pos)[0]
            ext_len = struct.unpack_from(">H", data, pos + 2)[0]
            extensions.append(ext_type)
            ext_data_start = pos + 4

            # SNI extension (type 0x0000)
            if ext_type == 0x0000 and ext_data_start + ext_len <= len(data):
                sni_data = data[ext_data_start:ext_data_start + ext_len]
                if len(sni_data) > 5:
                    name_len = struct.unpack_from(">H", sni_data, 3)[0]
                    if 5 + name_len <= len(sni_data):
                        sni = sni_data[5:5 + name_len].decode("ascii", errors="replace")
                        if sni:
                            tls_snis.append(sni)

            # Supported groups / elliptic curves (type 0x000a)
            if ext_type == 0x000A and ext_data_start + 2 <= len(data):
                curves_len = struct.unpack_from(">H", data, ext_data_start)[0]
                c_pos = ext_data_start + 2
                c_end = c_pos + curves_len
                while c_pos + 1 < c_end and c_pos + 1 < len(data):
                    curve = struct.unpack_from(">H", data, c_pos)[0]
                    elliptic_curves.append(curve)
                    c_pos += 2

            # EC point formats (type 0x000b)
            if ext_type == 0x000B and ext_data_start + 1 <= len(data):
                formats_len = data[ext_data_start]
                f_pos = ext_data_start + 1
                f_end = f_pos + formats_len
                while f_pos < f_end and f_pos < len(data):
                    ec_point_formats.append(data[f_pos])
                    f_pos += 1

            pos += 4 + ext_len

    # Compute JA3
    ja3 = compute_ja3(client_version, cipher_suites, extensions, elliptic_curves, ec_point_formats)
    tls_ja3_hashes.append({"ja3": ja3, "sni": sni})


def parse_packet(pkt_data: bytes, ts_sec: int, ts_usec: int) -> None:
    """Parse a single Ethernet frame from pcap data."""
    if len(pkt_data) < ETH_HDR_SIZE:
        return

    # Ethernet header
    dst_mac = pkt_data[0:6]
    src_mac = pkt_data[6:12]
    ethertype = struct.unpack_from(">H", pkt_data, 12)[0]

    _ = dst_mac
    _ = src_mac

    # Handle 802.1Q VLAN tagging
    ip_offset = ETH_HDR_SIZE
    if ethertype == 0x8100:
        if len(pkt_data) < ip_offset + 4:
            return
        ethertype = struct.unpack_from(">H", pkt_data, ip_offset + 2)[0]
        ip_offset += 4

    timestamp = ts_sec + ts_usec / 1_000_000.0

    # ── ARP ──────────────────────────────────────────────────────────────
    if ethertype == ETHERTYPE_ARP:
        if len(pkt_data) >= ip_offset + 28:
            arp_op = struct.unpack_from(">H", pkt_data, ip_offset + 6)[0]
            if arp_op == 1:  # ARP request
                sender_ip = ip_to_str(pkt_data[ip_offset + 14:ip_offset + 18])
                target_ip = ip_to_str(pkt_data[ip_offset + 24:ip_offset + 28])
                arp_requests.append({
                    "sender_ip": sender_ip,
                    "target_ip": target_ip,
                    "timestamp": timestamp,
                })
        return

    if ethertype != ETHERTYPE_IP:
        return

    # ── IP header ────────────────────────────────────────────────────────
    if len(pkt_data) < ip_offset + 20:
        return

    version_ihl = pkt_data[ip_offset]
    ihl = (version_ihl & 0x0F) * 4
    total_length = struct.unpack_from(">H", pkt_data, ip_offset + 2)[0]
    protocol = pkt_data[ip_offset + 9]
    src_ip = ip_to_str(pkt_data[ip_offset + 12:ip_offset + 16])
    dst_ip = ip_to_str(pkt_data[ip_offset + 16:ip_offset + 20])

    _ = total_length

    transport_offset = ip_offset + ihl

    # ── ICMP ─────────────────────────────────────────────────────────────
    if protocol == IPPROTO_ICMP:
        if len(pkt_data) >= transport_offset + 8:
            icmp_type = pkt_data[transport_offset]
            icmp_code = pkt_data[transport_offset + 1]
            payload_size = len(pkt_data) - transport_offset - 8
            icmp_packets.append({
                "type": icmp_type,
                "code": icmp_code,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "payload_size": payload_size,
                "timestamp": timestamp,
            })
        return

    # ── TCP ──────────────────────────────────────────────────────────────
    if protocol == IPPROTO_TCP:
        if len(pkt_data) < transport_offset + 20:
            return

        src_port = struct.unpack_from(">H", pkt_data, transport_offset)[0]
        dst_port = struct.unpack_from(">H", pkt_data, transport_offset + 2)[0]
        tcp_flags = pkt_data[transport_offset + 13]
        data_offset = ((pkt_data[transport_offset + 12] >> 4) & 0x0F) * 4

        # SYN flag = 0x02, check SYN but not ACK
        is_syn = (tcp_flags & 0x02) != 0 and (tcp_flags & 0x10) == 0
        if is_syn:
            tcp_syns.append({
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "timestamp": timestamp,
            })

        # Check for TLS ClientHello in TCP payload
        tcp_payload_offset = transport_offset + data_offset
        if tcp_payload_offset < len(pkt_data):
            tcp_payload = pkt_data[tcp_payload_offset:]
            if len(tcp_payload) > 5 and tcp_payload[0] == 0x16:
                try:
                    parse_tls_client_hello(pkt_data, tcp_payload_offset)
                except Exception:
                    pass

        return

    # ── UDP ──────────────────────────────────────────────────────────────
    if protocol == IPPROTO_UDP:
        if len(pkt_data) < transport_offset + 8:
            return

        src_port = struct.unpack_from(">H", pkt_data, transport_offset)[0]
        dst_port = struct.unpack_from(">H", pkt_data, transport_offset + 2)[0]
        udp_length = struct.unpack_from(">H", pkt_data, transport_offset + 4)[0]
        payload_size = udp_length - 8  # UDP header is 8 bytes

        if payload_size > 0:
            udp_payload_sizes.append(payload_size)

        # DNS (port 53)
        if dst_port == 53 or src_port == 53:
            dns_offset = transport_offset + 8
            if dns_offset + 12 <= len(pkt_data):
                # Only parse queries (QR bit = 0)
                flags = struct.unpack_from(">H", pkt_data, dns_offset + 2)[0]
                is_query = (flags & 0x8000) == 0
                if is_query:
                    qdcount = struct.unpack_from(">H", pkt_data, dns_offset + 4)[0]
                    if qdcount > 0:
                        try:
                            name, _ = parse_dns_name(pkt_data, dns_offset + 12)
                            dns_queries.append({
                                "domain": name,
                                "timestamp": timestamp,
                            })
                            dns_timestamps.append(timestamp)
                        except Exception:
                            pass

        return


def analyze_icmp(packets: list) -> dict:
    """Analyze ICMP packets for tunneling and ping sweep indicators."""
    if not packets:
        return {"total": 0, "tunneling_suspect": False, "ping_sweep_count": 0}

    # Tunneling: ICMP packets with unusually large payloads
    large_payloads = [p for p in packets if p["payload_size"] > 64]
    tunneling_suspect = len(large_payloads) > 5

    # Ping sweep: echo requests to many different IPs
    echo_requests = [p for p in packets if p["type"] == 8]  # Echo request
    unique_dst = len(set(p["dst_ip"] for p in echo_requests))
    ping_sweep_count = unique_dst

    return {
        "total": len(packets),
        "echo_requests": len(echo_requests),
        "tunneling_suspect": tunneling_suspect,
        "large_payload_count": len(large_payloads),
        "ping_sweep_count": ping_sweep_count,
        "unique_destinations": unique_dst,
    }


def analyze_dns_timing(timestamps: list) -> dict:
    """Compute DNS query timing statistics."""
    if not timestamps:
        return {"total_queries": 0, "qps": 0.0, "jitter": 0.0, "unique_ratio": 0.0}

    sorted_ts = sorted(timestamps)
    duration = sorted_ts[-1] - sorted_ts[0] if len(sorted_ts) > 1 else 1.0
    qps = len(sorted_ts) / max(duration, 0.001)

    # Jitter: standard deviation of inter-query intervals
    intervals: list = []
    for i in range(1, len(sorted_ts)):
        intervals.append(sorted_ts[i] - sorted_ts[i - 1])

    jitter = 0.0
    if intervals:
        mean_interval = sum(intervals) / len(intervals)
        variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
        jitter = variance ** 0.5

    # Unique domain ratio
    unique_domains = len(set(q["domain"] for q in dns_queries))
    unique_ratio = unique_domains / len(dns_queries) if dns_queries else 0.0

    return {
        "total_queries": len(dns_queries),
        "unique_domains": unique_domains,
        "unique_ratio": round(unique_ratio, 4),
        "qps": round(qps, 4),
        "jitter_seconds": round(jitter, 6),
        "duration_seconds": round(duration, 4),
    }


def build_udp_histogram(sizes: list) -> dict:
    """Build a histogram of UDP payload sizes."""
    if not sizes:
        return {"total": 0, "buckets": {}}

    buckets: dict = defaultdict(int)
    for size in sizes:
        if size <= 64:
            bucket = "0-64"
        elif size <= 128:
            bucket = "65-128"
        elif size <= 256:
            bucket = "129-256"
        elif size <= 512:
            bucket = "257-512"
        elif size <= 1024:
            bucket = "513-1024"
        else:
            bucket = "1025+"
        buckets[bucket] += 1

    return {
        "total": len(sizes),
        "min": min(sizes),
        "max": max(sizes),
        "mean": round(sum(sizes) / len(sizes), 2),
        "buckets": dict(buckets),
    }


def main() -> None:
    try:
        with open(PCAP_PATH, "rb") as f:
            data = f.read()
    except FileNotFoundError:
        json.dump({"error": f"pcap file not found: {PCAP_PATH}"}, sys.stdout)
        print()
        return
    except PermissionError:
        json.dump({"error": f"permission denied: {PCAP_PATH}"}, sys.stdout)
        print()
        return

    if len(data) < PCAP_GLOBAL_HDR_SIZE:
        json.dump({"error": "pcap file too small"}, sys.stdout)
        print()
        return

    # Parse global header
    magic, ver_major, ver_minor, thiszone, sigfigs, snaplen, network = \\
        struct.unpack_from(PCAP_GLOBAL_HDR_FMT, data, 0)

    # Determine byte order from magic number
    big_endian = False
    if magic == 0xA1B2C3D4:
        big_endian = False
    elif magic == 0xD4C3B2A1:
        big_endian = True
    else:
        json.dump({"error": f"invalid pcap magic: 0x{magic:08x}"}, sys.stdout)
        print()
        return

    _ = ver_major
    _ = ver_minor
    _ = thiszone
    _ = sigfigs
    _ = snaplen

    # Adjust format string for big-endian pcap
    pkt_fmt = '>IIII' if big_endian else '<IIII'

    # Only handle Ethernet (network type 1)
    if network != 1:
        json.dump({"error": f"unsupported link type: {network}"}, sys.stdout)
        print()
        return

    # Parse packets
    offset = PCAP_GLOBAL_HDR_SIZE
    packet_count = 0
    max_packets = 500_000  # Safety limit

    while offset + PCAP_PKT_HDR_SIZE <= len(data) and packet_count < max_packets:
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack_from(pkt_fmt, data, offset)
        _ = orig_len
        offset += PCAP_PKT_HDR_SIZE

        if offset + incl_len > len(data):
            break

        pkt_data = data[offset:offset + incl_len]
        offset += incl_len
        packet_count += 1

        try:
            parse_packet(pkt_data, ts_sec, ts_usec)
        except Exception:
            continue

    # ── Build results ────────────────────────────────────────────────────
    # De-duplicate JA3 entries
    seen_ja3: set = set()
    unique_ja3: list = []
    for entry in tls_ja3_hashes:
        key = entry["ja3"] + "|" + entry["sni"]
        if key not in seen_ja3:
            seen_ja3.add(key)
            unique_ja3.append(entry)

    # De-duplicate SNIs
    unique_snis = sorted(set(tls_snis))

    results = {
        "packet_count": packet_count,
        "tcp_syns": tcp_syns,
        "tcp_syn_count": len(tcp_syns),
        "unique_syn_destinations": len(set(
            f"{s['dst_ip']}:{s['dst_port']}" for s in tcp_syns
        )),
        "tls_ja3": unique_ja3,
        "tls_snis": unique_snis,
        "icmp_analysis": analyze_icmp(icmp_packets),
        "dns_timing": analyze_dns_timing(dns_timestamps),
        "udp_histogram": build_udp_histogram(udp_payload_sizes),
        "arp_requests": arp_requests,
        "arp_unique_targets": len(set(a["target_ip"] for a in arp_requests)),
    }

    json.dump(results, sys.stdout, indent=2)
    print()


if __name__ == "__main__":
    main()
`;
}
