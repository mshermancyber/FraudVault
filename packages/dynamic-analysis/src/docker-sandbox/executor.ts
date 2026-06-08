// ── Docker Sandbox Executor — the core detonation engine ────────────────────
//
// For each sample, spins up a fresh throwaway Docker container, executes the
// sample inside it with monitoring (strace, inotifywait, tcpdump), collects
// all behavioral data, then destroys the container.
//
// Docker commands are issued via child_process.execFile to the docker CLI,
// which communicates with the daemon through /var/run/docker.sock.

import { execFile as execFileCb } from 'node:child_process';
import { mkdtemp, writeFile, rm, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { promisify } from 'node:util';

import { ensureSandboxImage, getImageName } from './image-builder.js';
import {
  parseStraceOutput,
  parseInotifyOutput,
  parseNetworkCapture,
  parseProcInfo,
} from './monitor-parser.js';
import { buildReport, isSandboxInfra, type BuildReportInput } from './report-builder.js';
import type {
  ExecutionOptions,
  ResolvedExecutionOptions,
  DetonationReport,
  NetworkMode,
} from './types.js';

const execFile = promisify(execFileCb);

// ── Defaults ────────────────────────────────────────────────────────────────

const DEFAULT_TIMEOUT_SECONDS = 120;
const DEFAULT_CAPTURE_NETWORK = true;

const MEMORY_LIMIT = '512m';
const CPU_LIMIT = '1.0';
const CONTAINER_PREFIX = 'scanboy-det';

// Paths inside the container
const CONTAINER_SAMPLE_DIR = '/opt/scanboy';
const CONTAINER_SAMPLE_PATH = '/opt/scanboy/sample';
const CONTAINER_STRACE_LOG = '/tmp/scanboy-logs/strace.log';
const CONTAINER_INOTIFY_LOG = '/tmp/scanboy-logs/inotify.log';
const CONTAINER_TCPDUMP_LOG = '/tmp/scanboy-logs/tcpdump.log';
const MAX_SAMPLE_SIZE = 256 * 1024 * 1024; // 256 MB

// ── Docker CLI helpers ──────────────────────────────────────────────────────

interface ExecResult {
  readonly stdout: string;
  readonly stderr: string;
}

/**
 * Run a docker CLI command. Returns stdout/stderr.
 * Throws on non-zero exit or timeout.
 */
async function docker(
  args: readonly string[],
  timeoutMs: number = 60_000,
): Promise<ExecResult> {
  const { stdout, stderr } = await execFile('docker', args as string[], {
    timeout: timeoutMs,
    maxBuffer: 100 * 1024 * 1024, // 100 MB
  });
  return { stdout: stdout ?? '', stderr: stderr ?? '' };
}

/**
 * Run a docker command, ignoring errors (best-effort).
 */
async function dockerSafe(
  args: readonly string[],
  timeoutMs: number = 30_000,
): Promise<ExecResult> {
  try {
    return await docker(args, timeoutMs);
  } catch {
    return { stdout: '', stderr: '' };
  }
}

/**
 * Run `docker exec` inside a container. Returns stdout.
 */
async function dockerExec(
  containerId: string,
  command: string,
  timeoutMs: number = 30_000,
  user: string = 'root',
): Promise<string> {
  try {
    const { stdout, stderr } = await docker(
      ['exec', '-u', user, containerId, '/bin/sh', '-c', command],
      timeoutMs,
    );
    if (stderr) {
      console.error(`[dockerExec stderr] ${command.slice(0, 80)}: ${stderr.slice(0, 200)}`);
    }
    return stdout;
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`[dockerExec FAILED] ${command.slice(0, 80)}: ${msg.slice(0, 300)}`);
    return '';
  }
}

// ── File type detection ─────────────────────────────────────────────────────

type SampleType = 'pe' | 'elf' | 'script_python' | 'script_shell' | 'script_node' | 'archive' | 'container_image' | 'unknown';

interface SampleClassification {
  readonly type: SampleType;
  readonly label: string;
}

/**
 * Detect the sample type using the `file` command inside the container.
 */
async function classifySample(
  containerId: string,
  samplePath: string,
  originalFilename: string,
): Promise<SampleClassification> {
  const fileOutput = await dockerExec(
    containerId,
    `file -b "${samplePath}" 2>/dev/null || echo "unknown"`,
  );
  const lower = fileOutput.toLowerCase().trim();
  const extLower = originalFilename.toLowerCase();

  // PE (Windows) executable / DLL
  if (lower.includes('pe32') || lower.includes('pe64') || lower.includes('ms-dos executable')) {
    return { type: 'pe', label: 'Windows PE' };
  }
  if (extLower.endsWith('.exe') || extLower.endsWith('.dll') || extLower.endsWith('.scr')) {
    return { type: 'pe', label: 'Windows PE (by extension)' };
  }

  // ELF binary
  if (lower.includes('elf')) {
    return { type: 'elf', label: 'Linux ELF' };
  }

  // Python script
  if (lower.includes('python') || extLower.endsWith('.py') || extLower.endsWith('.pyw')) {
    return { type: 'script_python', label: 'Python script' };
  }

  // Shell script
  if (lower.includes('shell script') || lower.includes('bash') || lower.includes('sh script') ||
      extLower.endsWith('.sh') || extLower.endsWith('.bash')) {
    return { type: 'script_shell', label: 'Shell script' };
  }

  // Node/JS
  if (extLower.endsWith('.js') || extLower.endsWith('.mjs')) {
    return { type: 'script_node', label: 'JavaScript' };
  }

  // Container image (Docker/OCI tar) — detect by manifest.json inside the tar
  if (lower.includes('tar') || extLower.endsWith('.tar')) {
    try {
      const listOut = await dockerExec(containerId, `tar tf "${samplePath}" 2>/dev/null | head -20`, 5_000, 'root');
      if (listOut.includes('manifest.json') || listOut.includes('layer.tar') || listOut.includes('repositories')) {
        return { type: 'container_image', label: 'Container Image' };
      }
    } catch { /* not a container image */ }
  }

  // Archive
  if (lower.includes('zip') || lower.includes('gzip') || lower.includes('tar') ||
      lower.includes('7-zip') || lower.includes('rar') ||
      extLower.endsWith('.zip') || extLower.endsWith('.tar.gz') || extLower.endsWith('.7z') ||
      extLower.endsWith('.rar') || extLower.endsWith('.tgz')) {
    return { type: 'archive', label: 'Archive' };
  }

  return { type: 'unknown', label: `Unknown (${fileOutput.trim().slice(0, 80)})` };
}

/**
 * Build the execution command for a given sample type.
 */
function buildExecutionCommand(
  sampleType: SampleType,
  samplePath: string,
): string {
  switch (sampleType) {
    case 'pe':
      return `wine "${samplePath}" 2>&1 || wine64 "${samplePath}" 2>&1 || echo "wine execution failed"`;
    case 'elf':
      return `chmod +x "${samplePath}" && "${samplePath}" 2>&1`;
    case 'script_python':
      return `python3 "${samplePath}" 2>&1`;
    case 'script_shell':
      return `/bin/bash "${samplePath}" 2>&1`;
    case 'script_node':
      return `node "${samplePath}" 2>&1 || python3 "${samplePath}" 2>&1`;
    case 'archive':
      return [
        `mkdir -p /tmp/scanboy-extracted`,
        // Try extraction without password first, then common malware passwords
        `EXTRACTED=0`,
        `for PASS in "" "infected" "malware" "virus" "dangerous" "password" "123456" "test"; do`,
        `  if [ "$EXTRACTED" = "0" ]; then`,
        `    if [ -z "$PASS" ]; then`,
        `      unzip -o "${samplePath}" -d /tmp/scanboy-extracted 2>/dev/null && EXTRACTED=1`,
        `      [ "$EXTRACTED" = "0" ] && 7z x -o/tmp/scanboy-extracted -y "${samplePath}" 2>/dev/null && EXTRACTED=1`,
        `      [ "$EXTRACTED" = "0" ] && tar xzf "${samplePath}" -C /tmp/scanboy-extracted 2>/dev/null && EXTRACTED=1`,
        `      [ "$EXTRACTED" = "0" ] && tar xf "${samplePath}" -C /tmp/scanboy-extracted 2>/dev/null && EXTRACTED=1`,
        `    else`,
        `      unzip -o -P "$PASS" "${samplePath}" -d /tmp/scanboy-extracted 2>/dev/null && EXTRACTED=1`,
        `      [ "$EXTRACTED" = "0" ] && 7z x -o/tmp/scanboy-extracted -y -p"$PASS" "${samplePath}" 2>/dev/null && EXTRACTED=1`,
        `    fi`,
        `  fi`,
        `done`,
        `[ "$EXTRACTED" = "0" ] && echo "extraction failed - possibly password protected"`,
        // List what we extracted
        `echo "=== EXTRACTED FILES ==="`,
        `find /tmp/scanboy-extracted -type f -exec file {} \\;`,
        // Find executables: PE files, ELF, scripts, DLLs, anything with exec perms
        `EXEC_TARGET=""`,
        // Priority 1: PE executables (.exe, .dll, .scr, .msi)
        `[ -z "$EXEC_TARGET" ] && EXEC_TARGET=$(find /tmp/scanboy-extracted -type f \\( -iname "*.exe" -o -iname "*.dll" -o -iname "*.scr" -o -iname "*.msi" \\) | head -1)`,
        // Priority 2: ELF binaries (by file magic)
        `[ -z "$EXEC_TARGET" ] && EXEC_TARGET=$(find /tmp/scanboy-extracted -type f -print0 | while IFS= read -r -d '' f; do file -b "$f" 2>/dev/null | grep -qi "elf" && echo "$f" && break; done)`,
        // Priority 3: Scripts
        `[ -z "$EXEC_TARGET" ] && EXEC_TARGET=$(find /tmp/scanboy-extracted -type f \\( -iname "*.sh" -o -iname "*.py" -o -iname "*.ps1" -o -iname "*.bat" -o -iname "*.vbs" -o -iname "*.js" \\) | head -1)`,
        // Priority 4: Any file with PE magic
        `[ -z "$EXEC_TARGET" ] && EXEC_TARGET=$(find /tmp/scanboy-extracted -type f -print0 | while IFS= read -r -d '' f; do file -b "$f" 2>/dev/null | grep -qi "PE32\\|MS-DOS" && echo "$f" && break; done)`,
        // Priority 5: Any executable-permission file
        `[ -z "$EXEC_TARGET" ] && EXEC_TARGET=$(find /tmp/scanboy-extracted -type f -perm /111 | head -1)`,
        // Priority 6: Largest file (likely the payload)
        `[ -z "$EXEC_TARGET" ] && EXEC_TARGET=$(find /tmp/scanboy-extracted -type f -printf '%s %p\\n' 2>/dev/null | sort -rn | head -1 | awk '{print $2}')`,
        `echo "=== EXEC_TARGET: $EXEC_TARGET ==="`,
        `if [ -n "$EXEC_TARGET" ]; then`,
        `  chmod +x "$EXEC_TARGET" 2>/dev/null`,
        `  file_type=$(file -b "$EXEC_TARGET" 2>/dev/null)`,
        `  echo "=== FILE TYPE: $file_type ==="`,
        `  case "$file_type" in`,
        `    *ELF*) "$EXEC_TARGET" 2>&1 ;;`,
        `    *PE32*|*PE64*|*MS-DOS*) wine "$EXEC_TARGET" 2>&1 || wine64 "$EXEC_TARGET" 2>&1 || echo "wine failed" ;;`,
        `    *Python*) python3 "$EXEC_TARGET" 2>&1 ;;`,
        `    *shell*|*bash*|*POSIX*) /bin/bash "$EXEC_TARGET" 2>&1 ;;`,
        `    *) chmod +x "$EXEC_TARGET" 2>/dev/null; "$EXEC_TARGET" 2>&1 || /bin/bash "$EXEC_TARGET" 2>&1 ;;`,
        `  esac`,
        `else`,
        `  echo "no executable found in archive"`,
        `  ls -laR /tmp/scanboy-extracted/`,
        `fi`,
      ].join('\n');
    case 'container_image':
      return [
        `mkdir -p /tmp/scanboy-container/rootfs`,
        `tar xf "${samplePath}" -C /tmp/scanboy-container 2>/dev/null`,
        // Extract layers using manifest.json (supports both Docker v2 and OCI formats)
        `python3 -c "
import json, os, subprocess
cdir = '/tmp/scanboy-container'
rootfs = cdir + '/rootfs'
try:
    m = json.load(open(cdir + '/manifest.json'))
    if isinstance(m, list): m = m[0]
    layers = m.get('Layers', [])
    for lp in layers:
        full = os.path.join(cdir, lp)
        if os.path.isfile(full):
            subprocess.run(['tar', 'xf', full, '-C', rootfs], capture_output=True, timeout=30)
            print(f'Extracted: {lp}')
except Exception as e:
    print(f'Layer extraction error: {e}')
    # Fallback: try Docker v2 format
    import glob
    for lt in glob.glob(cdir + '/*/layer.tar'):
        subprocess.run(['tar', 'xf', lt, '-C', rootfs], capture_output=True, timeout=30)
        print(f'Extracted (v2): {lt}')
"`,
        // SBOM: list installed packages
        `echo "=== SBOM ==="`,
        `cat /tmp/scanboy-container/rootfs/etc/os-release 2>/dev/null || echo "unknown OS"`,
        // Alpine
        `[ -f /tmp/scanboy-container/rootfs/lib/apk/db/installed ] && echo "--- APK packages ---" && cat /tmp/scanboy-container/rootfs/lib/apk/db/installed 2>/dev/null | grep "^P:" | sed 's/^P://' | sort`,
        // Debian/Ubuntu
        `[ -d /tmp/scanboy-container/rootfs/var/lib/dpkg ] && echo "--- DPKG packages ---" && cat /tmp/scanboy-container/rootfs/var/lib/dpkg/status 2>/dev/null | grep "^Package:" | sed 's/^Package: //' | sort`,
        // RPM
        `[ -d /tmp/scanboy-container/rootfs/var/lib/rpm ] && echo "--- RPM packages ---" && ls /tmp/scanboy-container/rootfs/var/lib/rpm/ 2>/dev/null`,
        // Node
        `find /tmp/scanboy-container/rootfs -name "package.json" -maxdepth 5 2>/dev/null | head -10 | while read pj; do echo "--- $pj ---"; cat "$pj" 2>/dev/null | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('name','?'), d.get('version','?'))" 2>/dev/null; done`,
        // Python
        `find /tmp/scanboy-container/rootfs -name "requirements.txt" -maxdepth 5 2>/dev/null | head -5 | while read rq; do echo "--- $rq ---"; cat "$rq" 2>/dev/null; done`,
        // Secrets scan
        `echo "=== SECRETS SCAN ==="`,
        `grep -rn "password\\|secret\\|api_key\\|apikey\\|token\\|private_key\\|AWS_ACCESS\\|AKIA" /tmp/scanboy-container/rootfs/etc/ /tmp/scanboy-container/rootfs/root/ /tmp/scanboy-container/rootfs/home/ 2>/dev/null | grep -v "Binary" | head -20`,
        // Entrypoint/CMD
        `echo "=== ENTRYPOINT ==="`,
        `cat /tmp/scanboy-container/manifest.json 2>/dev/null | python3 -c "import json,sys; m=json.load(sys.stdin); print('Config:', m[0].get('Config','?')); print('Layers:', len(m[0].get('Layers',[])))" 2>/dev/null`,
        // Suspicious files
        `echo "=== SUSPICIOUS FILES ==="`,
        `find /tmp/scanboy-container/rootfs -type f \\( -name "*.sh" -o -name "*.py" -o -name "*.rb" -o -name "*.php" \\) -newer /tmp/scanboy-container/manifest.json 2>/dev/null | head -20`,
        `find /tmp/scanboy-container/rootfs -type f -perm /111 -size +100k 2>/dev/null | head -10`,
        // Setuid binaries
        `echo "=== SETUID BINARIES ==="`,
        `find /tmp/scanboy-container/rootfs -type f -perm -4000 2>/dev/null | head -10`,
        // Crypto miners / backdoors
        `echo "=== CRYPTO/BACKDOOR SCAN ==="`,
        `grep -rl "stratum\\|xmrig\\|monero\\|cryptonight\\|/bin/sh -i\\|/dev/tcp\\|reverse.*shell\\|bind.*shell" /tmp/scanboy-container/rootfs 2>/dev/null | head -10`,
      ].join('\n');
    case 'unknown':
    default:
      // Try running it; fall back to bash
      return `chmod +x "${samplePath}" 2>/dev/null; "${samplePath}" 2>&1 || /bin/bash "${samplePath}" 2>&1 || python3 "${samplePath}" 2>&1`;
  }
}

/**
 * Build the execution command for URL detonation.
 * Downloads the URL, captures headers/SSL/redirect chain, and if a file
 * is downloaded, attempts to execute it through the normal pipeline.
 */
function buildUrlDetonationCommand(targetUrl: string): string {
  // Validate URL format — reject shell metacharacters to prevent injection
  if (!/^https?:\/\/[a-zA-Z0-9\-._~:/?#\[\]@%+=,]+$/.test(targetUrl)) {
    return 'echo "ERROR: Invalid URL format — rejected for safety"';
  }
  if (/[`$!'"\\;|&<>(){}]/.test(targetUrl)) {
    return 'echo "ERROR: URL contains unsafe characters"';
  }
  const escaped = targetUrl.replace(/'/g, "'\\''");
  const lines: string[] = [
    'echo "=== URL DETONATION ==="',
    // Use a variable to avoid repeated interpolation of user input
    `TARGET_URL='${escaped}'`,
    'echo "Target: $TARGET_URL"',
    'echo ""',
    'echo "=== RESPONSE HEADERS ==="',
    `curl -sS -L -D /tmp/scanboy-logs/response-headers.txt -o /tmp/downloaded_payload --max-time 30 --max-redirs 10 "$TARGET_URL" 2>&1 || echo "curl failed"`,
    'cat /tmp/scanboy-logs/response-headers.txt 2>/dev/null || echo "no headers"',
    'echo ""',
    'echo "=== SSL CERTIFICATE ==="',
    // Extract host safely using shell parameter expansion instead of sed on user input
    'URL_HOST=$(echo "$TARGET_URL" | sed -E \'s|https?://||;s|/.*||;s|:.*||\')',
    'echo | openssl s_client -connect "$URL_HOST:443" 2>/dev/null | openssl x509 -noout -text 2>/dev/null | head -30 || echo "no SSL cert"',
    'echo ""',
    'echo "=== DOWNLOADED CONTENT ==="',
    'if [ -f /tmp/downloaded_payload ]; then',
    '  file_type=$(file -b /tmp/downloaded_payload 2>/dev/null || echo "unknown")',
    '  file_size=$(stat -c%s /tmp/downloaded_payload 2>/dev/null || echo "0")',
    '  echo "Type: $file_type"',
    '  echo "Size: $file_size bytes"',
    '  if echo "$file_type" | grep -qi "HTML\\|text"; then',
    '    echo "=== HTML ANALYSIS ==="',
    '    grep -ioE "(iframe|script|eval|document.write|window.location|unescape|fromCharCode|ActiveXObject|WScript|powershell|cmd.exe)" /tmp/downloaded_payload 2>/dev/null | sort | uniq -c | sort -rn || echo "clean"',
    '  fi',
    '  case "$file_type" in',
    '    *ELF*) chmod +x /tmp/downloaded_payload && /tmp/downloaded_payload 2>&1 ;;',
    '    *PE32*|*PE64*|*MS-DOS*) wine /tmp/downloaded_payload 2>&1 || echo "wine failed" ;;',
    '    *Zip*|*gzip*|*7-zip*) mkdir -p /tmp/scanboy-extracted && unzip -o /tmp/downloaded_payload -d /tmp/scanboy-extracted 2>/dev/null || echo "extract failed" ;;',
    '    *Python*) python3 /tmp/downloaded_payload 2>&1 ;;',
    '    *shell*|*bash*) /bin/bash /tmp/downloaded_payload 2>&1 ;;',
    '    *) echo "not directly executable" ;;',
    '  esac',
    'else',
    '  echo "no content downloaded"',
    'fi',
  ];
  return lines.join('\n');
}

// ── DockerSandboxExecutor ───────────────────────────────────────────────────

export class DockerSandboxExecutor {
  private imageReadyPromise: Promise<string> | null = null;

  /**
   * Execute a malware sample inside a disposable Docker container and
   * return a structured behavioral detonation report.
   *
   * @param submissionId - Unique ID for this submission.
   * @param fileBuffer   - Raw file bytes of the sample.
   * @param filename     - Original filename (used for type detection).
   * @param options      - Optional execution parameters.
   * @returns A comprehensive DetonationReport.
   */
  async execute(
    submissionId: string,
    fileBuffer: Buffer,
    filename: string,
    options?: ExecutionOptions,
  ): Promise<DetonationReport> {
    // Defense-in-depth: validate submissionId before using it in container names
    // and filesystem paths. Should already be validated by the API layer.
    if (!/^[a-f0-9\-]{36}$/.test(submissionId)) {
      throw new Error('Invalid submissionId format');
    }

    // Sanitize filename: strip path separators, null bytes, and shell metacharacters.
    // The filename is only used for extension-based type detection so we only need
    // the basename with safe characters.
    const safeFilename = filename
      .replace(/[\x00-\x1f\x7f]/g, '')                       // strip control chars including DEL
      .replace(/[/\\`$'";&|<>(){}!#~*?\[\]\n\r]/g, '_')     // strip all shell metacharacters
      .slice(-255)                                             // limit length
      || 'unknown';                                            // fallback for empty/degenerate names

    if (fileBuffer.length > MAX_SAMPLE_SIZE) {
      throw new Error(`Sample exceeds maximum size of ${MAX_SAMPLE_SIZE} bytes`);
    }

    const opts = resolveOptions(options);

    // a. Create a temp directory and write the sample to it
    const tmpDir = await mkdtemp(join(tmpdir(), `scanboy-det-${submissionId.slice(0, 8)}-`));
    const hostSamplePath = join(tmpDir, 'sample');
    await writeFile(hostSamplePath, fileBuffer);

    // Also create a log directory on host
    const hostLogDir = join(tmpDir, 'logs');
    await mkdir(hostLogDir, { recursive: true });

    // b. Ensure the sandbox image exists
    if (!this.imageReadyPromise) {
      this.imageReadyPromise = ensureSandboxImage();
    }
    await this.imageReadyPromise;

    const containerName = `${CONTAINER_PREFIX}-${submissionId.slice(0, 12)}-${Date.now()}`;
    let containerId = '';

    try {
      // c. Start the container with security constraints
      containerId = await this.startContainer(containerName, opts);

      // d. Copy sample into the container via stdin pipe (docker cp doesn't work with tmpfs overlays)
      await docker(['exec', '-u', 'root', containerId, 'sh', '-c', `mkdir -p ${CONTAINER_SAMPLE_DIR} /tmp/scanboy-logs /tmp/scanboy-extracted /tmp/scanboy-container /tmp/scanboy-container/rootfs && chmod 777 ${CONTAINER_SAMPLE_DIR} /tmp/scanboy-logs /tmp/scanboy-extracted /tmp/scanboy-container /tmp/scanboy-container/rootfs`]);
      // Use child_process.spawn to pipe file data via stdin to avoid shell arg length limits
      const { execFileSync } = await import('node:child_process');
      const { readFileSync } = await import('node:fs');
      const sampleBytes = readFileSync(hostSamplePath);
      execFileSync('docker', ['exec', '-i', '-u', 'root', containerId, 'sh', '-c', `cat > ${CONTAINER_SAMPLE_PATH} && chmod 777 ${CONTAINER_SAMPLE_PATH}`], { input: sampleBytes, timeout: 60_000, maxBuffer: 100 * 1024 * 1024 });

      // Classify the sample (use sanitized filename for type detection)
      const classification = await classifySample(containerId, CONTAINER_SAMPLE_PATH, safeFilename);
      console.error(`[SANDBOX] Classification: ${JSON.stringify(classification)}`);

      // e. Snapshot wine registry BEFORE execution for diffing
      let wineRegBefore = '';
      try {
        wineRegBefore = await dockerExec(containerId, `cat /home/sandbox/.wine/system.reg 2>/dev/null; echo "===SCANBOY_REG_SEP==="; cat /home/sandbox/.wine/user.reg 2>/dev/null`, 10_000, 'sandbox');
      } catch { /* wine registry may not exist */ }

      // f. Start monitoring processes
      await this.startMonitoring(containerId, opts);

      // g. Execute the sample (or detonate URL)
      let execCommand: string;
      let sampleLabel: string;

      if (opts.targetUrl) {
        // URL detonation mode
        execCommand = buildUrlDetonationCommand(opts.targetUrl);
        sampleLabel = 'URL detonation';
        console.error(`[SANDBOX] URL detonation: ${opts.targetUrl}`);
      } else {
        execCommand = buildExecutionCommand(classification.type, CONTAINER_SAMPLE_PATH);
        sampleLabel = classification.label;
      }
      console.error(`[SANDBOX] Exec command (first 200 chars): ${execCommand.slice(0, 200)}`);
      const execInfo = await this.executeSample(
        containerId,
        execCommand,
        opts.timeoutSeconds,
        sampleLabel,
      );

      // h. Strace integrity check — detect if the sample killed/escaped strace
      let straceIntegrityOk = true;
      try {
        const straceCheck = await dockerExec(
          containerId,
          `pgrep -c strace 2>/dev/null || echo "0"`,
          5_000,
        );
        const straceAlive = parseInt(straceCheck.trim(), 10) > 0;
        const straceSize = await dockerExec(
          containerId,
          `stat -c%s ${CONTAINER_STRACE_LOG} 2>/dev/null || echo "0"`,
          5_000,
        );
        const logBytes = parseInt(straceSize.trim(), 10);
        if (!straceAlive && logBytes < 50 && !execInfo.timedOut) {
          straceIntegrityOk = false;
          console.error('[SANDBOX] WARNING: strace appears to have been killed — behavioral data may be incomplete');
        }
      } catch {
        // Best-effort check; don't fail the analysis
      }

      // h2. Dump strings from process memory (best-effort, before processes exit)
      const memoryStrings = await this.collectMemoryStrings(containerId);

      // i. Collect monitoring output
      const monitorData = await this.collectMonitoringOutput(containerId);

      // g2b. Container SBOM extraction (only for container images)
      // Uses syft (CycloneDX 1.6 generator) + Python security scan
      let containerSbom: Record<string, unknown> | null = null;
      if (classification.type === 'container_image') {
        // Step 1: Generate CycloneDX SBOM with syft
        try {
          const syftOut = await dockerExec(containerId,
            `syft "${CONTAINER_SAMPLE_PATH}" -o cyclonedx-json 2>/dev/null | head -c 5000000`,
            60_000, 'sandbox');
          if (syftOut.trim().startsWith('{')) {
            const cyclonedx = JSON.parse(syftOut) as Record<string, unknown>;
            const meta = cyclonedx['metadata'] as Record<string, unknown> | undefined;
            if (meta?.['component']) {
              const comp = meta['component'] as Record<string, unknown>;
              comp['name'] = safeFilename;
            }
            const components = (cyclonedx['components'] ?? []) as Array<Record<string, unknown>>;
            console.error(`[SANDBOX] CycloneDX SBOM: ${components.length} components`);
            // Convert to our format
            containerSbom = {
              os: null,
              packages: components.map(c => ({
                name: String(c['name'] ?? ''),
                version: String(c['version'] ?? ''),
                type: String(c['type'] ?? 'library'),
                purl: String(c['purl'] ?? ''),
              })),
              secrets: [], setuid: [], suspicious: [], supplyChain: [],
              forgedKeys: [], unofficialSources: [], unsignedPackages: false,
              layers: 0, manifest: null,
              cyclonedx,
            };
          }
        } catch (syftErr) {
          console.error(`[SANDBOX] syft SBOM failed: ${syftErr instanceof Error ? syftErr.message : String(syftErr)}`);
        }

        // Step 2: Full container security scan via Python
        try {
          const { readFileSync: csReadFs } = await import('node:fs');
          const csPath = await import('node:path');
          let sbomScript = '';
          for (const p of [
            csPath.join(__dirname, '..', 'src', 'container-security-scan.py'),
            csPath.join(__dirname, 'container-security-scan.py'),
            csPath.join(process.cwd(), 'packages', 'dynamic-analysis', 'src', 'container-security-scan.py'),
          ]) { try { sbomScript = csReadFs(p, 'utf-8'); break; } catch { /* next */ } }
          if (!sbomScript) sbomScript = 'import json; print(json.dumps({"os":null,"packages":[],"secrets":[],"setuid":[],"suspicious":[],"layers":0}))';
          void `

def _is_priv(ip_str):
    if ip_str.startswith(("127.", "10.", "192.168.", "0.")):
        return True
    if ip_str.startswith("172."):
        parts = ip_str.split(".")
        if len(parts) >= 2:
            try:
                s = int(parts[1])
                if 16 <= s <= 31:
                    return True
            except ValueError:
                pass
    return False

rootfs = "/tmp/scanboy-container/rootfs"
container_dir = "/tmp/scanboy-container"

# Manifest
try:
    with open(os.path.join(container_dir, "manifest.json")) as f:
        result["manifest"] = json.load(f)
        if isinstance(result["manifest"], list) and result["manifest"]:
            result["layers"] = len(result["manifest"][0].get("Layers", []))
except: pass

# OS detection
for p in [os.path.join(rootfs, "etc/os-release"), os.path.join(rootfs, "etc/alpine-release")]:
    try:
        with open(p) as f:
            result["os"] = f.read().strip()[:200]
            break
    except: pass

# APK packages (Alpine)
apk_db = os.path.join(rootfs, "lib/apk/db/installed")
if os.path.isfile(apk_db):
    with open(apk_db) as f:
        name, ver = None, None
        for line in f:
            if line.startswith("P:"): name = line[2:].strip()
            elif line.startswith("V:"): ver = line[2:].strip()
            elif line.strip() == "" and name:
                result["packages"].append({"name": name, "version": ver or "?", "type": "apk"})
                name, ver = None, None

# DPKG packages (Debian/Ubuntu)
dpkg_status = os.path.join(rootfs, "var/lib/dpkg/status")
if os.path.isfile(dpkg_status):
    with open(dpkg_status) as f:
        name, ver = None, None
        for line in f:
            if line.startswith("Package: "): name = line.split(": ",1)[1].strip()
            elif line.startswith("Version: "): ver = line.split(": ",1)[1].strip()
            elif line.strip() == "" and name:
                result["packages"].append({"name": name, "version": ver or "?", "type": "dpkg"})
                name, ver = None, None

# Secrets scan
for search_dir in [os.path.join(rootfs, d) for d in ["etc", "root", "home", "app", "opt"]]:
    if not os.path.isdir(search_dir): continue
    for dirpath, _, filenames in os.walk(search_dir):
        for fn in filenames[:100]:
            fp = os.path.join(dirpath, fn)
            try:
                with open(fp, errors="ignore") as fh:
                    content = fh.read(10000)
                    for pattern in [r"password\\s*[=:]\\s*\\S+", r"api[_-]?key\\s*[=:]\\s*\\S+", r"AKIA[A-Z0-9]{16}", r"-----BEGIN (?:RSA |EC )?PRIVATE KEY"]:
                        for m in re.finditer(pattern, content, re.IGNORECASE):
                            result["secrets"].append({"file": fp.replace(rootfs, ""), "match": m.group()[:100]})
            except: pass

# Setuid binaries
for dirpath, _, filenames in os.walk(rootfs):
    for fn in filenames[:500]:
        fp = os.path.join(dirpath, fn)
        try:
            st = os.stat(fp)
            if st.st_mode & 0o4000:
                result["setuid"].append(fp.replace(rootfs, ""))
        except: pass

# Suspicious patterns
for dirpath, _, filenames in os.walk(rootfs):
    for fn in filenames[:500]:
        fp = os.path.join(dirpath, fn)
        try:
            with open(fp, "rb") as fh:
                head = fh.read(1000)
                if b"stratum" in head or b"xmrig" in head or b"cryptonight" in head:
                    result["suspicious"].append({"file": fp.replace(rootfs, ""), "type": "crypto_miner"})
                elif b"/dev/tcp" in head or b"reverse" in head.lower() and b"shell" in head.lower():
                    result["suspicious"].append({"file": fp.replace(rootfs, ""), "type": "backdoor"})
        except: pass

# Supply chain: unsigned packages / forged keys / unofficial sources
# APK key verification
apk_keys_dir = os.path.join(rootfs, "etc/apk/keys")
if os.path.isdir(apk_keys_dir):
    official_key_prefixes = ["alpine-devel@lists.alpinelinux.org"]
    for kf in os.listdir(apk_keys_dir):
        if not any(kf.startswith(p) for p in official_key_prefixes):
            result["forgedKeys"].append({"type": "apk", "file": f"/etc/apk/keys/{kf}", "reason": "non-official APK signing key"})
# APK repos
apk_repos = os.path.join(rootfs, "etc/apk/repositories")
if os.path.isfile(apk_repos):
    with open(apk_repos) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                if "dl-cdn.alpinelinux.org" not in line and "alpine" not in line.lower():
                    result["unofficialSources"].append({"type": "apk", "source": line})

# DPKG/APT key verification
apt_keys = os.path.join(rootfs, "etc/apt/trusted.gpg.d")
apt_sources = os.path.join(rootfs, "etc/apt/sources.list")
apt_sources_d = os.path.join(rootfs, "etc/apt/sources.list.d")
if os.path.isdir(apt_keys):
    for kf in os.listdir(apt_keys):
        fp = os.path.join(apt_keys, kf)
        try:
            with open(fp, "rb") as f:
                header = f.read(4)
                if header[:2] not in [b"\\x99\\x01", b"\\x99\\x02", b"\\xc6", b"-----"[:2]]:
                    result["forgedKeys"].append({"type": "apt-gpg", "file": f"/etc/apt/trusted.gpg.d/{kf}", "reason": "invalid GPG key format"})
        except: pass
if os.path.isfile(apt_sources):
    with open(apt_sources) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                official_hosts = ["deb.debian.org", "archive.ubuntu.com", "security.debian.org", "security.ubuntu.com", "ports.ubuntu.com"]
                if not any(h in line for h in official_hosts):
                    result["unofficialSources"].append({"type": "apt", "source": line})
if os.path.isdir(apt_sources_d):
    for sf in os.listdir(apt_sources_d):
        fp = os.path.join(apt_sources_d, sf)
        try:
            with open(fp) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "deb " in line:
                        result["unofficialSources"].append({"type": "apt-extra", "source": line, "file": sf})
        except: pass

# RPM key verification
rpm_keys = os.path.join(rootfs, "etc/pki/rpm-gpg")
if os.path.isdir(rpm_keys):
    for kf in os.listdir(rpm_keys):
        if not kf.startswith("RPM-GPG-KEY-"):
            result["forgedKeys"].append({"type": "rpm", "file": f"/etc/pki/rpm-gpg/{kf}", "reason": "non-standard RPM signing key"})

# Check for unsigned package installs (--no-check-certificate, --allow-unauthenticated)
for dirpath, _, filenames in os.walk(rootfs):
    for fn in filenames[:200]:
        if fn.endswith((".sh", ".bash", "Dockerfile", ".yml", ".yaml")):
            fp = os.path.join(dirpath, fn)
            try:
                with open(fp, errors="ignore") as f:
                    content = f.read(5000)
                    if "--no-check-certificate" in content or "--allow-unauthenticated" in content or "--force-yes" in content or "pip install --trusted-host" in content:
                        result["unsignedPackages"] = True
                        result["supplyChain"].append({"file": fp.replace(rootfs, ""), "issue": "unsigned/unverified package install", "evidence": [m for m in ["--no-check-certificate", "--allow-unauthenticated", "--force-yes", "--trusted-host"] if m in content]})
            except: pass

# Beaconing / C2 callback detection — curl/wget to external IPs or suspicious domains in scripts/entrypoint
for dirpath, _, filenames in os.walk(rootfs):
    for fn in filenames[:200]:
        if fn.endswith((".sh", ".bash", ".py", ".rb", ".php", "entrypoint", "start", "run")):
            fp = os.path.join(dirpath, fn)
            try:
                with open(fp, errors="ignore") as f:
                    content = f.read(10000)
                    # Curl/wget to IP addresses or suspicious domains
                    c2_patterns = re.findall(r'(?:curl|wget|fetch|nc|ncat|socat)\s+["\']?(?:-[a-zA-Z]*\s+)*(?:https?://)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}[^\s"\']*)', content)
                    for c2 in c2_patterns:
                        ip_part = c2.split("/")[0].split(":")[0]
                        if not _is_priv(ip_part):
                            result["suspicious"].append({"file": fp.replace(rootfs, ""), "type": "beacon", "evidence": c2[:100]})
                    # Reverse shells
                    if re.search(r'/dev/tcp/|mkfifo.*nc|bash -i.*>&.*/dev/tcp|socat.*exec|ncat.*-e', content):
                        result["suspicious"].append({"file": fp.replace(rootfs, ""), "type": "reverse_shell", "evidence": "reverse shell pattern"})
                    # Cron-based beaconing
                    if "crontab" in content or "* * * *" in content:
                        result["suspicious"].append({"file": fp.replace(rootfs, ""), "type": "cron_beacon", "evidence": "scheduled callback"})
            except: pass

# Check crontab files directly
for cron_path in ["etc/crontab", "var/spool/cron", "etc/cron.d"]:
    full_path = os.path.join(rootfs, cron_path)
    if os.path.isfile(full_path):
        try:
            with open(full_path, errors="ignore") as f:
                content = f.read(5000)
                if re.search(r'curl|wget|nc |python|perl|ruby|/dev/tcp', content):
                    result["suspicious"].append({"file": "/" + cron_path, "type": "cron_beacon", "evidence": content[:200]})
        except: pass
    elif os.path.isdir(full_path):
        for cf in os.listdir(full_path)[:20]:
            cfp = os.path.join(full_path, cf)
            try:
                with open(cfp, errors="ignore") as f:
                    content = f.read(5000)
                    if re.search(r'curl|wget|nc |python|perl|ruby|/dev/tcp', content):
                        result["suspicious"].append({"file": f"/{cron_path}/{cf}", "type": "cron_beacon", "evidence": content[:200]})
            except: pass

# npm/pip dependency confusion check — look for internal/private package names in package.json
for dirpath, _, filenames in os.walk(rootfs):
    for fn in filenames[:100]:
        if fn == "package.json":
            fp = os.path.join(dirpath, fn)
            try:
                import json as j2
                with open(fp) as f:
                    pj = j2.load(f)
                    deps = {**pj.get("dependencies", {}), **pj.get("devDependencies", {})}
                    for dep_name in deps:
                        if dep_name.startswith("@") and "/" in dep_name:
                            scope = dep_name.split("/")[0]
                            if scope not in ["@types", "@babel", "@vue", "@angular", "@react", "@next", "@emotion", "@mui", "@testing-library", "@jest"]:
                                result["supplyChain"].append({"file": fp.replace(rootfs, ""), "issue": "scoped npm package (verify ownership)", "package": dep_name})
            except: pass

# P0-1: Symlink/hardlink escape vector detection in tar layers
result["symlinkEscapes"] = []
container_dir = "/tmp/scanboy-container"
import tarfile as tf
try:
    manifest_path = os.path.join(container_dir, "manifest.json")
    if os.path.isfile(manifest_path):
        import json as j3
        with open(manifest_path) as mf:
            manifest = j3.load(mf)
        if isinstance(manifest, list) and manifest:
            layers = manifest[0].get("Layers", [])
            result["layers"] = len(layers)

            # P0-2: Trojan layer detection — track file hashes across layers
            result["trojanLayers"] = []
            file_versions = {}  # path -> [(layer_idx, size)]

            for idx, layer_rel in enumerate(layers):
                layer_path = os.path.join(container_dir, layer_rel)
                if not os.path.isfile(layer_path):
                    continue
                try:
                    with tf.open(layer_path) as ltf:
                        for member in ltf.getmembers():
                            # P0-3: Symlink escape detection
                            if member.issym():
                                target = member.linkname
                                if target.startswith("/proc/self") or target.startswith("/proc/1"):
                                    result["symlinkEscapes"].append({"path": member.name, "target": target, "type": "proc_escape", "layer": idx})
                                elif "../../../" in os.path.normpath(os.path.join(os.path.dirname(member.name), target)):
                                    result["symlinkEscapes"].append({"path": member.name, "target": target, "type": "traversal", "layer": idx})
                            if member.islnk() and member.linkname.startswith(".."):
                                result["symlinkEscapes"].append({"path": member.name, "target": member.linkname, "type": "hardlink_traversal", "layer": idx})

                            # Track file versions for trojan detection
                            if member.isfile() and member.name.startswith(("usr/bin/", "usr/sbin/", "usr/local/bin/", "bin/", "sbin/")):
                                if member.name not in file_versions:
                                    file_versions[member.name] = []
                                file_versions[member.name].append((idx, member.size))
                except Exception:
                    pass

            # P0-2: Flag binaries that appear in multiple layers with different sizes (possible trojan)
            for path, versions in file_versions.items():
                if len(versions) > 1:
                    sizes = [v[1] for v in versions]
                    if len(set(sizes)) > 1:
                        result["trojanLayers"].append({
                            "path": path,
                            "versions": [{"layer": v[0], "size": v[1]} for v in versions],
                            "reason": "binary modified across layers"
                        })
except Exception:
    pass

result["packages"] = result["packages"][:500]
result["secrets"] = result["secrets"][:50]
result["setuid"] = result["setuid"][:50]
result["suspicious"] = result["suspicious"][:50]
result["supplyChain"] = result["supplyChain"][:50]
result["forgedKeys"] = result["forgedKeys"][:20]
result["unofficialSources"] = result["unofficialSources"][:20]
result["symlinkEscapes"] = result["symlinkEscapes"][:20]
result["trojanLayers"] = result["trojanLayers"][:20]
print(json.dumps(result))
`;
          const { execFileSync: sbomExecFs } = await import('node:child_process');
          sbomExecFs('docker', ['exec', '-i', '-u', 'sandbox', containerId, 'sh', '-c', 'cat > /tmp/scanboy-sbom.py'], {
            input: Buffer.from(sbomScript), timeout: 10_000, maxBuffer: 1024 * 1024,
          });
          const sbomOut = await dockerExec(containerId, 'python3 /tmp/scanboy-sbom.py', 30_000, 'sandbox');
          const securityScan = JSON.parse(sbomOut.trim()) as Record<string, unknown>;
          // Merge ALL security scan fields into containerSbom
          if (containerSbom) {
            for (const [key, val] of Object.entries(securityScan)) {
              if (key !== 'packages' && key !== 'cyclonedx') {
                containerSbom[key] = val;
              }
            }
          } else {
            containerSbom = securityScan;
          }
          console.error(`[SANDBOX] Container security scan: ${(containerSbom['secrets'] as unknown[])?.length ?? 0} secrets, ${(containerSbom['forgedKeys'] as unknown[])?.length ?? 0} forged keys, ${(containerSbom['suspicious'] as unknown[])?.length ?? 0} suspicious`);
        } catch (sbomErr) {
          console.error(`[SANDBOX] Security scan failed: ${sbomErr instanceof Error ? sbomErr.message : String(sbomErr)}`);
        }
      }

      // g3. Full static analysis inside the jail on extracted executables
      let jailAnalysis = '';
      try {
        // Write a Python analysis script into the container
        const analysisScript = `
import json, math, sys, os, struct, hashlib, subprocess, re, datetime

def _is_priv(ip_str):
    if ip_str.startswith(("127.", "10.", "192.168.", "0.")):
        return True
    if ip_str.startswith("172."):
        parts = ip_str.split(".")
        if len(parts) >= 2:
            try:
                s = int(parts[1])
                if 16 <= s <= 31:
                    return True
            except ValueError:
                pass
    return False

def entropy(data):
    if not data: return 0
    freq = [0]*256
    for b in data: freq[b] += 1
    length = len(data)
    return -sum((c/length)*math.log2(c/length) for c in freq if c > 0)

def compute_imphash(data):
    """Compute import hash for PE files by hashing sorted DLL+function pairs."""
    if len(data) < 64 or data[:2] != b'MZ':
        return None
    try:
        pe_offset = struct.unpack_from('<I', data, 60)[0]
        if pe_offset + 4 > len(data) or data[pe_offset:pe_offset+4] != b'PE\\x00\\x00':
            return None
        # Parse PE header to find import directory
        is_pe32plus = struct.unpack_from('<H', data, pe_offset+24)[0] == 0x20b
        opt_offset = pe_offset + 24
        if is_pe32plus:
            import_dir_rva_offset = opt_offset + 120
        else:
            import_dir_rva_offset = opt_offset + 104
        if import_dir_rva_offset + 8 > len(data):
            return None
        import_rva = struct.unpack_from('<I', data, import_dir_rva_offset)[0]
        import_size = struct.unpack_from('<I', data, import_dir_rva_offset + 4)[0]
        if import_rva == 0 or import_size == 0:
            return None
        # Fall back to string scanning for DLL+function names
        text = data.decode('ascii', errors='ignore')
        dlls = re.findall(r'([A-Za-z][A-Za-z0-9_]*\\.dll)', text, re.IGNORECASE)
        if not dlls:
            return None
        entries = sorted(set(d.lower() for d in dlls))
        return hashlib.md5(','.join(entries).encode()).hexdigest()
    except:
        return None

def extract_compile_timestamp(data):
    """Extract PE compile timestamp from the TimeDateStamp field."""
    if len(data) < 64 or data[:2] != b'MZ':
        return None
    try:
        pe_offset = struct.unpack_from('<I', data, 60)[0]
        if pe_offset + 8 > len(data) or data[pe_offset:pe_offset+4] != b'PE\\x00\\x00':
            return None
        timestamp = struct.unpack_from('<I', data, pe_offset + 8)[0]
        if timestamp == 0 or timestamp > 2000000000:
            return None
        dt = datetime.datetime.utcfromtimestamp(timestamp)
        return {'unix': timestamp, 'utc': dt.strftime('%Y-%m-%d %H:%M:%S UTC')}
    except:
        return None

def extract_pdb_path(data):
    """Scan for .pdb debug paths in the binary."""
    try:
        text = data.decode('ascii', errors='ignore')
        pdb_matches = re.findall(r'[A-Za-z]:\\\\[^\\x00]{3,200}\\.pdb', text)
        if not pdb_matches:
            pdb_matches = re.findall(r'[A-Za-z]:[^\\x00]{3,200}\\.pdb', text)
        return list(set(pdb_matches))[:5]
    except:
        return []

def extract_emails(raw_strings):
    """Extract email addresses from strings."""
    try:
        emails = re.findall(r'[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}', raw_strings)
        # Filter out common false positives
        filtered = [e for e in emails if not e.endswith('.dll') and not e.endswith('.sys') and len(e) < 100]
        return list(set(filtered))[:30]
    except:
        return []

def extract_domains(raw_strings):
    """Extract domain names from strings that look like valid domains."""
    valid_tlds = {'com','net','org','io','info','biz','co','ru','cn','de','uk','fr',
                  'jp','br','it','nl','au','ca','ch','se','no','fi','es','pt','pl',
                  'cz','at','be','dk','ie','kr','in','tw','xyz','top','cc','pw','tk',
                  'ml','ga','cf','gq','onion','bit','i2p','su','to','me','tv','ws'}
    try:
        candidates = re.findall(r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,}', raw_strings)
        domains = []
        for c in candidates:
            tld = c.split('.')[-1].lower()
            # SLD >= 3 chars: single-char SLDs (h.pw, x.ws) are version strings, not real domains
            sld = c.split('.')[-2] if len(c.split('.')) >= 2 else ''
            if tld in valid_tlds and len(c) < 100 and len(sld) >= 3 and not c.endswith('.dll') and not c.endswith('.exe') and not c.endswith('.sys'):
                domains.append(c.lower())
        return list(set(domains))[:50]
    except:
        return []

def extract_registry_keys(raw_strings):
    """Scan for Windows registry key paths."""
    try:
        patterns = re.findall(r'(HK(?:LM|CU|CR|U|CC)\\\\[^\\x00\\n\\r]{3,200})', raw_strings)
        if not patterns:
            patterns = re.findall(r'(HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)\\\\[^\\x00\\n\\r]{3,200})', raw_strings)
        return list(set(p.strip()[:200] for p in patterns))[:30]
    except:
        return []

def extract_mutex_patterns(raw_strings):
    """Scan for common mutex name patterns."""
    try:
        # Common mutex patterns: Global\\\\, Local\\\\, or known mutex prefixes
        mutexes = re.findall(r'(?:Global|Local)\\\\[A-Za-z0-9_\\-{}]{3,100}', raw_strings)
        # Also look for CreateMutex-adjacent strings
        mutex_like = re.findall(r'(?:Mutex|mutex|MUTEX)[A-Za-z0-9_\\-]{2,50}', raw_strings)
        return list(set(mutexes + mutex_like))[:20]
    except:
        return []

def extract_file_paths(raw_strings):
    """Extract Windows file paths from strings."""
    try:
        # Standard drive paths
        paths = re.findall(r'[A-Za-z]:\\\\[^\\x00\\n\\r\\"]{3,200}', raw_strings)
        # Environment variable paths
        env_paths = re.findall(r'(%(?:TEMP|TMP|APPDATA|LOCALAPPDATA|PROGRAMFILES|PROGRAMDATA|SYSTEMROOT|WINDIR|USERPROFILE|PUBLIC|HOMEPATH)%[^\\x00\\n\\r\\"]{0,200})', raw_strings, re.IGNORECASE)
        all_paths = list(set(p.strip()[:200] for p in paths + env_paths))
        return all_paths[:40]
    except:
        return []

def parse_strace_output(strace_path):
    """Parse strace output to extract behavioral IOCs."""
    result = {
        'dnsConnections': [],
        'httpConnections': [],
        'externalIPs': [],
        'execCommands': []
    }
    # Sandbox resolv.conf points to 8.8.8.8/4.4.4.4
    # Filter from indicators (not real C2) but keep for PCAP generation
    sandbox_dns = {'8.8.8.8', '4.4.4.4'}
    all_dns_attempts = []  # Keep all DNS attempts for PCAP
    if not os.path.isfile(strace_path):
        return result
    try:
        with open(strace_path, 'r', errors='ignore') as f:
            for line in f:
                # Extract connect() calls
                m = re.search(r'connect\\(.*sa_family=AF_INET.*sin_port=htons\\((\\d+)\\).*sin_addr=inet_addr\\("([^"]+)"\\)', line)
                if m:
                    port = int(m.group(1))
                    ip = m.group(2)
                    all_dns_attempts.append({'ip': ip, 'port': port})
                    if ip in sandbox_dns:
                        continue
                    if port == 53:
                        result['dnsConnections'].append({'ip': ip, 'port': port})
                    elif port in (80, 8080):
                        result['httpConnections'].append({'ip': ip, 'port': port, 'protocol': 'http'})
                    elif port in (443, 8443):
                        result['httpConnections'].append({'ip': ip, 'port': port, 'protocol': 'https'})
                    # Track all external IPs
                    if not _is_priv(ip):
                        result['externalIPs'].append({'ip': ip, 'port': port})
                # Extract execve calls for process command lines
                m = re.search(r'execve\\("([^"]+)".*\\[(.*)\\]', line)
                if m:
                    exe = m.group(1)
                    args_raw = m.group(2)
                    result['execCommands'].append({'executable': exe, 'args': args_raw[:300]})
    except:
        pass
    # Deduplicate
    seen_ips = set()
    unique_external = []
    for e in result['externalIPs']:
        key = e['ip'] + ':' + str(e['port'])
        if key not in seen_ips:
            seen_ips.add(key)
            unique_external.append(e)
    result['externalIPs'] = unique_external[:50]
    result['dnsConnections'] = result['dnsConnections'][:30]
    result['httpConnections'] = result['httpConnections'][:30]
    result['execCommands'] = result['execCommands'][:30]
    result['allConnectionAttempts'] = all_dns_attempts + result['httpConnections'] + result['externalIPs']
    return result

def diff_wine_registry(before_text, after_path):
    """Diff wine registry files to find changes."""
    changes = []
    if not before_text or not os.path.isfile(after_path):
        return changes
    try:
        with open(after_path, 'r', errors='ignore') as f:
            after_text = f.read()
        before_lines = set(before_text.strip().split('\\n'))
        after_lines = after_text.strip().split('\\n')
        for line in after_lines:
            line = line.strip()
            if line and not line.startswith('#') and not line.startswith(';') and line not in before_lines:
                changes.append(line[:200])
    except:
        pass
    return changes[:50]

def analyze_file(path):
    result = {}
    data = open(path, 'rb').read()
    result['path'] = path
    result['size'] = len(data)
    result['sha256'] = hashlib.sha256(data).hexdigest()
    result['sha1'] = hashlib.sha1(data).hexdigest()
    result['md5'] = hashlib.md5(data).hexdigest()
    result['entropy'] = round(entropy(data), 4)

    # File type
    try:
        ft = subprocess.check_output(['file', '-b', path], timeout=5).decode().strip()
        result['fileType'] = ft
    except: result['fileType'] = 'unknown'

    result['isPE'] = data[:2] == b'MZ'
    result['isELF'] = data[:4] == b'\\x7fELF'

    # Imphash (PE import hash)
    imphash = compute_imphash(data)
    if imphash:
        result['imphash'] = imphash

    # Compile timestamp (PE)
    compile_ts = extract_compile_timestamp(data)
    if compile_ts:
        result['compileTimestamp'] = compile_ts

    # PDB debug path
    pdb_paths = extract_pdb_path(data)
    if pdb_paths:
        result['pdbPaths'] = pdb_paths

    # Fuzzy hash (ssdeep-style) — try python ssdeep if available
    try:
        import ssdeep as ssdeep_mod
        result['ssdeep'] = ssdeep_mod.hash(data)
    except:
        # Fallback: compute a simple block-based hash
        block_size = max(1, len(data) // 64)
        blocks = []
        for i in range(0, len(data), block_size):
            chunk = data[i:i+block_size]
            blocks.append(hashlib.md5(chunk).hexdigest()[:2])
        result['ssdeep'] = str(block_size) + ':' + ''.join(blocks[:64])

    # Digital signature / Authenticode check
    if result['isPE']:
        try:
            # Check for Authenticode signature (Certificate Table in PE optional header)
            pe_offset = struct.unpack_from('<I', data, 60)[0]
            # Security directory is at different offsets for PE32 vs PE32+
            opt_magic = struct.unpack_from('<H', data, pe_offset + 24)[0]
            if opt_magic == 0x10b:  # PE32
                cert_table_rva = struct.unpack_from('<I', data, pe_offset + 152)[0]
                cert_table_size = struct.unpack_from('<I', data, pe_offset + 156)[0]
            elif opt_magic == 0x20b:  # PE32+
                cert_table_rva = struct.unpack_from('<I', data, pe_offset + 168)[0]
                cert_table_size = struct.unpack_from('<I', data, pe_offset + 172)[0]
            else:
                cert_table_rva = 0
                cert_table_size = 0

            result['signature'] = {
                'hasCertificate': cert_table_size > 0,
                'certificateSize': cert_table_size,
            }

            # Try to extract signer info from the certificate
            if cert_table_size > 0 and cert_table_rva + cert_table_size <= len(data):
                cert_data = data[cert_table_rva:cert_table_rva + cert_table_size]
                # Decode as latin-1 to preserve all byte values as readable chars
                cert_text = cert_data.decode('latin-1', errors='ignore')
                # Look for common CA names in the certificate
                known_cas = ['DigiCert', 'Symantec', 'GlobalSign', 'Comodo', 'Thawte', 'VeriSign', 'Sectigo', 'GoDaddy', 'Entrust', 'Microsoft']
                found_cas = [ca for ca in known_cas if ca.lower() in cert_text.lower()]
                if found_cas:
                    result['signature']['issuer'] = found_cas[0]
                    result['signature']['isValidVendor'] = True
                # Extract the actual signer (organization) from the certificate.
                # Authenticode certs store names in ASN.1 DER, but the org name
                # typically appears as a readable ASCII string. Search for
                # company-name patterns (e.g. "Cisco Systems, Inc.").
                signer_found = False
                # Strategy 1: Look for organization-like strings (company names ending
                # with Inc, Corp, Ltd, LLC, or technology keywords)
                org_matches = re.findall(
                    r'([A-Z][a-zA-Z0-9][a-zA-Z0-9 &.,\\-]{2,50}(?:Inc|Corp|Ltd|LLC|Systems|Software|Technologies|Company|Corporation|Enterprises|GmbH|International|Foundation)[.,]?)',
                    cert_text
                )
                if org_matches:
                    # Filter out CA names so we get the actual signer, not the issuer
                    ca_lower = set(ca.lower() for ca in known_cas)
                    for org in org_matches:
                        org_clean = org.strip(' ,.')
                        # Skip if this is just a CA name
                        if any(ca in org_clean.lower() for ca in ca_lower):
                            continue
                        result['signature']['signer'] = org_clean[:100]
                        signer_found = True
                        break
                    # If all matches were CAs, use the first one anyway
                    if not signer_found and org_matches:
                        result['signature']['signer'] = org_matches[0].strip(' ,.')[:100]
                        signer_found = True
                # Strategy 2: Fallback to CN=/O= markers (may work for some certs)
                if not signer_found:
                    for marker in ['CN=', 'O=']:
                        idx = cert_text.find(marker)
                        if idx > 0:
                            end = cert_text.find(',', idx)
                            if end < 0: end = idx + 60
                            candidate = cert_text[idx+len(marker):end].strip()[:100]
                            # Only use if it looks like printable text
                            if candidate and all(c >= ' ' and c < '\\x7f' for c in candidate) and len(candidate) > 2:
                                result['signature']['signer'] = candidate
                                signer_found = True
                                break
                # Strategy 3: Look for well-known publisher names directly
                if not signer_found:
                    known_publishers = [
                        'Cisco Systems', 'Microsoft Corporation', 'Google LLC', 'Adobe Inc',
                        'Adobe Systems', 'Apple Inc', 'Mozilla Corporation', 'Oracle',
                        'VMware', 'Intel Corporation', 'NVIDIA', 'Samsung', 'Hewlett-Packard',
                        'Dell Technologies', 'Lenovo', 'Trend Micro', 'Kaspersky',
                        'CrowdStrike', 'Palo Alto Networks', 'Fortinet', 'Check Point',
                    ]
                    for pub in known_publishers:
                        if pub.lower() in cert_text.lower():
                            result['signature']['signer'] = pub
                            signer_found = True
                            break
        except:
            result['signature'] = {'hasCertificate': False}

    # PE Version Info / Resource extraction
    if result['isPE']:
        try:
            version_info = {}
            # Extract common version fields by searching for each field name
            # as UTF-16LE encoded bytes in the raw binary data.
            # VS_VERSIONINFO stores each string value as:
            #   WORD wLength, WORD wValueLength, WORD wType,
            #   szKey (null-terminated wchar), padding, Value (null-terminated wchar)
            # We find the field name bytes, skip past the null terminator and
            # alignment padding, then read the UTF-16LE value until double-null.
            fields = ['CompanyName', 'FileDescription', 'FileVersion', 'InternalName',
                      'LegalCopyright', 'OriginalFilename', 'ProductName', 'ProductVersion']
            for field in fields:
                field_bytes = field.encode('utf-16-le')
                idx = data.find(field_bytes)
                if idx < 0:
                    continue
                # Skip past the field name and its null terminator (2 bytes for UTF-16LE null)
                val_start = idx + len(field_bytes) + 2
                # Skip padding / null bytes (align to DWORD boundary)
                while val_start < len(data) and data[val_start] == 0:
                    val_start += 1
                # Read UTF-16LE string until double-null (two consecutive zero bytes)
                val_end = val_start
                while val_end + 1 < len(data):
                    if data[val_end] == 0 and data[val_end + 1] == 0:
                        break
                    val_end += 2
                value = data[val_start:val_end].decode('utf-16-le', errors='ignore').strip('\\x00')
                if value and len(value) > 1 and len(value) < 200:
                    version_info[field] = value

            if version_info:
                result['versionInfo'] = version_info
        except:
            pass

    # PE analysis
    if result['isPE'] and len(data) > 64:
        try:
            pe_offset = struct.unpack_from('<I', data, 60)[0]
            if data[pe_offset:pe_offset+4] == b'PE\\x00\\x00':
                machine = struct.unpack_from('<H', data, pe_offset+4)[0]
                num_sections = struct.unpack_from('<H', data, pe_offset+6)[0]
                result['peInfo'] = {'machine': hex(machine), 'sections': num_sections}

                # Extract imports by scanning for DLL names
                text = data.decode('ascii', errors='ignore')
                dlls = list(set(re.findall(r'([A-Za-z][A-Za-z0-9_]*\\.dll)', text, re.IGNORECASE)))
                result['imports'] = dlls[:50]

                # Suspicious imports
                suspicious = [d for d in dlls if any(s in d.lower() for s in ['ws2_32', 'wininet', 'winhttp', 'urlmon', 'crypt32', 'winsock'])]
                result['suspiciousImports'] = suspicious
        except: pass

    # Suspicious strings
    try:
        raw_strings = subprocess.check_output(['strings', '-n', '6', path], timeout=10).decode(errors='ignore')
        all_strings = raw_strings.split('\\n')
        benign_pe_strings = {'kernel32.dll','ntdll.dll','advapi32.dll','shell32.dll','user32.dll',
                             'gdi32.dll','ole32.dll','oleaut32.dll','msvcrt.dll','comctl32.dll',
                             'assemblyidentity','requestedprivileges','requestedexecutionlevel',
                             'trustinfo','mscoree.dll','upx0','upx1','upx!'}
        keywords = ['ransom','encrypt','decrypt','bitcoin','wallet','payment','locked','YOUR FILES',
                     'CreateRemoteThread','VirtualAlloc','WriteProcessMemory','NtUnmapViewOfSection',
                     'IsDebuggerPresent','cmd.exe','powershell','Invoke-Expression',
                     'RegSetValue','CurrentVersion\\\\Run','vssadmin','bcdedit','shadowcopy',
                     'cipher /w','wmic','delete shadows','recoveryenabled',
                     '.onion','tor2web',
                     'AES','RSA','credential','token',
                     'keylog','screenshot','clipboard','webcam','microphone',
                     'injection','hook','shellcode','payload',
                     'backdoor','trojan','rootkit','exploit',
                     'HttpSendRequest','InternetOpen','URLDownloadToFile',
                     'WinExec','ShellExecute','CreateProcess']
        suspicious_strings = []
        for s in all_strings:
            sl = s.lower().strip()
            if any(b in sl for b in benign_pe_strings):
                continue
            for kw in keywords:
                if kw.lower() in sl:
                    suspicious_strings.append(s.strip()[:100])
                    break
        result['suspiciousStrings'] = list(set(suspicious_strings))[:100]
        result['totalStrings'] = len(all_strings)

        # URLs — expanded regex
        result['urls'] = list(set(re.findall(r'(?:https?|ftp|ftps)://[^\\s\\'\"<>\\x00]{4,500}', raw_strings)))[:30]
        # IPs
        result['ips'] = list(set(re.findall(r'\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b', raw_strings)))[:30]
        # Email addresses
        result['emails'] = extract_emails(raw_strings)
        # Domain names
        result['domains'] = extract_domains(raw_strings)
        # Registry keys
        result['registryKeys'] = extract_registry_keys(raw_strings)
        # Mutex patterns
        result['mutexPatterns'] = extract_mutex_patterns(raw_strings)
        # File paths
        result['filePaths'] = extract_file_paths(raw_strings)
    except: pass

    # Section entropy (for PE files)
    if result['isPE'] and len(data) > 512:
        sections = []
        try:
            pe_offset = struct.unpack_from('<I', data, 60)[0]
            num_sections = struct.unpack_from('<H', data, pe_offset+6)[0]
            opt_size = struct.unpack_from('<H', data, pe_offset+20)[0]
            sec_offset = pe_offset + 24 + opt_size
            for i in range(min(num_sections, 20)):
                off = sec_offset + i * 40
                if off + 40 > len(data): break
                name = data[off:off+8].rstrip(b'\\x00').decode('ascii', errors='ignore')
                raw_size = struct.unpack_from('<I', data, off+16)[0]
                raw_ptr = struct.unpack_from('<I', data, off+20)[0]
                sec_data = data[raw_ptr:raw_ptr+raw_size] if raw_size > 0 and raw_ptr+raw_size <= len(data) else b''
                sec_entropy = round(entropy(sec_data), 2) if sec_data else 0
                sections.append({'name': name, 'size': raw_size, 'entropy': sec_entropy})
            result['sections'] = sections
        except: pass

    return result

# Find files to analyze
targets = []
for d in ['/tmp/scanboy-extracted', '${CONTAINER_SAMPLE_DIR}']:
    if os.path.isdir(d):
        for root_dir, dirs, files in os.walk(d):
            for f in files:
                fp = os.path.join(root_dir, f)
                if os.path.isfile(fp) and os.path.getsize(fp) > 0:
                    targets.append(fp)

results = []
for t in targets[:10]:
    try:
        results.append(analyze_file(t))
    except Exception as e:
        results.append({'path': t, 'error': str(e)})

# Parse strace output for behavioral IOCs
strace_data = parse_strace_output('/tmp/scanboy-logs/strace.log')

# Diff wine registry (before vs after) — read from file to avoid env var injection
wine_reg_before_file = os.environ.get('SCANBOY_WINE_REG_BEFORE_FILE', '')
wine_reg_before = ''
if wine_reg_before_file and os.path.isfile(wine_reg_before_file):
    try:
        with open(wine_reg_before_file, 'r', errors='ignore') as f:
            wine_reg_before = f.read()
    except:
        pass
system_reg_changes = diff_wine_registry(
    wine_reg_before.split('===SCANBOY_REG_SEP===')[0] if '===SCANBOY_REG_SEP===' in wine_reg_before else '',
    '/home/sandbox/.wine/system.reg'
)
user_reg_changes = diff_wine_registry(
    wine_reg_before.split('===SCANBOY_REG_SEP===')[1] if '===SCANBOY_REG_SEP===' in wine_reg_before else '',
    '/home/sandbox/.wine/user.reg'
)

output = {
    'files': results,
    'straceAnalysis': strace_data,
    'wineRegistryChanges': {
        'system': system_reg_changes,
        'user': user_reg_changes
    }
}
print(json.dumps(output))
`;
        const { execFileSync: analysisExecFs } = await import('node:child_process');
        analysisExecFs('docker', ['exec', '-i', '-u', 'root', containerId, 'sh', '-c', 'cat > /tmp/scanboy-analyze.py'], {
          input: Buffer.from(analysisScript), timeout: 10_000, maxBuffer: 1024 * 1024,
        });

        analysisExecFs('docker', ['exec', '-i', '-u', 'root', containerId, 'sh', '-c', 'cat > /tmp/scanboy-wine-reg-before.txt'], {
          input: Buffer.from(wineRegBefore.slice(0, 50000)), timeout: 10_000, maxBuffer: 1024 * 1024,
        });
      const { stdout } = await execFile('docker', [
        'exec', '-u', 'sandbox', '-e', 'SCANBOY_WINE_REG_BEFORE_FILE=/tmp/scanboy-wine-reg-before.txt',
        containerId, 'python3', '/tmp/scanboy-analyze.py',
      ], { timeout: 60_000, maxBuffer: 10 * 1024 * 1024 });
        jailAnalysis = stdout;
        console.error(`[SANDBOX] Jail static analysis: ${jailAnalysis.slice(0, 500)}`);
      } catch (err) {
        console.error(`[SANDBOX] Jail analysis failed: ${err instanceof Error ? err.message : String(err)}`);
      }

      // g3b. Run deep static analysis (PE/ELF deep extraction, format analysis)
      let deepAnalysisOutput = '';
      try {
        const { getDeepStaticAnalysisScript } = await import('../analyzers/pe-deep.js');
        const deepScript = getDeepStaticAnalysisScript();
        const { execFileSync: deepExecFs } = await import('node:child_process');
        deepExecFs('docker', ['exec', '-i', '-u', 'root', containerId, 'sh', '-c', 'cat > /tmp/scanboy-deep.py'], {
          input: Buffer.from(deepScript), timeout: 10_000, maxBuffer: 10 * 1024 * 1024,
        });
        const runnerScript = [
          'import json, sys',
          "exec(open('/tmp/scanboy-deep.py').read())",
          `data = open('${CONTAINER_SAMPLE_PATH}', 'rb').read()`,
          'r = {}',
          `deep_analysis('${CONTAINER_SAMPLE_PATH}', data, r)`,
          "print(json.dumps(r.get('deepAnalysis', {})))",
        ].join('\n');
        deepExecFs('docker', ['exec', '-i', '-u', 'root', containerId, 'sh', '-c', 'cat > /tmp/scanboy-deep-run.py'], {
          input: Buffer.from(runnerScript), timeout: 10_000, maxBuffer: 1024 * 1024,
        });
        const { stdout: deepOut } = await execFile('docker', [
          'exec', '-u', 'sandbox', containerId, 'python3', '/tmp/scanboy-deep-run.py',
        ], { timeout: 30_000, maxBuffer: 10 * 1024 * 1024 });
        deepAnalysisOutput = deepOut.trim();
        console.error(`[SANDBOX] Deep analysis: ${deepAnalysisOutput.slice(0, 200)}`);
      } catch (err) {
        console.error(`[SANDBOX] Deep analysis failed: ${err instanceof Error ? err.message : String(err)}`);
      }

      // g4. Run REMnux tools if available (capa, floss, yara)
      let capaOutput = '';
      let flossOutput = '';
      try {
        const { stdout: capaOut } = await execFile('docker', [
          'exec', containerId, 'bash', '-c',
          `which capa >/dev/null 2>&1 && capa -j ${CONTAINER_SAMPLE_PATH} 2>/dev/null || echo '{}'`,
        ], { timeout: 60_000, maxBuffer: 10 * 1024 * 1024 });
        capaOutput = capaOut;
      } catch { /* capa not available */ }

      try {
        const { stdout: flossOut } = await execFile('docker', [
          'exec', containerId, 'bash', '-c',
          `which floss >/dev/null 2>&1 && floss --json ${CONTAINER_SAMPLE_PATH} 2>/dev/null | head -c 500000 || echo '{}'`,
        ], { timeout: 60_000, maxBuffer: 10 * 1024 * 1024 });
        flossOutput = flossOut;
      } catch { /* floss not available */ }

      // g5. Built-in pattern scanner (ransomware, RATs, anti-debug, etc.)
      let yaraPatternOutput = '';
      try {
        const { getYaraScannerScript } = await import('../yara-pattern-scanner.js');
        const patternScript = getYaraScannerScript();
        const { execFileSync: patternExecFs } = await import('node:child_process');
        patternExecFs('docker', ['exec', '-i', '-u', 'root', containerId, 'sh', '-c', 'cat > /tmp/scanboy-yara-patterns.py'], {
          input: Buffer.from(patternScript), timeout: 10_000, maxBuffer: 10 * 1024 * 1024,
        });
        const { stdout: patternOut } = await execFile('docker', [
          'exec', '-u', 'sandbox', containerId, 'python3', '/tmp/scanboy-yara-patterns.py',
        ], { timeout: 60_000, maxBuffer: 10 * 1024 * 1024 });
        yaraPatternOutput = patternOut.trim();
        if (yaraPatternOutput) {
          try {
            const parsed = JSON.parse(yaraPatternOutput) as { yaraResults?: Array<{ matches?: unknown[] }> };
            const totalMatches = (parsed.yaraResults ?? []).reduce((s, r) => s + (r.matches?.length ?? 0), 0);
            console.error(`[SANDBOX] Pattern scanner: ${totalMatches} matches across ${parsed.yaraResults?.length ?? 0} files`);
          } catch { console.error(`[SANDBOX] Pattern scanner output (unparseable): ${yaraPatternOutput.slice(0, 200)}`); }
        }
      } catch (patternErr) {
        console.error(`[SANDBOX] Pattern scanner failed: ${patternErr instanceof Error ? patternErr.message : String(patternErr)}`);
      }

      // g5b. UPX unpack — if sample is UPX-packed, create unpacked copy for better YARA/string scanning
      try {
        await dockerExec(containerId,
          `for f in "${CONTAINER_SAMPLE_PATH}" /tmp/scanboy-extracted/*; do ` +
          `[ -f "$f" ] && upx -t "$f" >/dev/null 2>&1 && upx -d "$f" -o "$f.unpacked" >/dev/null 2>&1 && echo "Unpacked: $f"; ` +
          `done`, 30_000, 'root');
      } catch { /* UPX unpack is best-effort */ }

      // g6. Real YARA binary scanning with community rules from feeds service
      // CRITICAL: vuln-feeds requires x-internal-api-key header — without it you get
      // a silent 401 and zero rules load, causing the entire YARA pipeline to no-op.
      let yaraBinaryOutput = '';
      try {
        let feedRules = '';
        try {
          const feedRes = await fetch('http://vuln-feeds:9000/feeds/yara/rules', {
            signal: AbortSignal.timeout(15_000),
            headers: process.env['INTERNAL_API_KEY'] ? { 'x-internal-api-key': process.env['INTERNAL_API_KEY'] } : {},
          });
          if (feedRes.ok) {
            const feedData = await feedRes.json() as { rules?: Array<{ ruleText: string }> };
            if (Array.isArray(feedData.rules)) {
              feedRules = feedData.rules.map(r => r.ruleText).join('\n\n');
              console.error(`[SANDBOX] Loaded ${feedData.rules.length} YARA rules from feeds`);
            }
          }
        } catch (feedErr) {
          console.error(`[SANDBOX] Failed to fetch YARA rules from feeds: ${feedErr instanceof Error ? feedErr.message : String(feedErr)}`);
        }

        if (feedRules.length < 100) {
          console.error('[SANDBOX] No YARA rules available — skipping YARA scan');
        } else {
          const { execFileSync: execFs } = await import('node:child_process');

          execFs('docker', ['exec', '-i', '-u', 'root', containerId, 'sh', '-c', 'cat > /tmp/scanboy-rules.yar'], {
            input: Buffer.from(feedRules),
            timeout: 30_000, maxBuffer: 100 * 1024 * 1024,
          });

          const yaraScanCmd = `for t in "${CONTAINER_SAMPLE_PATH}" /tmp/scanboy-extracted/* /tmp/scanboy-extracted/*.unpacked "${CONTAINER_SAMPLE_PATH}.unpacked"; do ` +
            `[ -f "$t" ] && yara -w -s /tmp/scanboy-rules.yar "$t" 2>/dev/null; done` +
            `; echo SCANBOY_DONE`;

          const { stdout: yaraRealOut } = await execFile('docker', [
            'exec', containerId, 'bash', '-c', yaraScanCmd,
          ], { timeout: 300_000, maxBuffer: 10 * 1024 * 1024 });
          yaraBinaryOutput = yaraRealOut;
          const matchLines = yaraBinaryOutput.split('\n').filter(l => l.trim() && !l.includes('SCANBOY_') && !l.startsWith('error:') && !l.startsWith('warning:') && !l.startsWith('[YARA-DEBUG]'));
          console.error(`[SANDBOX] YARA binary scan: ${matchLines.length} match lines`);
          if (matchLines.length > 0) console.error(`[SANDBOX] YARA first matches: ${matchLines.slice(0, 5).join(' | ')}`);
        }
      } catch (yaraBinErr) {
        console.error(`[SANDBOX] YARA binary scan failed: ${yaraBinErr instanceof Error ? yaraBinErr.message : String(yaraBinErr)}`);
      }

      // g7. Config extraction for identified malware families
      // Detect family from community YARA binary matches
      let configExtractionOutput = '';
      try {
        let familyForExtraction = '';
        if (yaraBinaryOutput) {
          const binaryFamilyMap: Record<string, string> = {
            'Cobalt_Strike': 'cobalt strike', 'CobaltStrike': 'cobalt strike', 'Beacon': 'cobalt strike',
            'Meterpreter': 'meterpreter', 'Metasploit': 'meterpreter',
            'Emotet': 'emotet', 'Agent_Tesla': 'agent tesla', 'AgentTesla': 'agent tesla',
            'Remcos': 'remcos', 'AsyncRAT': 'asyncrat', 'Qakbot': 'qakbot', 'QBot': 'qakbot',
            'LockBit': 'lockbit', 'BlackCat': 'blackcat', 'ALPHV': 'blackcat',
            'Conti': 'conti', 'TrickBot': 'trickbot', 'IcedID': 'icedid', 'BokBot': 'icedid',
            'BumbleBee': 'bumblebee', 'Raccoon': 'raccoon', 'RedLine': 'redline',
            'Vidar': 'vidar', 'FormBook': 'formbook', 'XLoader': 'formbook',
            'LokiBot': 'lokibot', 'NjRAT': 'njrat', 'DarkComet': 'darkcomet',
            'Ursnif': 'ursnif', 'Gozi': 'ursnif', 'Dridex': 'dridex',
            'BazarLoader': 'bazarloader', 'SystemBC': 'systembc', 'SmokeLoader': 'smokeloader',
            'Amadey': 'amadey', 'StealC': 'stealc', 'Lumma': 'lumma',
            'Pikabot': 'pikabot', 'DarkGate': 'darkgate', 'Latrodectus': 'latrodectus',
            'PlugX': 'plugx', 'ShadowPad': 'shadowpad', 'Gh0st': 'gh0st',
            'PoisonIvy': 'poisonivy', 'NetWire': 'netwire', 'Warzone': 'warzone',
            'Havoc': 'havoc', 'Sliver': 'sliver', 'BruteRatel': 'bruteratel',
            'WannaCry': 'wannacry', 'REvil': 'revil', 'Sodinokibi': 'revil',
            'Ryuk': 'ryuk', 'Hive': 'hive', 'Royal': 'royal',
            'BlackBasta': 'blackbasta', 'Akira': 'akira', 'Play': 'play',
            'Clop': 'clop', 'Maze': 'maze', 'Medusa': 'medusa',
            'Phobos': 'phobos', 'Dharma': 'dharma', 'RedBoot': 'wannacry',
            'Nanocore': 'nanocore', 'QuasarRAT': 'quasarrat', 'Orcus': 'orcus',
          };
          for (const [rule, family] of Object.entries(binaryFamilyMap)) {
            if (yaraBinaryOutput.includes(rule)) { familyForExtraction = family; break; }
          }
        }
        // Use local variable instead of module-global to avoid race conditions
        const detectedFamily = familyForExtraction;
        void detectedFamily; // Used by report assembly below
        const configScript = buildConfigExtractorScript(familyForExtraction);
        if (configScript) {
          const { execFileSync: configExecFs } = await import('node:child_process');
          configExecFs('docker', ['exec', '-i', '-u', 'root', containerId, 'sh', '-c', 'cat > /tmp/scanboy-config-extract.py'], {
            input: Buffer.from(configScript), timeout: 10_000, maxBuffer: 10 * 1024 * 1024,
          });
          const { stdout: configOut } = await execFile('docker', [
            'exec', '-u', 'sandbox', containerId, 'python3', '/tmp/scanboy-config-extract.py',
          ], { timeout: 60_000, maxBuffer: 10 * 1024 * 1024 });
          configExtractionOutput = configOut;
          console.error(`[SANDBOX] Config extraction: ${configExtractionOutput.slice(0, 500)}`);
        }
      } catch (configErr) {
        console.error(`[SANDBOX] Config extraction failed: ${configErr instanceof Error ? configErr.message : String(configErr)}`);
      }

      // i. Parse monitoring output into structured behavioral data
      const processActivity = parseStraceOutput(monitorData.strace);
      const fileActivity = parseInotifyOutput(monitorData.inotify);
      const networkActivity = parseNetworkCapture(monitorData.tcpdump);
      const { processes, tree } = parseProcInfo(monitorData.ps);

      // Build the report
      const reportInput: BuildReportInput = {
        submissionId,
        processData: processActivity,
        fileData: fileActivity,
        networkData: networkActivity,
        execInfo: {
          exitCode: execInfo.exitCode,
          timedOut: execInfo.timedOut,
          executionDuration: execInfo.durationMs,
          straceOutput: monitorData.strace,
          inotifyOutput: monitorData.inotify,
          tcpdumpOutput: monitorData.tcpdump,
          psOutput: monitorData.ps,
          droppedFilesOutput: monitorData.droppedFiles,
          sampleType: classification.label,
        },
        processInfo: { processes, tree },
      };

      const report = buildReport(reportInput);

      // Enrich report with REMnux tool output
      const extraIndicators = [...report.suspiciousIndicators];

      if (!straceIntegrityOk) {
        extraIndicators.push({
          category: 'evasion',
          description: 'strace monitoring was terminated during execution — sample may have anti-analysis capabilities',
          severity: 'high',
          evidence: 'strace process not found after sample execution with minimal log output',
        });
      }

      if (capaOutput.trim() !== '{}' && capaOutput.trim() !== '') {
        try {
          const capaData = JSON.parse(capaOutput) as Record<string, unknown>;
          const rules = capaData['rules'] as Record<string, unknown> | undefined;
          if (rules) {
            for (const [ruleName, ruleData] of Object.entries(rules)) {
              const meta = (ruleData as Record<string, unknown>)['meta'] as Record<string, unknown> | undefined;
              const attack = meta?.['att&ck'] as Array<Record<string, unknown>> | undefined;
              extraIndicators.push({
                category: 'capability',
                description: `capa: ${ruleName}`,
                severity: attack ? 'high' : 'medium',
                evidence: JSON.stringify(meta ?? {}).slice(0, 200),
              });
            }
          }
        } catch { /* malformed capa output */ }
      }

      if (flossOutput.trim() !== '{}' && flossOutput.trim() !== '') {
        try {
          const flossData = JSON.parse(flossOutput) as Record<string, unknown>;
          const decoded = flossData['decoded_strings'] as string[] | undefined;
          if (decoded && decoded.length > 0) {
            extraIndicators.push({
              category: 'obfuscation',
              description: `floss: ${decoded.length} obfuscated strings decoded`,
              severity: 'high',
              evidence: decoded.slice(0, 5).join(', '),
            });
          }
        } catch { /* malformed floss output */ }
      }

      let packingDetected = false;
      // Parse jail static analysis results (JSON object from Python script)
      let jailFiles: Array<Record<string, unknown>> = [];
      let jailStraceAnalysis: Record<string, unknown> = {};
      let jailWineRegChanges: Record<string, unknown> = {};
      if (jailAnalysis) {
        try {
          const parsed = JSON.parse(jailAnalysis.trim()) as Record<string, unknown>;
          // New format: {files: [...], straceAnalysis: {...}, wineRegistryChanges: {...}}
          if (Array.isArray(parsed['files'])) {
            jailFiles = parsed['files'] as Array<Record<string, unknown>>;
            jailStraceAnalysis = (parsed['straceAnalysis'] as Record<string, unknown>) ?? {};
            jailWineRegChanges = (parsed['wineRegistryChanges'] as Record<string, unknown>) ?? {};
          } else if (Array.isArray(parsed)) {
            // Legacy format: direct array
            jailFiles = parsed as unknown as Array<Record<string, unknown>>;
          }
        } catch { /* not valid JSON */ }

        for (const entry of jailFiles) {
          const isPE = entry['isPE'] === true;
          const isELF = entry['isELF'] === true;
          const ent = typeof entry['entropy'] === 'number' ? entry['entropy'] : 0;
          const ftype = String(entry['fileType'] ?? '');
          const filePath = String(entry['path'] ?? '');

          // Packing: consolidate entropy + section name into ONE indicator
          const sections = entry['sections'] as Array<Record<string, unknown>> | undefined;
          const packedSections = (sections ?? []).filter(s => /UPX|packed|aspack|themida|vmprotect/i.test(String(s['name'] ?? '')));
          const isInstallerFormat = /nullsoft|inno setup|installshield|wix|nsis/i.test(ftype);

          if (!packingDetected && ((isPE || isELF) && ent > 7.0 || packedSections.length > 0)) {
            packingDetected = true;
            const packerName = packedSections.length > 0 ? packedSections.map(s => s['name']).join(', ') : 'unknown';
            extraIndicators.push({
              category: 'packing',
              description: packedSections.length > 0
                ? `Packed binary: ${packerName} (entropy ${ent.toFixed(2)})`
                : `High entropy executable (${ent.toFixed(2)}) — likely packed`,
              severity: isInstallerFormat ? 'low' : (ent > 7.5 ? 'high' : 'medium'),
              evidence: `${filePath}: ${ftype}, entropy=${ent.toFixed(2)}`,
            });
          }

          // Suspicious strings — only flag genuinely malicious strings
          const suspStrings = entry['suspiciousStrings'] as string[] | undefined;
          if (suspStrings && suspStrings.length > 0) {
            const severity = suspStrings.length > 15 ? 'critical' : suspStrings.length > 8 ? 'high' : suspStrings.length > 3 ? 'medium' : 'low';
            extraIndicators.push({
              category: 'suspicious_strings',
              description: `${suspStrings.length} suspicious strings found`,
              severity: severity as 'critical' | 'high' | 'medium' | 'low',
              evidence: suspStrings.slice(0, 10).join(', '),
            });
          }

          // URLs found in binary
          const urls = entry['urls'] as string[] | undefined;
          if (urls && urls.length > 0) {
            extraIndicators.push({
              category: 'network',
              description: `${urls.length} embedded URLs found`,
              severity: 'high',
              evidence: urls.slice(0, 5).join(', '),
            });
          }

          // PE with genuinely suspicious imports (network/crypto only)
          const suspImports = entry['suspiciousImports'] as string[] | undefined;
          if (suspImports && suspImports.length > 0) {
            extraIndicators.push({
              category: 'imports',
              description: `Network/crypto DLL imports: ${suspImports.join(', ')}`,
              severity: suspImports.length >= 3 ? 'high' : 'medium',
              evidence: suspImports.join(', '),
            });
          }

          // ── Heuristic checks for PE files ──
          if (isPE) {
            const imports = (entry['imports'] as string[]) ?? [];
            const versionInfo = entry['versionInfo'] as Record<string, string> | undefined;
            const compileTs = entry['compileTimestamp'] as { unix: number; utc: string } | undefined;
            const isNativeDriver = /\(native\)/i.test(ftype) || /\.sys$/i.test(filePath);
            const kernelImports = imports.filter(i => /^(HAL|ntoskrnl|NDIS|SCSIPORT|storport|wdf|fltmgr)/i.test(i));

            // Kernel-mode driver detection
            if (isNativeDriver || kernelImports.length > 0) {
              extraIndicators.push({
                category: 'kernel_driver',
                description: `Windows kernel-mode driver detected${kernelImports.length > 0 ? ` (imports: ${kernelImports.join(', ')})` : ''}`,
                severity: 'high',
                evidence: `${filePath}: ${ftype}`,
              });
            }

            // Ancient compile timestamp (>5 years old = suspicious in submission context)
            if (compileTs && compileTs.unix > 0) {
              const ageYears = (Date.now() / 1000 - compileTs.unix) / (365.25 * 86400);
              // Future timestamps are also suspicious (anti-analysis/timestomping)
              if (compileTs.unix > Date.now() / 1000 + 86400) {
                extraIndicators.push({
                  category: 'timestomping',
                  description: `PE has future compile timestamp: ${compileTs.utc}`,
                  severity: 'high',
                  evidence: `${filePath}: compiled ${compileTs.utc} (${Math.abs(Math.round(ageYears))} years in the future)`,
                });
              } else if (ageYears > 10) {
                extraIndicators.push({
                  category: 'suspicious_metadata',
                  description: `PE compiled ${Math.round(ageYears)} years ago: ${compileTs.utc}`,
                  severity: 'medium',
                  evidence: `${filePath}: compiled ${compileTs.utc}`,
                });
              }
            }

            // Spoofed version info detection
            if (versionInfo) {
              const company = versionInfo['CompanyName'] ?? '';
              const product = versionInfo['ProductName'] ?? '';
              const origFilename = versionInfo['OriginalFilename'] ?? '';
              const actualFilename = filePath.split('/').pop() ?? '';
              // Known vendor names that malware impersonates
              const spoofedVendors = /^(Microsoft|IBM|Intel|Adobe|Google|Apple|Oracle|Cisco|VMware|Symantec|Norton|McAfee)/i;
              const hasCert = (entry['signature'] as Record<string, unknown> | undefined)?.['hasCertificate'] === true;

              if (spoofedVendors.test(company) && !hasCert) {
                extraIndicators.push({
                  category: 'version_info_spoof',
                  description: `PE claims vendor "${company}" but is unsigned`,
                  severity: 'high',
                  evidence: `${filePath}: CompanyName="${company}", ProductName="${product}", no digital signature`,
                });
              }

              // OriginalFilename mismatch (common in malware that masquerades as system files)
              // Skip when actual filename is the sandbox sample name (always mismatches)
              if (origFilename && actualFilename && actualFilename !== 'sample' && origFilename.toLowerCase() !== actualFilename.toLowerCase()) {
                const isSysFile = /\.(sys|dll|exe|drv|ocx)$/i.test(origFilename);
                if (isSysFile) {
                  extraIndicators.push({
                    category: 'filename_mismatch',
                    description: `PE OriginalFilename "${origFilename}" doesn't match actual name "${actualFilename}"`,
                    severity: 'medium',
                    evidence: `${filePath}: OriginalFilename=${origFilename}`,
                  });
                }
              }
            }

            // No-import or minimal-import PE (shellcode-like or manually-resolved imports)
            if (imports.length <= 2 && !isNativeDriver) {
              extraIndicators.push({
                category: 'suspicious_structure',
                description: `PE has only ${imports.length} import${imports.length === 1 ? '' : 's'} — possible manual import resolution`,
                severity: 'medium',
                evidence: `${filePath}: imports=[${imports.join(', ')}]`,
              });
            }
          }
        }
      }

      // Add strace-derived indicators
      const straceIPs = jailStraceAnalysis['externalIPs'] as Array<Record<string, unknown>> | undefined;
      if (straceIPs && straceIPs.length > 0) {
        extraIndicators.push({
          category: 'network',
          description: `Strace detected ${straceIPs.length} external IP connection attempts`,
          severity: 'high',
          evidence: straceIPs.slice(0, 5).map(e => `${String(e['ip'])}:${String(e['port'])}`).join(', '),
        });
      }
      const straceDns = jailStraceAnalysis['dnsConnections'] as Array<Record<string, unknown>> | undefined;
      if (straceDns && straceDns.length > 0) {
        extraIndicators.push({
          category: 'network',
          description: `Strace detected ${straceDns.length} DNS connection attempts`,
          severity: 'medium',
          evidence: straceDns.slice(0, 5).map(e => String(e['ip'])).join(', '),
        });
      }
      const straceHttp = jailStraceAnalysis['httpConnections'] as Array<Record<string, unknown>> | undefined;
      if (straceHttp && straceHttp.length > 0) {
        extraIndicators.push({
          category: 'network',
          description: `Strace detected ${straceHttp.length} HTTP/HTTPS connections`,
          severity: 'high',
          evidence: straceHttp.slice(0, 5).map(e => `${String(e['protocol'])}://${String(e['ip'])}:${String(e['port'])}`).join(', '),
        });
      }

      // Add wine registry change indicators
      const sysRegChanges = jailWineRegChanges['system'] as string[] | undefined;
      const userRegChanges = jailWineRegChanges['user'] as string[] | undefined;
      const totalRegChanges = (sysRegChanges?.length ?? 0) + (userRegChanges?.length ?? 0);
      if (totalRegChanges > 0) {
        const runKeyChanges = [...(sysRegChanges ?? []), ...(userRegChanges ?? [])].filter(
          l => /Run|RunOnce|Startup/i.test(l)
        );
        if (runKeyChanges.length > 0) {
          extraIndicators.push({
            category: 'persistence',
            description: `Registry Run key modification detected (${runKeyChanges.length} entries)`,
            severity: 'critical',
            evidence: runKeyChanges.slice(0, 3).join('; '),
          });
        }
        extraIndicators.push({
          category: 'registry',
          description: `${totalRegChanges} wine registry changes detected during execution`,
          severity: totalRegChanges > 10 ? 'high' : 'medium',
          evidence: [...(sysRegChanges ?? []), ...(userRegChanges ?? [])].slice(0, 5).join('; '),
        });
      }

      // (yaraPatternMatches removed — all YARA detection comes from community rules in yaraBinaryMatches)

      // Extract PCAP — real capture if network enabled, synthetic from strace if not
      let pcapBase64 = '';
      if (opts.captureNetwork) {
        try {
          pcapBase64 = await dockerExec(containerId,
            `dd if=/tmp/scanboy-logs/capture.pcap bs=1M count=10 2>/dev/null | base64 -w 0 || echo ""`, 30_000);
          pcapBase64 = pcapBase64.trim();
        } catch { /* non-fatal */ }
      }
      // Generate synthetic PCAP from strace connection attempts (works even with --network none)
      if (!pcapBase64 || pcapBase64.length < 10) {
        const rawAllConns = jailStraceAnalysis['allConnectionAttempts'] as Array<Record<string, unknown>> | undefined;
        const allConns: Array<Record<string, unknown>> = (rawAllConns && rawAllConns.length > 0)
          ? rawAllConns
          : [
              ...((jailStraceAnalysis['dnsConnections'] ?? []) as Array<Record<string, unknown>>),
              ...((jailStraceAnalysis['httpConnections'] ?? []) as Array<Record<string, unknown>>),
              ...((jailStraceAnalysis['externalIPs'] ?? []) as Array<Record<string, unknown>>),
            ];
        if (allConns.length > 0) {
          try {
            // Write connection data via base64 to avoid shell expansion of $() or backticks
            const connsB64 = Buffer.from(JSON.stringify(allConns.slice(0, 100))).toString('base64');
            await dockerExec(containerId,
              `printf '%s' '${connsB64}' | base64 -d > /tmp/scanboy-synth-conns.json`, 5_000);
            const synthScript = `
import struct, json, sys
conns = json.loads(open('/tmp/scanboy-synth-conns.json').read())
pcap = struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
for i, c in enumerate(conns):
    ip = c.get('ip', '0.0.0.0')
    port = int(c.get('port', 0))
    proto = c.get('protocol', 'tcp')
    parts = [int(x) for x in ip.split('.') if x.isdigit()]
    if len(parts) != 4: continue
    dst_ip = struct.pack('BBBB', *parts)
    src_ip = struct.pack('BBBB', 10, 0, 0, 1)
    src_port = 49152 + i
    tcp_hdr = struct.pack('>HHIIBBHHH', src_port, port, i+1, 0, 0x50, 0x02, 65535, 0, 0)
    ip_len = 20 + 20
    ip_hdr = struct.pack('>BBHHHBBH', 0x45, 0, ip_len, i+1, 0x4000, 64, 6, 0) + src_ip + dst_ip
    eth_hdr = b'\\xff' * 6 + b'\\x00' * 6 + struct.pack('>H', 0x0800)
    pkt = eth_hdr + ip_hdr + tcp_hdr
    ts_sec = i
    pcap += struct.pack('<IIII', ts_sec, 0, len(pkt), len(pkt)) + pkt
sys.stdout.buffer.write(pcap)
`;
            const scriptB64 = Buffer.from(synthScript).toString('base64');
            await dockerExec(containerId,
              `printf '%s' '${scriptB64}' | base64 -d > /tmp/scanboy-synth-pcap.py`, 5_000);
            const synthOut = await dockerExec(containerId,
              `python3 /tmp/scanboy-synth-pcap.py 2>/dev/null | base64 -w 0`, 10_000);
            if (synthOut && synthOut.trim().length > 20) {
              pcapBase64 = synthOut.trim();
              console.error(`[SANDBOX] Generated synthetic PCAP from ${allConns.length} strace connections`);
            }
          } catch { /* non-fatal */ }
        }
      }

      // Parse real YARA binary matches (filter out SCANBOY_NO_MATCHES lines, don't reject entire output)
      const yaraBinaryMatches: Array<{ ruleName: string; filePath: string; matchedStrings: string[] }> = [];
      if (yaraBinaryOutput) {
        const lines = yaraBinaryOutput.split('\n').filter(l => l.trim() && !l.includes('SCANBOY_') && !l.startsWith('error:') && !l.startsWith('warning:') && !l.startsWith('['));
        let currentRule: { ruleName: string; filePath: string; matchedStrings: string[] } | null = null;
        for (const line of lines) {
          const ruleMatch = /^([A-Za-z0-9_]+)\s+(.+)$/.exec(line);
          if (ruleMatch && !line.startsWith('0x')) {
            if (currentRule) yaraBinaryMatches.push(currentRule);
            currentRule = { ruleName: ruleMatch[1]!, filePath: ruleMatch[2]!, matchedStrings: [] };
          } else if (line.startsWith('0x') && currentRule) {
            const strMatch = /^0x[0-9a-fA-F]+:(\$[a-zA-Z0-9_]+):\s*(.*)$/.exec(line);
            if (strMatch) {
              currentRule.matchedStrings.push(`${strMatch[1]}: ${(strMatch[2] ?? '').slice(0, 60)}`);
            }
          }
        }
        if (currentRule) yaraBinaryMatches.push(currentRule);
      }

      // Add binary YARA matches as indicators.
      // Category is always 'yara-binary' — YARA byte-pattern matches are prone to FPs
      // on legitimate packed software and must not trigger behavioral scoring floors
      // (ransomware/c2 floors are reserved for genuine runtime behavioral signals).
      for (const ym of yaraBinaryMatches) {
        const isRansomware = /ransom|crypt|lock|wanna|revil|ryuk|conti|hive|akira|phobos|dharma|maze|clop|medusa/i.test(ym.ruleName);
        const isWiper = /wiper|mbr_wiper|destroy|shamoon|hermetic|caddy|isaac|zero_?clear|dustman|killmbr|killdisk/i.test(ym.ruleName);
        const isRat = /rat|backdoor|trojan|remote|shell|c2|beacon|cobalt|sliver|havoc|meterpreter/i.test(ym.ruleName);
        const isInjection = /inject|hollow|process_inject|dll_inject|thread_inject|apc_inject/i.test(ym.ruleName);
        const isRootkit = /rootkit|bootkit|driver_load|kernel_exploit/i.test(ym.ruleName);
        const severity = (isRansomware || isWiper) ? 'critical' : (isRat || isInjection || isRootkit) ? 'high' : 'medium';
        const label = isRansomware ? 'Ransomware' : isWiper ? 'Wiper' : isRat ? 'C2/RAT' : isInjection ? 'Process injection' : isRootkit ? 'Rootkit' : '';
        extraIndicators.push({
          category: 'yara-binary',
          description: `YARA: ${ym.ruleName}${label ? ` — ${label} indicators` : ''}`,
          severity: severity as 'critical' | 'high' | 'medium' | 'low',
          evidence: ym.matchedStrings.slice(0, 5).join(', '),
        });
      }

      // Parse deep analysis JSON
      let deepAnalysis: Record<string, unknown> | undefined;
      if (deepAnalysisOutput) {
        try { deepAnalysis = JSON.parse(deepAnalysisOutput) as Record<string, unknown>; } catch { /* */ }
      }

      // Recalculate risk score from all indicators.
      // Generic yara-binary matches (medium/low severity like UPX_Packer) are excluded
      // to avoid FPs on legitimate packed software. Critical/high yara-binary hits
      // (ransomware, wipers, RATs, injection) are scored — they're specific signatures.
      const finalRiskScore = (() => {
        let s = report.riskScore;
        let hasYaraRansomware = false;
        let hasYaraWiper = false;
        let hasYaraRat = false;
        for (const ind of extraIndicators) {
          if (isSandboxInfra(ind.evidence)) continue;
          if (ind.category === 'yara-binary') {
            if (ind.severity === 'critical') {
              s += 15;
              if (/ransom/i.test(ind.description)) hasYaraRansomware = true;
              if (/wiper|mbr/i.test(ind.description)) hasYaraWiper = true;
            } else if (ind.severity === 'high') {
              s += 8;
              if (/rat|backdoor|c2/i.test(ind.description)) hasYaraRat = true;
            }
            continue;
          }
          if (ind.category === 'ransomware') s = Math.max(s, 70);
          else if (ind.category === 'c2_communication') s = Math.max(s, 50);
          else if (ind.severity === 'critical') s += 20;
          else if (ind.severity === 'high') s += 10;
          else if (ind.severity === 'medium') s += 4;
          else s += 2;
        }
        if (hasYaraRansomware || hasYaraWiper) s = Math.max(s, 75);
        else if (hasYaraRat) s = Math.max(s, 55);
        return Math.min(100, s);
      })();

      const finalReport = {
        ...report,
        riskScore: finalRiskScore,
        suspiciousIndicators: extraIndicators,
        extractedFiles: jailFiles,
        straceAnalysis: jailStraceAnalysis,
        wineRegistryChanges: jailWineRegChanges,
        memoryStrings,
        yaraPatternMatches: (() => {
          if (!yaraPatternOutput) return [];
          try {
            const parsed = JSON.parse(yaraPatternOutput) as { yaraResults?: Array<{ matches?: Array<{ ruleName: string; category: string; description: string; severity: string; matchedStrings: string[]; matchOffset: number | null }> }> };
            return (parsed.yaraResults ?? []).flatMap(r => r.matches ?? []);
          } catch { return []; }
        })(),
        yaraPatternOutput: yaraPatternOutput || undefined,
        yaraBinaryMatches,
        configExtractionOutput: configExtractionOutput || undefined,
        pcapBase64: pcapBase64 || undefined,
        deepAnalysis,
        containerSbom: containerSbom ?? undefined,
      };
      return finalReport as DetonationReport;
    } finally {
      // j. Kill and remove the container
      if (containerId) {
        await dockerSafe(['kill', containerId]);
        await dockerSafe(['rm', '-f', '-v', containerId]);
      }

      // k. Clean up temp directory
      try {
        await rm(tmpDir, { recursive: true, force: true });
      } catch {
        // Non-fatal
      }
    }
  }

  // ── Private: container lifecycle ──────────────────────────────────────────

  /**
   * Start a fresh container with strict resource limits and security constraints.
   */
  private async startContainer(
    containerName: string,
    opts: ResolvedExecutionOptions,
  ): Promise<string> {
    const imageName = getImageName();

    const runArgs: string[] = [
      'run',
      '-d',                              // Detached
      '--name', containerName,
      // Resource limits
      '--memory', MEMORY_LIMIT,
      '--memory-swap', MEMORY_LIMIT,     // No swap
      '--cpus', CPU_LIMIT,
      '--pids-limit', '256',
      // Security: drop all capabilities
      '--cap-drop', 'ALL',
      // Re-add only what we need for strace and tcpdump
      '--cap-add', 'SYS_PTRACE',
      '--cap-add', 'NET_RAW',
      '--read-only',
      '--tmpfs', '/tmp:rw,exec,size=256m',
      '--tmpfs', '/run:rw,size=16m',
      '--tmpfs', '/opt/scanboy:rw,exec,size=64m',
      '--tmpfs', '/home/sandbox:rw,exec,size=128m,uid=1000,gid=1000,mode=750',
      '--security-opt', 'no-new-privileges',
      '--security-opt', 'seccomp=/app/packages/dynamic-analysis/seccomp-sandbox.json',
      '--ulimit', 'nofile=1024:2048',
      '--ulimit', 'nproc=256:256',
      // Override DNS — prevent host DNS leak, give malware believable (but unreachable) DNS
      '--dns', '8.8.8.8',
      '--dns', '4.4.4.4',
      // Network controlled by SANDBOX_ALLOW_NETWORK env var (default: off)
      '--network', process.env['SANDBOX_ALLOW_NETWORK'] === 'true' && (opts.networkMode === 'simulated' || opts.internetAccess) ? (process.env['SANDBOX_NETWORK_NAME'] ?? 'scanboy-sandbox-net') : 'none',
      imageName,
      '/bin/bash', '-c', 'exec sleep infinity >/dev/null 2>/dev/null',
    ];

    const { stdout } = await docker(runArgs, 30_000);
    const containerId = stdout.trim();

    if (!containerId) {
      throw new Error('Failed to start container: no container ID returned');
    }

    return containerId;
  }

  /**
   * Start all monitoring processes inside the container.
   */
  private async startMonitoring(
    containerId: string,
    opts: ResolvedExecutionOptions,
  ): Promise<void> {
    // Create log directory (may need root)
    await dockerExec(containerId, 'mkdir -p /tmp/scanboy-logs');

    // /proc/mountinfo leaks host fs paths (containerd layers, btrfs subvol).
    // Info-disclosure only — no escape vector with --read-only + --cap-drop ALL + --network none.
    // Docker's runc blocks bind-mounting over /proc and --security-opt mask= is not available
    // in this Docker build. Accepted risk given container is disposable and network-isolated.

    // Start inotifywait to monitor file changes in /home/sandbox and /tmp
    await dockerExec(
      containerId,
      `nohup inotifywait -m -r ` +
        `--format "%T %w%f %e" --timefmt "%s" ` +
        `${CONTAINER_SAMPLE_DIR} /tmp ` +
        `> ${CONTAINER_INOTIFY_LOG} 2>&1 &`,
    );

    // Start tcpdump if network capture is enabled — write binary pcap for download
    if (opts.captureNetwork) {
      await dockerExec(
        containerId,
        `nohup tcpdump -nn -i any -w /tmp/scanboy-logs/capture.pcap ` +
          `> /dev/null 2>&1 &`,
      );
      // Also keep text log for parsing
      await dockerExec(
        containerId,
        `nohup tcpdump -nn -q -i any -l ` +
          `> ${CONTAINER_TCPDUMP_LOG} 2>&1 &`,
      );
    }

    // Start FakeNet (network simulation) if mode is 'simulated'
    if (opts.networkMode === 'simulated') {
      await this.startNetworkSimulation(containerId);
    }

    // A short delay to let monitors initialize
    await dockerExec(containerId, 'sleep 0.5');
  }

  /**
   * Start FakeNet-like network simulation inside the container.
   * Responds to all DNS queries with 127.0.0.1 and serves HTTP 200 on port 80.
   * This causes malware to reveal C2 communication behavior.
   */
  private async startNetworkSimulation(containerId: string): Promise<void> {
    const fakeNetScript = [
      'import socket, threading',
      'from http.server import HTTPServer, BaseHTTPRequestHandler',
      '',
      'def dns_server():',
      '    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)',
      '    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)',
      '    s.bind(("0.0.0.0", 53))',
      '    while True:',
      '        try:',
      '            data, addr = s.recvfrom(512)',
      '            response = data[:2] + b"\\x81\\x80" + data[4:6] + data[4:6] + b"\\x00\\x00\\x00\\x00"',
      '            response += data[12:]',
      '            response += b"\\xc0\\x0c\\x00\\x01\\x00\\x01\\x00\\x00\\x00\\x3c\\x00\\x04\\x7f\\x00\\x00\\x01"',
      '            s.sendto(response, addr)',
      '        except Exception:',
      '            pass',
      '',
      'threading.Thread(target=dns_server, daemon=True).start()',
      '',
      'class H(BaseHTTPRequestHandler):',
      '    def do_GET(self):',
      '        self.send_response(200)',
      '        self.send_header("Content-Type", "text/html")',
      '        self.end_headers()',
      '        self.wfile.write(b"<html><body>OK</body></html>")',
      '    def do_POST(self): self.do_GET()',
      '    def do_PUT(self): self.do_GET()',
      '    def log_message(self, *a): pass',
      '',
      'HTTPServer(("0.0.0.0", 80), H).serve_forever()',
    ].join('\n');

    await dockerExec(
      containerId,
      `cat > /tmp/scanboy-fakenet.py << 'FAKENET_EOF'\n${fakeNetScript}\nFAKENET_EOF\nnohup python3 /tmp/scanboy-fakenet.py > /dev/null 2>&1 &`,
      10_000,
      'root',
    );
    // Configure DNS resolution to point to localhost
    // Note: /etc/resolv.conf is managed by Docker separately from the rootfs
    // and remains writable even with --read-only
    await dockerExec(
      containerId,
      `echo "nameserver 127.0.0.1" > /etc/resolv.conf 2>/dev/null || echo "WARNING: Could not set DNS resolver"`,
      5_000,
      'root',
    );
    console.error('[SANDBOX] FakeNet network simulation started');
  }

  /**
   * Execute the sample inside the container under strace.
   */
  private async executeSample(
    containerId: string,
    command: string,
    timeoutSeconds: number,
    sampleTypeLabel: string,
  ): Promise<{ exitCode: number | null; timedOut: boolean; durationMs: number }> {
    const startTime = Date.now();

    const scriptContent = [
      '#!/bin/bash',
      `cd ${CONTAINER_SAMPLE_DIR}`,
      command,
    ].join('\n');

    const { execFileSync: writeExecFs } = await import('node:child_process');
    try {
      writeExecFs('docker', ['exec', '-i', '-u', 'root', containerId, 'sh', '-c', 'cat > /tmp/scanboy-exec.sh && chmod +x /tmp/scanboy-exec.sh'], {
        input: Buffer.from(scriptContent), timeout: 10_000, maxBuffer: 1024 * 1024,
      });
    } catch (writeErr) {
      console.error(`[SANDBOX] Failed to write exec script: ${writeErr instanceof Error ? writeErr.message : String(writeErr)}`);
    }

    // Run under strace with a timeout (fall back to plain execution if strace fails)
    const stracePrefix = [
      `strace -f -t -o ${CONTAINER_STRACE_LOG}`,
      `-e trace=open,openat,creat,connect,socket,bind,sendto,execve,clone,clone3,fork,vfork,write,pwrite64,unlink,unlinkat,rename,renameat,renameat2,chmod,fchmod,fchmodat,mkdir,mkdirat,symlink,link`,
    ].join(' ');
    const straceCommand = `timeout ${timeoutSeconds} ${stracePrefix} /bin/bash /tmp/scanboy-exec.sh`;
    const plainCommand = `timeout ${timeoutSeconds} /bin/bash /tmp/scanboy-exec.sh`;

    // Execute as the sandbox user
    let timedOut = false;
    let exitCode: number | null = null;
    void 0; // strace fallback tracking

    try {
      const { stdout, stderr } = await execFile(
        'docker',
        ['exec', '-u', 'sandbox', containerId, '/bin/sh', '-c', straceCommand] as string[],
        {
          timeout: (timeoutSeconds + 10) * 1000,
          maxBuffer: 50 * 1024 * 1024,
        },
      );
      exitCode = 0;
      if (stdout) console.error(`[SANDBOX] Exec stdout (last 300): ${stdout.slice(-300)}`);
      void stderr;
    } catch (err: unknown) {
      if (isExecError(err)) {
        const execErr = err as { stderr?: string; stdout?: string };
        const stderrStr = String(execErr.stderr ?? '');
        // If strace itself failed (ptrace denied), retry without strace
        if (stderrStr.includes('PTRACE') || stderrStr.includes('ptrace')) {
          console.error('[SANDBOX] strace failed (ptrace denied), retrying without strace');
          try {
            const { stdout: plainOut } = await execFile(
              'docker',
              ['exec', '-u', 'sandbox', containerId, '/bin/sh', '-c', plainCommand] as string[],
              {
                timeout: (timeoutSeconds + 10) * 1000,
                maxBuffer: 50 * 1024 * 1024,
              },
            );
            exitCode = 0;
            if (plainOut) console.error(`[SANDBOX] Exec stdout (last 300): ${plainOut.slice(-300)}`);
          } catch (retryErr: unknown) {
            if (isExecError(retryErr)) {
              if (retryErr.killed || (retryErr.code === null && retryErr.signal === 'SIGTERM')) {
                timedOut = true;
                exitCode = null;
              } else if (typeof retryErr.code === 'number') {
                exitCode = retryErr.code;
                if (exitCode === 124) timedOut = true;
              } else {
                exitCode = 1;
              }
              const retryExecErr = retryErr as { stderr?: string; stdout?: string };
              console.error(`[SANDBOX] Exec (no-strace) exit=${exitCode} timedOut=${timedOut} stderr=${String(retryExecErr.stderr ?? '').slice(0, 500)} stdout_tail=${String(retryExecErr.stdout ?? '').slice(-300)}`);
            } else {
              exitCode = 1;
              console.error(`[SANDBOX] Exec (no-strace) error: ${retryErr instanceof Error ? retryErr.message : String(retryErr)}`);
            }
          }
        } else {
          if (err.killed || (err.code === null && err.signal === 'SIGTERM')) {
            timedOut = true;
            exitCode = null;
          } else if (typeof err.code === 'number') {
            exitCode = err.code;
            if (exitCode === 124) {
              timedOut = true;
            }
          } else {
            exitCode = 1;
          }
          console.error(`[SANDBOX] Exec exit=${exitCode} timedOut=${timedOut} stderr=${stderrStr.slice(0, 500)} stdout_tail=${String(execErr.stdout ?? '').slice(-300)}`);
        }
      } else {
        exitCode = 1;
        console.error(`[SANDBOX] Exec non-exec error: ${err instanceof Error ? err.message : String(err)}`);
      }
    }

    const durationMs = Date.now() - startTime;
    console.error(`[SANDBOX] Execution took ${durationMs}ms, exitCode=${exitCode}, timedOut=${timedOut}`);

    void sampleTypeLabel; // Used by caller for labeling

    return { exitCode, timedOut, durationMs };
  }

  /**
   * Collect all monitoring output from the container.
   */
  private async collectMonitoringOutput(containerId: string): Promise<{
    strace: string;
    inotify: string;
    tcpdump: string;
    ps: string;
    droppedFiles: string;
  }> {
    // Collect all outputs in parallel
    const [strace, inotify, tcpdump, ps, droppedFiles] = await Promise.all([
      dockerExec(containerId, `cat ${CONTAINER_STRACE_LOG} 2>/dev/null || echo ""`, 30_000),
      dockerExec(containerId, `cat ${CONTAINER_INOTIFY_LOG} 2>/dev/null || echo ""`, 15_000),
      dockerExec(containerId, `cat ${CONTAINER_TCPDUMP_LOG} 2>/dev/null || echo ""`, 15_000),
      dockerExec(
        containerId,
        'ps -eo pid,ppid,user,comm,args --no-headers 2>/dev/null || echo ""',
        10_000,
      ),
      // Find files created/modified in the sandbox directories, with metadata
      dockerExec(
        containerId,
        `find /home/sandbox /tmp/scanboy-extracted -type f -not -path "*/scanboy-logs/*" -not -name "scanboy-exec.sh" -not -name "sample" 2>/dev/null | while read -r fpath; do\nfsize=$(stat -c%s "$fpath" 2>/dev/null || echo "0")\nfhash=$(sha256sum "$fpath" 2>/dev/null | cut -d' ' -f1 || echo "")\nfmime=$(file -b --mime-type "$fpath" 2>/dev/null || echo "")\necho "$fpath|$fsize|$fhash|$fmime"\ndone`,
        15_000,
      ),
    ]);

    return { strace, inotify, tcpdump, ps, droppedFiles };
  }

  /**
   * Dump strings from process memory of sandbox user processes (best-effort).
   * Finds IOC-like strings: URLs, IPs, domains, registry keys, file paths,
   * and other indicators from process memory regions.
   */
  private async collectMemoryStrings(containerId: string): Promise<string[]> {
    try {
      const dumpScript = [
        'RESULTS=""',
        'for pid in $(ps -u sandbox -o pid= 2>/dev/null); do',
        '  STRINGS=$(strings -n 8 /proc/$pid/mem 2>/dev/null | grep -iE "https?://|ftp://|\\.exe|\\.dll|\\.sys|\\.bat|\\.ps1|\\.vbs|HKLM|HKCU|HKEY_|password|encrypt|decrypt|ransom|bitcoin|wallet|C:\\\\\\\\|%APPDATA%|%TEMP%|cmd\\.exe|powershell|([0-9]{1,3}\\.){3}[0-9]{1,3}" | head -50)',
        '  if [ -n "$STRINGS" ]; then',
        '    RESULTS="${RESULTS}${STRINGS}\\n"',
        '  fi',
        'done',
        'echo "$RESULTS"',
      ].join('\n');

      const output = await dockerExec(containerId, dumpScript, 30_000, 'root');

      if (!output.trim()) {
        return [];
      }

      // Deduplicate, filter empty lines, limit total
      const lines = output.split('\n')
        .map(line => line.trim())
        .filter(line => line.length > 0);

      const unique = [...new Set(lines)];
      return unique.slice(0, 200);
    } catch {
      // Best-effort: processes may have already exited
      return [];
    }
  }
}

// ── Utility functions ────────────────────────────────────────────────���──────

function resolveOptions(options?: ExecutionOptions): ResolvedExecutionOptions {
  const networkMode: NetworkMode = options?.networkMode ?? 'isolated';

  // Clamp timeout to a safe maximum to prevent indefinite container lifetimes
  const MAX_TIMEOUT_SECONDS = 600; // 10 minutes absolute max
  const requestedTimeout = options?.timeoutSeconds ?? DEFAULT_TIMEOUT_SECONDS;
  const timeoutSeconds = Math.min(Math.max(1, requestedTimeout), MAX_TIMEOUT_SECONDS);

  return {
    timeoutSeconds,
    internetAccess: options?.internetAccess ?? (networkMode === 'controlled'),
    captureNetwork: options?.captureNetwork ?? DEFAULT_CAPTURE_NETWORK,
    networkMode,
    targetUrl: options?.targetUrl ?? null,
  };
}

interface ExecError {
  killed: boolean;
  code: number | string | null;
  signal: string | null;
  message: string;
}

function isExecError(err: unknown): err is ExecError {
  return (
    typeof err === 'object' &&
    err !== null &&
    'message' in err
  );
}

// (Former rule content deleted — UPX_Packer, Themida_VMProtect, etc.)

// ── Config Extraction Script Builder ────────────────────────────────────────

// NOTE: detectedFamily was previously a module-level mutable global, which
// caused a race condition when multiple sandbox executions ran concurrently.
// It is now declared as a local variable within the execute() method body.

/**
 * Returns a Python config extraction script for the given malware family,
 * or null if the family is not supported.
 */
function buildConfigExtractorScript(family: string): string | null {
  const supportedFamilies = [
    'cobalt strike', 'cobaltstrike', 'beacon',
    'emotet', 'agent tesla', 'agenttesla',
    'remcos', 'asyncrat', 'async rat',
    'qakbot', 'qbot',
  ];

  if (!family || !supportedFamilies.some(f => family.toLowerCase().includes(f))) {
    return null;
  }

  return `import json, os, sys, struct, re, hashlib, base64, binascii

FAMILY = ${JSON.stringify(family.toLowerCase().replace(/[^a-z0-9 _\-./]/g, ''))}
SAMPLE_PATH = "/opt/scanboy/sample"

def xor_decrypt(data, key):
    if isinstance(key, int):
        return bytes(b ^ key for b in data)
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

def rc4_decrypt(data, key):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    result = bytearray()
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        result.append(byte ^ S[(S[i] + S[j]) % 256])
    return bytes(result)

def extract_ipv4(data):
    text = data.decode('ascii', errors='ignore')
    ips = set()
    for m in re.finditer(r'(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})(:\\d{1,5})?', text):
        ip = m.group(1)
        parts = ip.split('.')
        if all(0 <= int(p) <= 255 for p in parts):
            if int(parts[0]) not in (0, 127, 169, 224, 255):
                ips.add(m.group(0))
    return list(ips)

def extract_urls(data):
    text = data.decode('ascii', errors='ignore')
    return list(set(re.findall(r'https?://[a-zA-Z0-9._/\\-:@]+', text)))

def extract_cobalt_strike(data):
    result = {'family': 'Cobalt Strike', 'confidence': 0, 'c2Servers': [], 'encryptionKeys': [], 'mutexes': [], 'campaignId': None, 'botId': None, 'raw': {}}
    xor_keys = [0x69, 0x2e]
    config_marker = b'\\x00\\x01\\x00\\x01\\x00\\x02'
    for key in xor_keys:
        decrypted = xor_decrypt(data, key)
        idx = decrypted.find(config_marker)
        if idx >= 0:
            cfg = decrypted[idx:idx+4096]
            pos = 0
            while pos < len(cfg) - 4:
                try:
                    ft = struct.unpack('>H', cfg[pos:pos+2])[0]
                    fl = struct.unpack('>H', cfg[pos+2:pos+4])[0]
                    pos += 4
                    if fl > 4096 or pos + fl > len(cfg): break
                    fd = cfg[pos:pos+fl]
                    pos += fl
                    if ft == 8:
                        c2 = fd.decode('ascii', errors='ignore').strip('\\x00')
                        for s in c2.split(','):
                            if s.strip(): result['c2Servers'].append(s.strip())
                    elif ft == 7:
                        result['encryptionKeys'].append(binascii.hexlify(fd[:32]).decode())
                    elif ft == 37 and fl == 4:
                        wm = struct.unpack('>I', fd)[0]
                        result['campaignId'] = str(wm)
                        result['raw']['watermark'] = wm
                except: break
            result['confidence'] = 90 if result['c2Servers'] else 60
            return result
    result['c2Servers'] = extract_urls(data)[:10] + extract_ipv4(data)[:10]
    result['confidence'] = 40 if result['c2Servers'] else 0
    return result if result['c2Servers'] else None

def extract_emotet(data):
    result = {'family': 'Emotet', 'confidence': 0, 'c2Servers': [], 'encryptionKeys': [], 'mutexes': [], 'campaignId': None, 'botId': None, 'raw': {}}
    for marker in [b'-----BEGIN PUBLIC KEY-----', b'RSA1']:
        idx = data.find(marker)
        if idx >= 0:
            result['encryptionKeys'].append(f"RSA key at 0x{idx:x}")
            break
    ips = extract_ipv4(data)
    result['c2Servers'] = ips[:30]
    result['confidence'] = 70 if len(ips) >= 3 else 40
    return result if result['c2Servers'] or result['encryptionKeys'] else None

def extract_agenttesla(data):
    result = {'family': 'Agent Tesla', 'confidence': 0, 'c2Servers': [], 'encryptionKeys': [], 'mutexes': [], 'campaignId': None, 'botId': None, 'raw': {}}
    text = data.decode('ascii', errors='ignore')
    for m in re.finditer(r'smtp\\.[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}', text):
        result['c2Servers'].append(m.group(0))
    for m in re.finditer(r'ftp://[a-zA-Z0-9._/\\-:@]+', text):
        result['c2Servers'].append(m.group(0))
    emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}', text)
    if emails: result['raw']['emails'] = emails[:10]
    result['confidence'] = 85 if result['c2Servers'] else 0
    return result if result['c2Servers'] else None

def extract_remcos(data):
    result = {'family': 'Remcos RAT', 'confidence': 0, 'c2Servers': [], 'encryptionKeys': [], 'mutexes': [], 'campaignId': None, 'botId': None, 'raw': {}}
    idx = data.find(b'SETTINGS')
    if idx >= 0:
        cfg = data[idx+8:idx+4096]
        if len(cfg) > 2:
            kl = cfg[0]
            if 1 <= kl <= 32 and kl + 1 < len(cfg):
                key = cfg[1:1+kl]
                decrypted = rc4_decrypt(cfg[1+kl:], key)
                result['encryptionKeys'].append(binascii.hexlify(key).decode())
                text = decrypted.decode('ascii', errors='ignore')
                for f in re.split(r'[|\\x00]', text):
                    f = f.strip()
                    if re.match(r'\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}', f):
                        result['c2Servers'].append(f)
                    elif re.match(r'[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}', f) and len(f) > 4:
                        result['c2Servers'].append(f)
    if not result['c2Servers']:
        result['c2Servers'] = extract_ipv4(data)[:10]
    result['confidence'] = 85 if result['c2Servers'] else 0
    return result if result['c2Servers'] or result['encryptionKeys'] else None

def extract_asyncrat(data):
    result = {'family': 'AsyncRAT', 'confidence': 0, 'c2Servers': [], 'encryptionKeys': [], 'mutexes': [], 'campaignId': None, 'botId': None, 'raw': {}}
    markers = ['Ports', 'Hosts', 'Version', 'MTX', 'Group']
    found = [m for m in markers if m.encode() in data]
    result['raw']['found_markers'] = found
    result['c2Servers'] = extract_ipv4(data)[:10]
    result['confidence'] = 75 if result['c2Servers'] and found else (40 if found else 0)
    return result if result['c2Servers'] or found else None

def extract_qakbot(data):
    result = {'family': 'QakBot', 'confidence': 0, 'c2Servers': [], 'encryptionKeys': [], 'mutexes': [], 'campaignId': None, 'botId': None, 'raw': {}}
    result['c2Servers'] = extract_ipv4(data)[:30]
    text = data.decode('ascii', errors='ignore')
    for m in re.finditer(r'(obama\\d*|biden\\d*|tok\\d*|bb\\d*|aa\\d*)', text, re.I):
        result['campaignId'] = m.group(0)
        break
    result['confidence'] = 70 if len(result['c2Servers']) >= 3 else 40
    return result if result['c2Servers'] else None

def main():
    if not os.path.isfile(SAMPLE_PATH):
        print(json.dumps({"success": False, "config": None, "error": "not found"}))
        return
    with open(SAMPLE_PATH, "rb") as f:
        data = f.read(50 * 1024 * 1024)
    extractors = {
        'cobalt strike': extract_cobalt_strike, 'cobaltstrike': extract_cobalt_strike, 'beacon': extract_cobalt_strike,
        'emotet': extract_emotet, 'agent tesla': extract_agenttesla, 'agenttesla': extract_agenttesla,
        'remcos': extract_remcos, 'asyncrat': extract_asyncrat, 'async rat': extract_asyncrat,
        'qakbot': extract_qakbot, 'qbot': extract_qakbot,
    }
    ext = None
    for k, f in extractors.items():
        if k in FAMILY: ext = f; break
    if not ext:
        print(json.dumps({"success": False, "config": None, "error": "unsupported family"}))
        return
    try:
        cfg = ext(data)
        if cfg:
            print(json.dumps({"success": True, "config": cfg, "error": None}))
        else:
            print(json.dumps({"success": False, "config": None, "error": "no config found"}))
    except Exception as e:
        print(json.dumps({"success": False, "config": None, "error": str(e)}))

if __name__ == "__main__":
    main()
`;
}
