// ── Sandbox Enhancements — helper functions for the Docker executor ──────────
//
// All functions are pure: they return strings or data structures with no side
// effects. The executor calls them at appropriate points in the detonation
// pipeline.

// ── 1. Sleep Acceleration ──────────────────────────────────────────────────────
//
// An LD_PRELOAD hook that intercepts sleep/usleep/nanosleep so that time-delay
// malware proceeds instantly.

/**
 * Returns bash commands to compile a shared library that neutralises all sleep
 * calls, then exports LD_PRELOAD so that any subsequently launched binary will
 * use it.
 */
export function getSleepAcceleratorSetup(): string {
  return `
cat > /tmp/nosleep.c << 'NOSLEEP_EOF'
#include <time.h>
#include <unistd.h>
#include <stdint.h>

/* Override sleep family - return immediately */
unsigned int sleep(unsigned int seconds) {
    (void)seconds;
    return 0;
}

int usleep(useconds_t usec) {
    (void)usec;
    return 0;
}

int nanosleep(const struct timespec *req, struct timespec *rem) {
    (void)req;
    if (rem) {
        rem->tv_sec = 0;
        rem->tv_nsec = 0;
    }
    return 0;
}

/* Also intercept clock_nanosleep which some malware uses */
int clock_nanosleep(clockid_t clock_id, int flags,
                    const struct timespec *request,
                    struct timespec *remain) {
    (void)clock_id;
    (void)flags;
    (void)request;
    if (remain) {
        remain->tv_sec = 0;
        remain->tv_nsec = 0;
    }
    return 0;
}
NOSLEEP_EOF
gcc -shared -fPIC -o /tmp/nosleep.so /tmp/nosleep.c 2>/dev/null || true
export LD_PRELOAD=/tmp/nosleep.so
`;
}

// ── 2. Fake User Activity Injection ────────────────────────────────────────────
//
// Many sandbox-aware malware checks for human interaction (mouse moves, clicks,
// keyboard activity). This script simulates ongoing user presence.

/**
 * Returns bash commands that launch a background process simulating user
 * activity. Uses xdotool if available, otherwise falls back to Python+Xlib.
 */
export function getFakeUserActivityScript(): string {
  return `
# Start fake user activity in the background
(
  if command -v xdotool >/dev/null 2>&1; then
    # xdotool approach - lightweight and reliable
    SCREEN_W=\${DISPLAY_WIDTH:-1024}
    SCREEN_H=\${DISPLAY_HEIGHT:-768}
    ITERATION=0
    while true; do
      ITERATION=$((ITERATION + 1))

      # Move mouse to a random position
      X=$((RANDOM % SCREEN_W))
      Y=$((RANDOM % SCREEN_H))
      xdotool mousemove --sync "$X" "$Y" 2>/dev/null

      # Every 3rd iteration, simulate a click
      if [ $((ITERATION % 3)) -eq 0 ]; then
        xdotool click 1 2>/dev/null
      fi

      # Every 5th iteration, type some characters
      if [ $((ITERATION % 5)) -eq 0 ]; then
        xdotool type --delay 50 "test" 2>/dev/null
      fi

      # Every 7th iteration, try to cycle window focus
      if [ $((ITERATION % 7)) -eq 0 ]; then
        xdotool key alt+Tab 2>/dev/null
      fi

      # Sleep 2-3 seconds between actions (use real sleep here, not hooked)
      /bin/sleep $((2 + RANDOM % 2))
    done
  elif command -v python3 >/dev/null 2>&1; then
    # Python fallback using ctypes to call X11 directly
    python3 << 'PYEOF'
import ctypes
import ctypes.util
import random
import time
import os

try:
    xlib_path = ctypes.util.find_library("X11")
    if not xlib_path:
        exit(0)
    xlib = ctypes.cdll.LoadLibrary(xlib_path)

    display = xlib.XOpenDisplay(None)
    if not display:
        exit(0)

    screen = xlib.XDefaultScreen(display)
    root = xlib.XRootWindow(display, screen)
    width = xlib.XDisplayWidth(display, screen)
    height = xlib.XDisplayHeight(display, screen)

    while True:
        # Move pointer to random position
        x = random.randint(0, width - 1)
        y = random.randint(0, height - 1)
        xlib.XWarpPointer(display, 0, root, 0, 0, 0, 0, x, y)
        xlib.XFlush(display)

        time.sleep(random.uniform(2.0, 3.0))
except Exception:
    pass
PYEOF
  else
    # No suitable tool - just do nothing
    true
  fi
) &
FAKE_USER_PID=$!
`;
}

// ── 3. Filesystem Snapshot Diffing ─────────────────────────────────────────────
//
// Captures filesystem state before execution and diffs after to discover all
// file-level changes the sample made.

/**
 * Returns bash commands to record a filesystem marker before sample execution.
 * The marker file's timestamp serves as the reference point.
 */
export function getPreExecutionSnapshot(): string {
  return `
# Create a timestamp marker for filesystem diffing
touch /tmp/scanboy_snapshot_marker
sync
# Record baseline of key directories (hash + path)
find /home /tmp /var /etc /usr/local /opt -type f 2>/dev/null | sort > /tmp/scanboy_baseline_files.txt
# Record permissions baseline
find /home /tmp /var /etc /usr/local /opt -type f -printf '%m %u:%g %p\\n' 2>/dev/null | sort > /tmp/scanboy_baseline_perms.txt
# Record symlinks baseline
find /home /tmp /var /etc /usr/local /opt -type l -printf '%p -> %l\\n' 2>/dev/null | sort > /tmp/scanboy_baseline_symlinks.txt
`;
}

/**
 * Returns bash commands to diff the filesystem against the pre-execution
 * snapshot. Outputs structured data about new, modified, deleted, and
 * permission-changed files.
 */
export function getPostExecutionDiff(): string {
  return `
echo "=== SCANBOY_FS_DIFF_START ==="

# 1. Files created (newer than the marker)
echo "--- NEW_FILES ---"
find /home /tmp /var /etc /usr/local /opt -type f -newer /tmp/scanboy_snapshot_marker 2>/dev/null | \
  while IFS= read -r f; do
    # Skip our own log/monitoring files
    case "$f" in
      /tmp/scanboy-logs/*|/tmp/scanboy_*|/tmp/nosleep*) continue ;;
    esac
    SIZE=$(stat -c%s "$f" 2>/dev/null || echo "0")
    HASH=$(sha256sum "$f" 2>/dev/null | cut -d' ' -f1 || echo "unknown")
    echo "NEW|$f|$SIZE|$HASH"
  done

# 2. Files modified (exist in baseline but newer than marker)
echo "--- MODIFIED_FILES ---"
find /home /tmp /var /etc /usr/local /opt -type f -newer /tmp/scanboy_snapshot_marker 2>/dev/null | sort > /tmp/scanboy_post_files.txt
comm -12 /tmp/scanboy_baseline_files.txt /tmp/scanboy_post_files.txt 2>/dev/null | \
  while IFS= read -r f; do
    case "$f" in
      /tmp/scanboy-logs/*|/tmp/scanboy_*|/tmp/nosleep*) continue ;;
    esac
    SIZE=$(stat -c%s "$f" 2>/dev/null || echo "0")
    HASH=$(sha256sum "$f" 2>/dev/null | cut -d' ' -f1 || echo "unknown")
    echo "MODIFIED|$f|$SIZE|$HASH"
  done

# 3. Files deleted (in baseline but no longer exist)
echo "--- DELETED_FILES ---"
find /home /tmp /var /etc /usr/local /opt -type f 2>/dev/null | sort > /tmp/scanboy_current_files.txt
comm -23 /tmp/scanboy_baseline_files.txt /tmp/scanboy_current_files.txt 2>/dev/null | \
  while IFS= read -r f; do
    case "$f" in
      /tmp/scanboy-logs/*|/tmp/scanboy_*|/tmp/nosleep*) continue ;;
    esac
    echo "DELETED|$f"
  done

# 4. Permission changes
echo "--- PERM_CHANGES ---"
find /home /tmp /var /etc /usr/local /opt -type f -printf '%m %u:%g %p\\n' 2>/dev/null | sort > /tmp/scanboy_current_perms.txt
diff /tmp/scanboy_baseline_perms.txt /tmp/scanboy_current_perms.txt 2>/dev/null | grep '^[<>]' | head -100 | \
  while IFS= read -r line; do
    echo "PERM|$line"
  done

# 5. New symlinks
echo "--- NEW_SYMLINKS ---"
find /home /tmp /var /etc /usr/local /opt -type l -printf '%p -> %l\\n' 2>/dev/null | sort > /tmp/scanboy_current_symlinks.txt
comm -13 /tmp/scanboy_baseline_symlinks.txt /tmp/scanboy_current_symlinks.txt 2>/dev/null | \
  while IFS= read -r line; do
    echo "SYMLINK|$line"
  done

echo "=== SCANBOY_FS_DIFF_END ==="
`;
}

// ── 4. Windows API Hooking via Wine DLL Overrides ──────────────────────────────
//
// Uses Wine's built-in relay tracing to log calls to security-relevant Windows
// APIs without needing to build actual override DLLs.

/**
 * Returns bash commands to configure Wine's relay tracing for security-relevant
 * API calls. The output must be filtered through the patterns returned by
 * getWineRelayFilterPatterns().
 */
export function getWineApiHookingSetup(): string {
  return `
# Configure Wine relay tracing for key APIs
export WINEDEBUG=+relay,+seh
export WINEPREFIX=/tmp/wineprefix

# Set up Wine prefix silently if needed
wineboot --init 2>/dev/null || true

# The relay trace will log all DLL function calls.
# We filter the output to only interesting functions during post-processing.
# Set DLL overrides to use built-in versions (ensures tracing works)
export WINEDLLOVERRIDES="kernel32=b;ws2_32=b;advapi32=b;shell32=b;ntdll=b"
`;
}

/**
 * Returns the grep pattern to filter Wine relay output for interesting API
 * calls. Use with: wine sample.exe 2>&1 | grep -E "$(getWineRelayFilter())"
 */
export function getWineRelayFilter(): string {
  const patterns = [
    // kernel32.dll - file and process operations
    'CreateFileW',
    'CreateFileA',
    'WriteFile',
    'CreateProcessW',
    'CreateProcessA',
    'VirtualAlloc',
    'VirtualAllocEx',
    'VirtualProtect',
    'LoadLibraryA',
    'LoadLibraryW',
    'LoadLibraryExA',
    'LoadLibraryExW',
    'GetProcAddress',
    'WinExec',
    // ws2_32.dll - network operations
    'connect',
    'send',
    'recv',
    'WSAConnect',
    'WSASend',
    'InternetOpenA',
    'InternetOpenUrlA',
    'HttpSendRequestA',
    // advapi32.dll - registry and service operations
    'RegSetValueExA',
    'RegSetValueExW',
    'RegCreateKeyExA',
    'RegCreateKeyExW',
    'CreateServiceA',
    'CreateServiceW',
    'OpenSCManagerA',
    'OpenSCManagerW',
    'StartServiceA',
    'StartServiceW',
    // shell32.dll - execution
    'ShellExecuteA',
    'ShellExecuteW',
    'ShellExecuteExA',
    'ShellExecuteExW',
    // ntdll.dll - low-level
    'NtWriteVirtualMemory',
    'NtCreateThread',
    'NtCreateThreadEx',
    'RtlCreateUserThread',
  ];
  return patterns.join('|');
}

/**
 * Returns the full wine execution command with relay tracing enabled and
 * output filtered to relevant API calls.
 */
export function getWineTracedExecutionCommand(samplePath: string): string {
  const filter = getWineRelayFilter();
  return `
export WINEDEBUG=+relay
export WINEPREFIX=/tmp/wineprefix
wineboot --init 2>/dev/null || true
wine "${samplePath}" 2>&1 | grep -E "${filter}" | head -5000
`;
}

// ── 5. Enhanced PE Execution with Proton Fallback ──────────────────────────────
//
// Tries multiple approaches to execute Windows PE files: standard wine, wine
// with Windows 10 version spoofing, wine64, and box86/box64 as last resort.

/**
 * Returns bash commands that attempt PE execution through multiple backends,
 * falling through on failure.
 */
export function getEnhancedPeExecutionCommand(samplePath: string): string {
  return `
export WINEPREFIX=/tmp/wineprefix
export WINEARCH=win32

# Initialize wine prefix
wineboot --init 2>/dev/null || true

# Spoof Windows 10 version to trigger version-gated malware behavior
wine reg add "HKLM\\\\Software\\\\Microsoft\\\\Windows NT\\\\CurrentVersion" /v CurrentVersion /d "10.0" /f 2>/dev/null || true
wine reg add "HKLM\\\\Software\\\\Microsoft\\\\Windows NT\\\\CurrentVersion" /v CurrentBuildNumber /d "19041" /f 2>/dev/null || true
wine reg add "HKLM\\\\Software\\\\Microsoft\\\\Windows NT\\\\CurrentVersion" /v ProductName /d "Windows 10 Pro" /f 2>/dev/null || true

# Attempt 1: wine (32-bit)
echo "=== WINE_EXEC_ATTEMPT_1: wine ==="
timeout 60 wine "${samplePath}" 2>&1 && exit 0

# Attempt 2: wine64 (if file is PE64)
echo "=== WINE_EXEC_ATTEMPT_2: wine64 ==="
export WINEARCH=win64
timeout 60 wine64 "${samplePath}" 2>&1 && exit 0

# Attempt 3: box86 for 32-bit PE (if available)
if command -v box86 >/dev/null 2>&1; then
  echo "=== WINE_EXEC_ATTEMPT_3: box86+wine ==="
  timeout 60 box86 wine "${samplePath}" 2>&1 && exit 0
fi

# Attempt 4: box64 for 64-bit PE (if available)
if command -v box64 >/dev/null 2>&1; then
  echo "=== WINE_EXEC_ATTEMPT_4: box64+wine64 ==="
  timeout 60 box64 wine64 "${samplePath}" 2>&1 && exit 0
fi

echo "PE execution failed - all backends exhausted"
`;
}

// ── 6. Detect Service Disable Attempts ─────────────────────────────────────────
//
// Patterns that indicate malware is trying to stop or disable security services
// (common in ransomware, wipers, and advanced persistent threats).

/**
 * Returns an array of patterns to match against strace/wine/process output
 * that indicate attempts to manipulate or disable system services.
 */
export function getServiceMonitorPatterns(): string[] {
  return [
    // Windows service manipulation (cmd/powershell)
    'net stop',
    'net start',
    'sc stop',
    'sc delete',
    'sc config.*disabled',
    'sc config.*demand',
    // Process termination
    'taskkill /f /im',
    'taskkill /F /IM',
    'wmic process.*delete',
    'wmic process.*terminate',
    // Shadow copy / backup deletion (ransomware hallmark)
    'vssadmin delete shadows',
    'vssadmin resize shadowstorage',
    'wmic shadowcopy delete',
    // Boot configuration tampering
    'bcdedit /set.*safeboot',
    'bcdedit /set.*recoveryenabled.*no',
    'bcdedit /set.*bootstatuspolicy.*ignoreallfailures',
    // PowerShell service manipulation
    'powershell.*Stop-Service',
    'powershell.*Set-Service.*Disabled',
    'powershell.*Remove-Service',
    'powershell.*Disable-ComputerRestore',
    // Backup catalog deletion
    'wbadmin delete catalog',
    'wbadmin delete systemstatebackup',
    // Windows Defender manipulation
    'powershell.*Set-MpPreference.*-DisableRealtimeMonitoring',
    'powershell.*Add-MpPreference.*-ExclusionPath',
    'reg.*Windows Defender.*DisableAntiSpyware',
    // Windows Firewall manipulation
    'netsh advfirewall set.*state off',
    'netsh firewall set opmode disable',
    // Event log clearing
    'wevtutil cl',
    'powershell.*Clear-EventLog',
    // Linux equivalents
    'systemctl stop',
    'systemctl disable',
    'service.*stop',
    'killall',
    'pkill',
  ];
}

// ── 7. Detect Windows Folder Write Attempts ────────────────────────────────────
//
// Paths that malware commonly targets for persistence, payload drops, or
// lateral movement.

/**
 * Returns an array of regex patterns matching Windows system directories that
 * malware attempts to write to (as seen in strace/wine output).
 */
export function getSystemFolderWritePatterns(): string[] {
  return [
    // Core system directories
    'C:\\\\Windows\\\\',
    'C:\\\\Windows\\\\System32\\\\',
    'C:\\\\Windows\\\\SysWOW64\\\\',
    'C:\\\\Windows\\\\Temp\\\\',
    'C:\\\\Windows\\\\Tasks\\\\',
    // Application data
    'C:\\\\ProgramData\\\\',
    'C:\\\\Program Files\\\\',
    'C:\\\\Program Files \\(x86\\)\\\\',
    // User profile directories
    'C:\\\\Users\\\\.*\\\\AppData\\\\',
    'C:\\\\Users\\\\.*\\\\AppData\\\\Local\\\\Temp\\\\',
    'C:\\\\Users\\\\.*\\\\AppData\\\\Roaming\\\\',
    // Startup persistence locations
    'C:\\\\Users\\\\.*\\\\Start Menu\\\\Programs\\\\Startup\\\\',
    'C:\\\\ProgramData\\\\Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\Startup\\\\',
    // Environment variable paths (as literal strings in malware output)
    '%TEMP%',
    '%TMP%',
    '%APPDATA%',
    '%LOCALAPPDATA%',
    '%SYSTEMROOT%',
    '%WINDIR%',
    '%PROGRAMDATA%',
    '%PROGRAMFILES%',
    '%USERPROFILE%',
    // Wine-mapped equivalents on Linux
    '/home/.*/.wine/drive_c/windows/',
    '/home/.*/.wine/drive_c/users/',
    '/home/.*/.wine/drive_c/ProgramData/',
  ];
}

// ── Utility: match output against patterns ─────────────────────────────────────

export interface PatternMatch {
  readonly pattern: string;
  readonly matchedText: string;
  readonly lineNumber: number;
}

/**
 * Scans output text against a list of patterns and returns all matches.
 * Used by the executor to detect service manipulation and system writes.
 */
export function matchPatterns(
  output: string,
  patterns: string[],
): PatternMatch[] {
  const matches: PatternMatch[] = [];
  const lines = output.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const pattern of patterns) {
      if (pattern.length > 200) continue;
      try {
        const re = new RegExp(pattern, 'i');
        const match = re.exec(line ?? '');
        if (match) {
          matches.push({
            pattern,
            matchedText: match[0].slice(0, 500),
            lineNumber: i + 1,
          });
        }
      } catch {
        if (line!.toLowerCase().includes(pattern.toLowerCase())) {
          matches.push({
            pattern,
            matchedText: pattern,
            lineNumber: i + 1,
          });
        }
      }
    }
  }

  return matches;
}
