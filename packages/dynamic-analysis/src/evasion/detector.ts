import type pino from 'pino';
import type { ProcessEvent } from '../monitors/processMonitor.js';
import type { FileEvent } from '../monitors/fileMonitor.js';
import type { RegistryEvent } from '../monitors/registryMonitor.js';
import type { NetworkEvent } from '../monitors/networkMonitor.js';

// ── Types ───────────────────────────────────────────────────────────────────

export interface EvasionDetectionResult {
  readonly attempts: readonly EvasionAttempt[];
  readonly overallEvasionScore: number;
  readonly categories: readonly EvasionCategorySummary[];
}

interface EvasionAttempt {
  readonly technique: string;
  readonly category: EvasionCategory;
  readonly description: string;
  readonly severity: 'low' | 'medium' | 'high' | 'critical';
  readonly evidence: string;
  readonly mitreTechniqueId: string | null;
}

type EvasionCategory =
  | 'vm_detection'
  | 'sandbox_detection'
  | 'timing_evasion'
  | 'environment_check'
  | 'anti_debug'
  | 'anti_analysis';

interface EvasionCategorySummary {
  readonly category: EvasionCategory;
  readonly attemptCount: number;
  readonly maxSeverity: 'low' | 'medium' | 'high' | 'critical';
}

interface AnalysisInput {
  readonly processEvents: readonly ProcessEvent[];
  readonly fileEvents: readonly FileEvent[];
  readonly registryEvents: readonly RegistryEvent[];
  readonly networkEvents: readonly NetworkEvent[];
  readonly executionOutput: string;
}

// ── Constants ───────────────────────────────────────────────────────────────

// VM detection: registry keys that malware checks for known VM artifacts
const VM_REGISTRY_INDICATORS: readonly { pattern: string; vm: string }[] = [
  { pattern: 'vmware', vm: 'VMware' },
  { pattern: 'virtualbox', vm: 'VirtualBox' },
  { pattern: 'vbox', vm: 'VirtualBox' },
  { pattern: 'qemu', vm: 'QEMU' },
  { pattern: 'xen', vm: 'Xen' },
  { pattern: 'parallels', vm: 'Parallels' },
  { pattern: 'hyper-v', vm: 'Hyper-V' },
  { pattern: 'virtual hd', vm: 'Virtual Hard Disk' },
  { pattern: 'red hat virtio', vm: 'KVM/QEMU' },
];

// VM detection: files that malware checks for
const VM_FILE_INDICATORS: readonly { pattern: string; vm: string }[] = [
  { pattern: 'vmwaretray.exe', vm: 'VMware' },
  { pattern: 'vmwareuser.exe', vm: 'VMware' },
  { pattern: 'vmtoolsd.exe', vm: 'VMware' },
  { pattern: 'vboxservice.exe', vm: 'VirtualBox' },
  { pattern: 'vboxtray.exe', vm: 'VirtualBox' },
  { pattern: 'vboxguest.sys', vm: 'VirtualBox' },
  { pattern: 'qemu-ga.exe', vm: 'QEMU' },
  { pattern: 'xenservice.exe', vm: 'Xen' },
  { pattern: 'prl_tools.exe', vm: 'Parallels' },
  { pattern: 'vmacthlp.exe', vm: 'VMware' },
];

// VM detection: processes that malware checks for
const VM_PROCESS_INDICATORS: readonly { pattern: string; vm: string }[] = [
  { pattern: 'vmtoolsd', vm: 'VMware' },
  { pattern: 'vmwaretray', vm: 'VMware' },
  { pattern: 'vboxservice', vm: 'VirtualBox' },
  { pattern: 'vboxtray', vm: 'VirtualBox' },
  { pattern: 'qemu-ga', vm: 'QEMU' },
  { pattern: 'xenservice', vm: 'Xen' },
  { pattern: 'prl_tools', vm: 'Parallels' },
];

// Sandbox detection: process names associated with analysis tools
const SANDBOX_PROCESS_INDICATORS: readonly string[] = [
  'procmon', 'procexp', 'wireshark', 'fiddler', 'tcpdump',
  'ollydbg', 'x64dbg', 'x32dbg', 'windbg', 'ida', 'ida64',
  'ghidra', 'pestudio', 'regshot', 'autoruns',
  'processhacker', 'apimonitor', 'dumpcap', 'filemon',
  'regmon', 'sysmon', 'fakenet', 'inetsim',
];

// Timing evasion: commands that introduce delays
const SLEEP_COMMANDS: readonly RegExp[] = [
  /sleep\s+\d+/i,
  /timeout\s+\/t\s+\d+/i,
  /ping\s+.*-n\s+\d+.*127\.0\.0\.1/i,
  /Start-Sleep/i,
  /WScript\.Sleep/i,
  /Thread\.Sleep/i,
  /time\.sleep/i,
  /select.*pg_sleep/i,
];

// Environment checks: commands to check domain, software, user count
const ENVIRONMENT_CHECK_PATTERNS: readonly { pattern: RegExp; check: string }[] = [
  { pattern: /systeminfo/i, check: 'System information enumeration' },
  { pattern: /hostname/i, check: 'Hostname check' },
  { pattern: /whoami/i, check: 'Current user check' },
  { pattern: /nltest.*\/dclist/i, check: 'Domain controller enumeration' },
  { pattern: /net\s+(?:user|group|localgroup)/i, check: 'User/group enumeration' },
  { pattern: /wmic.*computersystem.*get.*model/i, check: 'Hardware model check (VM detection)' },
  { pattern: /wmic.*bios.*get.*serialnumber/i, check: 'BIOS serial number check (VM detection)' },
  { pattern: /wmic.*diskdrive.*get.*model/i, check: 'Disk model check (VM detection)' },
  { pattern: /Get-WmiObject.*Win32_ComputerSystem/i, check: 'WMI computer system query' },
  { pattern: /Get-WmiObject.*Win32_BIOS/i, check: 'WMI BIOS query' },
  { pattern: /cpuid/i, check: 'CPUID instruction (hypervisor detection)' },
  { pattern: /GetTickCount/i, check: 'Tick count check (timing evasion)' },
  { pattern: /QueryPerformanceCounter/i, check: 'Performance counter (timing evasion)' },
  { pattern: /IsDebuggerPresent/i, check: 'Debugger presence check' },
  { pattern: /CheckRemoteDebuggerPresent/i, check: 'Remote debugger check' },
  { pattern: /NtQueryInformationProcess/i, check: 'Process information query (anti-debug)' },
  { pattern: /OutputDebugString/i, check: 'Debug string output (anti-debug)' },
];

// Screen resolution and mouse check patterns
const SANDBOX_ENV_PATTERNS: readonly { pattern: RegExp; check: string }[] = [
  { pattern: /GetCursorPos/i, check: 'Mouse position check (sandbox detection)' },
  { pattern: /GetAsyncKeyState/i, check: 'Keyboard state check (sandbox detection)' },
  { pattern: /GetSystemMetrics.*SM_CXSCREEN/i, check: 'Screen resolution check' },
  { pattern: /GetSystemMetrics.*SM_CYSCREEN/i, check: 'Screen resolution check' },
  { pattern: /EnumDisplaySettings/i, check: 'Display settings enumeration' },
  { pattern: /GlobalMemoryStatusEx/i, check: 'Memory size check (low memory = VM)' },
  { pattern: /GetDiskFreeSpace/i, check: 'Disk space check (small disk = VM)' },
  { pattern: /NumberOfProcessors/i, check: 'CPU count check (few CPUs = VM)' },
];

// ── Evasion Detector ────────────────────────────────────────────────────────

export class EvasionDetector {
  constructor(private readonly logger: pino.Logger) {}

  /**
   * Analyze all collected behavioral data for evasion attempts.
   */
  analyze(input: AnalysisInput): EvasionDetectionResult {
    const attempts: EvasionAttempt[] = [];

    attempts.push(...this.detectVmDetection(input));
    attempts.push(...this.detectSandboxDetection(input));
    attempts.push(...this.detectTimingEvasion(input));
    attempts.push(...this.detectEnvironmentChecks(input));
    attempts.push(...this.detectAntiDebug(input));
    attempts.push(...this.detectAntiAnalysis(input));

    const overallEvasionScore = this.calculateEvasionScore(attempts);
    const categories = this.summarizeCategories(attempts);

    if (attempts.length > 0) {
      this.logger.warn(
        {
          totalAttempts: attempts.length,
          score: overallEvasionScore,
          categories: categories.map((c) => `${c.category}:${c.attemptCount}`),
        },
        'Evasion attempts detected',
      );
    }

    return {
      attempts,
      overallEvasionScore,
      categories,
    };
  }

  // ── VM detection ────────────────────────────────────────────────────────

  private detectVmDetection(input: AnalysisInput): EvasionAttempt[] {
    const attempts: EvasionAttempt[] = [];

    // Check registry accesses for VM indicators
    for (const regEvent of input.registryEvents) {
      const lowerKey = regEvent.key.toLowerCase();
      for (const indicator of VM_REGISTRY_INDICATORS) {
        if (lowerKey.includes(indicator.pattern)) {
          attempts.push({
            technique: `VM registry check (${indicator.vm})`,
            category: 'vm_detection',
            description: `Registry access to VM-related key: ${regEvent.key}`,
            severity: 'medium',
            evidence: `Registry key: ${regEvent.key}`,
            mitreTechniqueId: 'T1497.001',
          });
        }
      }
    }

    // Check file accesses for VM indicators
    for (const fileEvent of input.fileEvents) {
      const lowerPath = fileEvent.path.toLowerCase();
      for (const indicator of VM_FILE_INDICATORS) {
        if (lowerPath.includes(indicator.pattern)) {
          attempts.push({
            technique: `VM file check (${indicator.vm})`,
            category: 'vm_detection',
            description: `File access to VM artifact: ${fileEvent.path}`,
            severity: 'medium',
            evidence: `File path: ${fileEvent.path}`,
            mitreTechniqueId: 'T1497.001',
          });
        }
      }
    }

    // Check process names for VM tool lookups
    for (const procEvent of input.processEvents) {
      const lowerCmd = procEvent.commandLine.toLowerCase();
      for (const indicator of VM_PROCESS_INDICATORS) {
        if (lowerCmd.includes(indicator.pattern)) {
          attempts.push({
            technique: `VM process check (${indicator.vm})`,
            category: 'vm_detection',
            description: `Process enumeration looking for VM tools: ${procEvent.commandLine}`,
            severity: 'medium',
            evidence: `Command: ${procEvent.commandLine}`,
            mitreTechniqueId: 'T1497.001',
          });
        }
      }
    }

    // Check execution output for CPUID/hardware queries
    const lowerOutput = input.executionOutput.toLowerCase();
    if (
      lowerOutput.includes('cpuid') ||
      lowerOutput.includes('hypervisor') ||
      lowerOutput.includes('vmware') ||
      lowerOutput.includes('virtualbox') ||
      lowerOutput.includes('qemu')
    ) {
      attempts.push({
        technique: 'VM detection via output strings',
        category: 'vm_detection',
        description: 'Execution output contains VM detection indicators',
        severity: 'medium',
        evidence: 'VM-related strings found in execution output',
        mitreTechniqueId: 'T1497.001',
      });
    }

    return attempts;
  }

  // ── Sandbox detection ─────────────────────────────────────────────────

  private detectSandboxDetection(input: AnalysisInput): EvasionAttempt[] {
    const attempts: EvasionAttempt[] = [];

    // Check for analysis tool process lookups
    for (const procEvent of input.processEvents) {
      const lowerCmd = procEvent.commandLine.toLowerCase();
      const lowerName = procEvent.name.toLowerCase();

      for (const toolName of SANDBOX_PROCESS_INDICATORS) {
        if (lowerCmd.includes(toolName) || lowerName.includes(toolName)) {
          attempts.push({
            technique: `Sandbox tool detection: ${toolName}`,
            category: 'sandbox_detection',
            description: `Process interaction with analysis tool: ${toolName}`,
            severity: 'high',
            evidence: `Process: ${procEvent.name}, Command: ${procEvent.commandLine}`,
            mitreTechniqueId: 'T1497.001',
          });
        }
      }
    }

    // Check for mouse/keyboard activity checks in output
    const lowerOutput = input.executionOutput.toLowerCase();
    for (const envPattern of SANDBOX_ENV_PATTERNS) {
      if (envPattern.pattern.test(lowerOutput)) {
        attempts.push({
          technique: envPattern.check,
          category: 'sandbox_detection',
          description: envPattern.check,
          severity: 'medium',
          evidence: 'Detected in execution output',
          mitreTechniqueId: 'T1497.001',
        });
      }
    }

    return attempts;
  }

  // ── Timing evasion ────────────────────────────────────────────────────

  private detectTimingEvasion(input: AnalysisInput): EvasionAttempt[] {
    const attempts: EvasionAttempt[] = [];

    for (const procEvent of input.processEvents) {
      const cmd = procEvent.commandLine;

      for (const pattern of SLEEP_COMMANDS) {
        if (pattern.test(cmd)) {
          // Extract sleep duration if possible
          const durationMatch = cmd.match(/\d+/);
          const duration = durationMatch ? parseInt(durationMatch[0], 10) : 0;

          attempts.push({
            technique: 'Sleep/delay evasion',
            category: 'timing_evasion',
            description: `Execution delay detected: ${cmd}`,
            severity: duration > 60 ? 'high' : 'medium',
            evidence: `Command: ${cmd}, Estimated delay: ${duration}s`,
            mitreTechniqueId: 'T1497.003',
          });
        }
      }
    }

    // Also check the raw output for sleep-related API calls
    const lowerOutput = input.executionOutput.toLowerCase();
    for (const pattern of SLEEP_COMMANDS) {
      if (pattern.test(lowerOutput)) {
        attempts.push({
          technique: 'Sleep/delay in execution output',
          category: 'timing_evasion',
          description: 'Sleep/delay pattern detected in execution output',
          severity: 'medium',
          evidence: 'Sleep pattern found in stdout/stderr',
          mitreTechniqueId: 'T1497.003',
        });
      }
    }

    return attempts;
  }

  // ── Environment checks ────────────────────────────────────────────────

  private detectEnvironmentChecks(input: AnalysisInput): EvasionAttempt[] {
    const attempts: EvasionAttempt[] = [];
    const checkedPatterns = new Set<string>();

    for (const procEvent of input.processEvents) {
      const cmd = procEvent.commandLine;

      for (const check of ENVIRONMENT_CHECK_PATTERNS) {
        if (check.pattern.test(cmd) && !checkedPatterns.has(check.check)) {
          checkedPatterns.add(check.check);
          attempts.push({
            technique: check.check,
            category: 'environment_check',
            description: check.check,
            severity: 'low',
            evidence: `Command: ${cmd}`,
            mitreTechniqueId: 'T1082',
          });
        }
      }
    }

    // Check for domain membership checks
    for (const procEvent of input.processEvents) {
      const lowerCmd = procEvent.commandLine.toLowerCase();
      if (
        lowerCmd.includes('nltest') ||
        lowerCmd.includes('dsquery') ||
        lowerCmd.includes('net view')
      ) {
        if (!checkedPatterns.has('domain_membership')) {
          checkedPatterns.add('domain_membership');
          attempts.push({
            technique: 'Domain membership check',
            category: 'environment_check',
            description: 'Checking domain membership (may exit if not domain-joined)',
            severity: 'medium',
            evidence: `Command: ${procEvent.commandLine}`,
            mitreTechniqueId: 'T1082',
          });
        }
      }
    }

    // Check for installed software enumeration
    for (const regEvent of input.registryEvents) {
      const lowerKey = regEvent.key.toLowerCase();
      if (
        lowerKey.includes('uninstall') &&
        !checkedPatterns.has('software_enumeration')
      ) {
        checkedPatterns.add('software_enumeration');
        attempts.push({
          technique: 'Installed software enumeration',
          category: 'environment_check',
          description: 'Checking installed software (may exit if key applications missing)',
          severity: 'low',
          evidence: `Registry key: ${regEvent.key}`,
          mitreTechniqueId: 'T1518',
        });
      }
    }

    return attempts;
  }

  // ── Anti-debug ────────────────────────────────────────────────────────

  private detectAntiDebug(input: AnalysisInput): EvasionAttempt[] {
    const attempts: EvasionAttempt[] = [];
    const lowerOutput = input.executionOutput.toLowerCase();

    const antiDebugPatterns: readonly { pattern: string; technique: string }[] = [
      { pattern: 'isdebuggerpresent', technique: 'IsDebuggerPresent API' },
      { pattern: 'checkremotedebuggerpresent', technique: 'CheckRemoteDebuggerPresent API' },
      { pattern: 'ntqueryinformationprocess', technique: 'NtQueryInformationProcess anti-debug' },
      { pattern: 'outputdebugstring', technique: 'OutputDebugString timing' },
      { pattern: 'int 2d', technique: 'INT 2Dh anti-debug' },
      { pattern: 'rdtsc', technique: 'RDTSC timing check' },
      { pattern: 'ntsetinformationthread', technique: 'Thread hiding from debugger' },
      { pattern: 'zwqueryinformationprocess', technique: 'ZwQueryInformationProcess' },
    ];

    for (const { pattern, technique } of antiDebugPatterns) {
      if (lowerOutput.includes(pattern)) {
        attempts.push({
          technique,
          category: 'anti_debug',
          description: `Anti-debugging technique detected: ${technique}`,
          severity: 'high',
          evidence: `API/instruction found in execution context: ${pattern}`,
          mitreTechniqueId: 'T1622',
        });
      }
    }

    return attempts;
  }

  // ── Anti-analysis ─────────────────────────────────────────────────────

  private detectAntiAnalysis(input: AnalysisInput): EvasionAttempt[] {
    const attempts: EvasionAttempt[] = [];

    // Check for processes being killed (analysis tools)
    for (const procEvent of input.processEvents) {
      const lowerCmd = procEvent.commandLine.toLowerCase();

      if (
        lowerCmd.includes('taskkill') ||
        lowerCmd.includes('kill') ||
        lowerCmd.includes('terminate')
      ) {
        for (const toolName of SANDBOX_PROCESS_INDICATORS) {
          if (lowerCmd.includes(toolName)) {
            attempts.push({
              technique: `Kill analysis tool: ${toolName}`,
              category: 'anti_analysis',
              description: `Attempting to terminate analysis tool: ${toolName}`,
              severity: 'critical',
              evidence: `Command: ${procEvent.commandLine}`,
              mitreTechniqueId: 'T1562.001',
            });
          }
        }
      }

      // Check for log/evidence deletion
      if (
        lowerCmd.includes('wevtutil') ||
        lowerCmd.includes('clear-eventlog') ||
        (lowerCmd.includes('del') && lowerCmd.includes('.log')) ||
        lowerCmd.includes('rm -rf /var/log')
      ) {
        attempts.push({
          technique: 'Log/evidence deletion',
          category: 'anti_analysis',
          description: `Attempting to clear logs: ${procEvent.commandLine}`,
          severity: 'high',
          evidence: `Command: ${procEvent.commandLine}`,
          mitreTechniqueId: 'T1070.001',
        });
      }
    }

    // Check for self-deletion
    for (const fileEvent of input.fileEvents) {
      if (
        fileEvent.operation === 'delete' &&
        fileEvent.path.toLowerCase().includes('desktop')
      ) {
        attempts.push({
          technique: 'Self-deletion',
          category: 'anti_analysis',
          description: `Sample may be self-deleting: ${fileEvent.path}`,
          severity: 'medium',
          evidence: `Deleted file: ${fileEvent.path}`,
          mitreTechniqueId: 'T1070.004',
        });
      }
    }

    return attempts;
  }

  // ── Scoring ───────────────────────────────────────────────────────────

  private calculateEvasionScore(attempts: readonly EvasionAttempt[]): number {
    if (attempts.length === 0) return 0;

    const severityWeights: Record<string, number> = {
      low: 1,
      medium: 3,
      high: 7,
      critical: 15,
    };

    let totalScore = 0;
    for (const attempt of attempts) {
      totalScore += severityWeights[attempt.severity] ?? 1;
    }

    // Normalize to 0-100 scale, capping at 100
    return Math.min(100, totalScore);
  }

  private summarizeCategories(
    attempts: readonly EvasionAttempt[],
  ): EvasionCategorySummary[] {
    const categoryMap = new Map<
      EvasionCategory,
      { count: number; maxSeverity: EvasionAttempt['severity'] }
    >();

    const severityRank: Record<string, number> = {
      low: 0,
      medium: 1,
      high: 2,
      critical: 3,
    };

    for (const attempt of attempts) {
      const existing = categoryMap.get(attempt.category);
      if (existing) {
        existing.count++;
        const existingRank = severityRank[existing.maxSeverity] ?? 0;
        const newRank = severityRank[attempt.severity] ?? 0;
        if (newRank > existingRank) {
          existing.maxSeverity = attempt.severity;
        }
      } else {
        categoryMap.set(attempt.category, {
          count: 1,
          maxSeverity: attempt.severity,
        });
      }
    }

    return [...categoryMap.entries()].map(([category, data]) => ({
      category,
      attemptCount: data.count,
      maxSeverity: data.maxSeverity,
    }));
  }
}
