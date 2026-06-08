import { describe, it, expect, vi } from 'vitest';
import { EvasionDetector } from '../evasion/detector.js';
import type { ProcessEvent } from '../monitors/processMonitor.js';
import type { FileEvent } from '../monitors/fileMonitor.js';
import type { RegistryEvent } from '../monitors/registryMonitor.js';
import type { NetworkEvent } from '../monitors/networkMonitor.js';

// Create a mock logger
function createMockLogger() {
  return {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
    trace: vi.fn(),
    fatal: vi.fn(),
    child: vi.fn().mockReturnThis(),
    level: 'info',
    silent: vi.fn(),
  } as unknown as import('pino').Logger;
}

interface AnalysisInput {
  processEvents: ProcessEvent[];
  fileEvents: FileEvent[];
  registryEvents: RegistryEvent[];
  networkEvents: NetworkEvent[];
  executionOutput: string;
}

function makeEmptyInput(): AnalysisInput {
  return {
    processEvents: [],
    fileEvents: [],
    registryEvents: [],
    networkEvents: [],
    executionOutput: '',
  };
}

function makeProcessEvent(overrides: Partial<ProcessEvent> = {}): ProcessEvent {
  return {
    eventType: 'create',
    pid: 100,
    parentPid: 1,
    name: 'test.exe',
    commandLine: 'test.exe',
    user: 'SYSTEM',
    timestamp: new Date().toISOString(),
    ...overrides,
  };
}

function makeRegistryEvent(overrides: Partial<RegistryEvent> = {}): RegistryEvent {
  return {
    operation: 'create',
    key: 'HKLM\\Software\\Test',
    valueName: null,
    valueData: null,
    valueType: null,
    timestamp: new Date().toISOString(),
    isSuspicious: false,
    category: null,
    ...overrides,
  };
}

function makeFileEvent(overrides: Partial<FileEvent> = {}): FileEvent {
  return {
    operation: 'create',
    path: 'C:\\temp\\test.txt',
    newPath: null,
    sha256: null,
    size: 100,
    timestamp: new Date().toISOString(),
    isSuspicious: false,
    suspiciousReason: null,
    ...overrides,
  };
}

describe('EvasionDetector', () => {
  describe('VM registry key detection', () => {
    it('detects VMware registry key access', () => {
      const detector = new EvasionDetector(createMockLogger());
      const input = makeEmptyInput();
      input.registryEvents = [
        makeRegistryEvent({
          key: 'HKLM\\Software\\VMware, Inc.\\VMware Tools',
        }),
      ];

      const result = detector.analyze(input);
      const vmAttempts = result.attempts.filter(
        (a) => a.category === 'vm_detection',
      );
      expect(vmAttempts.length).toBeGreaterThanOrEqual(1);
      expect(vmAttempts.some((a) => a.technique.includes('VMware'))).toBe(true);
    });

    it('detects VirtualBox registry key access', () => {
      const detector = new EvasionDetector(createMockLogger());
      const input = makeEmptyInput();
      input.registryEvents = [
        makeRegistryEvent({
          key: 'HKLM\\Software\\Oracle\\VirtualBox Guest Additions',
        }),
      ];

      const result = detector.analyze(input);
      const vmAttempts = result.attempts.filter(
        (a) => a.category === 'vm_detection',
      );
      expect(vmAttempts.length).toBeGreaterThanOrEqual(1);
    });

    it('detects QEMU artifacts', () => {
      const detector = new EvasionDetector(createMockLogger());
      const input = makeEmptyInput();
      input.registryEvents = [
        makeRegistryEvent({ key: 'HKLM\\System\\QEMU' }),
      ];

      const result = detector.analyze(input);
      const vmAttempts = result.attempts.filter(
        (a) => a.category === 'vm_detection',
      );
      expect(vmAttempts.length).toBeGreaterThanOrEqual(1);
    });

    it('detects VM artifacts in file paths', () => {
      const detector = new EvasionDetector(createMockLogger());
      const input = makeEmptyInput();
      input.fileEvents = [
        makeFileEvent({ path: 'C:\\Windows\\System32\\vmtoolsd.exe' }),
      ];

      const result = detector.analyze(input);
      const vmAttempts = result.attempts.filter(
        (a) => a.category === 'vm_detection',
      );
      expect(vmAttempts.length).toBeGreaterThanOrEqual(1);
    });

    it('detects VM tool process lookups', () => {
      const detector = new EvasionDetector(createMockLogger());
      const input = makeEmptyInput();
      input.processEvents = [
        makeProcessEvent({
          name: 'cmd.exe',
          commandLine: 'cmd.exe /c tasklist | findstr vmtoolsd',
        }),
      ];

      const result = detector.analyze(input);
      const vmAttempts = result.attempts.filter(
        (a) => a.category === 'vm_detection',
      );
      expect(vmAttempts.length).toBeGreaterThanOrEqual(1);
    });
  });

  describe('sandbox process detection', () => {
    it('detects wireshark process', () => {
      const detector = new EvasionDetector(createMockLogger());
      const input = makeEmptyInput();
      input.processEvents = [
        makeProcessEvent({
          name: 'wireshark',
          commandLine: 'wireshark.exe',
        }),
      ];

      const result = detector.analyze(input);
      const sbAttempts = result.attempts.filter(
        (a) => a.category === 'sandbox_detection',
      );
      expect(sbAttempts.length).toBeGreaterThanOrEqual(1);
      expect(sbAttempts[0]!.severity).toBe('high');
    });

    it('detects procmon process', () => {
      const detector = new EvasionDetector(createMockLogger());
      const input = makeEmptyInput();
      input.processEvents = [
        makeProcessEvent({
          name: 'procmon.exe',
          commandLine: 'procmon.exe /BackingFile trace.pml',
        }),
      ];

      const result = detector.analyze(input);
      const sbAttempts = result.attempts.filter(
        (a) => a.category === 'sandbox_detection',
      );
      expect(sbAttempts.length).toBeGreaterThanOrEqual(1);
    });

    it('detects debugger processes (x64dbg, ollydbg)', () => {
      const detector = new EvasionDetector(createMockLogger());
      const input = makeEmptyInput();
      input.processEvents = [
        makeProcessEvent({
          name: 'x64dbg.exe',
          commandLine: 'x64dbg sample.exe',
        }),
      ];

      const result = detector.analyze(input);
      const sbAttempts = result.attempts.filter(
        (a) => a.category === 'sandbox_detection',
      );
      expect(sbAttempts.length).toBeGreaterThanOrEqual(1);
    });
  });

  describe('sleep/delay technique detection', () => {
    it('detects sleep command', () => {
      const detector = new EvasionDetector(createMockLogger());
      const input = makeEmptyInput();
      input.processEvents = [
        makeProcessEvent({
          name: 'bash',
          commandLine: 'sleep 300',
        }),
      ];

      const result = detector.analyze(input);
      const timingAttempts = result.attempts.filter(
        (a) => a.category === 'timing_evasion',
      );
      expect(timingAttempts.length).toBeGreaterThanOrEqual(1);
    });

    it('detects timeout /t command', () => {
      const detector = new EvasionDetector(createMockLogger());
      const input = makeEmptyInput();
      input.processEvents = [
        makeProcessEvent({
          name: 'cmd.exe',
          commandLine: 'timeout /t 120 /nobreak',
        }),
      ];

      const result = detector.analyze(input);
      const timingAttempts = result.attempts.filter(
        (a) => a.category === 'timing_evasion',
      );
      expect(timingAttempts.length).toBeGreaterThanOrEqual(1);
    });

    it('detects ping-based delay', () => {
      const detector = new EvasionDetector(createMockLogger());
      const input = makeEmptyInput();
      input.processEvents = [
        makeProcessEvent({
          name: 'ping.exe',
          commandLine: 'ping -n 100 127.0.0.1',
        }),
      ];

      const result = detector.analyze(input);
      const timingAttempts = result.attempts.filter(
        (a) => a.category === 'timing_evasion',
      );
      expect(timingAttempts.length).toBeGreaterThanOrEqual(1);
    });

    it('detects Start-Sleep in execution output', () => {
      const detector = new EvasionDetector(createMockLogger());
      const input = makeEmptyInput();
      input.executionOutput = 'Running Start-Sleep -Seconds 60';

      const result = detector.analyze(input);
      const timingAttempts = result.attempts.filter(
        (a) => a.category === 'timing_evasion',
      );
      expect(timingAttempts.length).toBeGreaterThanOrEqual(1);
    });
  });

  describe('evasion score calculation', () => {
    it('returns 0 for no evasion attempts', () => {
      const detector = new EvasionDetector(createMockLogger());
      const result = detector.analyze(makeEmptyInput());
      expect(result.overallEvasionScore).toBe(0);
      expect(result.attempts).toHaveLength(0);
    });

    it('increases score with more attempts', () => {
      const detector = new EvasionDetector(createMockLogger());

      const input1 = makeEmptyInput();
      input1.processEvents = [
        makeProcessEvent({ name: 'wireshark', commandLine: 'wireshark' }),
      ];
      const result1 = detector.analyze(input1);

      const input2 = makeEmptyInput();
      input2.processEvents = [
        makeProcessEvent({ name: 'wireshark', commandLine: 'wireshark' }),
        makeProcessEvent({ name: 'procmon', commandLine: 'procmon.exe' }),
        makeProcessEvent({ name: 'x64dbg', commandLine: 'x64dbg.exe' }),
      ];
      const detector2 = new EvasionDetector(createMockLogger());
      const result2 = detector2.analyze(input2);

      expect(result2.overallEvasionScore).toBeGreaterThan(result1.overallEvasionScore);
    });

    it('caps score at 100', () => {
      const detector = new EvasionDetector(createMockLogger());
      const input = makeEmptyInput();

      // Add many high-severity indicators
      input.processEvents = [
        makeProcessEvent({ name: 'wireshark', commandLine: 'wireshark' }),
        makeProcessEvent({ name: 'procmon', commandLine: 'procmon' }),
        makeProcessEvent({ name: 'x64dbg', commandLine: 'x64dbg' }),
        makeProcessEvent({ name: 'ollydbg', commandLine: 'ollydbg' }),
        makeProcessEvent({ name: 'ida', commandLine: 'ida' }),
        makeProcessEvent({ name: 'ghidra', commandLine: 'ghidra' }),
        makeProcessEvent({ name: 'cmd.exe', commandLine: 'taskkill /f /im wireshark.exe' }),
        makeProcessEvent({ name: 'cmd.exe', commandLine: 'taskkill /f /im procmon.exe' }),
        makeProcessEvent({ name: 'cmd.exe', commandLine: 'sleep 9999' }),
        makeProcessEvent({ name: 'cmd.exe', commandLine: 'wevtutil cl System' }),
      ];
      input.registryEvents = [
        makeRegistryEvent({ key: 'HKLM\\Software\\VMware Tools' }),
        makeRegistryEvent({ key: 'HKLM\\Software\\VirtualBox' }),
      ];

      const result = detector.analyze(input);
      expect(result.overallEvasionScore).toBeLessThanOrEqual(100);
    });
  });

  describe('report generation / category summary', () => {
    it('generates category summaries', () => {
      const detector = new EvasionDetector(createMockLogger());
      const input = makeEmptyInput();
      input.processEvents = [
        makeProcessEvent({ name: 'wireshark', commandLine: 'wireshark' }),
      ];
      input.registryEvents = [
        makeRegistryEvent({ key: 'HKLM\\Software\\VMware' }),
      ];

      const result = detector.analyze(input);
      expect(result.categories.length).toBeGreaterThanOrEqual(2);

      const vmCategory = result.categories.find((c) => c.category === 'vm_detection');
      expect(vmCategory).toBeDefined();
      expect(vmCategory!.attemptCount).toBeGreaterThanOrEqual(1);

      const sbCategory = result.categories.find((c) => c.category === 'sandbox_detection');
      expect(sbCategory).toBeDefined();
    });

    it('tracks max severity per category', () => {
      const detector = new EvasionDetector(createMockLogger());
      const input = makeEmptyInput();
      // sandbox_detection has severity 'high'
      input.processEvents = [
        makeProcessEvent({ name: 'wireshark', commandLine: 'wireshark' }),
      ];

      const result = detector.analyze(input);
      const sbCategory = result.categories.find((c) => c.category === 'sandbox_detection');
      expect(sbCategory).toBeDefined();
      expect(sbCategory!.maxSeverity).toBe('high');
    });
  });

  describe('anti-debug detection', () => {
    it('detects IsDebuggerPresent in execution output', () => {
      const detector = new EvasionDetector(createMockLogger());
      const input = makeEmptyInput();
      input.executionOutput = 'Calling IsDebuggerPresent to check...';

      const result = detector.analyze(input);
      const antiDebug = result.attempts.filter(
        (a) => a.category === 'anti_debug',
      );
      expect(antiDebug.length).toBeGreaterThanOrEqual(1);
    });

    it('detects RDTSC timing check', () => {
      const detector = new EvasionDetector(createMockLogger());
      const input = makeEmptyInput();
      input.executionOutput = 'Using RDTSC instruction for timing';

      const result = detector.analyze(input);
      const antiDebug = result.attempts.filter(
        (a) => a.category === 'anti_debug',
      );
      expect(antiDebug.length).toBeGreaterThanOrEqual(1);
    });
  });

  describe('anti-analysis detection', () => {
    it('detects analysis tool termination attempts', () => {
      const detector = new EvasionDetector(createMockLogger());
      const input = makeEmptyInput();
      input.processEvents = [
        makeProcessEvent({
          name: 'cmd.exe',
          commandLine: 'taskkill /f /im wireshark.exe',
        }),
      ];

      const result = detector.analyze(input);
      const antiAnalysis = result.attempts.filter(
        (a) => a.category === 'anti_analysis',
      );
      expect(antiAnalysis.length).toBeGreaterThanOrEqual(1);
      expect(antiAnalysis[0]!.severity).toBe('critical');
    });

    it('detects log deletion', () => {
      const detector = new EvasionDetector(createMockLogger());
      const input = makeEmptyInput();
      input.processEvents = [
        makeProcessEvent({
          name: 'wevtutil.exe',
          commandLine: 'wevtutil cl System',
        }),
      ];

      const result = detector.analyze(input);
      const antiAnalysis = result.attempts.filter(
        (a) => a.category === 'anti_analysis',
      );
      expect(antiAnalysis.length).toBeGreaterThanOrEqual(1);
    });
  });
});
