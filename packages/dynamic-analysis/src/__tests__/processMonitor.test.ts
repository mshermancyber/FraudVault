import { describe, it, expect, vi } from 'vitest';
import { ProcessMonitor } from '../monitors/processMonitor.js';
import type { ProcessEvent } from '../monitors/processMonitor.js';

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

function makeEvent(overrides: Partial<ProcessEvent> = {}): ProcessEvent {
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

describe('ProcessMonitor', () => {
  describe('process tree building', () => {
    it('builds a simple parent-child tree', () => {
      const monitor = new ProcessMonitor(createMockLogger());

      monitor.addEvent(makeEvent({ pid: 1, parentPid: 0, name: 'explorer.exe', commandLine: 'explorer.exe' }));
      monitor.addEvent(makeEvent({ pid: 100, parentPid: 1, name: 'cmd.exe', commandLine: 'cmd.exe /c dir' }));
      monitor.addEvent(makeEvent({ pid: 200, parentPid: 100, name: 'whoami.exe', commandLine: 'whoami' }));

      const tree = monitor.buildProcessTree();

      // Root should be PID 1 (parentPid 0 not in events)
      expect(tree.length).toBe(1);
      expect(tree[0]!.pid).toBe(1);
      expect(tree[0]!.children.length).toBe(1);
      expect(tree[0]!.children[0]!.pid).toBe(100);
      expect(tree[0]!.children[0]!.children.length).toBe(1);
      expect(tree[0]!.children[0]!.children[0]!.pid).toBe(200);
    });

    it('handles multiple root processes', () => {
      const monitor = new ProcessMonitor(createMockLogger());

      monitor.addEvent(makeEvent({ pid: 1, parentPid: 0, name: 'init', commandLine: 'init' }));
      monitor.addEvent(makeEvent({ pid: 2, parentPid: 0, name: 'svchost.exe', commandLine: 'svchost.exe' }));

      const tree = monitor.buildProcessTree();
      expect(tree.length).toBe(2);
    });

    it('ignores terminate events in tree building', () => {
      const monitor = new ProcessMonitor(createMockLogger());

      monitor.addEvent(makeEvent({ eventType: 'create', pid: 1, parentPid: 0, name: 'parent.exe', commandLine: 'parent.exe' }));
      monitor.addEvent(makeEvent({ eventType: 'create', pid: 100, parentPid: 1, name: 'child.exe', commandLine: 'child.exe' }));
      monitor.addEvent(makeEvent({ eventType: 'terminate', pid: 100, parentPid: 1, name: 'child.exe', commandLine: 'child.exe' }));

      const tree = monitor.buildProcessTree();
      expect(tree.length).toBe(1);
      expect(tree[0]!.children.length).toBe(1); // Only create events form nodes
    });

    it('returns empty tree with no events', () => {
      const monitor = new ProcessMonitor(createMockLogger());
      const tree = monitor.buildProcessTree();
      expect(tree).toEqual([]);
    });
  });

  describe('privilege escalation detection', () => {
    it('detects runas.exe usage', () => {
      const monitor = new ProcessMonitor(createMockLogger());
      monitor.addEvent(
        makeEvent({
          pid: 500,
          parentPid: 1,
          name: 'runas.exe',
          commandLine: 'runas.exe /user:admin cmd.exe',
        }),
      );

      const indicators = monitor.detectPrivilegeEscalation();
      expect(indicators.length).toBeGreaterThanOrEqual(1);
      expect(indicators[0]!.indicator).toBe('privilege_escalation_tool');
      expect(indicators[0]!.severity).toBe('high');
    });

    it('detects sudo usage', () => {
      const monitor = new ProcessMonitor(createMockLogger());
      monitor.addEvent(
        makeEvent({
          pid: 500,
          parentPid: 1,
          name: 'sudo',
          commandLine: 'sudo /bin/bash',
        }),
      );

      const indicators = monitor.detectPrivilegeEscalation();
      expect(indicators.length).toBeGreaterThanOrEqual(1);
    });

    it('detects UAC bypass via eventvwr', () => {
      const monitor = new ProcessMonitor(createMockLogger());
      monitor.addEvent(
        makeEvent({
          pid: 500,
          parentPid: 1,
          name: 'cmd.exe',
          commandLine: 'cmd.exe /c eventvwr.msc',
        }),
      );

      const indicators = monitor.detectPrivilegeEscalation();
      const uacBypass = indicators.find((i) => i.indicator === 'uac_bypass_attempt');
      expect(uacBypass).toBeDefined();
      expect(uacBypass!.severity).toBe('critical');
    });

    it('detects UAC bypass via fodhelper', () => {
      const monitor = new ProcessMonitor(createMockLogger());
      monitor.addEvent(
        makeEvent({
          pid: 500,
          parentPid: 1,
          name: 'fodhelper.exe',
          commandLine: 'fodhelper.exe',
        }),
      );

      const indicators = monitor.detectPrivilegeEscalation();
      const uacBypass = indicators.find((i) => i.indicator === 'uac_bypass_attempt');
      expect(uacBypass).toBeDefined();
    });

    it('detects token manipulation', () => {
      const monitor = new ProcessMonitor(createMockLogger());
      monitor.addEvent(
        makeEvent({
          pid: 500,
          parentPid: 1,
          name: 'evil.exe',
          commandLine: 'evil.exe --impersonate-token',
        }),
      );

      const indicators = monitor.detectPrivilegeEscalation();
      const tokenManip = indicators.find((i) => i.indicator === 'token_manipulation');
      expect(tokenManip).toBeDefined();
      expect(tokenManip!.severity).toBe('high');
    });

    it('returns empty for benign processes', () => {
      const monitor = new ProcessMonitor(createMockLogger());
      monitor.addEvent(
        makeEvent({
          pid: 500,
          parentPid: 1,
          name: 'notepad.exe',
          commandLine: 'notepad.exe readme.txt',
        }),
      );

      const indicators = monitor.detectPrivilegeEscalation();
      expect(indicators).toEqual([]);
    });
  });

  describe('process injection detection', () => {
    it('detects CreateRemoteThread indicator in command line', () => {
      const monitor = new ProcessMonitor(createMockLogger());
      monitor.addEvent(
        makeEvent({
          pid: 500,
          parentPid: 1,
          name: 'inject.exe',
          commandLine: 'inject.exe --method createremotethread --target 1234',
        }),
      );

      const indicators = monitor.detectProcessInjection();
      expect(indicators.length).toBeGreaterThanOrEqual(1);
      expect(indicators[0]!.technique).toBe('createremotethread');
    });

    it('detects WriteProcessMemory indicator', () => {
      const monitor = new ProcessMonitor(createMockLogger());
      monitor.addEvent(
        makeEvent({
          pid: 500,
          parentPid: 1,
          name: 'injector.exe',
          commandLine: 'injector.exe writeprocessmemory payload.bin',
        }),
      );

      const indicators = monitor.detectProcessInjection();
      expect(indicators.some((i) => i.technique === 'writeprocessmemory')).toBe(true);
    });

    it('detects VirtualAllocEx indicator', () => {
      const monitor = new ProcessMonitor(createMockLogger());
      monitor.addEvent(
        makeEvent({
          pid: 500,
          parentPid: 1,
          name: 'loader.exe',
          commandLine: 'loader.exe --api virtualallocex --pid 4321',
        }),
      );

      const indicators = monitor.detectProcessInjection();
      expect(indicators.some((i) => i.technique === 'virtualallocex')).toBe(true);
    });

    it('detects process hollowing (suspended process creation)', () => {
      const monitor = new ProcessMonitor(createMockLogger());
      monitor.addEvent(
        makeEvent({
          pid: 500,
          parentPid: 1,
          name: 'hollow.exe',
          commandLine: 'hollow.exe --create_suspended svchost.exe',
        }),
      );

      const indicators = monitor.detectProcessInjection();
      const hollowing = indicators.find((i) => i.technique === 'process_hollowing');
      expect(hollowing).toBeDefined();
    });

    it('detects suspicious parent-child relationships', () => {
      const monitor = new ProcessMonitor(createMockLogger());
      // Parent: winword.exe
      monitor.addEvent(
        makeEvent({
          pid: 1000,
          parentPid: 0,
          name: 'winword.exe',
          commandLine: 'winword.exe document.docx',
        }),
      );
      // Child: cmd.exe spawned by winword.exe -> suspicious
      monitor.addEvent(
        makeEvent({
          pid: 2000,
          parentPid: 1000,
          name: 'cmd.exe',
          commandLine: 'cmd.exe /c whoami',
        }),
      );

      const indicators = monitor.detectProcessInjection();
      const suspiciousRelationship = indicators.find(
        (i) => i.technique === 'suspicious_parent_child',
      );
      expect(suspiciousRelationship).toBeDefined();
      expect(suspiciousRelationship!.details).toContain('winword.exe');
      expect(suspiciousRelationship!.details).toContain('cmd.exe');
    });

    it('returns empty for benign processes', () => {
      const monitor = new ProcessMonitor(createMockLogger());
      monitor.addEvent(
        makeEvent({
          pid: 500,
          parentPid: 1,
          name: 'calc.exe',
          commandLine: 'calc.exe',
        }),
      );

      const indicators = monitor.detectProcessInjection();
      expect(indicators).toEqual([]);
    });
  });

  describe('event management', () => {
    it('getEvents returns all added events', () => {
      const monitor = new ProcessMonitor(createMockLogger());
      monitor.addEvent(makeEvent({ pid: 1 }));
      monitor.addEvent(makeEvent({ pid: 2 }));
      monitor.addEvent(makeEvent({ pid: 3 }));

      const events = monitor.getEvents();
      expect(events).toHaveLength(3);
    });

    it('getEvents returns a copy (not the internal array)', () => {
      const monitor = new ProcessMonitor(createMockLogger());
      monitor.addEvent(makeEvent({ pid: 1 }));

      const events = monitor.getEvents();
      events.push(makeEvent({ pid: 999 }));

      expect(monitor.getEvents()).toHaveLength(1);
    });
  });
});
