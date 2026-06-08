import type pino from 'pino';

// ── Types ───────────────────────────────────────────────────────────────────

export interface ProcessEvent {
  readonly eventType: 'create' | 'terminate';
  readonly pid: number;
  readonly parentPid: number;
  readonly name: string;
  readonly commandLine: string;
  readonly user: string;
  readonly timestamp: string;
}

interface ProcessTreeNode {
  readonly pid: number;
  readonly parentPid: number;
  readonly name: string;
  readonly commandLine: string;
  readonly children: ProcessTreeNode[];
}

interface PrivilegeEscalationIndicator {
  readonly pid: number;
  readonly processName: string;
  readonly indicator: string;
  readonly severity: 'low' | 'medium' | 'high' | 'critical';
  readonly details: string;
}

interface ProcessInjectionIndicator {
  readonly sourcePid: number;
  readonly targetPid: number;
  readonly technique: string;
  readonly details: string;
}

// ── Constants ───────────────────────────────────────────────────────────────

const PRIVILEGE_ESCALATION_PROCESSES = new Set([
  'runas.exe',
  'sudo',
  'su',
  'pkexec',
  'doas',
]);

const SUSPICIOUS_PARENT_CHILD: ReadonlyMap<string, readonly string[]> = new Map([
  ['winword.exe', ['cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe']],
  ['excel.exe', ['cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe']],
  ['outlook.exe', ['cmd.exe', 'powershell.exe']],
  ['acrobat.exe', ['cmd.exe', 'powershell.exe']],
  ['acrord32.exe', ['cmd.exe', 'powershell.exe']],
  ['explorer.exe', ['powershell.exe', 'mshta.exe', 'regsvr32.exe']],
  ['svchost.exe', ['cmd.exe', 'powershell.exe', 'mshta.exe']],
]);

const INJECTION_INDICATORS = new Set([
  'createremotethread',
  'ntmapviewofsection',
  'queueuserapc',
  'setthreadcontext',
  'ntunmapviewofsection',
  'writeprocessmemory',
  'virtualallocex',
]);

// ── Process Monitor ─────────────────────────────────────────────────────────

export class ProcessMonitor {
  private readonly events: ProcessEvent[] = [];
  private readonly seenPids = new Set<number>();

  private readonly logger: pino.Logger;

  constructor(logger: pino.Logger) {
    this.logger = logger;
  }

  /**
   * Ingest raw output from process listing commands (ps, wmic, etc.).
   */
  ingestRawOutput(raw: string): void {
    const lines = raw.split('\n').filter((l) => l.trim().length > 0);
    let newCount = 0;

    for (const line of lines) {
      const event = this.parseLine(line);
      if (event && !this.seenPids.has(event.pid)) {
        this.events.push(event);
        this.seenPids.add(event.pid);
        newCount++;
      }
    }

    if (newCount > 0) {
      this.logger.debug({ newEvents: newCount }, 'Ingested process events');
    }
  }

  /**
   * Add a process event directly.
   */
  addEvent(event: ProcessEvent): void {
    this.events.push(event);
    this.seenPids.add(event.pid);
  }

  /**
   * Get all recorded process events.
   */
  getEvents(): ProcessEvent[] {
    return [...this.events];
  }

  /**
   * Build a process tree from the recorded events.
   */
  buildProcessTree(): ProcessTreeNode[] {
    const nodeMap = new Map<number, ProcessTreeNode>();
    const roots: ProcessTreeNode[] = [];

    // Create nodes
    for (const event of this.events) {
      if (event.eventType === 'create') {
        const node: ProcessTreeNode = {
          pid: event.pid,
          parentPid: event.parentPid,
          name: event.name,
          commandLine: event.commandLine,
          children: [],
        };
        nodeMap.set(event.pid, node);
      }
    }

    // Build tree
    for (const node of nodeMap.values()) {
      const parent = nodeMap.get(node.parentPid);
      if (parent) {
        parent.children.push(node);
      } else {
        roots.push(node);
      }
    }

    return roots;
  }

  /**
   * Detect potential privilege escalation indicators.
   */
  detectPrivilegeEscalation(): PrivilegeEscalationIndicator[] {
    const indicators: PrivilegeEscalationIndicator[] = [];

    for (const event of this.events) {
      if (event.eventType !== 'create') continue;
      const lowerName = event.name.toLowerCase();
      const lowerCmd = event.commandLine.toLowerCase();

      // Check for privilege escalation tools
      if (PRIVILEGE_ESCALATION_PROCESSES.has(lowerName)) {
        indicators.push({
          pid: event.pid,
          processName: event.name,
          indicator: 'privilege_escalation_tool',
          severity: 'high',
          details: `Process ${event.name} (PID ${event.pid}) used privilege escalation tool`,
        });
      }

      // Check for UAC bypass patterns
      if (
        lowerCmd.includes('eventvwr') ||
        lowerCmd.includes('fodhelper') ||
        lowerCmd.includes('computerdefaults') ||
        lowerCmd.includes('sdclt')
      ) {
        indicators.push({
          pid: event.pid,
          processName: event.name,
          indicator: 'uac_bypass_attempt',
          severity: 'critical',
          details: `Possible UAC bypass via ${event.commandLine}`,
        });
      }

      // Check for token manipulation
      if (
        lowerCmd.includes('impersonat') ||
        lowerCmd.includes('token') ||
        lowerCmd.includes('privilege')
      ) {
        indicators.push({
          pid: event.pid,
          processName: event.name,
          indicator: 'token_manipulation',
          severity: 'high',
          details: `Possible token manipulation: ${event.commandLine}`,
        });
      }
    }

    return indicators;
  }

  /**
   * Detect potential process injection indicators.
   */
  detectProcessInjection(): ProcessInjectionIndicator[] {
    const indicators: ProcessInjectionIndicator[] = [];

    for (const event of this.events) {
      if (event.eventType !== 'create') continue;
      const lowerCmd = event.commandLine.toLowerCase();

      // Check for known injection API indicators in command lines
      for (const api of INJECTION_INDICATORS) {
        if (lowerCmd.includes(api)) {
          indicators.push({
            sourcePid: event.parentPid,
            targetPid: event.pid,
            technique: api,
            details: `Injection API indicator: ${api} in process ${event.name}`,
          });
        }
      }

      // Check for suspicious parent-child relationships
      const parentEvent = this.events.find(
        (e) => e.pid === event.parentPid && e.eventType === 'create',
      );
      if (parentEvent) {
        const parentLower = parentEvent.name.toLowerCase();
        const suspiciousChildren = SUSPICIOUS_PARENT_CHILD.get(parentLower);
        if (suspiciousChildren?.includes(lowerCmd.split(' ')[0] ?? '')) {
          indicators.push({
            sourcePid: parentEvent.pid,
            targetPid: event.pid,
            technique: 'suspicious_parent_child',
            details: `Suspicious spawn: ${parentEvent.name} -> ${event.name}`,
          });
        }
      }

      // Check for hollowed processes (process started suspended then modified)
      if (
        lowerCmd.includes('/suspended') ||
        lowerCmd.includes('create_suspended')
      ) {
        indicators.push({
          sourcePid: event.parentPid,
          targetPid: event.pid,
          technique: 'process_hollowing',
          details: `Process created in suspended state: ${event.name}`,
        });
      }
    }

    return indicators;
  }

  // ── Private helpers ─────────────────────────────────────────────────────

  private parseLine(line: string): ProcessEvent | null {
    // Try CSV format (wmic output)
    if (line.includes(',')) {
      return this.parseWmicCsv(line);
    }

    // Try ps auxf format
    return this.parsePsAux(line);
  }

  private parseWmicCsv(line: string): ProcessEvent | null {
    // wmic format: Node,HandleCount,Name,Priority,ProcessId,ThreadCount
    const parts = line.split(',');
    if (parts.length < 5) return null;

    const name = parts[2]?.trim();
    const pidStr = parts[4]?.trim();
    if (!name || !pidStr) return null;

    const pid = parseInt(pidStr, 10);
    if (Number.isNaN(pid)) return null;

    return {
      eventType: 'create',
      pid,
      parentPid: 0,
      name,
      commandLine: name,
      user: '',
      timestamp: new Date().toISOString(),
    };
  }

  private parsePsAux(line: string): ProcessEvent | null {
    // ps auxf format: USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND
    const match = line.match(
      /^(\S+)\s+(\d+)\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(.+)$/,
    );
    if (!match) return null;

    const user = match[1] ?? '';
    const pid = parseInt(match[2] ?? '0', 10);
    const commandLine = match[3] ?? '';
    const name = commandLine.split(/\s+/)[0]?.split('/').pop() ?? '';

    if (Number.isNaN(pid)) return null;

    return {
      eventType: 'create',
      pid,
      parentPid: 0,
      name,
      commandLine,
      user,
      timestamp: new Date().toISOString(),
    };
  }
}
