import type pino from 'pino';

// ── Types ───────────────────────────────────────────────────────────────────

export interface RegistryEvent {
  readonly operation: 'create' | 'modify' | 'delete';
  readonly key: string;
  readonly valueName: string | null;
  readonly valueData: string | null;
  readonly valueType: string | null;
  readonly timestamp: string;
  readonly isSuspicious: boolean;
  readonly category: RegistryCategory | null;
}

type RegistryCategory =
  | 'persistence_run_key'
  | 'persistence_service'
  | 'persistence_scheduled_task'
  | 'persistence_startup'
  | 'security_policy'
  | 'firewall_modification'
  | 'uac_modification'
  | 'defender_modification'
  | 'proxy_modification'
  | 'file_association'
  | 'com_hijacking'
  | 'image_file_execution'
  | 'other';

// ── Constants ───────────────────────────────────────────────────────────────

interface SuspiciousRegistryPattern {
  readonly pattern: string;
  readonly category: RegistryCategory;
  readonly description: string;
  readonly severity: 'low' | 'medium' | 'high' | 'critical';
}

const SUSPICIOUS_REGISTRY_PATTERNS: readonly SuspiciousRegistryPattern[] = [
  // Persistence: Run keys
  {
    pattern: 'currentversion\\run',
    category: 'persistence_run_key',
    description: 'Run key modification (auto-start)',
    severity: 'high',
  },
  {
    pattern: 'currentversion\\runonce',
    category: 'persistence_run_key',
    description: 'RunOnce key modification',
    severity: 'high',
  },
  {
    pattern: 'currentversion\\runservicesonce',
    category: 'persistence_run_key',
    description: 'RunServicesOnce key modification',
    severity: 'high',
  },
  {
    pattern: 'currentversion\\policies\\explorer\\run',
    category: 'persistence_run_key',
    description: 'Policy-based run key modification',
    severity: 'high',
  },

  // Persistence: Services
  {
    pattern: 'currentcontrolset\\services',
    category: 'persistence_service',
    description: 'Service creation or modification',
    severity: 'high',
  },

  // Persistence: Scheduled Tasks
  {
    pattern: 'schedule\\taskcache',
    category: 'persistence_scheduled_task',
    description: 'Scheduled task cache modification',
    severity: 'high',
  },

  // Persistence: Startup folder
  {
    pattern: 'explorer\\user shell folders',
    category: 'persistence_startup',
    description: 'Startup folder redirection',
    severity: 'critical',
  },
  {
    pattern: 'explorer\\shell folders',
    category: 'persistence_startup',
    description: 'Shell folder modification',
    severity: 'high',
  },

  // Security: Policy changes
  {
    pattern: 'policies\\system',
    category: 'security_policy',
    description: 'System policy modification',
    severity: 'high',
  },
  {
    pattern: 'policies\\microsoft\\windows\\safer',
    category: 'security_policy',
    description: 'Software restriction policy modification',
    severity: 'high',
  },

  // Security: Firewall
  {
    pattern: 'firewallpolicy',
    category: 'firewall_modification',
    description: 'Firewall policy modification',
    severity: 'critical',
  },
  {
    pattern: 'authorizedapplications',
    category: 'firewall_modification',
    description: 'Firewall exception addition',
    severity: 'high',
  },

  // Security: UAC
  {
    pattern: 'enablelua',
    category: 'uac_modification',
    description: 'UAC setting modification',
    severity: 'critical',
  },
  {
    pattern: 'consentpromptbehavior',
    category: 'uac_modification',
    description: 'UAC consent prompt modification',
    severity: 'critical',
  },

  // Security: Windows Defender
  {
    pattern: 'windows defender',
    category: 'defender_modification',
    description: 'Windows Defender configuration change',
    severity: 'critical',
  },
  {
    pattern: 'disableantispyware',
    category: 'defender_modification',
    description: 'Antispyware disabling attempt',
    severity: 'critical',
  },
  {
    pattern: 'disablerealtimemonitoring',
    category: 'defender_modification',
    description: 'Real-time monitoring disabling attempt',
    severity: 'critical',
  },

  // Network: Proxy
  {
    pattern: 'internet settings',
    category: 'proxy_modification',
    description: 'Internet/proxy settings modification',
    severity: 'medium',
  },

  // Hijacking: File associations
  {
    pattern: 'classes\\exefile',
    category: 'file_association',
    description: 'EXE file association modification',
    severity: 'critical',
  },

  // Hijacking: COM objects
  {
    pattern: 'classes\\clsid',
    category: 'com_hijacking',
    description: 'COM object registration (potential hijacking)',
    severity: 'high',
  },
  {
    pattern: 'inprocserver32',
    category: 'com_hijacking',
    description: 'In-process COM server registration',
    severity: 'high',
  },

  // Hijacking: Image File Execution Options (IFEO)
  {
    pattern: 'image file execution options',
    category: 'image_file_execution',
    description: 'IFEO modification (debugger hijacking)',
    severity: 'critical',
  },
];

// ── Registry Monitor ────────────────────────────────────────────────────────

export class RegistryMonitor {
  private readonly events: RegistryEvent[] = [];
  private readonly seenKeys = new Set<string>();

  constructor(private readonly logger: pino.Logger) {}

  /**
   * Ingest raw output from registry monitoring (reg query, Sysmon, procmon, etc.).
   */
  ingestRawOutput(raw: string): void {
    const lines = raw.split('\n').filter((l) => l.trim().length > 0);

    for (const line of lines) {
      const event = this.parseLine(line);
      if (event) {
        this.addEvent(event);
      }
    }
  }

  /**
   * Add a registry event directly.
   */
  addEvent(event: RegistryEvent): void {
    const key = `${event.operation}:${event.key}:${event.valueName ?? ''}`;
    if (this.seenKeys.has(key)) return;
    this.seenKeys.add(key);

    this.events.push(event);

    if (event.isSuspicious) {
      this.logger.warn(
        {
          key: event.key,
          valueName: event.valueName,
          category: event.category,
        },
        'Suspicious registry modification detected',
      );
    }
  }

  /**
   * Get all recorded registry events.
   */
  getEvents(): RegistryEvent[] {
    return [...this.events];
  }

  /**
   * Get only persistence-related events.
   */
  getPersistenceEvents(): RegistryEvent[] {
    return this.events.filter(
      (e) =>
        e.category === 'persistence_run_key' ||
        e.category === 'persistence_service' ||
        e.category === 'persistence_scheduled_task' ||
        e.category === 'persistence_startup',
    );
  }

  /**
   * Get only security-modifying events.
   */
  getSecurityEvents(): RegistryEvent[] {
    return this.events.filter(
      (e) =>
        e.category === 'security_policy' ||
        e.category === 'firewall_modification' ||
        e.category === 'uac_modification' ||
        e.category === 'defender_modification',
    );
  }

  /**
   * Get summary of registry modifications by category.
   */
  getCategorySummary(): ReadonlyMap<RegistryCategory, number> {
    const summary = new Map<RegistryCategory, number>();

    for (const event of this.events) {
      if (event.category) {
        const current = summary.get(event.category) ?? 0;
        summary.set(event.category, current + 1);
      }
    }

    return summary;
  }

  // ── Private helpers ─────────────────────────────────────────────────────

  private parseLine(line: string): RegistryEvent | null {
    // reg query output format: HKEY_...\path\key    ValueName    REG_TYPE    Data
    const regMatch = line.match(
      /^(HK\S+)\s+(\S+)\s+(REG_\S+)\s+(.+)$/i,
    );
    if (regMatch) {
      return this.parseRegQueryLine(regMatch);
    }

    // Alternative: just a key path
    const keyMatch = line.match(/^(HK(?:LM|CU|CR|CC|U)\\.+)$/i);
    if (keyMatch) {
      const key = keyMatch[1] ?? '';
      const analysis = this.analyzeKey(key);
      return {
        operation: 'modify',
        key,
        valueName: null,
        valueData: null,
        valueType: null,
        timestamp: new Date().toISOString(),
        isSuspicious: analysis.isSuspicious,
        category: analysis.category,
      };
    }

    return null;
  }

  private parseRegQueryLine(match: RegExpMatchArray): RegistryEvent {
    const key = match[1] ?? '';
    const valueName = match[2] ?? '';
    const valueType = match[3] ?? '';
    const valueData = match[4]?.trim() ?? '';

    const analysis = this.analyzeKey(key, valueName);

    return {
      operation: 'modify',
      key,
      valueName,
      valueData,
      valueType,
      timestamp: new Date().toISOString(),
      isSuspicious: analysis.isSuspicious,
      category: analysis.category,
    };
  }

  private analyzeKey(
    key: string,
    valueName?: string,
  ): { isSuspicious: boolean; category: RegistryCategory | null } {
    const lowerKey = key.toLowerCase();
    const lowerValue = valueName?.toLowerCase() ?? '';

    for (const pattern of SUSPICIOUS_REGISTRY_PATTERNS) {
      if (
        lowerKey.includes(pattern.pattern) ||
        lowerValue.includes(pattern.pattern)
      ) {
        return {
          isSuspicious: true,
          category: pattern.category,
        };
      }
    }

    return { isSuspicious: false, category: null };
  }
}
