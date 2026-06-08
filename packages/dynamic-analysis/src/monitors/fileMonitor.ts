import { createHash } from 'node:crypto';
import type pino from 'pino';

// ── Types ───────────────────────────────────────────────────────────────────

export interface FileEvent {
  readonly operation: 'create' | 'modify' | 'delete' | 'rename';
  readonly path: string;
  readonly newPath: string | null;
  readonly sha256: string | null;
  readonly size: number | null;
  readonly timestamp: string;
  readonly isSuspicious: boolean;
  readonly suspiciousReason: string | null;
}

interface DroppedPayload {
  readonly path: string;
  readonly sha256: string;
  readonly size: number;
  readonly location: string;
  readonly isSuspiciousLocation: boolean;
}

// ── Constants ───────────────────────────────────────────────────────────────

const SUSPICIOUS_WINDOWS_PATHS: readonly string[] = [
  'c:\\windows\\temp',
  'c:\\users\\public',
  'c:\\programdata',
  'c:\\windows\\system32\\tasks',
  'c:\\windows\\system32\\drivers',
  '%appdata%\\microsoft\\windows\\start menu\\programs\\startup',
  'c:\\users\\*\\appdata\\local\\temp',
  'c:\\users\\*\\appdata\\roaming',
  'c:\\windows\\syswow64',
  'c:\\windows\\system32\\wbem',
];

const SUSPICIOUS_LINUX_PATHS: readonly string[] = [
  '/tmp',
  '/var/tmp',
  '/dev/shm',
  '/usr/local/bin',
  '/etc/cron.d',
  '/etc/cron.daily',
  '/etc/cron.hourly',
  '/etc/init.d',
  '/etc/systemd/system',
  '/root/.ssh',
  '/home/*/.ssh',
  '/etc/ld.so.preload',
  '/etc/profile.d',
];

const SUSPICIOUS_EXTENSIONS = new Set([
  '.exe', '.dll', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js',
  '.hta', '.wsf', '.msi', '.com', '.pif', '.cpl', '.inf',
  '.lnk', '.sys', '.drv',
]);

const STARTUP_LOCATIONS_WINDOWS: readonly string[] = [
  'start menu\\programs\\startup',
  'currentversion\\run',
  'currentversion\\runonce',
  'scheduled tasks',
];

const STARTUP_LOCATIONS_LINUX: readonly string[] = [
  '/etc/cron',
  '/etc/init.d',
  '/etc/systemd',
  '/etc/rc.local',
  '/.bashrc',
  '/.profile',
  '/.bash_profile',
];

// ── File Monitor ────────────────────────────────────────────────────────────

export class FileMonitor {
  private readonly events: FileEvent[] = [];
  private readonly droppedPayloads: DroppedPayload[] = [];
  private readonly seenPaths = new Set<string>();

  private readonly logger: pino.Logger;

  constructor(logger: pino.Logger) {
    this.logger = logger;
  }

  /**
   * Ingest raw output from file monitoring tools (inotifywait, procmon, etc.).
   */
  ingestRawOutput(raw: string): void {
    const lines = raw.split('\n').filter((l) => l.trim().length > 0);
    let newCount = 0;

    for (const line of lines) {
      const event = this.parseLine(line);
      if (event) {
        this.addEvent(event);
        newCount++;
      }
    }

    if (newCount > 0) {
      this.logger.debug({ newEvents: newCount }, 'Ingested file events');
    }
  }

  /**
   * Add a file event directly.
   */
  addEvent(event: FileEvent): void {
    const key = `${event.operation}:${event.path}:${event.timestamp}`;
    if (this.seenPaths.has(key)) return;
    this.seenPaths.add(key);

    this.events.push(event);

    // Track dropped payloads
    if (event.operation === 'create' && event.sha256) {
      const location = this.classifyLocation(event.path);
      this.droppedPayloads.push({
        path: event.path,
        sha256: event.sha256,
        size: event.size ?? 0,
        location,
        isSuspiciousLocation: event.isSuspicious,
      });
    }
  }

  /**
   * Get all recorded file events.
   */
  getEvents(): FileEvent[] {
    return [...this.events];
  }

  /**
   * Get all dropped payloads (newly created files with hashes).
   */
  getDroppedPayloads(): DroppedPayload[] {
    return [...this.droppedPayloads];
  }

  /**
   * Get files created or modified in suspicious locations.
   */
  getSuspiciousFiles(): FileEvent[] {
    return this.events.filter((e) => e.isSuspicious);
  }

  /**
   * Compute SHA256 hash of file content.
   */
  static hashContent(content: Buffer): string {
    return createHash('sha256').update(content).digest('hex');
  }

  // ── Private helpers ─────────────────────────────────────────────────────

  private parseLine(line: string): FileEvent | null {
    // inotifywait format: timestamp path event
    const inotifyMatch = line.match(
      /^(\d+)\s+(\S+)\s+(CREATE|MODIFY|DELETE|MOVED_FROM|MOVED_TO|CLOSE_WRITE)(?:,\S+)*\s*(.*)$/i,
    );
    if (inotifyMatch) {
      return this.parseInotifyEvent(inotifyMatch);
    }

    // Procmon CSV-style format
    const csvMatch = line.match(
      /^"[^"]*","[^"]*","([^"]*)","(CreateFile|WriteFile|DeleteFile|SetRenameInformationFile)","([^"]*)"/,
    );
    if (csvMatch) {
      return this.parseProcmonEvent(csvMatch);
    }

    return null;
  }

  private parseInotifyEvent(match: RegExpMatchArray): FileEvent {
    const timestamp = match[1] ?? '0';
    const path = match[2] ?? '';
    const eventType = (match[3] ?? '').toUpperCase();
    const extra = match[4]?.trim() ?? '';

    const operation = this.mapInotifyOperation(eventType);
    const fullPath = extra ? `${path}${extra}` : path;
    const isSuspicious = this.isPathSuspicious(fullPath);

    return {
      operation,
      path: fullPath,
      newPath: eventType === 'MOVED_TO' ? fullPath : null,
      sha256: null,
      size: null,
      timestamp: new Date(parseInt(timestamp, 10) * 1000).toISOString(),
      isSuspicious,
      suspiciousReason: isSuspicious
        ? this.getSuspiciousReason(fullPath)
        : null,
    };
  }

  private parseProcmonEvent(match: RegExpMatchArray): FileEvent {
    const path = match[1] ?? '';
    const opStr = match[2] ?? '';
    const result = match[3] ?? '';

    const operation = this.mapProcmonOperation(opStr);
    const isSuspicious = this.isPathSuspicious(path);

    return {
      operation,
      path,
      newPath: operation === 'rename' ? result : null,
      sha256: null,
      size: null,
      timestamp: new Date().toISOString(),
      isSuspicious,
      suspiciousReason: isSuspicious
        ? this.getSuspiciousReason(path)
        : null,
    };
  }

  private mapInotifyOperation(eventType: string): FileEvent['operation'] {
    switch (eventType) {
      case 'CREATE':
      case 'CLOSE_WRITE':
        return 'create';
      case 'MODIFY':
        return 'modify';
      case 'DELETE':
        return 'delete';
      case 'MOVED_FROM':
      case 'MOVED_TO':
        return 'rename';
      default:
        return 'modify';
    }
  }

  private mapProcmonOperation(op: string): FileEvent['operation'] {
    switch (op) {
      case 'CreateFile':
        return 'create';
      case 'WriteFile':
        return 'modify';
      case 'DeleteFile':
        return 'delete';
      case 'SetRenameInformationFile':
        return 'rename';
      default:
        return 'modify';
    }
  }

  private isPathSuspicious(filePath: string): boolean {
    const lower = filePath.toLowerCase().replace(/\\/g, '/');

    // Check against suspicious locations
    for (const sp of SUSPICIOUS_WINDOWS_PATHS) {
      const normalized = sp.toLowerCase().replace(/\\/g, '/').replace(/\*/g, '');
      if (lower.includes(normalized)) return true;
    }

    for (const sp of SUSPICIOUS_LINUX_PATHS) {
      const normalized = sp.replace(/\*/g, '');
      if (lower.startsWith(normalized)) return true;
    }

    // Check for suspicious file extensions
    const dotIndex = filePath.lastIndexOf('.');
    if (dotIndex !== -1) {
      const ext = filePath.slice(dotIndex).toLowerCase();
      if (SUSPICIOUS_EXTENSIONS.has(ext)) return true;
    }

    // Check for startup locations
    for (const loc of STARTUP_LOCATIONS_WINDOWS) {
      if (lower.includes(loc.toLowerCase())) return true;
    }
    for (const loc of STARTUP_LOCATIONS_LINUX) {
      if (lower.includes(loc)) return true;
    }

    return false;
  }

  private getSuspiciousReason(filePath: string): string {
    const lower = filePath.toLowerCase().replace(/\\/g, '/');

    for (const loc of [...STARTUP_LOCATIONS_WINDOWS, ...STARTUP_LOCATIONS_LINUX]) {
      if (lower.includes(loc.toLowerCase().replace(/\\/g, '/'))) {
        return `File in startup/persistence location: ${loc}`;
      }
    }

    const dotIndex = filePath.lastIndexOf('.');
    if (dotIndex !== -1) {
      const ext = filePath.slice(dotIndex).toLowerCase();
      if (SUSPICIOUS_EXTENSIONS.has(ext)) {
        return `Executable file extension: ${ext}`;
      }
    }

    return 'File in suspicious location';
  }

  private classifyLocation(filePath: string): string {
    const lower = filePath.toLowerCase();

    if (lower.includes('temp') || lower.includes('/tmp')) return 'temp_directory';
    if (lower.includes('startup')) return 'startup_directory';
    if (lower.includes('system32') || lower.includes('syswow64')) return 'system_directory';
    if (lower.includes('desktop')) return 'desktop';
    if (lower.includes('download')) return 'downloads';
    if (lower.includes('appdata') || lower.includes('.local')) return 'user_appdata';
    if (lower.includes('/etc/') || lower.includes('/usr/')) return 'system_config';

    return 'other';
  }
}
