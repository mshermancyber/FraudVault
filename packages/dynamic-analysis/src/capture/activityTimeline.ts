import { writeFile } from 'node:fs/promises';
import type pino from 'pino';
import type { ProcessEvent } from '../monitors/processMonitor.js';
import type { FileEvent } from '../monitors/fileMonitor.js';
import type { RegistryEvent } from '../monitors/registryMonitor.js';
import type { NetworkEvent } from '../monitors/networkMonitor.js';
import type { ScreenshotTimelineEntry } from './screenshotCapture.js';

// ── Types ───────────────────────────────────────────────────────────────────

export type TimelineEventType =
  | 'screenshot'
  | 'process_create'
  | 'process_terminate'
  | 'network_connection'
  | 'dns_query'
  | 'http_request'
  | 'file_create'
  | 'file_modify'
  | 'file_delete'
  | 'file_rename'
  | 'registry_create'
  | 'registry_modify'
  | 'registry_delete';

export interface TimelineEvent {
  readonly timestamp: string;
  readonly type: TimelineEventType;
  readonly description: string;
  readonly screenshotPath: string | null;
  readonly details: Readonly<Record<string, string | number | boolean | null>>;
}

export interface KeyMoment {
  readonly timestamp: string;
  readonly type: TimelineEventType;
  readonly description: string;
  readonly screenshotPath: string | null;
  readonly significance: string;
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/**
 * Find the screenshot whose timestamp is closest to the given ISO timestamp.
 */
function findNearestScreenshot(
  screenshots: readonly ScreenshotTimelineEntry[],
  timestamp: string,
): string | null {
  if (screenshots.length === 0) return null;

  const targetMs = new Date(timestamp).getTime();
  let bestPath: string | null = null;
  let bestDelta = Infinity;

  for (const ss of screenshots) {
    const delta = Math.abs(new Date(ss.timestamp).getTime() - targetMs);
    if (delta < bestDelta) {
      bestDelta = delta;
      bestPath = ss.path;
    }
  }

  return bestPath;
}

/**
 * Derive a TimelineEventType from a ProcessEvent.
 */
function processEventType(pe: ProcessEvent): TimelineEventType {
  return pe.eventType === 'create' ? 'process_create' : 'process_terminate';
}

/**
 * Derive a TimelineEventType from a FileEvent.
 */
function fileEventType(fe: FileEvent): TimelineEventType {
  switch (fe.operation) {
    case 'create':
      return 'file_create';
    case 'modify':
      return 'file_modify';
    case 'delete':
      return 'file_delete';
    case 'rename':
      return 'file_rename';
  }
}

/**
 * Derive a TimelineEventType from a NetworkEvent.
 */
function networkEventType(ne: NetworkEvent): TimelineEventType {
  switch (ne.eventType) {
    case 'dns_query':
      return 'dns_query';
    case 'http_request':
      return 'http_request';
    default:
      return 'network_connection';
  }
}

/**
 * Derive a TimelineEventType from a RegistryEvent.
 */
function registryEventType(re: RegistryEvent): TimelineEventType {
  switch (re.operation) {
    case 'create':
      return 'registry_create';
    case 'modify':
      return 'registry_modify';
    case 'delete':
      return 'registry_delete';
  }
}

// ── ActivityTimeline ────────────────────────────────────────────────────────

export class ActivityTimeline {
  private screenshotEntries: readonly ScreenshotTimelineEntry[] = [];
  private processEvents: readonly ProcessEvent[] = [];
  private networkEvents: readonly NetworkEvent[] = [];
  private fileEvents: readonly FileEvent[] = [];
  private registryEvents: readonly RegistryEvent[] = [];

  constructor(private readonly logger: pino.Logger) {}

  // ── Data ingestion ──────────────────────────────────────────────────────

  setScreenshots(entries: readonly ScreenshotTimelineEntry[]): void {
    this.screenshotEntries = entries;
  }

  setProcessEvents(events: readonly ProcessEvent[]): void {
    this.processEvents = events;
  }

  setNetworkEvents(events: readonly NetworkEvent[]): void {
    this.networkEvents = events;
  }

  setFileEvents(events: readonly FileEvent[]): void {
    this.fileEvents = events;
  }

  setRegistryEvents(events: readonly RegistryEvent[]): void {
    this.registryEvents = events;
  }

  // ── Timeline generation ─────────────────────────────────────────────────

  /**
   * Merge all event sources into a single chronologically ordered timeline.
   */
  generateTimeline(): readonly TimelineEvent[] {
    const events: TimelineEvent[] = [];

    // Screenshot events
    for (const ss of this.screenshotEntries) {
      events.push({
        timestamp: ss.timestamp,
        type: 'screenshot',
        description: ss.eventDescription,
        screenshotPath: ss.path,
        details: {},
      });
    }

    // Process events
    for (const pe of this.processEvents) {
      events.push({
        timestamp: pe.timestamp,
        type: processEventType(pe),
        description: `Process ${pe.eventType}: ${pe.name} (PID ${pe.pid})`,
        screenshotPath: findNearestScreenshot(this.screenshotEntries, pe.timestamp),
        details: {
          pid: pe.pid,
          parentPid: pe.parentPid,
          name: pe.name,
          commandLine: pe.commandLine,
          user: pe.user,
        },
      });
    }

    // Network events
    for (const ne of this.networkEvents) {
      const dest = ne.domain ?? ne.destinationAddress;
      events.push({
        timestamp: ne.timestamp,
        type: networkEventType(ne),
        description: `${ne.eventType}: ${dest}:${ne.destinationPort} (${ne.protocol})`,
        screenshotPath: findNearestScreenshot(this.screenshotEntries, ne.timestamp),
        details: {
          protocol: ne.protocol,
          sourceAddress: ne.sourceAddress,
          sourcePort: ne.sourcePort,
          destinationAddress: ne.destinationAddress,
          destinationPort: ne.destinationPort,
          domain: ne.domain,
          isSuspicious: ne.isSuspicious,
          suspiciousReason: ne.suspiciousReason,
        },
      });
    }

    // File events
    for (const fe of this.fileEvents) {
      events.push({
        timestamp: fe.timestamp,
        type: fileEventType(fe),
        description: `File ${fe.operation}: ${fe.path}`,
        screenshotPath: findNearestScreenshot(this.screenshotEntries, fe.timestamp),
        details: {
          operation: fe.operation,
          path: fe.path,
          newPath: fe.newPath,
          sha256: fe.sha256,
          isSuspicious: fe.isSuspicious,
          suspiciousReason: fe.suspiciousReason,
        },
      });
    }

    // Registry events
    for (const re of this.registryEvents) {
      events.push({
        timestamp: re.timestamp,
        type: registryEventType(re),
        description: `Registry ${re.operation}: ${re.key}${re.valueName ? `\\${re.valueName}` : ''}`,
        screenshotPath: findNearestScreenshot(this.screenshotEntries, re.timestamp),
        details: {
          operation: re.operation,
          key: re.key,
          valueName: re.valueName,
          valueData: re.valueData,
          isSuspicious: re.isSuspicious,
          category: re.category,
        },
      });
    }

    // Sort chronologically
    events.sort((a, b) => {
      const ta = new Date(a.timestamp).getTime();
      const tb = new Date(b.timestamp).getTime();
      return ta - tb;
    });

    return events;
  }

  /**
   * Return the subset of the most significant events:
   * - First process creation
   * - First network connection
   * - First DNS query
   * - First HTTP request
   * - First file creation (file drop)
   * - First file modification
   * - First registry modification
   * - Any suspicious file events
   * - Any suspicious network events
   * - Any suspicious registry events
   */
  getKeyMoments(): readonly KeyMoment[] {
    const moments: KeyMoment[] = [];
    const seen = new Set<TimelineEventType>();

    const firstOf = (
      type: TimelineEventType,
      description: string,
      significance: string,
      timestamp: string,
      screenshotPath: string | null,
    ): void => {
      if (!seen.has(type)) {
        seen.add(type);
        moments.push({ timestamp, type, description, screenshotPath, significance });
      }
    };

    // Walk chronologically for "first" events
    const timeline = this.generateTimeline();

    for (const event of timeline) {
      switch (event.type) {
        case 'process_create':
          firstOf(
            event.type,
            event.description,
            'First process created by sample',
            event.timestamp,
            event.screenshotPath,
          );
          break;

        case 'network_connection':
          firstOf(
            event.type,
            event.description,
            'First outbound network connection',
            event.timestamp,
            event.screenshotPath,
          );
          break;

        case 'dns_query':
          firstOf(
            event.type,
            event.description,
            'First DNS resolution attempt',
            event.timestamp,
            event.screenshotPath,
          );
          break;

        case 'http_request':
          firstOf(
            event.type,
            event.description,
            'First HTTP/HTTPS request',
            event.timestamp,
            event.screenshotPath,
          );
          break;

        case 'file_create':
          firstOf(
            event.type,
            event.description,
            'First file dropped to disk',
            event.timestamp,
            event.screenshotPath,
          );
          break;

        case 'file_modify':
          firstOf(
            event.type,
            event.description,
            'First file modification',
            event.timestamp,
            event.screenshotPath,
          );
          break;

        case 'registry_create':
        case 'registry_modify':
          firstOf(
            'registry_modify',
            event.description,
            'First registry modification',
            event.timestamp,
            event.screenshotPath,
          );
          break;

        default:
          break;
      }

      // Also capture suspicious events regardless of first/not
      const isSuspicious = event.details['isSuspicious'];
      if (isSuspicious === true) {
        const reason =
          typeof event.details['suspiciousReason'] === 'string'
            ? event.details['suspiciousReason']
            : 'Suspicious activity detected';
        moments.push({
          timestamp: event.timestamp,
          type: event.type,
          description: event.description,
          screenshotPath: event.screenshotPath,
          significance: reason,
        });
      }
    }

    // De-duplicate: suspicious events that overlap with "first" events
    const unique = new Map<string, KeyMoment>();
    for (const m of moments) {
      const key = `${m.timestamp}:${m.type}:${m.significance}`;
      if (!unique.has(key)) {
        unique.set(key, m);
      }
    }

    const result = [...unique.values()];

    // Sort chronologically
    result.sort((a, b) => {
      const ta = new Date(a.timestamp).getTime();
      const tb = new Date(b.timestamp).getTime();
      return ta - tb;
    });

    return result;
  }

  /**
   * Export the full merged timeline as a JSON file.
   */
  async exportAsJson(outputPath: string): Promise<void> {
    const timeline = this.generateTimeline();
    const keyMoments = this.getKeyMoments();

    const payload = {
      generatedAt: new Date().toISOString(),
      totalEvents: timeline.length,
      keyMomentsCount: keyMoments.length,
      keyMoments,
      timeline,
    };

    await writeFile(outputPath, JSON.stringify(payload, null, 2), 'utf-8');

    this.logger.info(
      { outputPath, totalEvents: timeline.length, keyMoments: keyMoments.length },
      'Activity timeline exported',
    );
  }
}
