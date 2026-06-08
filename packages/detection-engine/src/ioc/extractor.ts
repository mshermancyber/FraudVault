import {
  IOCType,
  type IOC,
  type DynamicAnalysisResult,
  type StaticAnalysisResult,
  type NetworkConnection,
  type FileModification,
  type RegistryModification,
} from '@scanboy/shared';
import { getTrancoTier } from '../domainReputation.js';

/**
 * IOC extraction result with deduplication metadata.
 */
export interface ExtractedIOCs {
  /** Deduplicated IOC list with confidence scores. */
  iocs: IOC[];
  /** Count by type. */
  counts: Record<string, number>;
  /** Total unique IOCs. */
  total: number;
}

/** Internal representation before dedup / ID assignment. */
interface RawIOC {
  type: IOCType;
  value: string;
  context: string | null;
  confidence: number;
  source: string;
}

// ── Regex patterns for IOC extraction ───────────────────────────────────────

const IPV4_REGEX = /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b/g;

const DOMAIN_REGEX = /\b(?:[a-zA-Z0-9][a-zA-Z0-9-]{2,61}[a-zA-Z0-9]\.)+(?:[a-zA-Z]{2,63})\b/g;

const URL_REGEX = /https?:\/\/[^\s<>"'`,;)}\]]+/gi;

const EMAIL_REGEX = /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g;

// Domains to always exclude regardless of Tranco status
const DOMAIN_EXCLUSIONS = new Set([
  'localhost', 'example.com', 'test.com',
]);

function adjustConfidenceByTranco(confidence: number, domain: string): number {
  const tier = getTrancoTier(domain);
  if (tier === 'trusted') return -1;   // suppress entirely (top 50K)
  if (tier === 'likely_legit') return Math.min(confidence, 25);  // top 200K
  if (tier === 'known') return Math.min(confidence, 40);         // top 1M
  return confidence;
}

function isPrivateOrBoguIp(ip: string): boolean {
  if (
    ip.startsWith('127.') || ip.startsWith('10.') ||
    ip.startsWith('192.168.') || ip === '0.0.0.0' || ip === '255.255.255.255'
  ) {
    return true;
  }
  if (ip.startsWith('172.')) {
    const second = parseInt(ip.split('.')[1] ?? '', 10);
    if (second >= 16 && second <= 31) return true;
  }
  // Filter version-number-like IPs (first octet 0-9) — almost never real destinations
  const firstOctet = parseInt(ip.split('.')[0] ?? '', 10);
  if (firstOctet >= 0 && firstOctet <= 9) return true;
  return false;
}

// ── Extractors ──────────────────────────────────────────────────────────────

/**
 * Extract IOCs from network connections.
 */
function extractFromNetworkConnections(
  connections: NetworkConnection[],
): RawIOC[] {
  const iocs: RawIOC[] = [];

  for (const conn of connections) {
    // IPs
    if (conn.destinationAddress && !isPrivateOrBoguIp(conn.destinationAddress)) {
      iocs.push({
        type: IOCType.IPv4,
        value: conn.destinationAddress,
        context: `${conn.protocol} connection to port ${conn.destinationPort}`,
        confidence: 70,
        source: 'network_connection',
      });
    }

    // Domains
    if (conn.domain) {
      const domainLower = conn.domain.toLowerCase();
      if (!DOMAIN_EXCLUSIONS.has(domainLower) && !domainLower.endsWith('.local')) {
        const adjusted = adjustConfidenceByTranco(75, domainLower);
        if (adjusted >= 0) {
          iocs.push({
            type: IOCType.Domain,
            value: conn.domain,
            context: `${conn.protocol} connection to ${conn.destinationAddress}:${conn.destinationPort}`,
            confidence: adjusted,
            source: 'network_connection',
          });
        }
      }
    }

    // URLs (from HTTP connections)
    if ((conn.protocol === 'http' || conn.protocol === 'https') && conn.domain) {
      const scheme = conn.protocol === 'https' ? 'https' : 'http';
      const port = (conn.protocol === 'http' && conn.destinationPort !== 80) ||
                   (conn.protocol === 'https' && conn.destinationPort !== 443)
        ? `:${conn.destinationPort}` : '';
      const url = `${scheme}://${conn.domain}${port}`;
      iocs.push({
        type: IOCType.URL,
        value: url,
        context: `${conn.bytesSent} bytes sent, ${conn.bytesReceived} bytes received`,
        confidence: 70,
        source: 'network_connection',
      });
    }
  }

  return iocs;
}

/**
 * Extract IOCs from dropped/modified files.
 */
function extractFromFileModifications(
  modifications: FileModification[],
): RawIOC[] {
  const iocs: RawIOC[] = [];

  for (const mod of modifications) {
    // File hashes from dropped files
    if (mod.sha256 && mod.operation === 'create') {
      iocs.push({
        type: IOCType.FileHash,
        value: mod.sha256,
        context: `Dropped file: ${mod.path}`,
        confidence: 30,
        source: 'dropped_file',
      });
    }

    // File paths (for created/modified files)
    if (mod.operation === 'create' || mod.operation === 'modify') {
      iocs.push({
        type: IOCType.FilePath,
        value: mod.path,
        context: `File ${mod.operation}d`,
        confidence: 60,
        source: 'file_modification',
      });
    }
  }

  return iocs;
}

/**
 * Extract IOCs from registry modifications.
 */
function extractFromRegistryModifications(
  modifications: RegistryModification[],
): RawIOC[] {
  const iocs: RawIOC[] = [];

  for (const mod of modifications) {
    if (mod.operation === 'create' || mod.operation === 'modify') {
      iocs.push({
        type: IOCType.RegistryKey,
        value: mod.valueName ? `${mod.key}\\${mod.valueName}` : mod.key,
        context: `Registry ${mod.operation}: ${mod.valueData ?? '(empty)'}`,
        confidence: 65,
        source: 'registry_modification',
      });

      // Check registry value data for embedded URLs, IPs, etc.
      if (mod.valueData) {
        const urls = mod.valueData.match(URL_REGEX);
        if (urls) {
          for (const url of urls) {
            iocs.push({
              type: IOCType.URL,
              value: url,
              context: `Found in registry value: ${mod.key}`,
              confidence: 80,
              source: 'registry_data',
            });
          }
        }
      }
    }
  }

  return iocs;
}

/**
 * Extract IOCs from mutexes.
 */
function extractFromMutexes(mutexes: string[]): RawIOC[] {
  return mutexes
    .filter((m) => m.length > 3) // Skip very short/generic mutexes
    .map((mutex) => ({
      type: IOCType.Mutex,
      value: mutex,
      context: 'Created during execution',
      confidence: 60,
      source: 'process_activity',
    }));
}

/**
 * Extract IOCs from static analysis strings.
 */
function extractFromStaticStrings(
  staticAnalysis: StaticAnalysisResult,
): RawIOC[] {
  const iocs: RawIOC[] = [];

  for (const str of staticAnalysis.strings) {
    const val = str.value;

    // URLs
    const urls = val.match(URL_REGEX);
    if (urls) {
      for (const url of urls) {
        iocs.push({
          type: IOCType.URL,
          value: url,
          context: `Extracted string at offset 0x${str.offset.toString(16)} (${str.encoding})`,
          confidence: 65,
          source: 'static_string',
        });
      }
    }

    // IPv4 addresses
    const ips = val.match(IPV4_REGEX);
    if (ips) {
      for (const ip of ips) {
        if (!isPrivateOrBoguIp(ip)) {
          iocs.push({
            type: IOCType.IPv4,
            value: ip,
            context: `Extracted string at offset 0x${str.offset.toString(16)}`,
            confidence: 55,
            source: 'static_string',
          });
        }
      }
    }

    // Domains
    const domains = val.match(DOMAIN_REGEX);
    if (domains) {
      for (const domain of domains) {
        const dl = domain.toLowerCase();
        // SLD >= 3 chars: single-char SLDs (h.pw, x.ws, ca.pl) are version strings
        // or PE section names, not real domains. This filter prevents FP IOCs.
        const sld = dl.split('.').slice(-2, -1)[0] ?? '';
        if (!DOMAIN_EXCLUSIONS.has(dl) && domain.includes('.') && domain.length > 4 && sld.length >= 3) {
          const adjusted = adjustConfidenceByTranco(50, dl);
          if (adjusted >= 0) {
            iocs.push({
              type: IOCType.Domain,
              value: domain,
              context: `Extracted string at offset 0x${str.offset.toString(16)}`,
              confidence: adjusted,
              source: 'static_string',
            });
          }
        }
      }
    }

    // Email addresses
    const emails = val.match(EMAIL_REGEX);
    if (emails) {
      for (const email of emails) {
        iocs.push({
          type: IOCType.Email,
          value: email,
          context: `Extracted string at offset 0x${str.offset.toString(16)}`,
          confidence: 55,
          source: 'static_string',
        });
      }
    }
  }

  return iocs;
}

/**
 * Extract IOCs from TLS certificate information.
 */
function extractFromCertificates(
  staticAnalysis: StaticAnalysisResult,
): RawIOC[] {
  const iocs: RawIOC[] = [];

  for (const cert of staticAnalysis.certificates) {
    iocs.push({
      type: IOCType.Certificate,
      value: cert.serial,
      context: `Subject: ${cert.subject}, Issuer: ${cert.issuer}, Valid: ${cert.isValid}`,
      confidence: cert.isValid ? 40 : 70,
      source: 'certificate',
    });
  }

  return iocs;
}

// ── Deduplication ───────────────────────────────────────────────────────────

/**
 * Deduplicate IOCs by type+value, keeping the highest confidence score and
 * merging context/source information.
 */
function deduplicateIOCs(raw: RawIOC[], submissionId: string): IOC[] {
  const deduped = new Map<string, IOC>();

  for (const ioc of raw) {
    const key = `${ioc.type}:${ioc.value.toLowerCase()}`;
    const existing = deduped.get(key);

    if (existing) {
      // Keep the higher confidence
      if (ioc.confidence > existing.confidence) {
        existing.confidence = ioc.confidence;
      }
      // Append source if different
      if (ioc.source && !existing.source.includes(ioc.source)) {
        existing.source = `${existing.source}, ${ioc.source}`;
      }
    } else {
      deduped.set(key, {
        id: `ioc-${deduped.size + 1}`,
        submissionId,
        type: ioc.type,
        value: ioc.value,
        context: ioc.context,
        confidence: ioc.confidence,
        source: ioc.source,
        firstSeenAt: new Date().toISOString(),
        createdAt: new Date().toISOString(),
      });
    }
  }

  return Array.from(deduped.values());
}

// ── Main extraction function ────────────────────────────────────────────────

/**
 * Extract all IOCs from static and dynamic analysis results.
 *
 * Gathers indicators from:
 *   - Network connections: domains, URLs, IPs
 *   - Dropped files: hashes
 *   - Registry modifications: registry keys, embedded URLs
 *   - Process activity: mutexes
 *   - File activity: file paths
 *   - Static strings: URLs, IPs, domains, emails
 *   - Certificates: serial numbers
 *
 * Results are deduplicated and assigned confidence scores.
 */
export function extractIOCs(
  staticAnalysis: StaticAnalysisResult | null,
  dynamicAnalysis: DynamicAnalysisResult | null,
  submissionId: string,
): ExtractedIOCs {
  const rawIOCs: RawIOC[] = [];

  // Dynamic analysis extractions
  if (dynamicAnalysis) {
    rawIOCs.push(...extractFromNetworkConnections(dynamicAnalysis.networkConnections));
    rawIOCs.push(...extractFromFileModifications(dynamicAnalysis.filesModified));
    rawIOCs.push(...extractFromRegistryModifications(dynamicAnalysis.registryModifications));
    rawIOCs.push(...extractFromMutexes(dynamicAnalysis.mutexesCreated));
  }

  // Static analysis extractions
  if (staticAnalysis) {
    rawIOCs.push(...extractFromStaticStrings(staticAnalysis));
    rawIOCs.push(...extractFromCertificates(staticAnalysis));
  }

  // Deduplicate
  const iocs = deduplicateIOCs(rawIOCs, submissionId);

  // Sort by confidence descending
  iocs.sort((a, b) => b.confidence - a.confidence);

  // Count by type
  const counts: Record<string, number> = {};
  for (const ioc of iocs) {
    counts[ioc.type] = (counts[ioc.type] ?? 0) + 1;
  }

  return {
    iocs,
    counts,
    total: iocs.length,
  };
}
