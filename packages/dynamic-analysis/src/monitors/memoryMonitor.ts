import type pino from 'pino';

// ── Types ───────────────────────────────────────────────────────────────────

export interface MemoryAnalysisResult {
  readonly injectedModules: readonly InjectedModule[];
  readonly suspiciousRegions: readonly SuspiciousMemoryRegion[];
  readonly extractedStrings: readonly ExtractedMemoryString[];
  readonly extractedIocs: readonly MemoryIoc[];
  readonly totalRegionsScanned: number;
  readonly totalBytesScanned: number;
}

interface InjectedModule {
  readonly pid: number;
  readonly processName: string;
  readonly modulePath: string;
  readonly baseAddress: string;
  readonly size: number;
  readonly reason: string;
}

interface SuspiciousMemoryRegion {
  readonly pid: number;
  readonly processName: string;
  readonly address: string;
  readonly size: number;
  readonly permissions: string;
  readonly reason: string;
  readonly entropy: number;
}

interface ExtractedMemoryString {
  readonly value: string;
  readonly offset: number;
  readonly encoding: 'ascii' | 'utf16';
  readonly category: StringCategory;
}

type StringCategory =
  | 'url'
  | 'ip_address'
  | 'domain'
  | 'email'
  | 'file_path'
  | 'registry_key'
  | 'command'
  | 'crypto_key'
  | 'credential'
  | 'other';

interface MemoryIoc {
  readonly type: 'ipv4' | 'ipv6' | 'domain' | 'url' | 'email' | 'file_path' | 'registry_key';
  readonly value: string;
  readonly offset: number;
  readonly context: string;
}

// ── Constants ───────────────────────────────────────────────────────────────

const IPV4_REGEX = /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g;
const IPV6_REGEX = /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b/g;
const DOMAIN_REGEX = /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|ru|cn|tk|xyz|top|info|biz|cc|ws|pw|su|onion|bit)\b/g;
const URL_REGEX = /https?:\/\/[^\s"'<>]{4,200}/g;
const EMAIL_REGEX = /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g;
const WINDOWS_PATH_REGEX = /[A-Z]:\\(?:[^\\\s"<>|?*]{1,60}\\){1,15}[^\\\s"<>|?*]{1,60}/g;
const LINUX_PATH_REGEX = /\/(?:usr|etc|var|tmp|home|opt|root)\/[^\s"']{2,100}/g;
const REGISTRY_KEY_REGEX = /HK(?:LM|CU|CR|U|CC)\\[^\s"]{5,200}/g;

const SUSPICIOUS_MEMORY_STRINGS = [
  'VirtualAlloc',
  'VirtualProtect',
  'WriteProcessMemory',
  'CreateRemoteThread',
  'NtMapViewOfSection',
  'RtlCreateUserThread',
  'LoadLibrary',
  'GetProcAddress',
  'WinExec',
  'ShellExecute',
  'cmd.exe',
  'powershell',
  'mimikatz',
  'sekurlsa',
  'lsass',
  'credentials',
  'password',
  'token',
  'ntdll',
  'kernel32',
];

/** Shannon entropy threshold for flagging high-entropy (encrypted/packed) regions. */
const HIGH_ENTROPY_THRESHOLD = 7.0;

/** Minimum string length to extract. */
const MIN_STRING_LENGTH = 6;

// ── Memory Monitor ──────────────────────────────────────────────────────────

export class MemoryMonitor {
  constructor(private readonly logger: pino.Logger) {}

  /**
   * Analyze a full memory dump buffer.
   */
  analyzeMemoryDump(dump: Buffer): MemoryAnalysisResult {
    this.logger.info(
      { dumpSize: dump.length },
      'Starting memory dump analysis',
    );

    const extractedStrings = this.extractStrings(dump);
    const extractedIocs = this.extractIocs(dump);
    const suspiciousRegions = this.findSuspiciousRegions(dump);

    this.logger.info(
      {
        strings: extractedStrings.length,
        iocs: extractedIocs.length,
        suspiciousRegions: suspiciousRegions.length,
      },
      'Memory dump analysis complete',
    );

    return {
      injectedModules: [],
      suspiciousRegions,
      extractedStrings,
      extractedIocs,
      totalRegionsScanned: 1,
      totalBytesScanned: dump.length,
    };
  }

  /**
   * Analyze process memory maps output to find injected/suspicious modules.
   */
  analyzeProcessMaps(
    mapsOutput: string,
    pid: number,
    processName: string,
  ): {
    injectedModules: InjectedModule[];
    suspiciousRegions: SuspiciousMemoryRegion[];
  } {
    const injectedModules: InjectedModule[] = [];
    const suspiciousRegions: SuspiciousMemoryRegion[] = [];

    const lines = mapsOutput.split('\n').filter((l) => l.trim().length > 0);

    for (const line of lines) {
      // /proc/PID/maps format: address perms offset dev inode pathname
      const match = line.match(
        /^([0-9a-f]+-[0-9a-f]+)\s+(r[wxp-]{3})\s+\S+\s+\S+\s+\d+\s*(.*)?$/i,
      );
      if (!match) continue;

      const addressRange = match[1] ?? '';
      const perms = match[2] ?? '';
      const pathname = match[3]?.trim() ?? '';

      // Parse address range
      const [startStr, endStr] = addressRange.split('-');
      const start = parseInt(startStr ?? '0', 16);
      const end = parseInt(endStr ?? '0', 16);
      const size = end - start;

      // Suspicious: RWX permissions (readable, writable, executable)
      if (perms.includes('r') && perms.includes('w') && perms.includes('x')) {
        suspiciousRegions.push({
          pid,
          processName,
          address: `0x${startStr ?? '0'}`,
          size,
          permissions: perms,
          reason: 'Memory region has RWX permissions (common in code injection)',
          entropy: 0,
        });
      }

      // Suspicious: anonymous executable region (no mapped file)
      if (!pathname && perms.includes('x')) {
        suspiciousRegions.push({
          pid,
          processName,
          address: `0x${startStr ?? '0'}`,
          size,
          permissions: perms,
          reason: 'Anonymous executable memory region (possible shellcode)',
          entropy: 0,
        });
      }

      // Check for modules loaded from suspicious paths
      if (
        pathname &&
        (pathname.includes('/tmp/') ||
          pathname.includes('/dev/shm/') ||
          pathname.includes('\\Temp\\') ||
          pathname.includes('\\AppData\\'))
      ) {
        injectedModules.push({
          pid,
          processName,
          modulePath: pathname,
          baseAddress: `0x${startStr ?? '0'}`,
          size,
          reason: 'Module loaded from suspicious location',
        });
      }
    }

    return { injectedModules, suspiciousRegions };
  }

  /**
   * Return an empty result (used when memory dump fails).
   */
  emptyResult(): MemoryAnalysisResult {
    return {
      injectedModules: [],
      suspiciousRegions: [],
      extractedStrings: [],
      extractedIocs: [],
      totalRegionsScanned: 0,
      totalBytesScanned: 0,
    };
  }

  // ── Private helpers ─────────────────────────────────────────────────────

  /**
   * Extract printable ASCII and UTF-16 strings from a memory buffer.
   */
  private extractStrings(dump: Buffer): ExtractedMemoryString[] {
    const results: ExtractedMemoryString[] = [];
    const maxResults = 10_000; // Cap to avoid excessive output

    // ASCII strings
    let currentAscii = '';
    let asciiStart = 0;

    for (let i = 0; i < dump.length && results.length < maxResults; i++) {
      const byte = dump[i] ?? 0;
      if (byte >= 0x20 && byte <= 0x7e) {
        if (currentAscii.length === 0) {
          asciiStart = i;
        }
        currentAscii += String.fromCharCode(byte);
      } else {
        if (currentAscii.length >= MIN_STRING_LENGTH) {
          const category = this.categorizeString(currentAscii);
          results.push({
            value: currentAscii.slice(0, 500), // Truncate very long strings
            offset: asciiStart,
            encoding: 'ascii',
            category,
          });
        }
        currentAscii = '';
      }
    }

    // Handle trailing ASCII string
    if (currentAscii.length >= MIN_STRING_LENGTH && results.length < maxResults) {
      results.push({
        value: currentAscii.slice(0, 500),
        offset: asciiStart,
        encoding: 'ascii',
        category: this.categorizeString(currentAscii),
      });
    }

    // UTF-16LE strings (common in Windows memory)
    let currentUtf16 = '';
    let utf16Start = 0;

    for (let i = 0; i + 1 < dump.length && results.length < maxResults; i += 2) {
      const lo = dump[i] ?? 0;
      const hi = dump[i + 1] ?? 0;
      const charCode = lo | (hi << 8);

      if (charCode >= 0x20 && charCode <= 0x7e) {
        if (currentUtf16.length === 0) {
          utf16Start = i;
        }
        currentUtf16 += String.fromCharCode(charCode);
      } else {
        if (currentUtf16.length >= MIN_STRING_LENGTH) {
          results.push({
            value: currentUtf16.slice(0, 500),
            offset: utf16Start,
            encoding: 'utf16',
            category: this.categorizeString(currentUtf16),
          });
        }
        currentUtf16 = '';
      }
    }

    if (currentUtf16.length >= MIN_STRING_LENGTH && results.length < maxResults) {
      results.push({
        value: currentUtf16.slice(0, 500),
        offset: utf16Start,
        encoding: 'utf16',
        category: this.categorizeString(currentUtf16),
      });
    }

    return results;
  }

  /**
   * Extract IOCs (indicators of compromise) from a memory dump.
   */
  private extractIocs(dump: Buffer): MemoryIoc[] {
    const iocs: MemoryIoc[] = [];
    const text = dump.toString('utf-8');
    const maxIocs = 5000;

    // Extract IPv4 addresses
    for (const match of text.matchAll(IPV4_REGEX)) {
      if (iocs.length >= maxIocs) break;
      const value = match[0];
      if (!this.isBoringIp(value)) {
        iocs.push({
          type: 'ipv4',
          value,
          offset: match.index ?? 0,
          context: this.getContext(text, match.index ?? 0),
        });
      }
    }

    // Extract IPv6 addresses
    for (const match of text.matchAll(IPV6_REGEX)) {
      if (iocs.length >= maxIocs) break;
      iocs.push({
        type: 'ipv6',
        value: match[0],
        offset: match.index ?? 0,
        context: this.getContext(text, match.index ?? 0),
      });
    }

    // Extract URLs
    for (const match of text.matchAll(URL_REGEX)) {
      if (iocs.length >= maxIocs) break;
      iocs.push({
        type: 'url',
        value: match[0],
        offset: match.index ?? 0,
        context: this.getContext(text, match.index ?? 0),
      });
    }

    // Extract domains
    for (const match of text.matchAll(DOMAIN_REGEX)) {
      if (iocs.length >= maxIocs) break;
      iocs.push({
        type: 'domain',
        value: match[0],
        offset: match.index ?? 0,
        context: this.getContext(text, match.index ?? 0),
      });
    }

    // Extract emails
    for (const match of text.matchAll(EMAIL_REGEX)) {
      if (iocs.length >= maxIocs) break;
      iocs.push({
        type: 'email',
        value: match[0],
        offset: match.index ?? 0,
        context: this.getContext(text, match.index ?? 0),
      });
    }

    // Extract file paths
    for (const match of text.matchAll(WINDOWS_PATH_REGEX)) {
      if (iocs.length >= maxIocs) break;
      iocs.push({
        type: 'file_path',
        value: match[0],
        offset: match.index ?? 0,
        context: this.getContext(text, match.index ?? 0),
      });
    }

    for (const match of text.matchAll(LINUX_PATH_REGEX)) {
      if (iocs.length >= maxIocs) break;
      iocs.push({
        type: 'file_path',
        value: match[0],
        offset: match.index ?? 0,
        context: this.getContext(text, match.index ?? 0),
      });
    }

    // Extract registry keys
    for (const match of text.matchAll(REGISTRY_KEY_REGEX)) {
      if (iocs.length >= maxIocs) break;
      iocs.push({
        type: 'registry_key',
        value: match[0],
        offset: match.index ?? 0,
        context: this.getContext(text, match.index ?? 0),
      });
    }

    return iocs;
  }

  /**
   * Find suspicious memory regions based on entropy analysis.
   */
  private findSuspiciousRegions(dump: Buffer): SuspiciousMemoryRegion[] {
    const regions: SuspiciousMemoryRegion[] = [];
    const blockSize = 4096; // Analyze in 4KB blocks

    for (let offset = 0; offset + blockSize <= dump.length; offset += blockSize) {
      const block = dump.subarray(offset, offset + blockSize);
      const entropy = this.calculateEntropy(block);

      if (entropy > HIGH_ENTROPY_THRESHOLD) {
        regions.push({
          pid: 0,
          processName: 'memory_dump',
          address: `0x${offset.toString(16)}`,
          size: blockSize,
          permissions: 'unknown',
          reason: `High entropy region (${entropy.toFixed(2)} bits) - possible encrypted/packed data`,
          entropy,
        });
      }
    }

    return regions;
  }

  /**
   * Calculate Shannon entropy of a buffer.
   */
  private calculateEntropy(data: Buffer): number {
    if (data.length === 0) return 0;

    const freq = new Uint32Array(256);
    for (let i = 0; i < data.length; i++) {
      const byteVal = data[i] ?? 0;
      freq[byteVal] = (freq[byteVal] ?? 0) + 1;
    }

    let entropy = 0;
    const len = data.length;

    for (let i = 0; i < 256; i++) {
      const count = freq[i] ?? 0;
      if (count > 0) {
        const p = count / len;
        entropy -= p * Math.log2(p);
      }
    }

    return entropy;
  }

  /**
   * Categorize an extracted string.
   */
  private categorizeString(str: string): StringCategory {
    URL_REGEX.lastIndex = 0;
    if (URL_REGEX.test(str)) return 'url';

    IPV4_REGEX.lastIndex = 0;
    if (IPV4_REGEX.test(str)) return 'ip_address';

    DOMAIN_REGEX.lastIndex = 0;
    if (DOMAIN_REGEX.test(str)) return 'domain';

    EMAIL_REGEX.lastIndex = 0;
    if (EMAIL_REGEX.test(str)) return 'email';

    WINDOWS_PATH_REGEX.lastIndex = 0;
    LINUX_PATH_REGEX.lastIndex = 0;
    if (WINDOWS_PATH_REGEX.test(str) || LINUX_PATH_REGEX.test(str)) return 'file_path';

    REGISTRY_KEY_REGEX.lastIndex = 0;
    if (REGISTRY_KEY_REGEX.test(str)) return 'registry_key';

    const lower = str.toLowerCase();
    if (
      lower.includes('password') ||
      lower.includes('credential') ||
      lower.includes('secret') ||
      lower.includes('token')
    ) {
      return 'credential';
    }

    if (SUSPICIOUS_MEMORY_STRINGS.some((s) => lower.includes(s.toLowerCase()))) {
      return 'command';
    }

    return 'other';
  }

  /**
   * Get surrounding context of a match for IOC reporting.
   */
  private getContext(text: string, offset: number): string {
    const contextSize = 40;
    const start = Math.max(0, offset - contextSize);
    const end = Math.min(text.length, offset + contextSize);
    const context = text.slice(start, end).replace(/[^\x20-\x7e]/g, '.');
    return context;
  }

  /**
   * Filter out boring/common private IP addresses.
   */
  private isBoringIp(ip: string): boolean {
    return (
      ip === '0.0.0.0' ||
      ip === '127.0.0.1' ||
      ip === '255.255.255.255' ||
      ip.startsWith('0.') ||
      ip === '1.0.0.0' ||
      ip === '1.0.0.1'
    );
  }
}
