import * as fs from 'node:fs/promises';

// ── Result types ─────────────────────────────────────────────────────────────

export type StringCategory =
  | 'url'
  | 'ipv4'
  | 'ipv6'
  | 'email'
  | 'file_path_windows'
  | 'file_path_unix'
  | 'registry_key'
  | 'base64'
  | 'hex_encoded'
  | 'domain'
  | null;

export interface ExtractedStringEntry {
  value: string;
  encoding: 'ascii' | 'utf16';
  offset: number;
  category: StringCategory;
}

export interface StringAnalysisResult {
  /** Total number of ASCII strings found (before limit). */
  totalAsciiStrings: number;
  /** Total number of Unicode (UTF-16LE) strings found (before limit). */
  totalUnicodeStrings: number;
  /** Extracted strings (capped to maxStrings). */
  strings: ExtractedStringEntry[];
  /** IOC-like strings grouped by category. */
  urls: string[];
  ipv4Addresses: string[];
  ipv6Addresses: string[];
  emailAddresses: string[];
  filePaths: string[];
  registryKeys: string[];
  base64Strings: string[];
  domains: string[];
}

// ── Regex patterns ───────────────────────────────────────────────────────────

const URL_RE = /https?:\/\/[^\s'"<>]{4,200}/g;
const IPV4_RE = /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g;
const IPV6_RE = /\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b/g;
const EMAIL_RE = /\b[a-zA-Z0-9._%+\-]{1,64}@[a-zA-Z0-9.\-]{1,255}\.[a-zA-Z]{2,}\b/g;
const WIN_PATH_RE = /[A-Z]:\\(?:[^\s\\/:*?"<>|]{1,100}\\){1,20}[^\s\\/:*?"<>|]{1,100}/gi;
const UNIX_PATH_RE = /\/(?:usr|etc|tmp|var|home|opt|bin|sbin|dev|proc|sys|mnt|root)\/[^\s'"<>]{2,200}/g;
const REGISTRY_RE = /HK(?:LM|CU|CR|U|CC)\\[^\s'"]{4,300}/g;
const DOMAIN_RE = /\b(?:[a-zA-Z0-9][a-zA-Z0-9\-]{2,61}[a-zA-Z0-9]\.)+(?:com|net|org|io|ru|cn|tk|xyz|info|biz|top|pw|cc|me|tv|co)\b/gi;

// Base64: at least 20 chars of valid base64 with optional padding
const BASE64_RE = /\b[A-Za-z0-9+/]{20,}={0,2}\b/g;

// ── ASCII string extraction ──────────────────────────────────────────────────

function extractAsciiStrings(buf: Buffer, minLength: number): ExtractedStringEntry[] {
  const results: ExtractedStringEntry[] = [];
  let current = '';
  let startOffset = 0;

  for (let i = 0; i < buf.length; i++) {
    const byte = buf[i]!;
    // Printable ASCII range 0x20-0x7E plus tab (0x09)
    if ((byte >= 0x20 && byte <= 0x7e) || byte === 0x09) {
      if (current.length === 0) {
        startOffset = i;
      }
      current += String.fromCharCode(byte);
    } else {
      if (current.length >= minLength) {
        results.push({
          value: current,
          encoding: 'ascii',
          offset: startOffset,
          category: null,
        });
      }
      current = '';
    }
  }

  // Handle trailing string.
  if (current.length >= minLength) {
    results.push({
      value: current,
      encoding: 'ascii',
      offset: startOffset,
      category: null,
    });
  }

  return results;
}

// ── UTF-16LE string extraction ───────────────────────────────────────────────

function extractUnicodeStrings(buf: Buffer, minLength: number): ExtractedStringEntry[] {
  const results: ExtractedStringEntry[] = [];
  let current = '';
  let startOffset = 0;

  // UTF-16LE: printable char followed by 0x00 byte
  for (let i = 0; i < buf.length - 1; i += 2) {
    const lo = buf[i]!;
    const hi = buf[i + 1]!;

    if (hi === 0x00 && ((lo >= 0x20 && lo <= 0x7e) || lo === 0x09)) {
      if (current.length === 0) {
        startOffset = i;
      }
      current += String.fromCharCode(lo);
    } else {
      if (current.length >= minLength) {
        results.push({
          value: current,
          encoding: 'utf16',
          offset: startOffset,
          category: null,
        });
      }
      current = '';
    }
  }

  if (current.length >= minLength) {
    results.push({
      value: current,
      encoding: 'utf16',
      offset: startOffset,
      category: null,
    });
  }

  return results;
}

// ── Categorization ───────────────────────────────────────────────────────────

function categorizeString(s: string): StringCategory {
  if (URL_RE.test(s)) { URL_RE.lastIndex = 0; return 'url'; }
  if (EMAIL_RE.test(s)) { EMAIL_RE.lastIndex = 0; return 'email'; }
  if (REGISTRY_RE.test(s)) { REGISTRY_RE.lastIndex = 0; return 'registry_key'; }
  if (WIN_PATH_RE.test(s)) { WIN_PATH_RE.lastIndex = 0; return 'file_path_windows'; }
  if (UNIX_PATH_RE.test(s)) { UNIX_PATH_RE.lastIndex = 0; return 'file_path_unix'; }
  if (IPV4_RE.test(s)) { IPV4_RE.lastIndex = 0; return 'ipv4'; }
  if (IPV6_RE.test(s)) { IPV6_RE.lastIndex = 0; return 'ipv6'; }
  if (DOMAIN_RE.test(s)) { DOMAIN_RE.lastIndex = 0; return 'domain'; }
  if (BASE64_RE.test(s)) {
    BASE64_RE.lastIndex = 0;
    // Verify it actually decodes and isn't just a long word.
    try {
      const decoded = Buffer.from(s, 'base64');
      // If the round-trip matches and the decoded content has non-trivial bytes,
      // treat it as base64.
      if (decoded.length > 10 && decoded.toString('base64') === s) {
        return 'base64';
      }
    } catch {
      // Not valid base64.
    }
    return null;
  }

  // Reset all lastIndex values.
  URL_RE.lastIndex = 0;
  EMAIL_RE.lastIndex = 0;
  REGISTRY_RE.lastIndex = 0;
  WIN_PATH_RE.lastIndex = 0;
  UNIX_PATH_RE.lastIndex = 0;
  IPV4_RE.lastIndex = 0;
  IPV6_RE.lastIndex = 0;
  DOMAIN_RE.lastIndex = 0;
  BASE64_RE.lastIndex = 0;

  return null;
}

function collectMatches(allStrings: string[], re: RegExp): string[] {
  const results = new Set<string>();
  for (const s of allStrings) {
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(s)) !== null) {
      results.add(m[0]);
    }
  }
  re.lastIndex = 0;
  return [...results];
}

// ── Main extraction function ─────────────────────────────────────────────────

export async function extractStrings(
  filePath: string,
  minLength: number = 4,
  maxStrings: number = 10_000,
): Promise<StringAnalysisResult> {
  const buf = await fs.readFile(filePath);

  const asciiStrings = extractAsciiStrings(buf, minLength);
  const unicodeStrings = extractUnicodeStrings(buf, minLength);

  // De-duplicate unicode strings that are subsets of ascii strings at same offset.
  const asciiOffsets = new Set(asciiStrings.map((s) => `${String(s.offset)}:${s.value}`));
  const uniqueUnicode = unicodeStrings.filter(
    (s) => !asciiOffsets.has(`${String(s.offset)}:${s.value}`),
  );

  const totalAsciiStrings = asciiStrings.length;
  const totalUnicodeStrings = uniqueUnicode.length;

  // Merge and cap.
  let allEntries = [...asciiStrings, ...uniqueUnicode];
  if (allEntries.length > maxStrings) {
    allEntries = allEntries.slice(0, maxStrings);
  }

  // Categorize each string.
  for (const entry of allEntries) {
    entry.category = categorizeString(entry.value);
  }

  // Collect IOC-like strings for easy access.
  const allValues = allEntries.map((e) => e.value);
  const urls = collectMatches(allValues, URL_RE);
  const ipv4Addresses = collectMatches(allValues, IPV4_RE);
  const ipv6Addresses = collectMatches(allValues, IPV6_RE);
  const emailAddresses = collectMatches(allValues, EMAIL_RE);
  const windowsPaths = collectMatches(allValues, WIN_PATH_RE);
  const unixPaths = collectMatches(allValues, UNIX_PATH_RE);
  const filePaths = [...windowsPaths, ...unixPaths];
  const registryKeys = collectMatches(allValues, REGISTRY_RE);
  const domains = collectMatches(allValues, DOMAIN_RE);

  // Detect base64-encoded strings.
  const base64Strings: string[] = [];
  for (const entry of allEntries) {
    if (entry.category === 'base64') {
      base64Strings.push(entry.value);
    }
  }

  return {
    totalAsciiStrings,
    totalUnicodeStrings,
    strings: allEntries,
    urls,
    ipv4Addresses,
    ipv6Addresses,
    emailAddresses,
    filePaths,
    registryKeys,
    base64Strings,
    domains,
  };
}
