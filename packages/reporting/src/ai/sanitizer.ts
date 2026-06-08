// ── Input Sanitizer ─────────────────────────────────────────────────────────
// Ensures that NO binary data, raw samples, or payloads are ever sent to AI.
// Only metadata, behavioral summaries, IOCs, and technique mappings pass through.

/** Maximum input size in bytes after sanitization (50 KB). */
const MAX_INPUT_BYTES = 50 * 1024;

/** Maximum length for individual string values before truncation. */
const MAX_STRING_LENGTH = 2000;

/** Maximum number of items in arrays before truncation. */
const MAX_ARRAY_LENGTH = 100;

/** Patterns that indicate base64-encoded binary data. */
const BASE64_PATTERN = /^(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

/** Patterns that indicate raw hex dumps. */
const HEX_DUMP_PATTERN = /^(?:[0-9a-fA-F]{2}\s*){16,}$/;

/** Keys whose values should always be removed (contain binary/payload data). */
const BLOCKED_KEYS = new Set([
  'storagePath',
  'storage_path',
  'pcapPath',
  'pcap_path',
  'memoryDumpPath',
  'memory_dump_path',
  'filesystemDiffPath',
  'filesystem_diff_path',
  'registryDiffPath',
  'registry_diff_path',
  'processTreePath',
  'process_tree_path',
  'screenshotPaths',
  'screenshot_paths',
  'ruleContent',
  'rule_content',
  'rawResponse',
  'raw_response',
  'rawPayload',
  'raw_payload',
  'fileContent',
  'file_content',
  'binaryContent',
  'binary_content',
  'hexDump',
  'hex_dump',
  'disassembly',
  'shellcode',
  'payload',
  'sampleData',
  'sample_data',
  'rawBytes',
  'raw_bytes',
  'encodedContent',
  'encoded_content',
]);

/**
 * Sanitize arbitrary data for safe transmission to an AI provider.
 * Removes binary content, hex dumps, base64 payloads, and file paths
 * that could reference actual malware samples. Enforces size limits.
 */
export function sanitizeForAI(data: unknown): object {
  const sanitized = sanitizeValue(data, 0);
  const result = typeof sanitized === 'object' && sanitized !== null ? sanitized : { data: sanitized };

  // Enforce maximum size by serializing and checking byte length
  const serialized = JSON.stringify(result);
  const byteLength = Buffer.byteLength(serialized, 'utf-8');

  if (byteLength <= MAX_INPUT_BYTES) {
    return result as object;
  }

  // If too large, progressively truncate string values
  return truncateToFit(result as Record<string, unknown>, MAX_INPUT_BYTES);
}

function sanitizeValue(value: unknown, depth: number): unknown {
  // Prevent deeply nested objects from blowing up
  if (depth > 20) {
    return '[nested data truncated]';
  }

  if (value === null || value === undefined) {
    return value;
  }

  if (typeof value === 'boolean' || typeof value === 'number') {
    return value;
  }

  if (typeof value === 'string') {
    return sanitizeString(value);
  }

  if (Array.isArray(value)) {
    return sanitizeArray(value, depth);
  }

  if (typeof value === 'object') {
    return sanitizeObject(value as Record<string, unknown>, depth);
  }

  // Functions, symbols, etc. are dropped
  return undefined;
}

function sanitizeString(value: string): string | undefined {
  // Remove base64-encoded binary data
  if (BASE64_PATTERN.test(value.trim()) && value.length > 100) {
    return '[base64 content removed]';
  }

  // Remove hex dumps
  if (HEX_DUMP_PATTERN.test(value.trim()) && value.length > 64) {
    return '[hex dump removed]';
  }

  // Truncate overly long strings
  if (value.length > MAX_STRING_LENGTH) {
    return value.slice(0, MAX_STRING_LENGTH) + `... [truncated, original length: ${value.length}]`;
  }

  return value;
}

function sanitizeArray(arr: unknown[], depth: number): unknown[] {
  const truncated = arr.length > MAX_ARRAY_LENGTH;
  const items = truncated ? arr.slice(0, MAX_ARRAY_LENGTH) : arr;
  const result = items
    .map((item) => sanitizeValue(item, depth + 1))
    .filter((item) => item !== undefined);

  if (truncated) {
    result.push(`[... ${arr.length - MAX_ARRAY_LENGTH} more items truncated]`);
  }

  return result;
}

function sanitizeObject(obj: Record<string, unknown>, depth: number): Record<string, unknown> {
  const result: Record<string, unknown> = {};

  for (const [key, value] of Object.entries(obj)) {
    // Skip blocked keys entirely
    if (BLOCKED_KEYS.has(key)) {
      result[key] = '[removed for security]';
      continue;
    }

    const sanitized = sanitizeValue(value, depth + 1);
    if (sanitized !== undefined) {
      result[key] = sanitized;
    }
  }

  return result;
}

/**
 * Progressively truncate string values in an object until it fits within maxBytes.
 */
function truncateToFit(
  obj: Record<string, unknown>,
  maxBytes: number,
): Record<string, unknown> {
  let serialized = JSON.stringify(obj);
  let byteLength = Buffer.byteLength(serialized, 'utf-8');

  if (byteLength <= maxBytes) {
    return obj;
  }

  // Progressively reduce max string length
  const reductionSteps = [1000, 500, 200, 100, 50];

  for (const maxLen of reductionSteps) {
    const reduced = reduceStringLengths(obj, maxLen) as Record<string, unknown>;
    serialized = JSON.stringify(reduced);
    byteLength = Buffer.byteLength(serialized, 'utf-8');

    if (byteLength <= maxBytes) {
      return reduced;
    }
  }

  // Last resort: return a minimal summary
  return {
    _notice: 'Analysis data was too large and has been heavily truncated',
    _originalSize: byteLength,
    data: reduceStringLengths(obj, 30),
  };
}

function reduceStringLengths(
  value: unknown,
  maxLen: number,
): unknown {
  if (value === null || value === undefined) return value;
  if (typeof value === 'boolean' || typeof value === 'number') return value;

  if (typeof value === 'string') {
    if (value.length > maxLen) {
      return value.slice(0, maxLen) + '...';
    }
    return value;
  }

  if (Array.isArray(value)) {
    const truncatedArr = value.slice(0, Math.min(value.length, 20));
    return truncatedArr.map((item) => reduceStringLengths(item, maxLen));
  }

  if (typeof value === 'object') {
    const result: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      result[k] = reduceStringLengths(v, maxLen);
    }
    return result;
  }

  return undefined;
}
