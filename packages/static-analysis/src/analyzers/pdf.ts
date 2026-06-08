import * as fs from 'node:fs/promises';

// ── Result types ─────────────────────────────────────────────────────────────

export interface PDFObject {
  id: number;
  generation: number;
  /** Byte offset of the object in the file. */
  offset: number;
  /** Keys found in the object dictionary. */
  keys: string[];
}

export interface PDFSuspiciousEntry {
  keyword: string;
  context: string;
  offset: number;
  reason: string;
  severity: 'info' | 'warning' | 'critical';
}

export interface PDFEmbeddedFile {
  name: string | null;
  objectId: number;
  offset: number;
}

export interface PDFAction {
  type: string;
  objectId: number;
  offset: number;
  context: string;
}

export interface PDFAnalysisResult {
  /** Whether the file is a valid PDF. */
  isPDF: boolean;
  /** PDF version string (e.g. "1.7"). */
  version: string | null;
  /** Total number of objects found. */
  objectCount: number;
  /** Total number of streams found. */
  streamCount: number;
  /** Whether JavaScript was detected. */
  hasJavaScript: boolean;
  /** Whether embedded files / file attachments were detected. */
  hasEmbeddedFiles: boolean;
  /** Whether auto-actions (OpenAction, AA) were detected. */
  hasAutoActions: boolean;
  /** Whether form elements (AcroForm) were detected. */
  hasForms: boolean;
  /** Whether encryption is used. */
  isEncrypted: boolean;
  /** Suspicious keywords and their contexts. */
  suspiciousEntries: PDFSuspiciousEntry[];
  /** Embedded files / attachments. */
  embeddedFiles: PDFEmbeddedFile[];
  /** Actions found (OpenAction, AA, etc.). */
  actions: PDFAction[];
  /** Named objects (from /Names or /EmbeddedFiles). */
  objects: PDFObject[];
}

// ── Suspicious PDF keywords ──────────────────────────────────────────────────

const SUSPICIOUS_KEYWORDS: ReadonlyArray<{
  pattern: RegExp;
  keyword: string;
  reason: string;
  severity: 'info' | 'warning' | 'critical';
}> = [
  // JavaScript
  { pattern: /\/JavaScript\b/g, keyword: '/JavaScript', reason: 'JavaScript action type', severity: 'critical' },
  { pattern: /\/JS\b/g, keyword: '/JS', reason: 'JavaScript content reference', severity: 'critical' },

  // Actions
  { pattern: /\/OpenAction\b/g, keyword: '/OpenAction', reason: 'Auto-execute on document open', severity: 'critical' },
  { pattern: /\/AA\b/g, keyword: '/AA', reason: 'Additional actions (triggers on events)', severity: 'critical' },
  { pattern: /\/Launch\b/g, keyword: '/Launch', reason: 'Launch external application', severity: 'critical' },
  { pattern: /\/SubmitForm\b/g, keyword: '/SubmitForm', reason: 'Form data submission', severity: 'warning' },
  { pattern: /\/ImportData\b/g, keyword: '/ImportData', reason: 'Data import action', severity: 'warning' },
  { pattern: /\/GoToR\b/g, keyword: '/GoToR', reason: 'Go to remote destination', severity: 'warning' },
  { pattern: /\/GoToE\b/g, keyword: '/GoToE', reason: 'Go to embedded destination', severity: 'warning' },
  { pattern: /\/URI\b/g, keyword: '/URI', reason: 'URI action (may trigger external connection)', severity: 'info' },

  // Embedding
  { pattern: /\/EmbeddedFile\b/g, keyword: '/EmbeddedFile', reason: 'Embedded file', severity: 'warning' },
  { pattern: /\/EmbeddedFiles\b/g, keyword: '/EmbeddedFiles', reason: 'Embedded files collection', severity: 'warning' },
  { pattern: /\/RichMedia\b/g, keyword: '/RichMedia', reason: 'Rich media (Flash/3D) content', severity: 'critical' },
  { pattern: /\/XFA\b/g, keyword: '/XFA', reason: 'XML Forms Architecture (attack surface)', severity: 'warning' },

  // Obfuscation / evasion
  { pattern: /\/AcroForm\b/g, keyword: '/AcroForm', reason: 'Interactive form (potential exploit vector)', severity: 'info' },
  { pattern: /\/JBIG2Decode\b/g, keyword: '/JBIG2Decode', reason: 'JBIG2 decoder (known exploit target)', severity: 'warning' },
  { pattern: /\/ObjStm\b/g, keyword: '/ObjStm', reason: 'Object stream (can hide objects)', severity: 'info' },
  { pattern: /\/Encrypt\b/g, keyword: '/Encrypt', reason: 'PDF encryption', severity: 'info' },

  // Dangerous patterns
  { pattern: /\/Colors\s+\d{5,}/g, keyword: '/Colors (large)', reason: 'Abnormally large color table (potential heap spray)', severity: 'critical' },
  { pattern: /\/ASCIIHexDecode\b/g, keyword: '/ASCIIHexDecode', reason: 'Hex encoding (obfuscation)', severity: 'info' },
  { pattern: /\/ASCII85Decode\b/g, keyword: '/ASCII85Decode', reason: 'ASCII85 encoding (obfuscation)', severity: 'info' },
  { pattern: /\/FlateDecode\b/g, keyword: '/FlateDecode', reason: 'Deflate compression', severity: 'info' },

  // Shell / OS commands
  { pattern: /cmd\.exe/gi, keyword: 'cmd.exe', reason: 'Windows command shell reference', severity: 'critical' },
  { pattern: /powershell/gi, keyword: 'powershell', reason: 'PowerShell reference', severity: 'critical' },
  { pattern: /\/bin\/sh/g, keyword: '/bin/sh', reason: 'Unix shell reference', severity: 'critical' },
  { pattern: /WScript\.Shell/gi, keyword: 'WScript.Shell', reason: 'Windows Script Host', severity: 'critical' },
];

// ── PDF object parser ────────────────────────────────────────────────────────

const OBJ_START_RE = /(\d+)\s+(\d+)\s+obj\b/g;
const STREAM_RE = /\bstream\r?\n/g;

function parseObjects(text: string, _buf: Buffer): PDFObject[] {
  const objects: PDFObject[] = [];
  OBJ_START_RE.lastIndex = 0;

  let match: RegExpExecArray | null;
  while ((match = OBJ_START_RE.exec(text)) !== null) {
    const id = parseInt(match[1]!, 10);
    const gen = parseInt(match[2]!, 10);
    const offset = match.index;

    // Find the end of this object (endobj).
    const endIdx = text.indexOf('endobj', offset);
    const objContent = endIdx > 0 ? text.substring(offset, endIdx + 6) : text.substring(offset, offset + 4096);

    // Extract dictionary keys (simple heuristic: look for /Name patterns).
    const keyPattern = /\/([A-Za-z][A-Za-z0-9]*)/g;
    const keys: string[] = [];
    const keySet = new Set<string>();
    let keyMatch: RegExpExecArray | null;
    keyPattern.lastIndex = 0;
    while ((keyMatch = keyPattern.exec(objContent)) !== null) {
      const key = keyMatch[1]!;
      if (!keySet.has(key)) {
        keySet.add(key);
        keys.push(key);
      }
    }

    objects.push({ id, generation: gen, offset, keys });

    // Avoid re-scanning the same content.
    if (objects.length > 10000) break;
  }

  return objects;
}

// ── Scan for suspicious patterns ─────────────────────────────────────────────

function scanSuspiciousPatterns(text: string): {
  entries: PDFSuspiciousEntry[];
  hasJavaScript: boolean;
  hasAutoActions: boolean;
  hasEmbeddedFiles: boolean;
  hasForms: boolean;
  isEncrypted: boolean;
} {
  const entries: PDFSuspiciousEntry[] = [];
  let hasJavaScript = false;
  let hasAutoActions = false;
  let hasEmbeddedFiles = false;
  let hasForms = false;
  let isEncrypted = false;

  for (const kw of SUSPICIOUS_KEYWORDS) {
    kw.pattern.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = kw.pattern.exec(text)) !== null) {
      // Extract some surrounding context.
      const start = Math.max(0, match.index - 40);
      const end = Math.min(text.length, match.index + match[0].length + 60);
      const context = text.substring(start, end).replace(/[\r\n]+/g, ' ').trim();

      entries.push({
        keyword: kw.keyword,
        context,
        offset: match.index,
        reason: kw.reason,
        severity: kw.severity,
      });

      // Track high-level flags.
      if (kw.keyword === '/JavaScript' || kw.keyword === '/JS') hasJavaScript = true;
      if (kw.keyword === '/OpenAction' || kw.keyword === '/AA') hasAutoActions = true;
      if (kw.keyword === '/EmbeddedFile' || kw.keyword === '/EmbeddedFiles') hasEmbeddedFiles = true;
      if (kw.keyword === '/AcroForm') hasForms = true;
      if (kw.keyword === '/Encrypt') isEncrypted = true;
    }
    kw.pattern.lastIndex = 0;
  }

  return { entries, hasJavaScript, hasAutoActions, hasEmbeddedFiles, hasForms, isEncrypted };
}

// ── Detect actions in objects ────────────────────────────────────────────────

function detectActions(text: string, objects: PDFObject[]): PDFAction[] {
  const actions: PDFAction[] = [];
  const actionKeywords = ['OpenAction', 'AA', 'Launch', 'JavaScript', 'JS', 'SubmitForm', 'ImportData', 'GoToR', 'URI'];

  for (const obj of objects) {
    for (const key of obj.keys) {
      if (actionKeywords.includes(key)) {
        // Get surrounding text for context.
        const start = Math.max(0, obj.offset);
        const end = Math.min(text.length, obj.offset + 500);
        const context = text.substring(start, end).replace(/[\r\n]+/g, ' ').substring(0, 200);

        actions.push({
          type: key,
          objectId: obj.id,
          offset: obj.offset,
          context,
        });
      }
    }
  }

  return actions;
}

// ── Detect embedded files ────────────────────────────────────────────────────

function detectEmbeddedFiles(objects: PDFObject[]): PDFEmbeddedFile[] {
  const files: PDFEmbeddedFile[] = [];

  for (const obj of objects) {
    if (obj.keys.includes('EmbeddedFile') || obj.keys.includes('EmbeddedFiles')) {
      const nameKey = obj.keys.find((k) => k === 'F' || k === 'UF');
      files.push({
        name: nameKey ?? null,
        objectId: obj.id,
        offset: obj.offset,
      });
    }
  }

  return files;
}

// ── Main analysis function ───────────────────────────────────────────────────

export async function analyzePDF(filePath: string): Promise<PDFAnalysisResult> {
  const buf = await fs.readFile(filePath);

  const emptyResult: PDFAnalysisResult = {
    isPDF: false,
    version: null,
    objectCount: 0,
    streamCount: 0,
    hasJavaScript: false,
    hasEmbeddedFiles: false,
    hasAutoActions: false,
    hasForms: false,
    isEncrypted: false,
    suspiciousEntries: [],
    embeddedFiles: [],
    actions: [],
    objects: [],
  };

  // Check for %PDF- magic.
  if (buf.length < 8) return emptyResult;
  const header = buf.subarray(0, 10).toString('ascii');
  if (!header.startsWith('%PDF-')) return emptyResult;

  // Extract version.
  const versionMatch = header.match(/%PDF-(\d+\.\d+)/);
  const version = versionMatch ? versionMatch[1]! : null;

  // Convert buffer to latin1 text for pattern matching.
  // This is intentionally lossy for binary data, but we only care about
  // ASCII-visible PDF structural keywords.
  const text = buf.toString('latin1');

  // Count objects and streams.
  const objects = parseObjects(text, buf);

  STREAM_RE.lastIndex = 0;
  let streamCount = 0;
  while (STREAM_RE.exec(text) !== null) {
    streamCount++;
    if (streamCount > 50000) break;
  }
  STREAM_RE.lastIndex = 0;

  // Scan for suspicious patterns.
  const suspicious = scanSuspiciousPatterns(text);

  // Detect actions.
  const actions = detectActions(text, objects);

  // Detect embedded files.
  const embeddedFiles = detectEmbeddedFiles(objects);

  return {
    isPDF: true,
    version,
    objectCount: objects.length,
    streamCount,
    hasJavaScript: suspicious.hasJavaScript,
    hasEmbeddedFiles: suspicious.hasEmbeddedFiles || embeddedFiles.length > 0,
    hasAutoActions: suspicious.hasAutoActions || actions.some((a) => a.type === 'OpenAction' || a.type === 'AA'),
    hasForms: suspicious.hasForms,
    isEncrypted: suspicious.isEncrypted,
    suspiciousEntries: suspicious.entries,
    embeddedFiles,
    actions,
    objects,
  };
}
