import * as fs from 'node:fs/promises';

// ── Result types ─────────────────────────────────────────────────────────────

export interface OLEStreamInfo {
  name: string;
  size: number;
  offset: number;
}

export interface MacroIndicator {
  /** Name of the stream or file containing the macro indicator. */
  location: string;
  /** Description of the indicator. */
  description: string;
  /** Severity: 'info' | 'warning' | 'critical'. */
  severity: 'info' | 'warning' | 'critical';
}

export interface EmbeddedObject {
  type: string;
  name: string;
  size: number;
}

export interface OfficeAnalysisResult {
  /** Whether the file is an OLE compound document or OOXML (ZIP-based Office). */
  isOfficeDocument: boolean;
  /** 'ole' for binary Office, 'ooxml' for .docx/.xlsx/.pptx, null otherwise. */
  format: 'ole' | 'ooxml' | null;
  /** OLE streams found in the document. */
  oleStreams: OLEStreamInfo[];
  /** Macro-related indicators. */
  macroIndicators: MacroIndicator[];
  /** Whether the document likely contains VBA macros. */
  hasMacros: boolean;
  /** Embedded objects found. */
  embeddedObjects: EmbeddedObject[];
  /** Auto-execution hooks detected. */
  autoExecHooks: string[];
  /** Suspicious keywords found within the document. */
  suspiciousKeywords: string[];
}

// ── OLE Compound Document magic ──────────────────────────────────────────────

// D0 CF 11 E0 A1 B1 1A E1
const OLE_MAGIC = Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]);

// ZIP (PK\x03\x04) for OOXML
const ZIP_MAGIC = Buffer.from([0x50, 0x4b, 0x03, 0x04]);

// ── VBA macro stream names that indicate macro presence ──────────────────────

const VBA_STREAM_NAMES = [
  'VBA',
  'Macros',
  '_VBA_PROJECT',
  'dir',
  'PROJECT',
  'PROJECTwm',
  'VBA_PROJECT',
  'ThisDocument',
  'ThisWorkbook',
  'Sheet1',
  'Module1',
  'Module2',
  'Module3',
  'NewMacros',
  'UserForm1',
];

// ── Auto-execution hook names (VBA) ──────────────────────────────────────────

const AUTO_EXEC_PATTERNS: ReadonlyArray<{ pattern: RegExp; name: string }> = [
  { pattern: /\bAutoOpen\b/gi, name: 'AutoOpen' },
  { pattern: /\bAutoClose\b/gi, name: 'AutoClose' },
  { pattern: /\bAutoExec\b/gi, name: 'AutoExec' },
  { pattern: /\bAutoExit\b/gi, name: 'AutoExit' },
  { pattern: /\bAutoNew\b/gi, name: 'AutoNew' },
  { pattern: /\bDocument_Open\b/gi, name: 'Document_Open' },
  { pattern: /\bDocument_Close\b/gi, name: 'Document_Close' },
  { pattern: /\bDocument_New\b/gi, name: 'Document_New' },
  { pattern: /\bWorkbook_Open\b/gi, name: 'Workbook_Open' },
  { pattern: /\bWorkbook_Close\b/gi, name: 'Workbook_Close' },
  { pattern: /\bWorkbook_Activate\b/gi, name: 'Workbook_Activate' },
  { pattern: /\bWorkbook_BeforeClose\b/gi, name: 'Workbook_BeforeClose' },
  { pattern: /\bWorksheet_Change\b/gi, name: 'Worksheet_Change' },
  { pattern: /\bWorksheet_Activate\b/gi, name: 'Worksheet_Activate' },
  { pattern: /\bAuto_Open\b/gi, name: 'Auto_Open' },
  { pattern: /\bAuto_Close\b/gi, name: 'Auto_Close' },
  { pattern: /\bSlide_Show\b/gi, name: 'Slide_Show' },
];

// ── Suspicious VBA keywords ──────────────────────────────────────────────────

const SUSPICIOUS_VBA_KEYWORDS: ReadonlyArray<{ pattern: RegExp; keyword: string; reason: string }> = [
  { pattern: /\bShell\b/gi, keyword: 'Shell', reason: 'Command execution' },
  { pattern: /\bWScript\.Shell\b/gi, keyword: 'WScript.Shell', reason: 'Windows Script Host shell execution' },
  { pattern: /\bPowerShell\b/gi, keyword: 'PowerShell', reason: 'PowerShell invocation' },
  { pattern: /\bcmd\.exe\b/gi, keyword: 'cmd.exe', reason: 'Command prompt execution' },
  { pattern: /\bCreateObject\b/gi, keyword: 'CreateObject', reason: 'COM object creation' },
  { pattern: /\bGetObject\b/gi, keyword: 'GetObject', reason: 'COM object retrieval' },
  { pattern: /\bCallByName\b/gi, keyword: 'CallByName', reason: 'Dynamic function invocation' },
  { pattern: /\bURLDownloadToFile\b/gi, keyword: 'URLDownloadToFile', reason: 'File download' },
  { pattern: /\bMSXML2\.XMLHTTP\b/gi, keyword: 'MSXML2.XMLHTTP', reason: 'HTTP request' },
  { pattern: /\bWinHttp\b/gi, keyword: 'WinHttp', reason: 'HTTP request via WinHTTP' },
  { pattern: /\bADODB\.Stream\b/gi, keyword: 'ADODB.Stream', reason: 'Binary stream manipulation' },
  { pattern: /\bScripting\.FileSystemObject\b/gi, keyword: 'Scripting.FileSystemObject', reason: 'File system access' },
  { pattern: /\bEnviron\b/gi, keyword: 'Environ', reason: 'Environment variable access' },
  { pattern: /\bChrW?\s*\(/gi, keyword: 'Chr/ChrW', reason: 'Character code obfuscation' },
  { pattern: /\bStrReverse\b/gi, keyword: 'StrReverse', reason: 'String reversal (obfuscation)' },
  { pattern: /\bBase64\b/gi, keyword: 'Base64', reason: 'Base64 encoding/decoding' },
  { pattern: /\bRegWrite\b/gi, keyword: 'RegWrite', reason: 'Registry modification' },
  { pattern: /\bRegRead\b/gi, keyword: 'RegRead', reason: 'Registry read' },
  { pattern: /\bRegDelete\b/gi, keyword: 'RegDelete', reason: 'Registry deletion' },
  { pattern: /\bKill\b/gi, keyword: 'Kill', reason: 'File deletion (VBA Kill statement)' },
  { pattern: /\bVirtualAlloc\b/gi, keyword: 'VirtualAlloc', reason: 'Memory allocation via API' },
  { pattern: /\bRtlMoveMemory\b/gi, keyword: 'RtlMoveMemory', reason: 'Memory copy (shellcode injection)' },
  { pattern: /\bDeclare\s+(PtrSafe\s+)?Function\b/gi, keyword: 'Declare Function', reason: 'Windows API declaration' },
  { pattern: /\bLib\s+"kernel32/gi, keyword: 'kernel32', reason: 'Kernel32 API import' },
  { pattern: /\bLib\s+"user32/gi, keyword: 'user32', reason: 'User32 API import' },
  { pattern: /\bLib\s+"ntdll/gi, keyword: 'ntdll', reason: 'NTDLL API import' },
];

// ── OOXML file paths that indicate macros ────────────────────────────────────

const OOXML_MACRO_PATHS = [
  'word/vbaProject.bin',
  'xl/vbaProject.bin',
  'ppt/vbaProject.bin',
  'word/vbaData.xml',
  'xl/vbaData.xml',
];

const OOXML_EMBEDDED_PATHS = [
  'word/embeddings/',
  'xl/embeddings/',
  'ppt/embeddings/',
  'word/activeX/',
  'xl/activeX/',
];

// ── OLE directory entry parsing ──────────────────────────────────────────────

interface OLEDirectoryEntry {
  name: string;
  type: number; // 0=unknown, 1=storage, 2=stream, 5=root
  size: number;
  startSector: number;
}

function parseOLEDirectory(buf: Buffer): OLEDirectoryEntry[] {
  const entries: OLEDirectoryEntry[] = [];

  if (buf.length < 512) return entries;

  // Read the header to find the first directory sector.
  const sectorSize = 1 << buf.readUInt16LE(30);
  const firstDirSector = buf.readUInt32LE(48);

  if (sectorSize < 512 || sectorSize > 4096) return entries;

  // Directory entries start at the first directory sector.
  // Each entry is 128 bytes.
  const dirOffset = (firstDirSector + 1) * sectorSize;
  const ENTRY_SIZE = 128;
  const MAX_ENTRIES = 500;

  for (let i = 0; i < MAX_ENTRIES; i++) {
    const entryOffset = dirOffset + i * ENTRY_SIZE;
    if (entryOffset + ENTRY_SIZE > buf.length) break;

    const objectType = buf[entryOffset + 66]!;
    if (objectType === 0) continue; // empty/unused entry

    // Entry name is UTF-16LE, up to 64 bytes (32 chars).
    const nameLength = buf.readUInt16LE(entryOffset + 64);
    let name = '';
    const charCount = Math.min(Math.floor(nameLength / 2) - 1, 31);
    for (let j = 0; j < charCount && j >= 0; j++) {
      const ch = buf.readUInt16LE(entryOffset + j * 2);
      if (ch === 0) break;
      name += String.fromCharCode(ch);
    }

    const startSector = buf.readUInt32LE(entryOffset + 116);
    const sizeLow = buf.readUInt32LE(entryOffset + 120);

    entries.push({
      name,
      type: objectType,
      size: sizeLow,
      startSector,
    });
  }

  return entries;
}

// ── Scan buffer for string patterns ──────────────────────────────────────────

function scanForPatterns(buf: Buffer): {
  autoExecHooks: string[];
  suspiciousKeywords: string[];
  macroIndicators: MacroIndicator[];
} {
  // Convert buffer to a string (lossy is fine, we're looking for ASCII patterns).
  const text = buf.toString('latin1');

  const autoExecHooks: string[] = [];
  const suspiciousKeywords: string[] = [];
  const macroIndicators: MacroIndicator[] = [];

  for (const hook of AUTO_EXEC_PATTERNS) {
    hook.pattern.lastIndex = 0;
    if (hook.pattern.test(text)) {
      autoExecHooks.push(hook.name);
      macroIndicators.push({
        location: 'document_body',
        description: `Auto-execution hook: ${hook.name}`,
        severity: 'critical',
      });
    }
    hook.pattern.lastIndex = 0;
  }

  for (const kw of SUSPICIOUS_VBA_KEYWORDS) {
    kw.pattern.lastIndex = 0;
    if (kw.pattern.test(text)) {
      suspiciousKeywords.push(kw.keyword);
      macroIndicators.push({
        location: 'document_body',
        description: `Suspicious keyword: ${kw.keyword} - ${kw.reason}`,
        severity: 'warning',
      });
    }
    kw.pattern.lastIndex = 0;
  }

  return { autoExecHooks, suspiciousKeywords, macroIndicators };
}

// ── OOXML analysis (ZIP-based) ───────────────────────────────────────────────

function analyzeOOXML(buf: Buffer): {
  hasMacros: boolean;
  macroIndicators: MacroIndicator[];
  embeddedObjects: EmbeddedObject[];
  filePaths: string[];
} {
  const macroIndicators: MacroIndicator[] = [];
  const embeddedObjects: EmbeddedObject[] = [];
  const filePaths: string[] = [];
  let hasMacros = false;

  // Scan the ZIP for filenames by looking for local file headers (PK\x03\x04).
  let offset = 0;
  const MAX_FILES = 2000;
  let fileCount = 0;

  while (offset < buf.length - 30 && fileCount < MAX_FILES) {
    // Find next PK\x03\x04 signature.
    if (buf[offset] !== 0x50 || buf[offset + 1] !== 0x4b ||
        buf[offset + 2] !== 0x03 || buf[offset + 3] !== 0x04) {
      offset++;
      continue;
    }

    fileCount++;
    const compressedSize = buf.readUInt32LE(offset + 18);
    const uncompressedSize = buf.readUInt32LE(offset + 22);
    const fileNameLen = buf.readUInt16LE(offset + 26);
    const extraFieldLen = buf.readUInt16LE(offset + 28);

    if (offset + 30 + fileNameLen > buf.length) break;

    const fileName = buf.subarray(offset + 30, offset + 30 + fileNameLen).toString('utf-8');
    filePaths.push(fileName);

    // Check for macro indicators.
    for (const macroPath of OOXML_MACRO_PATHS) {
      if (fileName.toLowerCase() === macroPath.toLowerCase()) {
        hasMacros = true;
        macroIndicators.push({
          location: fileName,
          description: `VBA project binary found: ${fileName}`,
          severity: 'critical',
        });
      }
    }

    // Check for embedded objects.
    for (const embedPath of OOXML_EMBEDDED_PATHS) {
      if (fileName.toLowerCase().startsWith(embedPath.toLowerCase())) {
        embeddedObjects.push({
          type: 'embedded_object',
          name: fileName,
          size: uncompressedSize || compressedSize,
        });
      }
    }

    // Check for external relationships (potential template injection).
    if (fileName.endsWith('.rels') || fileName.endsWith('.xml')) {
      const dataStart = offset + 30 + fileNameLen + extraFieldLen;
      const dataEnd = Math.min(dataStart + (compressedSize || 4096), buf.length);
      const chunk = buf.subarray(dataStart, dataEnd).toString('latin1');

      if (/Target\s*=\s*"https?:\/\//i.test(chunk)) {
        macroIndicators.push({
          location: fileName,
          description: 'External relationship URL detected (potential template injection)',
          severity: 'warning',
        });
      }
    }

    // Move past this entry.
    offset += 30 + fileNameLen + extraFieldLen + compressedSize;
  }

  return { hasMacros, macroIndicators, embeddedObjects, filePaths };
}

// ── Main analysis function ───────────────────────────────────────────────────

export async function analyzeOffice(filePath: string): Promise<OfficeAnalysisResult> {
  const buf = await fs.readFile(filePath);

  const emptyResult: OfficeAnalysisResult = {
    isOfficeDocument: false,
    format: null,
    oleStreams: [],
    macroIndicators: [],
    hasMacros: false,
    embeddedObjects: [],
    autoExecHooks: [],
    suspiciousKeywords: [],
  };

  const isOLE = buf.length >= 8 && buf.subarray(0, 8).equals(OLE_MAGIC);
  const isZIP = buf.length >= 4 && buf.subarray(0, 4).equals(ZIP_MAGIC);

  if (!isOLE && !isZIP) return emptyResult;

  // ── OLE Compound Document analysis ───────────────────────
  if (isOLE) {
    const dirEntries = parseOLEDirectory(buf);
    const oleStreams: OLEStreamInfo[] = dirEntries
      .filter((e) => e.type === 2) // type 2 = stream
      .map((e) => ({
        name: e.name,
        size: e.size,
        offset: e.startSector,
      }));

    let hasMacros = false;
    const macroIndicators: MacroIndicator[] = [];
    const embeddedObjects: EmbeddedObject[] = [];

    // Check stream names for VBA indicators.
    for (const stream of oleStreams) {
      for (const vbaName of VBA_STREAM_NAMES) {
        if (stream.name.toLowerCase().includes(vbaName.toLowerCase())) {
          hasMacros = true;
          macroIndicators.push({
            location: stream.name,
            description: `VBA-related OLE stream: ${stream.name}`,
            severity: 'warning',
          });
          break;
        }
      }

      // Detect embedded OLE objects.
      if (stream.name === 'Ole' || stream.name === 'CompObj' ||
          stream.name.startsWith('ObjectPool') || stream.name.startsWith('Package')) {
        embeddedObjects.push({
          type: 'ole_embedded',
          name: stream.name,
          size: stream.size,
        });
      }
    }

    // Scan entire file content for VBA patterns.
    const patterns = scanForPatterns(buf);

    return {
      isOfficeDocument: true,
      format: 'ole',
      oleStreams,
      macroIndicators: [...macroIndicators, ...patterns.macroIndicators],
      hasMacros: hasMacros || patterns.autoExecHooks.length > 0,
      embeddedObjects,
      autoExecHooks: patterns.autoExecHooks,
      suspiciousKeywords: patterns.suspiciousKeywords,
    };
  }

  // ── OOXML (ZIP-based Office) analysis ────────────────────
  const ooxml = analyzeOOXML(buf);

  // Even in OOXML, check for raw VBA patterns in the binary stream.
  const patterns = scanForPatterns(buf);

  return {
    isOfficeDocument: true,
    format: 'ooxml',
    oleStreams: [], // OOXML doesn't have top-level OLE streams
    macroIndicators: [...ooxml.macroIndicators, ...patterns.macroIndicators],
    hasMacros: ooxml.hasMacros || patterns.autoExecHooks.length > 0,
    embeddedObjects: ooxml.embeddedObjects,
    autoExecHooks: patterns.autoExecHooks,
    suspiciousKeywords: patterns.suspiciousKeywords,
  };
}
