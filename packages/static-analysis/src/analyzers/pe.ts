import * as fs from 'node:fs/promises';
import * as crypto from 'node:crypto';
import { calculateEntropy } from './entropy.js';

// ── Result types ─────────────────────────────────────────────────────────────

export interface PESection {
  name: string;
  virtualSize: number;
  virtualAddress: number;
  rawSize: number;
  rawDataPointer: number;
  characteristics: number;
  characteristicFlags: string[];
  entropy: number;
  md5: string;
}

export interface PEImportEntry {
  dll: string;
  functions: string[];
}

export interface PEExportEntry {
  name: string;
  ordinal: number;
}

export interface PEResourceEntry {
  type: string;
  name: string;
  size: number;
  offset: number;
  language: number;
}

export interface PECertificateInfo {
  offset: number;
  size: number;
  revision: number;
  certType: number;
  /** Whether the PE has an Authenticode signature table entry. */
  hasCertificate: boolean;
}

export interface PEHeaderInfo {
  machine: string;
  machineRaw: number;
  numberOfSections: number;
  timeDateStamp: number;
  compiledAt: string;
  characteristics: number;
  characteristicFlags: string[];
  /** True for PE32+, false for PE32. */
  is64Bit: boolean;
  /** Optional header magic value. */
  magic: number;
  entryPoint: number;
  imageBase: number;
  subsystem: string;
  dllCharacteristics: number;
  dllCharacteristicFlags: string[];
}

export interface SuspiciousImport {
  dll: string;
  function: string;
  reason: string;
}

export interface PEVersionInfo {
  CompanyName?: string;
  FileDescription?: string;
  FileVersion?: string;
  InternalName?: string;
  LegalCopyright?: string;
  OriginalFilename?: string;
  ProductName?: string;
  ProductVersion?: string;
}

export interface PEAnalysisResult {
  /** Whether the file is a valid PE. */
  isPE: boolean;
  header: PEHeaderInfo | null;
  sections: PESection[];
  imports: PEImportEntry[];
  exports: PEExportEntry[];
  resources: PEResourceEntry[];
  certificate: PECertificateInfo | null;
  suspiciousImports: SuspiciousImport[];
  /** Flat list of all imported function names. */
  importedFunctions: string[];
  /** Flat list of all exported function names. */
  exportedFunctions: string[];
  versionInfo: PEVersionInfo | null;
}

// ── Constants ────────────────────────────────────────────────────────────────

const MACHINE_TYPES: Record<number, string> = {
  0x0000: 'UNKNOWN',
  0x014c: 'I386',
  0x0166: 'MIPS_R4000',
  0x0200: 'IA64',
  0x8664: 'AMD64',
  0xaa64: 'ARM64',
  0x01c0: 'ARM',
  0x01c4: 'ARMNT',
};

const CHARACTERISTICS_FLAGS: Record<number, string> = {
  0x0001: 'RELOCS_STRIPPED',
  0x0002: 'EXECUTABLE_IMAGE',
  0x0004: 'LINE_NUMS_STRIPPED',
  0x0008: 'LOCAL_SYMS_STRIPPED',
  0x0020: 'LARGE_ADDRESS_AWARE',
  0x0100: '32BIT_MACHINE',
  0x0200: 'DEBUG_STRIPPED',
  0x2000: 'DLL',
};

const DLL_CHARACTERISTICS_FLAGS: Record<number, string> = {
  0x0020: 'HIGH_ENTROPY_VA',
  0x0040: 'DYNAMIC_BASE',
  0x0080: 'FORCE_INTEGRITY',
  0x0100: 'NX_COMPAT',
  0x0200: 'NO_ISOLATION',
  0x0400: 'NO_SEH',
  0x0800: 'NO_BIND',
  0x1000: 'APPCONTAINER',
  0x2000: 'WDM_DRIVER',
  0x4000: 'GUARD_CF',
  0x8000: 'TERMINAL_SERVER_AWARE',
};

const SUBSYSTEM_NAMES: Record<number, string> = {
  0: 'UNKNOWN',
  1: 'NATIVE',
  2: 'WINDOWS_GUI',
  3: 'WINDOWS_CUI',
  5: 'OS2_CUI',
  7: 'POSIX_CUI',
  9: 'WINDOWS_CE_GUI',
  10: 'EFI_APPLICATION',
  11: 'EFI_BOOT_SERVICE_DRIVER',
  12: 'EFI_RUNTIME_DRIVER',
  14: 'XBOX',
};

const SECTION_CHARACTERISTIC_FLAGS: Record<number, string> = {
  0x00000020: 'CNT_CODE',
  0x00000040: 'CNT_INITIALIZED_DATA',
  0x00000080: 'CNT_UNINITIALIZED_DATA',
  0x02000000: 'MEM_DISCARDABLE',
  0x04000000: 'MEM_NOT_CACHED',
  0x08000000: 'MEM_NOT_PAGED',
  0x10000000: 'MEM_SHARED',
  0x20000000: 'MEM_EXECUTE',
  0x40000000: 'MEM_READ',
  0x80000000: 'MEM_WRITE',
};

const RESOURCE_TYPE_NAMES: Record<number, string> = {
  1: 'RT_CURSOR',
  2: 'RT_BITMAP',
  3: 'RT_ICON',
  4: 'RT_MENU',
  5: 'RT_DIALOG',
  6: 'RT_STRING',
  7: 'RT_FONTDIR',
  8: 'RT_FONT',
  9: 'RT_ACCELERATOR',
  10: 'RT_RCDATA',
  11: 'RT_MESSAGETABLE',
  12: 'RT_GROUP_CURSOR',
  14: 'RT_GROUP_ICON',
  16: 'RT_VERSION',
  24: 'RT_MANIFEST',
};

// Suspicious imports that indicate potentially malicious behaviour.
const SUSPICIOUS_IMPORTS: ReadonlyArray<{ func: string; reason: string }> = [
  { func: 'VirtualAlloc', reason: 'Memory allocation for code injection' },
  { func: 'VirtualAllocEx', reason: 'Remote process memory allocation' },
  { func: 'VirtualProtect', reason: 'Changing memory protection (DEP bypass)' },
  { func: 'VirtualProtectEx', reason: 'Remote memory protection change' },
  { func: 'WriteProcessMemory', reason: 'Writing to another process memory' },
  { func: 'ReadProcessMemory', reason: 'Reading another process memory' },
  { func: 'CreateRemoteThread', reason: 'Remote thread creation (code injection)' },
  { func: 'CreateRemoteThreadEx', reason: 'Remote thread creation (code injection)' },
  { func: 'NtCreateThreadEx', reason: 'Native API thread creation' },
  { func: 'RtlCreateUserThread', reason: 'Native API thread creation' },
  { func: 'QueueUserAPC', reason: 'APC injection technique' },
  { func: 'NtQueueApcThread', reason: 'Native APC injection' },
  { func: 'SetWindowsHookEx', reason: 'Hooking / keylogging' },
  { func: 'SetWindowsHookExA', reason: 'Hooking / keylogging' },
  { func: 'SetWindowsHookExW', reason: 'Hooking / keylogging' },
  { func: 'OpenProcess', reason: 'Opening handle to another process' },
  { func: 'LoadLibraryA', reason: 'Dynamic library loading' },
  { func: 'LoadLibraryW', reason: 'Dynamic library loading' },
  { func: 'LoadLibraryExA', reason: 'Dynamic library loading' },
  { func: 'LoadLibraryExW', reason: 'Dynamic library loading' },
  { func: 'GetProcAddress', reason: 'Dynamic function resolution (API hashing)' },
  { func: 'WinExec', reason: 'Process execution' },
  { func: 'ShellExecute', reason: 'Process execution via shell' },
  { func: 'ShellExecuteA', reason: 'Process execution via shell' },
  { func: 'ShellExecuteW', reason: 'Process execution via shell' },
  { func: 'ShellExecuteExA', reason: 'Process execution via shell' },
  { func: 'ShellExecuteExW', reason: 'Process execution via shell' },
  { func: 'CreateProcessA', reason: 'Process creation' },
  { func: 'CreateProcessW', reason: 'Process creation' },
  { func: 'CreateProcessInternalA', reason: 'Internal process creation' },
  { func: 'CreateProcessInternalW', reason: 'Internal process creation' },
  { func: 'URLDownloadToFile', reason: 'File download from URL' },
  { func: 'URLDownloadToFileA', reason: 'File download from URL' },
  { func: 'URLDownloadToFileW', reason: 'File download from URL' },
  { func: 'InternetOpen', reason: 'Internet connection' },
  { func: 'InternetOpenA', reason: 'Internet connection' },
  { func: 'InternetOpenW', reason: 'Internet connection' },
  { func: 'InternetOpenUrl', reason: 'URL access' },
  { func: 'InternetOpenUrlA', reason: 'URL access' },
  { func: 'InternetOpenUrlW', reason: 'URL access' },
  { func: 'HttpOpenRequest', reason: 'HTTP request' },
  { func: 'HttpSendRequest', reason: 'HTTP request' },
  { func: 'RegSetValueEx', reason: 'Registry modification (persistence)' },
  { func: 'RegSetValueExA', reason: 'Registry modification (persistence)' },
  { func: 'RegSetValueExW', reason: 'Registry modification (persistence)' },
  { func: 'RegCreateKeyEx', reason: 'Registry key creation (persistence)' },
  { func: 'RegCreateKeyExA', reason: 'Registry key creation (persistence)' },
  { func: 'RegCreateKeyExW', reason: 'Registry key creation (persistence)' },
  { func: 'CryptEncrypt', reason: 'Encryption (potential ransomware)' },
  { func: 'CryptDecrypt', reason: 'Decryption operation' },
  { func: 'CryptGenKey', reason: 'Cryptographic key generation' },
  { func: 'CryptAcquireContext', reason: 'Crypto provider access' },
  { func: 'CryptAcquireContextA', reason: 'Crypto provider access' },
  { func: 'CryptAcquireContextW', reason: 'Crypto provider access' },
  { func: 'IsDebuggerPresent', reason: 'Anti-debugging' },
  { func: 'CheckRemoteDebuggerPresent', reason: 'Anti-debugging' },
  { func: 'NtQueryInformationProcess', reason: 'Anti-debugging / evasion' },
  { func: 'GetTickCount', reason: 'Timing-based anti-analysis' },
  { func: 'QueryPerformanceCounter', reason: 'Timing-based anti-analysis' },
  { func: 'AdjustTokenPrivileges', reason: 'Privilege escalation' },
  { func: 'LookupPrivilegeValueA', reason: 'Privilege escalation' },
  { func: 'LookupPrivilegeValueW', reason: 'Privilege escalation' },
  { func: 'CreateService', reason: 'Service creation (persistence)' },
  { func: 'CreateServiceA', reason: 'Service creation (persistence)' },
  { func: 'CreateServiceW', reason: 'Service creation (persistence)' },
  { func: 'NtUnmapViewOfSection', reason: 'Process hollowing' },
  { func: 'MapViewOfFile', reason: 'Memory-mapped file (injection)' },
  { func: 'CreateFileMappingA', reason: 'File mapping (injection)' },
  { func: 'CreateFileMappingW', reason: 'File mapping (injection)' },
  { func: 'SetThreadContext', reason: 'Thread context manipulation (injection)' },
  { func: 'GetThreadContext', reason: 'Thread context inspection (injection)' },
  { func: 'SuspendThread', reason: 'Thread suspension (injection)' },
  { func: 'ResumeThread', reason: 'Thread resumption (injection)' },
];

// ── Helper functions ─────────────────────────────────────────────────────────

function decodeFlags(value: number, table: Record<number, string>): string[] {
  const flags: string[] = [];
  for (const [bit, name] of Object.entries(table)) {
    if (value & Number(bit)) {
      flags.push(name);
    }
  }
  return flags;
}

function readNullTerminatedAscii(buf: Buffer, offset: number, maxLen: number = 256): string {
  let s = '';
  for (let i = 0; i < maxLen && offset + i < buf.length; i++) {
    const ch = buf[offset + i]!;
    if (ch === 0) break;
    if (ch >= 0x20 && ch <= 0x7e) {
      s += String.fromCharCode(ch);
    }
  }
  return s;
}

/**
 * Resolves an RVA to a file offset using the section table.
 * Returns -1 if the RVA cannot be resolved.
 */
function rvaToOffset(
  rva: number,
  sections: Array<{ virtualAddress: number; rawDataPointer: number; virtualSize: number; rawSize: number }>,
): number {
  for (const sec of sections) {
    if (rva >= sec.virtualAddress && rva < sec.virtualAddress + Math.max(sec.virtualSize, sec.rawSize)) {
      return sec.rawDataPointer + (rva - sec.virtualAddress);
    }
  }
  return -1;
}

// ── Import parsing ───────────────────────────────────────────────────────────

function parseImports(
  buf: Buffer,
  importTableRVA: number,
  _importTableSize: number,
  is64: boolean,
  sections: Array<{ virtualAddress: number; rawDataPointer: number; virtualSize: number; rawSize: number }>,
): PEImportEntry[] {
  const imports: PEImportEntry[] = [];
  if (importTableRVA === 0) return imports;

  const importTableOffset = rvaToOffset(importTableRVA, sections);
  if (importTableOffset < 0 || importTableOffset >= buf.length) return imports;

  // Each Import Directory Entry is 20 bytes
  const IMPORT_ENTRY_SIZE = 20;
  const MAX_IMPORTS = 500; // Safety limit

  for (let i = 0; i < MAX_IMPORTS; i++) {
    const entryOffset = importTableOffset + i * IMPORT_ENTRY_SIZE;
    if (entryOffset + IMPORT_ENTRY_SIZE > buf.length) break;

    const originalFirstThunk = buf.readUInt32LE(entryOffset);
    const nameRVA = buf.readUInt32LE(entryOffset + 12);
    const firstThunk = buf.readUInt32LE(entryOffset + 16);

    // A zero entry signals the end of the import directory.
    if (nameRVA === 0 && originalFirstThunk === 0 && firstThunk === 0) break;

    const nameOffset = rvaToOffset(nameRVA, sections);
    const dllName = nameOffset >= 0 ? readNullTerminatedAscii(buf, nameOffset) : `unknown_${String(i)}`;

    // Parse the Import Lookup Table (ILT) / Import Name Table (INT).
    const iltRVA = originalFirstThunk !== 0 ? originalFirstThunk : firstThunk;
    const iltOffset = rvaToOffset(iltRVA, sections);
    const functions: string[] = [];

    if (iltOffset >= 0) {
      const thunkSize = is64 ? 8 : 4;
      const MAX_FUNCTIONS = 2000;

      for (let j = 0; j < MAX_FUNCTIONS; j++) {
        const thunkOffset = iltOffset + j * thunkSize;
        if (thunkOffset + thunkSize > buf.length) break;

        let thunkValue: number;
        if (is64) {
          const bigVal = buf.readBigUInt64LE(thunkOffset);
          // Check ordinal flag (bit 63)
          if (bigVal & 0x8000000000000000n) {
            functions.push(`Ordinal_${String(Number(bigVal & 0xFFFFn))}`);
            continue;
          }
          thunkValue = Number(bigVal);
        } else {
          thunkValue = buf.readUInt32LE(thunkOffset);
          // Check ordinal flag (bit 31)
          if (thunkValue & 0x80000000) {
            functions.push(`Ordinal_${String(thunkValue & 0xFFFF)}`);
            continue;
          }
        }

        if (thunkValue === 0) break;

        // Hint/Name table entry: 2-byte hint + null-terminated name
        const hintNameOffset = rvaToOffset(thunkValue, sections);
        if (hintNameOffset >= 0 && hintNameOffset + 2 < buf.length) {
          const funcName = readNullTerminatedAscii(buf, hintNameOffset + 2);
          if (funcName.length > 0) {
            functions.push(funcName);
          }
        }
      }
    }

    imports.push({ dll: dllName, functions });
  }

  return imports;
}

// ── Export parsing ───────────────────────────────────────────────────────────

function parseExports(
  buf: Buffer,
  exportTableRVA: number,
  _exportTableSize: number,
  sections: Array<{ virtualAddress: number; rawDataPointer: number; virtualSize: number; rawSize: number }>,
): PEExportEntry[] {
  const exports: PEExportEntry[] = [];
  if (exportTableRVA === 0) return exports;

  const exportTableOffset = rvaToOffset(exportTableRVA, sections);
  if (exportTableOffset < 0 || exportTableOffset + 40 > buf.length) return exports;

  const numberOfNames = buf.readUInt32LE(exportTableOffset + 24);
  const addressOfNamesRVA = buf.readUInt32LE(exportTableOffset + 32);
  const addressOfOrdinalsRVA = buf.readUInt32LE(exportTableOffset + 36);
  const ordinalBase = buf.readUInt32LE(exportTableOffset + 16);

  const namesOffset = rvaToOffset(addressOfNamesRVA, sections);
  const ordinalsOffset = rvaToOffset(addressOfOrdinalsRVA, sections);

  if (namesOffset < 0 || ordinalsOffset < 0) return exports;

  const MAX_EXPORTS = 5000;
  const count = Math.min(numberOfNames, MAX_EXPORTS);

  for (let i = 0; i < count; i++) {
    const nameRVAOffset = namesOffset + i * 4;
    const ordinalOffset = ordinalsOffset + i * 2;

    if (nameRVAOffset + 4 > buf.length || ordinalOffset + 2 > buf.length) break;

    const nameRVA = buf.readUInt32LE(nameRVAOffset);
    const ordinal = buf.readUInt16LE(ordinalOffset) + ordinalBase;

    const nameFileOffset = rvaToOffset(nameRVA, sections);
    const name = nameFileOffset >= 0 ? readNullTerminatedAscii(buf, nameFileOffset) : `Ordinal_${String(ordinal)}`;

    exports.push({ name, ordinal });
  }

  return exports;
}

// ── Resource parsing (top-level only) ────────────────────────────────────────

function parseResources(
  buf: Buffer,
  resourceRVA: number,
  resourceSize: number,
  sections: Array<{ virtualAddress: number; rawDataPointer: number; virtualSize: number; rawSize: number }>,
): PEResourceEntry[] {
  const resources: PEResourceEntry[] = [];
  if (resourceRVA === 0 || resourceSize === 0) return resources;

  const resourceOffset = rvaToOffset(resourceRVA, sections);
  if (resourceOffset < 0 || resourceOffset + 16 > buf.length) return resources;

  // Parse the root resource directory.
  const numberOfNamedEntries = buf.readUInt16LE(resourceOffset + 12);
  const numberOfIdEntries = buf.readUInt16LE(resourceOffset + 14);
  const totalEntries = numberOfNamedEntries + numberOfIdEntries;

  const MAX_ENTRIES = 200;
  const count = Math.min(totalEntries, MAX_ENTRIES);

  for (let i = 0; i < count; i++) {
    const entryStart = resourceOffset + 16 + i * 8;
    if (entryStart + 8 > buf.length) break;

    const nameOrId = buf.readUInt32LE(entryStart);
    const offsetOrData = buf.readUInt32LE(entryStart + 4);

    const typeId = nameOrId & 0x0000FFFF;
    const typeName = RESOURCE_TYPE_NAMES[typeId] ?? `TYPE_${String(typeId)}`;

    // High bit indicates subdirectory.
    const isSubdir = (offsetOrData & 0x80000000) !== 0;
    const subdirOffset = offsetOrData & 0x7FFFFFFF;

    if (isSubdir) {
      // Walk one level into the subdirectory to count entries.
      const subOffset = resourceOffset + subdirOffset;
      if (subOffset + 16 <= buf.length) {
        const subNamedEntries = buf.readUInt16LE(subOffset + 12);
        const subIdEntries = buf.readUInt16LE(subOffset + 14);
        const subTotal = Math.min(subNamedEntries + subIdEntries, 50);

        for (let j = 0; j < subTotal; j++) {
          const subEntryStart = subOffset + 16 + j * 8;
          if (subEntryStart + 8 > buf.length) break;

          const subNameOrId = buf.readUInt32LE(subEntryStart);
          const subOffsetOrData = buf.readUInt32LE(subEntryStart + 4);
          const subIsSubdir = (subOffsetOrData & 0x80000000) !== 0;
          const subSubOffset = subOffsetOrData & 0x7FFFFFFF;

          if (subIsSubdir) {
            // Third level: language entries with actual data.
            const langDirOffset = resourceOffset + subSubOffset;
            if (langDirOffset + 16 <= buf.length) {
              const langNamed = buf.readUInt16LE(langDirOffset + 12);
              const langId = buf.readUInt16LE(langDirOffset + 14);
              const langTotal = Math.min(langNamed + langId, 10);

              for (let k = 0; k < langTotal; k++) {
                const langEntryStart = langDirOffset + 16 + k * 8;
                if (langEntryStart + 8 > buf.length) break;

                const language = buf.readUInt32LE(langEntryStart) & 0xFFFF;
                const dataEntryOffset = buf.readUInt32LE(langEntryStart + 4) & 0x7FFFFFFF;
                const dataEntryAbsolute = resourceOffset + dataEntryOffset;

                if (dataEntryAbsolute + 16 <= buf.length) {
                  const dataRVA = buf.readUInt32LE(dataEntryAbsolute);
                  const dataSize = buf.readUInt32LE(dataEntryAbsolute + 4);
                  const dataFileOffset = rvaToOffset(dataRVA, sections);

                  resources.push({
                    type: typeName,
                    name: `${typeName}_${String(subNameOrId & 0xFFFF)}`,
                    size: dataSize,
                    offset: dataFileOffset >= 0 ? dataFileOffset : dataRVA,
                    language,
                  });
                }
              }
            }
          }
        }
      }
    }
  }

  return resources;
}

// ── Certificate detection ────────────────────────────────────────────────────

function parseCertificate(
  buf: Buffer,
  certTableRVA: number,
  certTableSize: number,
): PECertificateInfo | null {
  // The certificate table entry uses a file offset, not an RVA.
  if (certTableRVA === 0 || certTableSize === 0) return null;

  if (certTableRVA + 8 > buf.length) {
    return {
      offset: certTableRVA,
      size: certTableSize,
      revision: 0,
      certType: 0,
      hasCertificate: true,
    };
  }

  const certLength = buf.readUInt32LE(certTableRVA);
  const revision = buf.readUInt16LE(certTableRVA + 4);
  const certType = buf.readUInt16LE(certTableRVA + 6);

  return {
    offset: certTableRVA,
    size: certLength,
    revision,
    certType,
    hasCertificate: true,
  };
}

// ── VS_VERSION_INFO parsing ──────────────────────────────────────────────────

const VERSION_STRING_KEYS = [
  'CompanyName', 'FileDescription', 'FileVersion', 'InternalName',
  'LegalCopyright', 'OriginalFilename', 'ProductName', 'ProductVersion',
];

function scanBufferForVersionStrings(
  buf: Buffer,
  start: number,
  end: number,
): PEVersionInfo | null {
  const info: PEVersionInfo = {};

  for (const key of VERSION_STRING_KEYS) {
    const keyUtf16 = Buffer.from(key, 'utf16le');
    let pos = start;
    while (pos < end - keyUtf16.length) {
      pos = buf.indexOf(keyUtf16, pos);
      if (pos < 0 || pos >= end) break;

      let valStart = pos + keyUtf16.length;
      while (valStart < end - 1 && buf.readUInt16LE(valStart) === 0) valStart += 2;
      if (valStart % 4 !== 0) valStart += 4 - (valStart % 4);
      if (valStart >= end) break;

      let valEnd = valStart;
      while (valEnd < end - 1) {
        const ch = buf.readUInt16LE(valEnd);
        if (ch === 0) break;
        valEnd += 2;
      }

      if (valEnd > valStart) {
        const value = buf.subarray(valStart, valEnd).toString('utf16le').trim();
        if (value.length > 0 && value.length < 500) {
          (info as Record<string, string>)[key] = value;
          break;
        }
      }
      pos += keyUtf16.length;
    }
  }

  return Object.keys(info).length > 0 ? info : null;
}

function parseVersionInfo(
  buf: Buffer,
  resources: PEResourceEntry[],
): PEVersionInfo | null {
  // Try from parsed VERSION resource first
  const versionResource = resources.find(r => r.type === 'VERSION');
  if (versionResource && versionResource.offset >= 0) {
    const start = versionResource.offset;
    const end = Math.min(start + versionResource.size, buf.length);
    if (start < buf.length && end - start >= 40) {
      const result = scanBufferForVersionStrings(buf, start, end);
      if (result) return result;
    }
  }

  // Fallback: scan .rsrc section or full binary for VS_VERSION_INFO marker
  const vsMarker = Buffer.from('VS_VERSION_INFO', 'utf16le');
  let searchStart = 0;
  const idx = buf.indexOf(vsMarker, searchStart);
  if (idx >= 0) {
    const regionStart = Math.max(0, idx - 64);
    const regionEnd = Math.min(buf.length, idx + 32768);
    const result = scanBufferForVersionStrings(buf, regionStart, regionEnd);
    if (result) return result;
  }

  return null;
}

// ── Main PE analysis function ────────────────────────────────────────────────

export async function analyzePE(filePath: string): Promise<PEAnalysisResult> {
  const buf = await fs.readFile(filePath);

  const emptyResult: PEAnalysisResult = {
    isPE: false,
    header: null,
    sections: [],
    imports: [],
    exports: [],
    resources: [],
    certificate: null,
    suspiciousImports: [],
    importedFunctions: [],
    exportedFunctions: [],
    versionInfo: null,
  };

  // ── Validate DOS header ──────────────────────────────────
  if (buf.length < 64) return emptyResult;
  if (buf[0] !== 0x4d || buf[1] !== 0x5a) return emptyResult; // "MZ"

  const peOffset = buf.readUInt32LE(0x3c);
  if (peOffset + 24 > buf.length) return emptyResult;

  // ── Validate PE signature ────────────────────────────────
  if (
    buf[peOffset] !== 0x50 ||
    buf[peOffset + 1] !== 0x45 ||
    buf[peOffset + 2] !== 0x00 ||
    buf[peOffset + 3] !== 0x00
  ) {
    return emptyResult;
  }

  // ── Parse COFF header ────────────────────────────────────
  const coffOffset = peOffset + 4;
  const machineRaw = buf.readUInt16LE(coffOffset);
  const numberOfSections = buf.readUInt16LE(coffOffset + 2);
  const timeDateStamp = buf.readUInt32LE(coffOffset + 4);
  const sizeOfOptionalHeader = buf.readUInt16LE(coffOffset + 16);
  const characteristics = buf.readUInt16LE(coffOffset + 18);

  // ── Parse optional header ────────────────────────────────
  const optOffset = coffOffset + 20;
  if (optOffset + sizeOfOptionalHeader > buf.length) return emptyResult;

  const magic = buf.readUInt16LE(optOffset);
  const is64 = magic === 0x20b; // PE32+ = 0x20b, PE32 = 0x10b

  const entryPoint = buf.readUInt32LE(optOffset + 16);
  const imageBase = is64
    ? Number(buf.readBigUInt64LE(optOffset + 24))
    : buf.readUInt32LE(optOffset + 28);
  const subsystemOffset = is64 ? optOffset + 68 : optOffset + 68;
  const subsystem = buf.readUInt16LE(subsystemOffset);
  const dllCharacteristics = buf.readUInt16LE(subsystemOffset + 2);

  // Data directories start at offset 96/112 from optional header start.
  const dataDirOffset = is64 ? optOffset + 112 : optOffset + 96;
  const numberOfRvaAndSizes = buf.readUInt32LE(is64 ? optOffset + 108 : optOffset + 92);

  // Read data directory entries (each 8 bytes: RVA + Size).
  function readDataDir(index: number): { rva: number; size: number } {
    if (index >= numberOfRvaAndSizes) return { rva: 0, size: 0 };
    const off = dataDirOffset + index * 8;
    if (off + 8 > buf.length) return { rva: 0, size: 0 };
    return {
      rva: buf.readUInt32LE(off),
      size: buf.readUInt32LE(off + 4),
    };
  }

  const importDir = readDataDir(1);   // Import Table
  const resourceDir = readDataDir(2); // Resource Table
  const certDir = readDataDir(4);     // Certificate Table
  const exportDir = readDataDir(0);   // Export Table

  // ── Parse section table ──────────────────────────────────
  const sectionTableOffset = optOffset + sizeOfOptionalHeader;
  const rawSections: Array<{
    virtualAddress: number;
    rawDataPointer: number;
    virtualSize: number;
    rawSize: number;
  }> = [];
  const sections: PESection[] = [];

  for (let i = 0; i < numberOfSections; i++) {
    const secOffset = sectionTableOffset + i * 40;
    if (secOffset + 40 > buf.length) break;

    let name = '';
    for (let j = 0; j < 8; j++) {
      const ch = buf[secOffset + j]!;
      if (ch === 0) break;
      name += String.fromCharCode(ch);
    }

    const virtualSize = buf.readUInt32LE(secOffset + 8);
    const virtualAddress = buf.readUInt32LE(secOffset + 12);
    const rawSize = buf.readUInt32LE(secOffset + 16);
    const rawDataPointer = buf.readUInt32LE(secOffset + 20);
    const secCharacteristics = buf.readUInt32LE(secOffset + 36);

    rawSections.push({ virtualAddress, rawDataPointer, virtualSize, rawSize });

    // Compute section entropy and hash.
    let entropy = 0;
    let md5 = '';
    if (rawSize > 0 && rawDataPointer + rawSize <= buf.length) {
      const sectionData = buf.subarray(rawDataPointer, rawDataPointer + rawSize);
      entropy = calculateEntropy(sectionData);
      md5 = crypto.createHash('md5').update(sectionData).digest('hex');
    }

    sections.push({
      name,
      virtualSize,
      virtualAddress,
      rawSize,
      rawDataPointer,
      characteristics: secCharacteristics,
      characteristicFlags: decodeFlags(secCharacteristics, SECTION_CHARACTERISTIC_FLAGS),
      entropy,
      md5,
    });
  }

  // ── Parse imports ────────────────────────────────────────
  const imports = parseImports(buf, importDir.rva, importDir.size, is64, rawSections);

  // ── Parse exports ────────────────────────────────────────
  const exports = parseExports(buf, exportDir.rva, exportDir.size, rawSections);

  // ── Parse resources ──────────────────────────────────────
  const resources = parseResources(buf, resourceDir.rva, resourceDir.size, rawSections);

  // ── Parse certificate ────────────────────────────────────
  const certificate = parseCertificate(buf, certDir.rva, certDir.size);

  // ── Build flat import/export lists ───────────────────────
  const importedFunctions = imports.flatMap((imp) => imp.functions);
  const exportedFunctions = exports.map((exp) => exp.name);

  // ── Detect suspicious imports ────────────────────────────
  const importedSet = new Set(importedFunctions);
  const suspiciousImports: SuspiciousImport[] = [];

  for (const sus of SUSPICIOUS_IMPORTS) {
    if (importedSet.has(sus.func)) {
      // Find which DLL imports this function.
      const dll = imports.find((imp) => imp.functions.includes(sus.func))?.dll ?? 'unknown';
      suspiciousImports.push({
        dll,
        function: sus.func,
        reason: sus.reason,
      });
    }
  }

  // ── Assemble header info ─────────────────────────────────
  const header: PEHeaderInfo = {
    machine: MACHINE_TYPES[machineRaw] ?? `UNKNOWN_0x${machineRaw.toString(16)}`,
    machineRaw,
    numberOfSections,
    timeDateStamp,
    compiledAt: new Date(timeDateStamp * 1000).toISOString(),
    characteristics,
    characteristicFlags: decodeFlags(characteristics, CHARACTERISTICS_FLAGS),
    is64Bit: is64,
    magic,
    entryPoint,
    imageBase,
    subsystem: SUBSYSTEM_NAMES[subsystem] ?? `UNKNOWN_${String(subsystem)}`,
    dllCharacteristics,
    dllCharacteristicFlags: decodeFlags(dllCharacteristics, DLL_CHARACTERISTICS_FLAGS),
  };

  // ── Parse version info from resources ─────────────────────
  const versionInfo = parseVersionInfo(buf, resources);

  return {
    isPE: true,
    header,
    sections,
    imports,
    exports,
    resources,
    certificate,
    suspiciousImports,
    importedFunctions,
    exportedFunctions,
    versionInfo,
  };
}
