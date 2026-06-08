import * as fs from 'node:fs/promises';
import { calculateEntropy } from './entropy.js';

// ── Result types ─────────────────────────────────────────────────────────────

export interface ELFHeaderInfo {
  /** ELF class: 32 or 64. */
  elfClass: 32 | 64;
  /** Data encoding: 'little' or 'big'. */
  endianness: 'little' | 'big';
  /** ELF version (should be 1). */
  version: number;
  /** OS/ABI. */
  osAbi: string;
  /** Object file type. */
  type: string;
  typeRaw: number;
  /** Machine architecture. */
  machine: string;
  machineRaw: number;
  /** Entry point address. */
  entryPoint: number;
  /** Flags from the ELF header. */
  flags: number;
}

export interface ELFSection {
  name: string;
  type: string;
  typeRaw: number;
  flags: number;
  flagNames: string[];
  address: number;
  offset: number;
  size: number;
  entropy: number;
}

export interface ELFSymbol {
  name: string;
  type: string;
  binding: string;
  section: string;
  value: number;
}

export interface ELFDynamicEntry {
  tag: string;
  value: number | string;
}

export interface SuspiciousFunction {
  name: string;
  reason: string;
}

export interface ELFAnalysisResult {
  /** Whether the file is a valid ELF. */
  isELF: boolean;
  header: ELFHeaderInfo | null;
  sections: ELFSection[];
  /** Shared libraries referenced via DT_NEEDED. */
  libraries: string[];
  /** Dynamic symbols. */
  symbols: ELFSymbol[];
  /** Key dynamic entries. */
  dynamicEntries: ELFDynamicEntry[];
  /** Suspicious functions found in the symbol table. */
  suspiciousFunctions: SuspiciousFunction[];
  /** Whether the binary is statically linked (no .dynamic section). */
  isStaticLinked: boolean;
  /** Whether the binary is stripped (no .symtab). */
  isStripped: boolean;
  /** Whether the binary has a RELRO segment. */
  hasRelro: boolean;
  /** Whether the binary has stack canary references. */
  hasStackCanary: boolean;
  /** Whether NX (non-executable stack) is enabled. */
  hasNX: boolean;
  /** Whether the binary is a position-independent executable. */
  isPIE: boolean;
}

// ── Constants ────────────────────────────────────────────────────────────────

const OS_ABI_NAMES: Record<number, string> = {
  0: 'ELFOSABI_NONE',
  1: 'ELFOSABI_HPUX',
  2: 'ELFOSABI_NETBSD',
  3: 'ELFOSABI_LINUX',
  6: 'ELFOSABI_SOLARIS',
  7: 'ELFOSABI_AIX',
  8: 'ELFOSABI_IRIX',
  9: 'ELFOSABI_FREEBSD',
  12: 'ELFOSABI_OPENBSD',
  97: 'ELFOSABI_ARM',
  255: 'ELFOSABI_STANDALONE',
};

const TYPE_NAMES: Record<number, string> = {
  0: 'ET_NONE',
  1: 'ET_REL',
  2: 'ET_EXEC',
  3: 'ET_DYN',
  4: 'ET_CORE',
};

const MACHINE_NAMES: Record<number, string> = {
  0: 'EM_NONE',
  3: 'EM_386',
  8: 'EM_MIPS',
  20: 'EM_PPC',
  21: 'EM_PPC64',
  40: 'EM_ARM',
  50: 'EM_IA_64',
  62: 'EM_X86_64',
  183: 'EM_AARCH64',
  243: 'EM_RISCV',
};

const SECTION_TYPE_NAMES: Record<number, string> = {
  0: 'SHT_NULL',
  1: 'SHT_PROGBITS',
  2: 'SHT_SYMTAB',
  3: 'SHT_STRTAB',
  4: 'SHT_RELA',
  5: 'SHT_HASH',
  6: 'SHT_DYNAMIC',
  7: 'SHT_NOTE',
  8: 'SHT_NOBITS',
  9: 'SHT_REL',
  11: 'SHT_DYNSYM',
  14: 'SHT_INIT_ARRAY',
  15: 'SHT_FINI_ARRAY',
};

const SECTION_FLAGS: Record<number, string> = {
  0x1: 'SHF_WRITE',
  0x2: 'SHF_ALLOC',
  0x4: 'SHF_EXECINSTR',
  0x10: 'SHF_MERGE',
  0x20: 'SHF_STRINGS',
};

const SYMBOL_TYPE_NAMES: Record<number, string> = {
  0: 'STT_NOTYPE',
  1: 'STT_OBJECT',
  2: 'STT_FUNC',
  3: 'STT_SECTION',
  4: 'STT_FILE',
  5: 'STT_COMMON',
  10: 'STT_GNU_IFUNC',
};

const SYMBOL_BINDING_NAMES: Record<number, string> = {
  0: 'STB_LOCAL',
  1: 'STB_GLOBAL',
  2: 'STB_WEAK',
};

const DT_TAG_NAMES: Record<number, string> = {
  0: 'DT_NULL',
  1: 'DT_NEEDED',
  2: 'DT_PLTRELSZ',
  3: 'DT_PLTGOT',
  4: 'DT_HASH',
  5: 'DT_STRTAB',
  6: 'DT_SYMTAB',
  7: 'DT_RELA',
  10: 'DT_STRSZ',
  12: 'DT_INIT',
  13: 'DT_FINI',
  14: 'DT_SONAME',
  15: 'DT_RPATH',
  17: 'DT_REL',
  20: 'DT_PLTREL',
  21: 'DT_DEBUG',
  23: 'DT_JMPREL',
  24: 'DT_BIND_NOW',
  25: 'DT_INIT_ARRAY',
  26: 'DT_FINI_ARRAY',
  29: 'DT_FLAGS',
  30: 'DT_RUNPATH',
  0x6ffffffb: 'DT_FLAGS_1',
  0x6ffffffe: 'DT_VERNEED',
  0x6fffffff: 'DT_VERNEEDNUM',
};

// Program header types relevant for security checks.
const PT_GNU_STACK = 0x6474e551;
const PT_GNU_RELRO = 0x6474e552;

const SUSPICIOUS_FUNCTIONS: ReadonlyArray<{ name: string; reason: string }> = [
  // Network
  { name: 'socket', reason: 'Network socket creation' },
  { name: 'connect', reason: 'Network connection' },
  { name: 'bind', reason: 'Network port binding' },
  { name: 'listen', reason: 'Network listening' },
  { name: 'accept', reason: 'Network connection acceptance' },
  { name: 'send', reason: 'Network data transmission' },
  { name: 'recv', reason: 'Network data reception' },
  { name: 'sendto', reason: 'Network datagram send' },
  { name: 'recvfrom', reason: 'Network datagram receive' },
  { name: 'getaddrinfo', reason: 'DNS resolution' },
  { name: 'gethostbyname', reason: 'DNS resolution (legacy)' },
  // Process execution
  { name: 'execve', reason: 'Process execution' },
  { name: 'execvp', reason: 'Process execution via PATH' },
  { name: 'system', reason: 'Shell command execution' },
  { name: 'popen', reason: 'Shell command with pipe' },
  { name: 'fork', reason: 'Process forking' },
  { name: 'clone', reason: 'Process/thread cloning' },
  // Code injection / memory manipulation
  { name: 'ptrace', reason: 'Process tracing / anti-debugging / injection' },
  { name: 'mmap', reason: 'Memory mapping (potential code injection)' },
  { name: 'mprotect', reason: 'Memory protection change' },
  { name: 'dlopen', reason: 'Dynamic library loading' },
  { name: 'dlsym', reason: 'Dynamic symbol resolution' },
  // File system
  { name: 'unlink', reason: 'File deletion' },
  { name: 'rmdir', reason: 'Directory removal' },
  { name: 'chmod', reason: 'Permission modification' },
  { name: 'chown', reason: 'Ownership modification' },
  { name: 'mount', reason: 'Filesystem mounting' },
  { name: 'umount', reason: 'Filesystem unmounting' },
  // Privilege escalation
  { name: 'setuid', reason: 'Set user ID (privilege escalation)' },
  { name: 'setgid', reason: 'Set group ID (privilege escalation)' },
  { name: 'seteuid', reason: 'Set effective UID' },
  { name: 'setegid', reason: 'Set effective GID' },
  { name: 'setreuid', reason: 'Set real/effective UID' },
  { name: 'setregid', reason: 'Set real/effective GID' },
  // Anti-analysis
  { name: 'prctl', reason: 'Process control (anti-debugging)' },
  { name: 'personality', reason: 'Process personality change' },
  // Keylogging / input capture
  { name: 'XOpenDisplay', reason: 'X11 display access (keylogging)' },
  { name: 'XQueryKeymap', reason: 'X11 keyboard state query' },
  // Encryption
  { name: 'EVP_EncryptInit', reason: 'OpenSSL encryption' },
  { name: 'EVP_EncryptInit_ex', reason: 'OpenSSL encryption' },
  { name: 'AES_encrypt', reason: 'AES encryption' },
  { name: 'AES_set_encrypt_key', reason: 'AES key setup' },
  // Kernel module
  { name: 'init_module', reason: 'Kernel module loading' },
  { name: 'finit_module', reason: 'Kernel module loading (fd-based)' },
  { name: 'delete_module', reason: 'Kernel module unloading' },
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

function readNullTerminatedString(buf: Buffer, offset: number, maxLen: number = 256): string {
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

// ── Main ELF analysis function ───────────────────────────────────────────────

export async function analyzeELF(filePath: string): Promise<ELFAnalysisResult> {
  const buf = await fs.readFile(filePath);

  const emptyResult: ELFAnalysisResult = {
    isELF: false,
    header: null,
    sections: [],
    libraries: [],
    symbols: [],
    dynamicEntries: [],
    suspiciousFunctions: [],
    isStaticLinked: false,
    isStripped: false,
    hasRelro: false,
    hasStackCanary: false,
    hasNX: false,
    isPIE: false,
  };

  // ── Validate ELF magic ───────────────────────────────────
  if (buf.length < 64) return emptyResult;
  if (buf[0] !== 0x7f || buf[1] !== 0x45 || buf[2] !== 0x4c || buf[3] !== 0x46) {
    return emptyResult;
  }

  const elfClass = buf[4] === 2 ? 64 : 32;
  const is64 = elfClass === 64;
  const isLE = buf[5] === 1;
  const elfVersion = buf[6]!;
  const osAbi = buf[7]!;

  // Set up endian-aware readers.
  const readU16 = isLE
    ? (offset: number) => buf.readUInt16LE(offset)
    : (offset: number) => buf.readUInt16BE(offset);
  const readU32 = isLE
    ? (offset: number) => buf.readUInt32LE(offset)
    : (offset: number) => buf.readUInt32BE(offset);
  const readU64 = isLE
    ? (offset: number) => Number(buf.readBigUInt64LE(offset))
    : (offset: number) => Number(buf.readBigUInt64BE(offset));

  // ── Parse ELF header ─────────────────────────────────────
  const typeRaw = readU16(16);
  const machineRaw = readU16(18);

  let entryPoint: number;
  let phoff: number;
  let shoff: number;
  let phentsize: number;
  let phnum: number;
  let shentsize: number;
  let shnum: number;
  let shstrndx: number;

  if (is64) {
    entryPoint = readU64(24);
    phoff = readU64(32);
    shoff = readU64(40);
    phentsize = readU16(54);
    phnum = readU16(56);
    shentsize = readU16(58);
    shnum = readU16(60);
    shstrndx = readU16(62);
  } else {
    entryPoint = readU32(24);
    phoff = readU32(28);
    shoff = readU32(32);
    phentsize = readU16(42);
    phnum = readU16(44);
    shentsize = readU16(46);
    shnum = readU16(48);
    shstrndx = readU16(50);
  }

  const header: ELFHeaderInfo = {
    elfClass,
    endianness: isLE ? 'little' : 'big',
    version: elfVersion,
    osAbi: OS_ABI_NAMES[osAbi] ?? `UNKNOWN_${String(osAbi)}`,
    type: TYPE_NAMES[typeRaw] ?? `UNKNOWN_${String(typeRaw)}`,
    typeRaw,
    machine: MACHINE_NAMES[machineRaw] ?? `UNKNOWN_${String(machineRaw)}`,
    machineRaw,
    entryPoint,
    flags: is64 ? readU32(48) : readU32(36),
  };

  // ── Read section header string table ─────────────────────
  let strtabOffset = 0;
  let strtabSize = 0;

  if (shoff > 0 && shstrndx < shnum) {
    const strSecOffset = shoff + shstrndx * shentsize;
    if (is64 && strSecOffset + 64 <= buf.length) {
      strtabOffset = readU64(strSecOffset + 24);
      strtabSize = readU64(strSecOffset + 32);
    } else if (!is64 && strSecOffset + 40 <= buf.length) {
      strtabOffset = readU32(strSecOffset + 16);
      strtabSize = readU32(strSecOffset + 20);
    }
  }

  function readSectionName(nameIndex: number): string {
    if (strtabOffset === 0 || nameIndex >= strtabSize) return '';
    return readNullTerminatedString(buf, strtabOffset + nameIndex);
  }

  // ── Parse section table ──────────────────────────────────
  const sections: ELFSection[] = [];
  let hasDynamic = false;
  let hasSymtab = false;
  let dynstrOffset = 0;
  let dynstrSize = 0;
  let dynsymOffset = 0;
  let dynsymSize = 0;
  let dynsymEntsize = 0;
  let dynamicOffset = 0;
  let dynamicSize = 0;
  let dynamicEntsize = 0;

  if (shoff > 0) {
    for (let i = 0; i < shnum; i++) {
      const secHeaderOffset = shoff + i * shentsize;
      if (secHeaderOffset + shentsize > buf.length) break;

      const nameIdx = readU32(secHeaderOffset);
      const shType = readU32(secHeaderOffset + 4);
      const name = readSectionName(nameIdx);

      let shFlags: number;
      let shAddr: number;
      let shFileOffset: number;
      let shSize: number;

      if (is64) {
        shFlags = readU64(secHeaderOffset + 8);
        shAddr = readU64(secHeaderOffset + 16);
        shFileOffset = readU64(secHeaderOffset + 24);
        shSize = readU64(secHeaderOffset + 32);
      } else {
        shFlags = readU32(secHeaderOffset + 8);
        shAddr = readU32(secHeaderOffset + 12);
        shFileOffset = readU32(secHeaderOffset + 16);
        shSize = readU32(secHeaderOffset + 20);
      }

      // Track specific sections for later.
      if (shType === 6) { // SHT_DYNAMIC
        hasDynamic = true;
        dynamicOffset = shFileOffset;
        dynamicSize = shSize;
        dynamicEntsize = is64 ? 16 : 8;
      }
      if (shType === 2) { // SHT_SYMTAB
        hasSymtab = true;
      }
      if (shType === 11) { // SHT_DYNSYM
        dynsymOffset = shFileOffset;
        dynsymSize = shSize;
        dynsymEntsize = is64 ? 24 : 16;
      }
      if (name === '.dynstr' && shType === 3) {
        dynstrOffset = shFileOffset;
        dynstrSize = shSize;
      }

      // Compute entropy (skip NULL, NOBITS).
      let entropy = 0;
      if (shType !== 0 && shType !== 8 && shSize > 0 && shFileOffset + shSize <= buf.length) {
        const sectionData = buf.subarray(shFileOffset, shFileOffset + shSize);
        entropy = calculateEntropy(sectionData);
      }

      sections.push({
        name,
        type: SECTION_TYPE_NAMES[shType] ?? `SHT_${String(shType)}`,
        typeRaw: shType,
        flags: shFlags,
        flagNames: decodeFlags(shFlags, SECTION_FLAGS),
        address: shAddr,
        offset: shFileOffset,
        size: shSize,
        entropy,
      });
    }
  }

  // ── Parse dynamic entries (DT_NEEDED, etc.) ──────────────
  const libraries: string[] = [];
  const dynamicEntries: ELFDynamicEntry[] = [];

  if (dynamicOffset > 0 && dynamicSize > 0 && dynamicEntsize > 0) {
    const numEntries = Math.floor(dynamicSize / dynamicEntsize);
    const MAX_DYNAMIC = 500;

    for (let i = 0; i < Math.min(numEntries, MAX_DYNAMIC); i++) {
      const entOffset = dynamicOffset + i * dynamicEntsize;
      if (entOffset + dynamicEntsize > buf.length) break;

      let tag: number;
      let val: number;

      if (is64) {
        tag = readU64(entOffset);
        val = readU64(entOffset + 8);
      } else {
        tag = readU32(entOffset);
        val = readU32(entOffset + 4);
      }

      // DT_NULL signals the end.
      if (tag === 0) break;

      const tagName = DT_TAG_NAMES[tag] ?? `DT_0x${tag.toString(16)}`;

      if (tag === 1 && dynstrOffset > 0) { // DT_NEEDED
        const libName = readNullTerminatedString(buf, dynstrOffset + val);
        libraries.push(libName);
        dynamicEntries.push({ tag: tagName, value: libName });
      } else if (tag === 14 && dynstrOffset > 0) { // DT_SONAME
        const soname = readNullTerminatedString(buf, dynstrOffset + val);
        dynamicEntries.push({ tag: tagName, value: soname });
      } else if (tag === 15 && dynstrOffset > 0) { // DT_RPATH
        const rpath = readNullTerminatedString(buf, dynstrOffset + val);
        dynamicEntries.push({ tag: tagName, value: rpath });
      } else if (tag === 30 && dynstrOffset > 0) { // DT_RUNPATH
        const runpath = readNullTerminatedString(buf, dynstrOffset + val);
        dynamicEntries.push({ tag: tagName, value: runpath });
      } else {
        dynamicEntries.push({ tag: tagName, value: val });
      }
    }
  }

  // ── Parse dynamic symbols ────────────────────────────────
  const symbols: ELFSymbol[] = [];

  if (dynsymOffset > 0 && dynsymSize > 0 && dynsymEntsize > 0 && dynstrOffset > 0) {
    const numSymbols = Math.floor(dynsymSize / dynsymEntsize);
    const MAX_SYMBOLS = 5000;

    for (let i = 0; i < Math.min(numSymbols, MAX_SYMBOLS); i++) {
      const symOffset = dynsymOffset + i * dynsymEntsize;
      if (symOffset + dynsymEntsize > buf.length) break;

      let nameIdx: number;
      let info: number;
      let shndx: number;
      let value: number;

      if (is64) {
        nameIdx = readU32(symOffset);
        info = buf[symOffset + 4]!;
        shndx = readU16(symOffset + 6);
        value = readU64(symOffset + 8);
      } else {
        nameIdx = readU32(symOffset);
        value = readU32(symOffset + 4);
        info = buf[symOffset + 12]!;
        shndx = readU16(symOffset + 14);
      }

      const symType = info & 0xf;
      const symBinding = (info >> 4) & 0xf;

      const name = nameIdx > 0 && nameIdx < dynstrSize
        ? readNullTerminatedString(buf, dynstrOffset + nameIdx)
        : '';

      if (name.length === 0) continue;

      // Resolve section name for the symbol.
      let sectionName = '';
      if (shndx === 0) sectionName = 'UND';
      else if (shndx === 0xfff1) sectionName = 'ABS';
      else if (shndx === 0xfff2) sectionName = 'COMMON';
      else if (shndx < sections.length) sectionName = sections[shndx]?.name ?? '';

      symbols.push({
        name,
        type: SYMBOL_TYPE_NAMES[symType] ?? `STT_${String(symType)}`,
        binding: SYMBOL_BINDING_NAMES[symBinding] ?? `STB_${String(symBinding)}`,
        section: sectionName,
        value,
      });
    }
  }

  // ── Detect suspicious functions ──────────────────────────
  const symbolNameSet = new Set(symbols.map((s) => s.name));
  const suspiciousFunctions: SuspiciousFunction[] = [];

  for (const sus of SUSPICIOUS_FUNCTIONS) {
    if (symbolNameSet.has(sus.name)) {
      suspiciousFunctions.push({ name: sus.name, reason: sus.reason });
    }
  }

  // ── Security feature detection via program headers ───────
  let hasRelro = false;
  let hasNX = false;
  const isPIE = typeRaw === 3; // ET_DYN with entry point suggests PIE

  if (phoff > 0 && phnum > 0) {
    for (let i = 0; i < phnum; i++) {
      const phEntryOffset = phoff + i * phentsize;
      if (phEntryOffset + phentsize > buf.length) break;

      const pType = readU32(phEntryOffset);
      const pFlags = is64 ? readU32(phEntryOffset + 4) : readU32(phEntryOffset + 24);

      if (pType === PT_GNU_RELRO) {
        hasRelro = true;
      }
      if (pType === PT_GNU_STACK) {
        // If the stack segment does NOT have PF_X (execute), NX is enabled.
        hasNX = (pFlags & 0x1) === 0;
      }
    }
  }

  // Stack canary detection: look for __stack_chk_fail in symbols.
  const hasStackCanary = symbolNameSet.has('__stack_chk_fail') || symbolNameSet.has('__stack_chk_guard');

  return {
    isELF: true,
    header,
    sections,
    libraries,
    symbols,
    dynamicEntries,
    suspiciousFunctions,
    isStaticLinked: !hasDynamic,
    isStripped: !hasSymtab,
    hasRelro,
    hasStackCanary,
    hasNX,
    isPIE,
  };
}
