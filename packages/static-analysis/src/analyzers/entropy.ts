import * as fs from 'node:fs/promises';

// ── Result types ─────────────────────────────────────────────────────────────

export interface SectionEntropy {
  name: string;
  offset: number;
  size: number;
  entropy: number;
  isHighEntropy: boolean;
}

export interface EntropyResult {
  /** Shannon entropy of the entire file (0.0 - 8.0 for byte-level). */
  overallEntropy: number;
  /** Whether the file is likely packed or encrypted based on overall entropy. */
  isPacked: boolean;
  /** Per-section entropy (populated for PE/ELF files, empty otherwise). */
  sections: SectionEntropy[];
  /** Histogram of byte frequencies (256 entries, each 0.0-1.0). */
  byteHistogram: number[];
}

// ── Shannon entropy calculation ──────────────────────────────────────────────

/**
 * Computes Shannon entropy of a byte buffer.
 * Returns a value between 0.0 (all identical bytes) and 8.0 (uniformly random).
 */
export function calculateEntropy(data: Buffer | Uint8Array): number {
  if (data.length === 0) return 0;

  const freq = new Float64Array(256);
  for (let i = 0; i < data.length; i++) {
    const b = data[i];
    // b is always defined when i < data.length for typed arrays / Buffers.
    if (b !== undefined) freq[b] = (freq[b] ?? 0) + 1;
  }

  let entropy = 0;
  const len = data.length;
  for (let i = 0; i < 256; i++) {
    const f = freq[i] ?? 0;
    if (f > 0) {
      const p = f / len;
      entropy -= p * Math.log2(p);
    }
  }

  return entropy;
}

/**
 * Computes a normalised byte-frequency histogram (256 buckets, each 0.0-1.0).
 */
function computeHistogram(data: Buffer): number[] {
  const freq = new Float64Array(256);
  for (let i = 0; i < data.length; i++) {
    const b = data[i];
    if (b !== undefined) freq[b] = (freq[b] ?? 0) + 1;
  }
  const len = data.length || 1;
  return Array.from(freq, (f) => f / len);
}

// ── PE section parsing (minimal, for entropy-per-section) ────────────────────

interface RawSection {
  name: string;
  offset: number;
  size: number;
}

/**
 * Extracts PE section table entries for entropy analysis.
 * Returns an empty array if the file is not a PE.
 */
function parsePESections(buf: Buffer): RawSection[] {
  if (buf.length < 64) return [];
  // MZ signature
  if (buf[0] !== 0x4d || buf[1] !== 0x5a) return [];

  const peOffset = buf.readUInt32LE(0x3c);
  if (peOffset + 24 > buf.length) return [];

  // PE\0\0 signature
  if (
    buf[peOffset] !== 0x50 ||
    buf[peOffset + 1] !== 0x45 ||
    buf[peOffset + 2] !== 0x00 ||
    buf[peOffset + 3] !== 0x00
  ) {
    return [];
  }

  const coffHeaderOffset = peOffset + 4;
  const numberOfSections = buf.readUInt16LE(coffHeaderOffset + 2);
  const sizeOfOptionalHeader = buf.readUInt16LE(coffHeaderOffset + 16);
  const sectionTableOffset = coffHeaderOffset + 20 + sizeOfOptionalHeader;

  const sections: RawSection[] = [];
  for (let i = 0; i < numberOfSections; i++) {
    const entryOffset = sectionTableOffset + i * 40;
    if (entryOffset + 40 > buf.length) break;

    // Section name: 8 bytes, null-padded
    let name = '';
    for (let j = 0; j < 8; j++) {
      const ch = buf[entryOffset + j]!;
      if (ch === 0) break;
      name += String.fromCharCode(ch);
    }

    const rawDataSize = buf.readUInt32LE(entryOffset + 16);
    const rawDataPointer = buf.readUInt32LE(entryOffset + 20);

    if (rawDataSize > 0 && rawDataPointer + rawDataSize <= buf.length) {
      sections.push({
        name,
        offset: rawDataPointer,
        size: rawDataSize,
      });
    }
  }

  return sections;
}

/**
 * Extracts ELF section table entries for entropy analysis.
 * Returns an empty array if the file is not an ELF.
 */
function parseELFSections(buf: Buffer): RawSection[] {
  if (buf.length < 64) return [];
  // ELF magic: 0x7f E L F
  if (buf[0] !== 0x7f || buf[1] !== 0x45 || buf[2] !== 0x4c || buf[3] !== 0x46) {
    return [];
  }

  const is64 = buf[4] === 2;
  const isLE = buf[5] === 1;

  const readU16 = isLE
    ? (offset: number) => buf.readUInt16LE(offset)
    : (offset: number) => buf.readUInt16BE(offset);
  const readU32 = isLE
    ? (offset: number) => buf.readUInt32LE(offset)
    : (offset: number) => buf.readUInt32BE(offset);

  let shoff: number;
  let shentsize: number;
  let shnum: number;
  let shstrndx: number;

  if (is64) {
    if (buf.length < 64) return [];
    // e_shoff at offset 40 (8 bytes, but we'll use readU32 for lower 32 bits)
    shoff = Number(isLE ? buf.readBigUInt64LE(40) : buf.readBigUInt64BE(40));
    shentsize = readU16(58);
    shnum = readU16(60);
    shstrndx = readU16(62);
  } else {
    if (buf.length < 52) return [];
    shoff = readU32(32);
    shentsize = readU16(46);
    shnum = readU16(48);
    shstrndx = readU16(50);
  }

  if (shoff === 0 || shnum === 0 || shoff + shnum * shentsize > buf.length) {
    return [];
  }

  // Read the section header string table to get names.
  let strtabOffset = 0;
  let strtabSize = 0;

  if (shstrndx < shnum) {
    const strSecOffset = shoff + shstrndx * shentsize;
    if (is64) {
      strtabOffset = Number(isLE ? buf.readBigUInt64LE(strSecOffset + 24) : buf.readBigUInt64BE(strSecOffset + 24));
      strtabSize = Number(isLE ? buf.readBigUInt64LE(strSecOffset + 32) : buf.readBigUInt64BE(strSecOffset + 32));
    } else {
      strtabOffset = readU32(strSecOffset + 16);
      strtabSize = readU32(strSecOffset + 20);
    }
  }

  function readSectionName(nameIndex: number): string {
    if (strtabOffset === 0 || nameIndex >= strtabSize) return `section_${String(nameIndex)}`;
    let name = '';
    for (let i = strtabOffset + nameIndex; i < strtabOffset + strtabSize && i < buf.length; i++) {
      const ch = buf[i]!;
      if (ch === 0) break;
      name += String.fromCharCode(ch);
    }
    return name || `section_${String(nameIndex)}`;
  }

  const sections: RawSection[] = [];

  for (let i = 0; i < shnum; i++) {
    const entryOffset = shoff + i * shentsize;
    if (entryOffset + shentsize > buf.length) break;

    const nameIdx = readU32(entryOffset);
    const shType = readU32(entryOffset + 4);

    // Skip NULL and NOBITS sections
    if (shType === 0 || shType === 8) continue;

    let secOffset: number;
    let secSize: number;

    if (is64) {
      secOffset = Number(isLE ? buf.readBigUInt64LE(entryOffset + 24) : buf.readBigUInt64BE(entryOffset + 24));
      secSize = Number(isLE ? buf.readBigUInt64LE(entryOffset + 32) : buf.readBigUInt64BE(entryOffset + 32));
    } else {
      secOffset = readU32(entryOffset + 16);
      secSize = readU32(entryOffset + 20);
    }

    if (secSize > 0 && secOffset + secSize <= buf.length) {
      sections.push({
        name: readSectionName(nameIdx),
        offset: secOffset,
        size: secSize,
      });
    }
  }

  return sections;
}

// ── Main analysis function ───────────────────────────────────────────────────

export async function analyzeEntropy(
  filePath: string,
  highEntropyThreshold: number = 7.0,
): Promise<EntropyResult> {
  const buf = await fs.readFile(filePath);

  const overallEntropy = calculateEntropy(buf);
  const byteHistogram = computeHistogram(buf);

  // Try PE sections first, then ELF.
  let rawSections = parsePESections(buf);
  if (rawSections.length === 0) {
    rawSections = parseELFSections(buf);
  }

  const sections: SectionEntropy[] = rawSections.map((sec) => {
    const sectionData = buf.subarray(sec.offset, sec.offset + sec.size);
    const entropy = calculateEntropy(sectionData);
    return {
      name: sec.name,
      offset: sec.offset,
      size: sec.size,
      entropy,
      isHighEntropy: entropy >= highEntropyThreshold,
    };
  });

  // A file with overall entropy > 7.0 and/or a large percentage of
  // high-entropy sections is likely packed/encrypted.
  const hasHighEntropySections = sections.length > 0 &&
    sections.filter((s) => s.isHighEntropy).length / sections.length > 0.5;
  const isPacked = overallEntropy >= highEntropyThreshold || hasHighEntropySections;

  return {
    overallEntropy,
    isPacked,
    sections,
    byteHistogram,
  };
}
