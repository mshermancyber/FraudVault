import { describe, it, expect, vi } from 'vitest';
import * as fs from 'node:fs/promises';
import { analyzePE } from '../analyzers/pe.js';

vi.mock('node:fs/promises', () => ({
  readFile: vi.fn(),
}));

const mockedReadFile = vi.mocked(fs.readFile);

/**
 * Build a minimal valid PE file buffer for testing.
 * This creates a PE32 (i386) file with one section (.text) and
 * one import entry pointing to kernel32.dll importing VirtualAllocEx.
 */
function buildMinimalPE(): Buffer {
  // Allocate a generous buffer
  const buf = Buffer.alloc(1024, 0);

  // ── DOS Header ──
  buf.write('MZ', 0, 'ascii');             // e_magic
  buf.writeUInt32LE(0x80, 0x3c);           // e_lfanew -> PE header at offset 0x80

  // ── PE Signature ──
  const peOff = 0x80;
  buf.write('PE', peOff, 'ascii');         // "PE\0\0"
  buf[peOff + 2] = 0;
  buf[peOff + 3] = 0;

  // ── COFF Header ──
  const coffOff = peOff + 4;
  buf.writeUInt16LE(0x014c, coffOff);       // Machine: I386
  buf.writeUInt16LE(1, coffOff + 2);        // NumberOfSections: 1
  buf.writeUInt32LE(0x65000000, coffOff + 4); // TimeDateStamp
  buf.writeUInt16LE(0xe0, coffOff + 16);    // SizeOfOptionalHeader (224 bytes for PE32)
  buf.writeUInt16LE(0x0002, coffOff + 18);  // Characteristics: EXECUTABLE_IMAGE

  // ── Optional Header (PE32) ──
  const optOff = coffOff + 20;
  buf.writeUInt16LE(0x10b, optOff);         // Magic: PE32
  buf.writeUInt32LE(0x1000, optOff + 16);   // AddressOfEntryPoint
  buf.writeUInt32LE(0x00400000, optOff + 28); // ImageBase
  buf.writeUInt16LE(3, optOff + 68);        // Subsystem: WINDOWS_CUI
  buf.writeUInt16LE(0x0040, optOff + 70);   // DllCharacteristics: DYNAMIC_BASE
  buf.writeUInt32LE(16, optOff + 92);       // NumberOfRvaAndSizes

  // Data directory[1] = Import Table: RVA=0x200, Size=0x50
  const dataDirOff = optOff + 96;
  // Dir 0 = Export Table (skip)
  // Dir 1 = Import Table
  buf.writeUInt32LE(0x200, dataDirOff + 8);  // Import Table RVA
  buf.writeUInt32LE(0x50, dataDirOff + 12);  // Import Table Size

  // ── Section Table ──
  const sectionOff = optOff + 0xe0; // after optional header
  buf.write('.text', sectionOff, 'ascii');
  buf.writeUInt32LE(0x100, sectionOff + 8);   // VirtualSize
  buf.writeUInt32LE(0x1000, sectionOff + 12);  // VirtualAddress
  buf.writeUInt32LE(0x200, sectionOff + 16);   // SizeOfRawData
  buf.writeUInt32LE(0x200, sectionOff + 20);   // PointerToRawData
  buf.writeUInt32LE(0x60000020, sectionOff + 36); // Characteristics: CODE|MEM_EXECUTE|MEM_READ

  // ── Section data at file offset 0x200 ──
  // This section's VA = 0x1000, file offset = 0x200
  // Import table RVA=0x200 -> resolved via section: VA=0x1000, ptr=0x200
  // So RVA 0x200 means: 0x200 - 0x1000 would be negative... we need RVA within section range.
  // Let's adjust: Import Table RVA = 0x1000 (within section VA range)
  buf.writeUInt32LE(0x1000, dataDirOff + 8);  // Fix Import Table RVA to 0x1000

  // Import Directory Entry at file offset 0x200 (section start)
  // OriginalFirstThunk RVA: 0x1028
  buf.writeUInt32LE(0x1028, 0x200);
  // TimeDateStamp: 0
  // ForwarderChain: 0
  // Name RVA: 0x1040
  buf.writeUInt32LE(0x1040, 0x200 + 12);
  // FirstThunk RVA: 0x1028
  buf.writeUInt32LE(0x1028, 0x200 + 16);

  // End of import directory (null entry)
  // Already zeros at 0x200 + 20

  // ILT at file offset 0x228 (0x200 + 0x28 = RVA 0x1028)
  // Thunk entry pointing to Hint/Name at RVA 0x1060
  buf.writeUInt32LE(0x1060, 0x228);
  // null terminator thunk
  buf.writeUInt32LE(0, 0x22c);

  // DLL name at file offset 0x240 (0x200 + 0x40 = RVA 0x1040)
  buf.write('kernel32.dll', 0x240, 'ascii');

  // Hint/Name at file offset 0x260 (0x200 + 0x60 = RVA 0x1060)
  buf.writeUInt16LE(0, 0x260); // Hint
  buf.write('VirtualAllocEx', 0x262, 'ascii');

  return buf;
}

describe('analyzePE', () => {
  describe('PE magic number detection', () => {
    it('detects a valid PE file with MZ header', async () => {
      const pe = buildMinimalPE();
      mockedReadFile.mockResolvedValue(pe);

      const result = await analyzePE('/fake/path.exe');
      expect(result.isPE).toBe(true);
      expect(result.header).not.toBeNull();
    });

    it('reports correct machine type for I386', async () => {
      const pe = buildMinimalPE();
      mockedReadFile.mockResolvedValue(pe);

      const result = await analyzePE('/fake/path.exe');
      expect(result.header!.machine).toBe('I386');
      expect(result.header!.machineRaw).toBe(0x014c);
    });

    it('reports PE32 (not 64-bit) for our minimal PE', async () => {
      const pe = buildMinimalPE();
      mockedReadFile.mockResolvedValue(pe);

      const result = await analyzePE('/fake/path.exe');
      expect(result.header!.is64Bit).toBe(false);
      expect(result.header!.magic).toBe(0x10b);
    });
  });

  describe('non-PE file rejection', () => {
    it('returns isPE=false for an empty buffer', async () => {
      mockedReadFile.mockResolvedValue(Buffer.alloc(0));
      const result = await analyzePE('/fake/empty');
      expect(result.isPE).toBe(false);
      expect(result.header).toBeNull();
    });

    it('returns isPE=false for a too-small buffer', async () => {
      mockedReadFile.mockResolvedValue(Buffer.alloc(32, 0x41));
      const result = await analyzePE('/fake/small');
      expect(result.isPE).toBe(false);
    });

    it('returns isPE=false for an ELF file', async () => {
      const elf = Buffer.alloc(128, 0);
      elf[0] = 0x7f;
      elf.write('ELF', 1, 'ascii');
      mockedReadFile.mockResolvedValue(elf);

      const result = await analyzePE('/fake/elf');
      expect(result.isPE).toBe(false);
    });

    it('returns isPE=false for a PDF file', async () => {
      const pdf = Buffer.from('%PDF-1.4 some content here');
      mockedReadFile.mockResolvedValue(pdf);

      const result = await analyzePE('/fake/pdf');
      expect(result.isPE).toBe(false);
    });

    it('returns isPE=false for MZ without valid PE signature', async () => {
      const buf = Buffer.alloc(256, 0);
      buf.write('MZ', 0, 'ascii');
      buf.writeUInt32LE(0x80, 0x3c);
      // Do NOT write PE signature at 0x80
      buf.write('XX', 0x80, 'ascii');
      mockedReadFile.mockResolvedValue(buf);

      const result = await analyzePE('/fake/fakemz');
      expect(result.isPE).toBe(false);
    });
  });

  describe('suspicious import detection', () => {
    it('detects VirtualAllocEx as suspicious', async () => {
      const pe = buildMinimalPE();
      mockedReadFile.mockResolvedValue(pe);

      const result = await analyzePE('/fake/path.exe');
      expect(result.importedFunctions).toContain('VirtualAllocEx');
      expect(result.suspiciousImports.length).toBeGreaterThanOrEqual(1);

      const virtualAllocSus = result.suspiciousImports.find(
        (s) => s.function === 'VirtualAllocEx',
      );
      expect(virtualAllocSus).toBeDefined();
      expect(virtualAllocSus!.reason).toContain('Remote process memory allocation');
    });

    it('includes the DLL name in suspicious imports', async () => {
      const pe = buildMinimalPE();
      mockedReadFile.mockResolvedValue(pe);

      const result = await analyzePE('/fake/path.exe');
      const sus = result.suspiciousImports[0];
      expect(sus).toBeDefined();
      expect(sus!.dll).toBe('kernel32.dll');
    });
  });

  describe('section parsing', () => {
    it('parses the .text section', async () => {
      const pe = buildMinimalPE();
      mockedReadFile.mockResolvedValue(pe);

      const result = await analyzePE('/fake/path.exe');
      expect(result.sections.length).toBeGreaterThanOrEqual(1);

      const textSection = result.sections.find((s) => s.name === '.text');
      expect(textSection).toBeDefined();
      expect(textSection!.rawSize).toBeGreaterThan(0);
    });

    it('includes characteristic flags for sections', async () => {
      const pe = buildMinimalPE();
      mockedReadFile.mockResolvedValue(pe);

      const result = await analyzePE('/fake/path.exe');
      const textSection = result.sections.find((s) => s.name === '.text');
      expect(textSection!.characteristicFlags).toContain('CNT_CODE');
      expect(textSection!.characteristicFlags).toContain('MEM_EXECUTE');
      expect(textSection!.characteristicFlags).toContain('MEM_READ');
    });
  });

  describe('header characteristic flags', () => {
    it('detects EXECUTABLE_IMAGE flag', async () => {
      const pe = buildMinimalPE();
      mockedReadFile.mockResolvedValue(pe);

      const result = await analyzePE('/fake/path.exe');
      expect(result.header!.characteristicFlags).toContain('EXECUTABLE_IMAGE');
    });
  });
});
