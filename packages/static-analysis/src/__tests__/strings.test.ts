import { describe, it, expect, vi } from 'vitest';
import * as fs from 'node:fs/promises';
import { extractStrings } from '../analyzers/strings.js';

// Mock the fs module so extractStrings reads from our test buffers
vi.mock('node:fs/promises', () => ({
  readFile: vi.fn(),
}));

const mockedReadFile = vi.mocked(fs.readFile);

function setFileContent(buf: Buffer): void {
  mockedReadFile.mockResolvedValue(buf);
}

describe('extractStrings', () => {
  describe('ASCII string extraction', () => {
    it('extracts ASCII strings from a buffer with known strings', async () => {
      const content = Buffer.from(
        'Hello World\x00This is a test\x00\x01\x02\x03short\x00LongerStringHere\x00',
      );
      setFileContent(content);

      const result = await extractStrings('/fake/path', 4);
      const values = result.strings.map((s) => s.value);

      expect(values).toContain('Hello World');
      expect(values).toContain('This is a test');
      expect(values).toContain('LongerStringHere');
    });

    it('respects minimum length filtering', async () => {
      const content = Buffer.from('AB\x00ABCD\x00ABCDEFGH\x00');
      setFileContent(content);

      // minLength = 4 -> "AB" (len 2) should be excluded
      const result = await extractStrings('/fake/path', 4);
      const values = result.strings.map((s) => s.value);

      expect(values).not.toContain('AB');
      expect(values).toContain('ABCD');
      expect(values).toContain('ABCDEFGH');
    });

    it('extracts strings with tabs as valid characters', async () => {
      const content = Buffer.from('col1\tcol2\tcol3\x00');
      setFileContent(content);

      const result = await extractStrings('/fake/path', 4);
      const values = result.strings.map((s) => s.value);

      expect(values).toContain('col1\tcol2\tcol3');
    });
  });

  describe('URL extraction', () => {
    it('extracts URLs from mixed content', async () => {
      const content = Buffer.from(
        'junk\x00https://evil.com/malware.exe\x00more stuff\x00http://c2server.ru/beacon\x00',
      );
      setFileContent(content);

      const result = await extractStrings('/fake/path', 4);

      expect(result.urls).toContain('https://evil.com/malware.exe');
      expect(result.urls).toContain('http://c2server.ru/beacon');
    });

    it('categorizes URL strings correctly', async () => {
      const content = Buffer.from('https://malware.example.com/payload\x00');
      setFileContent(content);

      const result = await extractStrings('/fake/path', 4);
      const urlStrings = result.strings.filter((s) => s.category === 'url');
      expect(urlStrings.length).toBeGreaterThanOrEqual(1);
    });
  });

  describe('IP address extraction', () => {
    it('extracts IPv4 addresses', async () => {
      const content = Buffer.from(
        'connecting to 192.168.1.100\x00also 10.0.0.1\x00and 8.8.8.8\x00',
      );
      setFileContent(content);

      const result = await extractStrings('/fake/path', 4);

      expect(result.ipv4Addresses).toContain('192.168.1.100');
      expect(result.ipv4Addresses).toContain('10.0.0.1');
      expect(result.ipv4Addresses).toContain('8.8.8.8');
    });

    it('categorizes IP strings', async () => {
      const content = Buffer.from('target: 203.0.113.50\x00');
      setFileContent(content);

      const result = await extractStrings('/fake/path', 4);
      const ipStrings = result.strings.filter((s) => s.category === 'ipv4');
      expect(ipStrings.length).toBeGreaterThanOrEqual(1);
    });
  });

  describe('Unicode string extraction', () => {
    it('extracts UTF-16LE strings', async () => {
      // "Hello" in UTF-16LE: H\x00e\x00l\x00l\x00o\x00
      const utf16 = Buffer.from('Hello', 'utf16le');
      // Add null terminator and padding
      const buf = Buffer.concat([Buffer.alloc(2, 0xff), utf16, Buffer.alloc(4, 0x00)]);
      setFileContent(buf);

      const result = await extractStrings('/fake/path', 4);
      const unicodeStrings = result.strings.filter((s) => s.encoding === 'utf16');
      const values = unicodeStrings.map((s) => s.value);
      expect(values).toContain('Hello');
    });
  });

  describe('domain extraction', () => {
    it('extracts domains from strings', async () => {
      const content = Buffer.from(
        'contacting malicious-c2.com for commands\x00also evil-domain.ru/path\x00',
      );
      setFileContent(content);

      const result = await extractStrings('/fake/path', 4);
      expect(result.domains).toContain('malicious-c2.com');
    });
  });

  describe('email extraction', () => {
    it('extracts email addresses', async () => {
      const content = Buffer.from('send report to attacker@evil.com\x00');
      setFileContent(content);

      const result = await extractStrings('/fake/path', 4);
      expect(result.emailAddresses).toContain('attacker@evil.com');
    });
  });

  describe('registry key extraction', () => {
    it('extracts Windows registry keys', async () => {
      const content = Buffer.from(
        'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\x00',
      );
      setFileContent(content);

      const result = await extractStrings('/fake/path', 4);
      expect(result.registryKeys.length).toBeGreaterThanOrEqual(1);
      expect(
        result.registryKeys.some((k) => k.includes('HKLM')),
      ).toBe(true);
    });
  });

  describe('result counts', () => {
    it('reports correct ASCII and Unicode string counts', async () => {
      const asciiPart = Buffer.from('ascii_string_one\x00ascii_string_two\x00');
      const utf16Part = Buffer.from('UniStr', 'utf16le');
      const buf = Buffer.concat([asciiPart, Buffer.alloc(2, 0xff), utf16Part, Buffer.alloc(4, 0)]);
      setFileContent(buf);

      const result = await extractStrings('/fake/path', 4);
      expect(result.totalAsciiStrings).toBeGreaterThanOrEqual(2);
    });
  });
});
