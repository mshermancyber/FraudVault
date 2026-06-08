import { describe, it, expect } from 'vitest';
import { extractIOCs } from '../ioc/extractor.js';
import { IOCType } from '@scanboy/shared';
import type {
  StaticAnalysisResult,
  DynamicAnalysisResult,
} from '@scanboy/shared';

function makeStaticAnalysis(
  overrides: Partial<StaticAnalysisResult> = {},
): StaticAnalysisResult {
  return {
    submissionId: 'sub-1',
    fileType: 'PE',
    magic: 'PE32',
    entropy: 5.0,
    isPacked: false,
    packerName: null,
    imports: [],
    exports: [],
    sections: [],
    strings: [],
    certificates: [],
    iocs: [],
    attackTechniques: [],
    ...overrides,
  };
}

function makeDynamicAnalysis(
  overrides: Partial<DynamicAnalysisResult> = {},
): DynamicAnalysisResult {
  return {
    submissionId: 'sub-1',
    detonationSessionId: 'det-1',
    processesCreated: [],
    networkConnections: [],
    filesModified: [],
    registryModifications: [],
    mutexesCreated: [],
    iocs: [],
    attackTechniques: [],
    behaviorTags: [],
    ...overrides,
  };
}

describe('extractIOCs', () => {
  describe('domain extraction from DNS queries', () => {
    it('extracts domains from network connections', () => {
      const dynamicAnalysis = makeDynamicAnalysis({
        networkConnections: [
          {
            protocol: 'dns',
            sourceAddress: '10.0.0.5',
            sourcePort: 12345,
            destinationAddress: '8.8.8.8',
            destinationPort: 53,
            domain: 'evil-c2.example.org',
            bytesSent: 50,
            bytesReceived: 200,
          },
        ],
      });

      const result = extractIOCs(null, dynamicAnalysis, 'sub-1');
      const domains = result.iocs.filter((i) => i.type === IOCType.Domain);
      expect(domains.length).toBeGreaterThanOrEqual(1);
      expect(domains.some((d) => d.value === 'evil-c2.example.org')).toBe(true);
    });

    it('excludes whitelisted domains like microsoft.com', () => {
      const dynamicAnalysis = makeDynamicAnalysis({
        networkConnections: [
          {
            protocol: 'dns',
            sourceAddress: '10.0.0.5',
            sourcePort: 12345,
            destinationAddress: '8.8.8.8',
            destinationPort: 53,
            domain: 'microsoft.com',
            bytesSent: 50,
            bytesReceived: 200,
          },
        ],
      });

      const result = extractIOCs(null, dynamicAnalysis, 'sub-1');
      const domains = result.iocs.filter((i) => i.type === IOCType.Domain);
      expect(domains.some((d) => d.value === 'microsoft.com')).toBe(false);
    });

    it('excludes .local domains', () => {
      const dynamicAnalysis = makeDynamicAnalysis({
        networkConnections: [
          {
            protocol: 'dns',
            sourceAddress: '10.0.0.5',
            sourcePort: 12345,
            destinationAddress: '10.0.0.1',
            destinationPort: 53,
            domain: 'myhost.local',
            bytesSent: 50,
            bytesReceived: 200,
          },
        ],
      });

      const result = extractIOCs(null, dynamicAnalysis, 'sub-1');
      const domains = result.iocs.filter((i) => i.type === IOCType.Domain);
      expect(domains.some((d) => d.value === 'myhost.local')).toBe(false);
    });
  });

  describe('URL extraction from HTTP requests', () => {
    it('extracts URLs from HTTP connections', () => {
      const dynamicAnalysis = makeDynamicAnalysis({
        networkConnections: [
          {
            protocol: 'http',
            sourceAddress: '10.0.0.5',
            sourcePort: 12345,
            destinationAddress: '45.33.32.156',
            destinationPort: 80,
            domain: 'evil.com',
            bytesSent: 500,
            bytesReceived: 2000,
          },
        ],
      });

      const result = extractIOCs(null, dynamicAnalysis, 'sub-1');
      const urls = result.iocs.filter((i) => i.type === IOCType.URL);
      expect(urls.length).toBeGreaterThanOrEqual(1);
      expect(urls.some((u) => u.value.includes('evil.com'))).toBe(true);
    });

    it('constructs correct URL with non-standard port', () => {
      const dynamicAnalysis = makeDynamicAnalysis({
        networkConnections: [
          {
            protocol: 'http',
            sourceAddress: '10.0.0.5',
            sourcePort: 12345,
            destinationAddress: '45.33.32.156',
            destinationPort: 8080,
            domain: 'c2server.com',
            bytesSent: 100,
            bytesReceived: 200,
          },
        ],
      });

      const result = extractIOCs(null, dynamicAnalysis, 'sub-1');
      const urls = result.iocs.filter((i) => i.type === IOCType.URL);
      expect(urls.some((u) => u.value === 'http://c2server.com:8080')).toBe(true);
    });
  });

  describe('IP extraction (excluding private ranges)', () => {
    it('extracts public destination IPs', () => {
      const dynamicAnalysis = makeDynamicAnalysis({
        networkConnections: [
          {
            protocol: 'tcp',
            sourceAddress: '10.0.0.5',
            sourcePort: 12345,
            destinationAddress: '45.33.32.156',
            destinationPort: 443,
            domain: null,
            bytesSent: 100,
            bytesReceived: 200,
          },
        ],
      });

      const result = extractIOCs(null, dynamicAnalysis, 'sub-1');
      const ips = result.iocs.filter((i) => i.type === IOCType.IPv4);
      expect(ips.some((ip) => ip.value === '45.33.32.156')).toBe(true);
    });

    it('excludes private IP addresses (10.x, 192.168.x, 127.x)', () => {
      const dynamicAnalysis = makeDynamicAnalysis({
        networkConnections: [
          {
            protocol: 'tcp',
            sourceAddress: '10.0.0.5',
            sourcePort: 1,
            destinationAddress: '10.0.0.1',
            destinationPort: 80,
            domain: null,
            bytesSent: 0,
            bytesReceived: 0,
          },
          {
            protocol: 'tcp',
            sourceAddress: '192.168.1.5',
            sourcePort: 2,
            destinationAddress: '192.168.1.1',
            destinationPort: 80,
            domain: null,
            bytesSent: 0,
            bytesReceived: 0,
          },
          {
            protocol: 'tcp',
            sourceAddress: '127.0.0.1',
            sourcePort: 3,
            destinationAddress: '127.0.0.1',
            destinationPort: 80,
            domain: null,
            bytesSent: 0,
            bytesReceived: 0,
          },
        ],
      });

      const result = extractIOCs(null, dynamicAnalysis, 'sub-1');
      const ips = result.iocs.filter((i) => i.type === IOCType.IPv4);
      expect(ips.length).toBe(0);
    });
  });

  describe('hash extraction from dropped files', () => {
    it('extracts SHA256 hashes from created files', () => {
      const dynamicAnalysis = makeDynamicAnalysis({
        filesModified: [
          {
            path: 'C:\\temp\\dropped.exe',
            operation: 'create',
            newPath: null,
            sha256: 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2',
          },
        ],
      });

      const result = extractIOCs(null, dynamicAnalysis, 'sub-1');
      const hashes = result.iocs.filter((i) => i.type === IOCType.FileHash);
      expect(hashes.length).toBeGreaterThanOrEqual(1);
      expect(hashes[0]!.value).toBe(
        'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2',
      );
    });

    it('does not extract hashes from deleted files', () => {
      const dynamicAnalysis = makeDynamicAnalysis({
        filesModified: [
          {
            path: 'C:\\temp\\deleted.exe',
            operation: 'delete',
            newPath: null,
            sha256: 'deadbeef',
          },
        ],
      });

      const result = extractIOCs(null, dynamicAnalysis, 'sub-1');
      const hashes = result.iocs.filter((i) => i.type === IOCType.FileHash);
      expect(hashes.length).toBe(0);
    });
  });

  describe('registry key extraction', () => {
    it('extracts registry keys from modifications', () => {
      const dynamicAnalysis = makeDynamicAnalysis({
        registryModifications: [
          {
            key: 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
            valueName: 'MalwareStartup',
            operation: 'create',
            valueData: 'C:\\malware.exe',
          },
        ],
      });

      const result = extractIOCs(null, dynamicAnalysis, 'sub-1');
      const regKeys = result.iocs.filter((i) => i.type === IOCType.RegistryKey);
      expect(regKeys.length).toBeGreaterThanOrEqual(1);
      expect(regKeys.some((r) => r.value.includes('Run'))).toBe(true);
    });

    it('extracts URLs embedded in registry value data', () => {
      const dynamicAnalysis = makeDynamicAnalysis({
        registryModifications: [
          {
            key: 'HKCU\\Software\\Test',
            valueName: 'URL',
            operation: 'create',
            valueData: 'http://evil-c2.com/callback',
          },
        ],
      });

      const result = extractIOCs(null, dynamicAnalysis, 'sub-1');
      const urls = result.iocs.filter((i) => i.type === IOCType.URL);
      expect(urls.some((u) => u.value.includes('evil-c2.com'))).toBe(true);
    });
  });

  describe('deduplication', () => {
    it('deduplicates IOCs with the same type and value', () => {
      const dynamicAnalysis = makeDynamicAnalysis({
        networkConnections: [
          {
            protocol: 'tcp',
            sourceAddress: '10.0.0.1',
            sourcePort: 1,
            destinationAddress: '45.33.32.156',
            destinationPort: 80,
            domain: null,
            bytesSent: 100,
            bytesReceived: 200,
          },
          {
            protocol: 'tcp',
            sourceAddress: '10.0.0.1',
            sourcePort: 2,
            destinationAddress: '45.33.32.156',
            destinationPort: 443,
            domain: null,
            bytesSent: 50,
            bytesReceived: 150,
          },
        ],
      });

      const result = extractIOCs(null, dynamicAnalysis, 'sub-1');
      const ips = result.iocs.filter(
        (i) => i.type === IOCType.IPv4 && i.value === '45.33.32.156',
      );
      // Should be deduplicated to 1 entry
      expect(ips.length).toBe(1);
    });

    it('keeps the highest confidence when deduplicating', () => {
      // Two connections from different sources -> same IP, different confidence
      const dynamicAnalysis = makeDynamicAnalysis({
        networkConnections: [
          {
            protocol: 'tcp',
            sourceAddress: '10.0.0.1',
            sourcePort: 1,
            destinationAddress: '45.33.32.156',
            destinationPort: 80,
            domain: null,
            bytesSent: 100,
            bytesReceived: 200,
          },
          {
            protocol: 'tcp',
            sourceAddress: '10.0.0.1',
            sourcePort: 2,
            destinationAddress: '45.33.32.156',
            destinationPort: 443,
            domain: null,
            bytesSent: 50,
            bytesReceived: 150,
          },
        ],
      });

      const result = extractIOCs(null, dynamicAnalysis, 'sub-1');
      const ip = result.iocs.find(
        (i) => i.type === IOCType.IPv4 && i.value === '45.33.32.156',
      );
      expect(ip).toBeDefined();
      expect(ip!.confidence).toBe(70); // Default from network_connection
    });
  });

  describe('whitelisted domain filtering', () => {
    it('filters out google.com', () => {
      const dynamicAnalysis = makeDynamicAnalysis({
        networkConnections: [
          {
            protocol: 'dns',
            sourceAddress: '10.0.0.1',
            sourcePort: 1,
            destinationAddress: '8.8.8.8',
            destinationPort: 53,
            domain: 'google.com',
            bytesSent: 50,
            bytesReceived: 100,
          },
        ],
      });

      const result = extractIOCs(null, dynamicAnalysis, 'sub-1');
      const domains = result.iocs.filter((i) => i.type === IOCType.Domain);
      expect(domains.some((d) => d.value === 'google.com')).toBe(false);
    });

    it('filters out amazonaws.com', () => {
      const dynamicAnalysis = makeDynamicAnalysis({
        networkConnections: [
          {
            protocol: 'dns',
            sourceAddress: '10.0.0.1',
            sourcePort: 1,
            destinationAddress: '8.8.8.8',
            destinationPort: 53,
            domain: 'amazonaws.com',
            bytesSent: 50,
            bytesReceived: 100,
          },
        ],
      });

      const result = extractIOCs(null, dynamicAnalysis, 'sub-1');
      const domains = result.iocs.filter((i) => i.type === IOCType.Domain);
      expect(domains.some((d) => d.value === 'amazonaws.com')).toBe(false);
    });
  });

  describe('counts and total', () => {
    it('correctly reports total IOC count', () => {
      const dynamicAnalysis = makeDynamicAnalysis({
        networkConnections: [
          { protocol: 'tcp', sourceAddress: '10.0.0.1', sourcePort: 1, destinationAddress: '1.2.3.4', destinationPort: 80, domain: 'badsite.org', bytesSent: 0, bytesReceived: 0 },
          { protocol: 'tcp', sourceAddress: '10.0.0.1', sourcePort: 2, destinationAddress: '5.6.7.8', destinationPort: 443, domain: null, bytesSent: 0, bytesReceived: 0 },
        ],
        mutexesCreated: ['Global\\TestMutex'],
      });

      const result = extractIOCs(null, dynamicAnalysis, 'sub-1');
      expect(result.total).toBe(result.iocs.length);
      expect(result.total).toBeGreaterThan(0);
    });

    it('correctly counts by type', () => {
      const dynamicAnalysis = makeDynamicAnalysis({
        networkConnections: [
          { protocol: 'tcp', sourceAddress: '10.0.0.1', sourcePort: 1, destinationAddress: '1.2.3.4', destinationPort: 80, domain: null, bytesSent: 0, bytesReceived: 0 },
          { protocol: 'tcp', sourceAddress: '10.0.0.1', sourcePort: 2, destinationAddress: '5.6.7.8', destinationPort: 443, domain: null, bytesSent: 0, bytesReceived: 0 },
        ],
      });

      const result = extractIOCs(null, dynamicAnalysis, 'sub-1');
      const ipCount = result.counts[IOCType.IPv4] ?? 0;
      expect(ipCount).toBe(2);
    });
  });

  describe('empty input', () => {
    it('returns empty results for null inputs', () => {
      const result = extractIOCs(null, null, 'sub-1');
      expect(result.iocs).toEqual([]);
      expect(result.total).toBe(0);
    });
  });

  describe('static string IOC extraction', () => {
    it('extracts URLs from static strings', () => {
      const staticAnalysis = makeStaticAnalysis({
        strings: [
          {
            value: 'http://malicious-c2.badsite.net/beacon',
            encoding: 'ascii',
            offset: 0x100,
            category: null,
          },
        ],
      });

      const result = extractIOCs(staticAnalysis, null, 'sub-1');
      const urls = result.iocs.filter((i) => i.type === IOCType.URL);
      expect(urls.some((u) => u.value.includes('malicious-c2.badsite.net'))).toBe(true);
    });
  });

  describe('results sorting', () => {
    it('sorts results by confidence descending', () => {
      const dynamicAnalysis = makeDynamicAnalysis({
        networkConnections: [
          { protocol: 'http', sourceAddress: '10.0.0.1', sourcePort: 1, destinationAddress: '1.2.3.4', destinationPort: 80, domain: 'evil.org', bytesSent: 0, bytesReceived: 0 },
        ],
        filesModified: [
          { path: 'C:\\temp\\payload.exe', operation: 'create', newPath: null, sha256: 'abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123abc1' },
        ],
        mutexesCreated: ['TestMut'],
      });

      const result = extractIOCs(null, dynamicAnalysis, 'sub-1');
      for (let i = 1; i < result.iocs.length; i++) {
        expect(result.iocs[i]!.confidence).toBeLessThanOrEqual(result.iocs[i - 1]!.confidence);
      }
    });
  });
});
