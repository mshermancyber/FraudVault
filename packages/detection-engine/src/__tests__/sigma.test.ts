import { describe, it, expect } from 'vitest';
import { generateSigmaRules } from '../rule-generation/sigma.js';
import type { DynamicAnalysisResult } from '@scanboy/shared';

function makeDynamicAnalysis(
  overrides: Partial<DynamicAnalysisResult> = {},
): DynamicAnalysisResult {
  return {
    submissionId: 'sub-123',
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

describe('generateSigmaRules', () => {
  describe('valid YAML structure', () => {
    it('generates rules with required Sigma fields', () => {
      const dynAnalysis = makeDynamicAnalysis({
        processesCreated: [
          {
            pid: 1234,
            parentPid: 1,
            name: 'malware.exe',
            commandLine: 'malware.exe --evil',
            createdAt: new Date().toISOString(),
          },
        ],
      });

      const rules = generateSigmaRules(dynAnalysis, 'sub-123');
      expect(rules.length).toBeGreaterThanOrEqual(1);

      const rule = rules[0]!;
      expect(rule.title).toBeTruthy();
      expect(rule.id).toBeTruthy();
      expect(rule.status).toBe('experimental');
      expect(rule.logsource).toBeDefined();
      expect(rule.logsource.category).toBeTruthy();
      expect(rule.logsource.product).toBeTruthy();
      expect(rule.yaml).toBeTruthy();
    });

    it('YAML contains title, id, status, logsource, detection, and level', () => {
      const dynAnalysis = makeDynamicAnalysis({
        processesCreated: [
          {
            pid: 100,
            parentPid: 1,
            name: 'test.exe',
            commandLine: 'test.exe /flag',
            createdAt: new Date().toISOString(),
          },
        ],
      });

      const rules = generateSigmaRules(dynAnalysis, 'sub-123');
      const yaml = rules[0]!.yaml;

      expect(yaml).toContain('title:');
      expect(yaml).toContain('id:');
      expect(yaml).toContain('status:');
      expect(yaml).toContain('logsource:');
      expect(yaml).toContain('detection:');
      expect(yaml).toContain('level:');
      expect(yaml).toContain('condition:');
    });
  });

  describe('process creation rules', () => {
    it('generates process_creation category rules', () => {
      const dynAnalysis = makeDynamicAnalysis({
        processesCreated: [
          {
            pid: 100,
            parentPid: 1,
            name: 'cmd.exe',
            commandLine: 'cmd.exe /c ipconfig',
            createdAt: new Date().toISOString(),
          },
        ],
      });

      const rules = generateSigmaRules(dynAnalysis, 'sub-123');
      const procRules = rules.filter((r) => r.logsource.category === 'process_creation');
      expect(procRules.length).toBeGreaterThanOrEqual(1);
      expect(procRules[0]!.logsource.product).toBe('windows');
    });

    it('includes Image|endswith and CommandLine in detection', () => {
      const dynAnalysis = makeDynamicAnalysis({
        processesCreated: [
          {
            pid: 100,
            parentPid: 1,
            name: 'powershell.exe',
            commandLine: 'powershell.exe -NoProfile -Command Get-Process',
            createdAt: new Date().toISOString(),
          },
        ],
      });

      const rules = generateSigmaRules(dynAnalysis, 'sub-123');
      const yaml = rules[0]!.yaml;

      expect(yaml).toContain('Image|endswith');
      expect(yaml).toContain('powershell.exe');
      expect(yaml).toContain('CommandLine|contains');
    });

    it('assigns high level for powershell.exe', () => {
      const dynAnalysis = makeDynamicAnalysis({
        processesCreated: [
          {
            pid: 100,
            parentPid: 1,
            name: 'powershell.exe',
            commandLine: 'powershell.exe -enc test',
            createdAt: new Date().toISOString(),
          },
        ],
      });

      const rules = generateSigmaRules(dynAnalysis, 'sub-123');
      expect(rules[0]!.level).toBe('high');
    });

    it('assigns critical level for mimikatz.exe', () => {
      const dynAnalysis = makeDynamicAnalysis({
        processesCreated: [
          {
            pid: 100,
            parentPid: 1,
            name: 'mimikatz.exe',
            commandLine: 'mimikatz.exe privilege::debug',
            createdAt: new Date().toISOString(),
          },
        ],
      });

      const rules = generateSigmaRules(dynAnalysis, 'sub-123');
      expect(rules[0]!.level).toBe('critical');
    });

    it('skips conhost.exe', () => {
      const dynAnalysis = makeDynamicAnalysis({
        processesCreated: [
          {
            pid: 100,
            parentPid: 1,
            name: 'conhost.exe',
            commandLine: 'conhost.exe 0xffffffff',
            createdAt: new Date().toISOString(),
          },
        ],
      });

      const rules = generateSigmaRules(dynAnalysis, 'sub-123');
      const conhostRules = rules.filter((r) => r.yaml.includes('conhost.exe'));
      expect(conhostRules.length).toBe(0);
    });
  });

  describe('registry rules', () => {
    it('generates registry_set category rules', () => {
      const dynAnalysis = makeDynamicAnalysis({
        registryModifications: [
          {
            key: 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
            valueName: 'EvilApp',
            operation: 'create',
            valueData: 'C:\\evil.exe',
          },
        ],
      });

      const rules = generateSigmaRules(dynAnalysis, 'sub-123');
      const regRules = rules.filter((r) => r.logsource.category === 'registry_set');
      expect(regRules.length).toBeGreaterThanOrEqual(1);
      expect(regRules[0]!.yaml).toContain('TargetObject|contains');
    });

    it('assigns high level for Run key modifications', () => {
      const dynAnalysis = makeDynamicAnalysis({
        registryModifications: [
          {
            key: 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
            valueName: 'Test',
            operation: 'create',
            valueData: 'test.exe',
          },
        ],
      });

      const rules = generateSigmaRules(dynAnalysis, 'sub-123');
      const regRules = rules.filter((r) => r.logsource.category === 'registry_set');
      expect(regRules[0]!.level).toBe('high');
    });

    it('skips delete operations', () => {
      const dynAnalysis = makeDynamicAnalysis({
        registryModifications: [
          {
            key: 'HKCU\\Software\\Test',
            valueName: 'Val',
            operation: 'delete',
            valueData: null,
          },
        ],
      });

      const rules = generateSigmaRules(dynAnalysis, 'sub-123');
      const regRules = rules.filter((r) => r.logsource.category === 'registry_set');
      expect(regRules.length).toBe(0);
    });
  });

  describe('network rules', () => {
    it('generates firewall category rules for network connections', () => {
      const dynAnalysis = makeDynamicAnalysis({
        networkConnections: [
          {
            protocol: 'tcp',
            sourceAddress: '10.0.0.1',
            sourcePort: 12345,
            destinationAddress: '45.33.32.156',
            destinationPort: 4444,
            domain: null,
            bytesSent: 100,
            bytesReceived: 200,
          },
        ],
      });

      const rules = generateSigmaRules(dynAnalysis, 'sub-123');
      const netRules = rules.filter((r) => r.logsource.category === 'firewall');
      expect(netRules.length).toBeGreaterThanOrEqual(1);
      expect(netRules[0]!.yaml).toContain('dst_ip');
      expect(netRules[0]!.yaml).toContain('dst_port');
    });

    it('deduplicates network rules by dest:port', () => {
      const dynAnalysis = makeDynamicAnalysis({
        networkConnections: [
          { protocol: 'tcp', sourceAddress: '10.0.0.1', sourcePort: 1, destinationAddress: '1.2.3.4', destinationPort: 80, domain: null, bytesSent: 0, bytesReceived: 0 },
          { protocol: 'tcp', sourceAddress: '10.0.0.1', sourcePort: 2, destinationAddress: '1.2.3.4', destinationPort: 80, domain: null, bytesSent: 0, bytesReceived: 0 },
        ],
      });

      const rules = generateSigmaRules(dynAnalysis, 'sub-123');
      const netRules = rules.filter((r) => r.logsource.category === 'firewall');
      expect(netRules.length).toBe(1);
    });
  });

  describe('empty analysis', () => {
    it('returns no rules for empty dynamic analysis', () => {
      const rules = generateSigmaRules(makeDynamicAnalysis(), 'sub-123');
      expect(rules).toEqual([]);
    });
  });

  describe('rule metadata', () => {
    it('includes submission reference in YAML', () => {
      const dynAnalysis = makeDynamicAnalysis({
        processesCreated: [
          { pid: 1, parentPid: 0, name: 'test.exe', commandLine: 'test.exe', createdAt: '' },
        ],
      });

      const rules = generateSigmaRules(dynAnalysis, 'sub-123');
      expect(rules[0]!.yaml).toContain('sub-123');
      expect(rules[0]!.yaml).toContain('references:');
    });

    it('includes author', () => {
      const dynAnalysis = makeDynamicAnalysis({
        processesCreated: [
          { pid: 1, parentPid: 0, name: 'test.exe', commandLine: 'test.exe', createdAt: '' },
        ],
      });

      const rules = generateSigmaRules(dynAnalysis, 'sub-123');
      expect(rules[0]!.yaml).toContain('author: FraudVault Detection Engine');
    });
  });
});
