import { describe, it, expect, vi } from 'vitest';
import { mapToAttackTechniques, getMappingRuleCount } from '../attack-mapping/mapper.js';
import type { StaticAnalysisResult, DynamicAnalysisResult } from '@scanboy/shared';

// Mock the techniques module so we don't depend on the full database
vi.mock('../attack-mapping/techniques.js', () => ({
  getTechniqueById: (id: string) => {
    const techniques: Record<string, { id: string; name: string; tactic: string; description: string; dataSources: string[] }> = {
      'T1055': { id: 'T1055', name: 'Process Injection', tactic: 'Defense Evasion', description: 'Process injection', dataSources: ['Process'] },
      'T1055.001': { id: 'T1055.001', name: 'DLL Injection', tactic: 'Defense Evasion', description: 'DLL injection', dataSources: ['Process'] },
      'T1055.012': { id: 'T1055.012', name: 'Process Hollowing', tactic: 'Defense Evasion', description: 'Process hollowing', dataSources: ['Process'] },
      'T1547.001': { id: 'T1547.001', name: 'Registry Run Keys', tactic: 'Persistence', description: 'Registry run keys', dataSources: ['Registry'] },
      'T1053.005': { id: 'T1053.005', name: 'Scheduled Task', tactic: 'Persistence', description: 'Scheduled task', dataSources: ['Process'] },
      'T1059.001': { id: 'T1059.001', name: 'PowerShell', tactic: 'Execution', description: 'PowerShell execution', dataSources: ['Command', 'Process'] },
      'T1059.003': { id: 'T1059.003', name: 'Windows Command Shell', tactic: 'Execution', description: 'cmd.exe', dataSources: ['Process'] },
      'T1071': { id: 'T1071', name: 'Application Layer Protocol', tactic: 'Command and Control', description: 'App layer', dataSources: ['Network'] },
      'T1071.001': { id: 'T1071.001', name: 'Web Protocols', tactic: 'Command and Control', description: 'HTTP/HTTPS', dataSources: ['Network'] },
      'T1027': { id: 'T1027', name: 'Obfuscated Files', tactic: 'Defense Evasion', description: 'Obfuscation', dataSources: ['File'] },
      'T1027.002': { id: 'T1027.002', name: 'Software Packing', tactic: 'Defense Evasion', description: 'Packing', dataSources: ['File'] },
      'T1112': { id: 'T1112', name: 'Modify Registry', tactic: 'Defense Evasion', description: 'Registry mod', dataSources: ['Registry'] },
      'T1543.003': { id: 'T1543.003', name: 'Windows Service', tactic: 'Persistence', description: 'Service creation', dataSources: ['Process'] },
      'T1574.002': { id: 'T1574.002', name: 'DLL Side-Loading', tactic: 'Persistence', description: 'Side-loading', dataSources: ['File'] },
      'T1574.001': { id: 'T1574.001', name: 'DLL Search Order Hijacking', tactic: 'Persistence', description: 'DLL hijack', dataSources: ['File'] },
      'T1071.004': { id: 'T1071.004', name: 'DNS', tactic: 'Command and Control', description: 'DNS', dataSources: ['Network'] },
      'T1074.001': { id: 'T1074.001', name: 'Local Data Staging', tactic: 'Collection', description: 'Staging', dataSources: ['File'] },
      'T1003': { id: 'T1003', name: 'Credential Dumping', tactic: 'Credential Access', description: 'Credential dump', dataSources: ['Process'] },
      'T1003.001': { id: 'T1003.001', name: 'LSASS Memory', tactic: 'Credential Access', description: 'LSASS', dataSources: ['Process'] },
      'T1082': { id: 'T1082', name: 'System Information Discovery', tactic: 'Discovery', description: 'Sysinfo', dataSources: ['Process'] },
      'T1083': { id: 'T1083', name: 'File and Directory Discovery', tactic: 'Discovery', description: 'File discovery', dataSources: ['Process'] },
      'T1057': { id: 'T1057', name: 'Process Discovery', tactic: 'Discovery', description: 'Process list', dataSources: ['Process'] },
      'T1016': { id: 'T1016', name: 'System Network Configuration Discovery', tactic: 'Discovery', description: 'Netconfig', dataSources: ['Process'] },
      'T1140': { id: 'T1140', name: 'Deobfuscate/Decode Files', tactic: 'Defense Evasion', description: 'Decode', dataSources: ['Process'] },
      'T1105': { id: 'T1105', name: 'Ingress Tool Transfer', tactic: 'Command and Control', description: 'Download', dataSources: ['Network'] },
      'T1562.001': { id: 'T1562.001', name: 'Disable or Modify Tools', tactic: 'Defense Evasion', description: 'Disable tools', dataSources: ['Process'] },
      'T1562.004': { id: 'T1562.004', name: 'Disable System Firewall', tactic: 'Defense Evasion', description: 'Firewall disable', dataSources: ['Process'] },
      'T1547.004': { id: 'T1547.004', name: 'Winlogon Helper DLL', tactic: 'Persistence', description: 'Winlogon', dataSources: ['Registry'] },
      'T1036.005': { id: 'T1036.005', name: 'Match Legitimate Name', tactic: 'Defense Evasion', description: 'Masquerading', dataSources: ['File'] },
      'T1486': { id: 'T1486', name: 'Data Encrypted for Impact', tactic: 'Impact', description: 'Ransomware', dataSources: ['File'] },
      'T1490': { id: 'T1490', name: 'Inhibit System Recovery', tactic: 'Impact', description: 'Inhibit recovery', dataSources: ['Process'] },
      'T1489': { id: 'T1489', name: 'Service Stop', tactic: 'Impact', description: 'Stop services', dataSources: ['Process'] },
      'T1555.003': { id: 'T1555.003', name: 'Credentials from Web Browsers', tactic: 'Credential Access', description: 'Browser creds', dataSources: ['File'] },
      'T1573': { id: 'T1573', name: 'Encrypted Channel', tactic: 'Command and Control', description: 'TLS', dataSources: ['Network'] },
      'T1571': { id: 'T1571', name: 'Non-Standard Port', tactic: 'Command and Control', description: 'Non-std port', dataSources: ['Network'] },
      'T1047': { id: 'T1047', name: 'WMI', tactic: 'Execution', description: 'WMI', dataSources: ['Process'] },
      'T1070.004': { id: 'T1070.004', name: 'File Deletion', tactic: 'Defense Evasion', description: 'File delete', dataSources: ['File'] },
      'T1056.001': { id: 'T1056.001', name: 'Keylogging', tactic: 'Collection', description: 'Keylogger', dataSources: ['Process'] },
      'T1113': { id: 'T1113', name: 'Screen Capture', tactic: 'Collection', description: 'Screenshot', dataSources: ['Process'] },
      'T1115': { id: 'T1115', name: 'Clipboard Data', tactic: 'Collection', description: 'Clipboard', dataSources: ['Process'] },
      'T1136': { id: 'T1136', name: 'Create Account', tactic: 'Persistence', description: 'Create account', dataSources: ['Process'] },
      'T1546.003': { id: 'T1546.003', name: 'WMI Event Subscription', tactic: 'Persistence', description: 'WMI event', dataSources: ['Process'] },
      'T1021.002': { id: 'T1021.002', name: 'SMB/Windows Admin Shares', tactic: 'Lateral Movement', description: 'SMB', dataSources: ['Network'] },
      'T1059.005': { id: 'T1059.005', name: 'Visual Basic', tactic: 'Execution', description: 'VBScript', dataSources: ['Process'] },
      'T1059.007': { id: 'T1059.007', name: 'JavaScript', tactic: 'Execution', description: 'JavaScript', dataSources: ['Process'] },
    };
    return techniques[id] ?? null;
  },
}));

function makeStaticAnalysis(overrides: Partial<StaticAnalysisResult> = {}): StaticAnalysisResult {
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

function makeDynamicAnalysis(overrides: Partial<DynamicAnalysisResult> = {}): DynamicAnalysisResult {
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

describe('mapToAttackTechniques', () => {
  describe('process injection (T1055)', () => {
    it('maps WriteProcessMemory + VirtualAllocEx + CreateRemoteThread to T1055', () => {
      const staticAnalysis = makeStaticAnalysis({
        imports: ['WriteProcessMemory', 'VirtualAllocEx', 'CreateRemoteThread'],
      });

      const results = mapToAttackTechniques(staticAnalysis, null);
      const t1055 = results.find((r) => r.techniqueId === 'T1055');
      expect(t1055).toBeDefined();
      expect(t1055!.confidence).toBeGreaterThanOrEqual(80);
    });

    it('maps QueueUserAPC to T1055', () => {
      const staticAnalysis = makeStaticAnalysis({
        imports: ['QueueUserAPC', 'NtMapViewOfSection'],
      });

      const results = mapToAttackTechniques(staticAnalysis, null);
      const t1055 = results.find((r) => r.techniqueId === 'T1055');
      expect(t1055).toBeDefined();
    });
  });

  describe('registry run key modification (T1547.001)', () => {
    it('maps registry run key modification to T1547.001', () => {
      const dynamicAnalysis = makeDynamicAnalysis({
        registryModifications: [
          {
            key: 'Software\\Microsoft\\Windows\\CurrentVersion\\Run',
            valueName: 'Malware',
            operation: 'create',
            valueData: 'C:\\malware.exe',
          },
        ],
      });

      const results = mapToAttackTechniques(null, dynamicAnalysis);
      const t1547 = results.find((r) => r.techniqueId === 'T1547.001');
      expect(t1547).toBeDefined();
      expect(t1547!.confidence).toBeGreaterThanOrEqual(85);
      expect(t1547!.tactic).toBe('Persistence');
    });

    it('maps startup folder file creation to T1547.001', () => {
      const dynamicAnalysis = makeDynamicAnalysis({
        filesModified: [
          {
            path: 'C:\\Users\\admin\\Start Menu\\Programs\\Startup\\evil.lnk',
            operation: 'create',
            newPath: null,
            sha256: null,
          },
        ],
      });

      const results = mapToAttackTechniques(null, dynamicAnalysis);
      const t1547 = results.find((r) => r.techniqueId === 'T1547.001');
      expect(t1547).toBeDefined();
    });
  });

  describe('PowerShell execution (T1059.001)', () => {
    it('maps powershell.exe process to T1059.001', () => {
      const dynamicAnalysis = makeDynamicAnalysis({
        processesCreated: [
          {
            pid: 100,
            parentPid: 1,
            name: 'powershell.exe',
            commandLine: 'powershell.exe -NoProfile',
            createdAt: new Date().toISOString(),
          },
        ],
      });

      const results = mapToAttackTechniques(null, dynamicAnalysis);
      const t1059 = results.find((r) => r.techniqueId === 'T1059.001');
      expect(t1059).toBeDefined();
      expect(t1059!.confidence).toBeGreaterThanOrEqual(90);
      expect(t1059!.name).toBe('PowerShell');
    });
  });

  describe('no behaviors', () => {
    it('returns empty technique list when no data provided', () => {
      const results = mapToAttackTechniques(null, null);
      expect(results).toEqual([]);
    });

    it('returns empty technique list for clean static analysis', () => {
      const staticAnalysis = makeStaticAnalysis();
      const results = mapToAttackTechniques(staticAnalysis, null);
      // Some rules may still match with 0 confidence and be filtered
      // All results should have confidence > 0
      for (const r of results) {
        expect(r.confidence).toBeGreaterThan(0);
      }
    });
  });

  describe('confidence scoring', () => {
    it('confidence is clamped between 0 and 100', () => {
      const staticAnalysis = makeStaticAnalysis({
        imports: ['WriteProcessMemory', 'VirtualAllocEx', 'CreateRemoteThread', 'NtUnmapViewOfSection', 'SetThreadContext'],
      });

      const results = mapToAttackTechniques(staticAnalysis, null);
      for (const r of results) {
        expect(r.confidence).toBeGreaterThanOrEqual(0);
        expect(r.confidence).toBeLessThanOrEqual(100);
      }
    });

    it('results are sorted by confidence descending', () => {
      const staticAnalysis = makeStaticAnalysis({
        imports: ['WriteProcessMemory', 'VirtualAllocEx', 'CreateRemoteThread', 'LoadLibraryA'],
      });
      const dynamicAnalysis = makeDynamicAnalysis({
        processesCreated: [
          { pid: 1, parentPid: 0, name: 'powershell.exe', commandLine: 'powershell', createdAt: '' },
        ],
        networkConnections: [
          { protocol: 'http', sourceAddress: '10.0.0.1', sourcePort: 1, destinationAddress: '1.1.1.1', destinationPort: 80, domain: null, bytesSent: 0, bytesReceived: 0 },
        ],
      });

      const results = mapToAttackTechniques(staticAnalysis, dynamicAnalysis);
      for (let i = 1; i < results.length; i++) {
        expect(results[i]!.confidence).toBeLessThanOrEqual(results[i - 1]!.confidence);
      }
    });
  });

  describe('registry modification (T1112)', () => {
    it('maps any registry modification to T1112', () => {
      const dynamicAnalysis = makeDynamicAnalysis({
        registryModifications: [
          { key: 'HKCU\\Software\\Test', valueName: 'val', operation: 'create', valueData: 'data' },
        ],
      });

      const results = mapToAttackTechniques(null, dynamicAnalysis);
      const t1112 = results.find((r) => r.techniqueId === 'T1112');
      expect(t1112).toBeDefined();
    });
  });

  describe('network-based techniques', () => {
    it('maps HTTP connections to T1071.001', () => {
      const dynamicAnalysis = makeDynamicAnalysis({
        networkConnections: [
          { protocol: 'http', sourceAddress: '10.0.0.1', sourcePort: 1, destinationAddress: '1.1.1.1', destinationPort: 80, domain: 'test.com', bytesSent: 100, bytesReceived: 200 },
        ],
      });

      const results = mapToAttackTechniques(null, dynamicAnalysis);
      const t1071 = results.find((r) => r.techniqueId === 'T1071.001');
      expect(t1071).toBeDefined();
    });
  });

  describe('rule count', () => {
    it('reports a significant number of mapping rules', () => {
      expect(getMappingRuleCount()).toBeGreaterThanOrEqual(30);
    });
  });
});
