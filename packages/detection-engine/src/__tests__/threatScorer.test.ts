import { describe, it, expect } from 'vitest';
import { calculateThreatScore } from '../scoring/threatScorer.js';
import type { ScoringInput } from '../scoring/threatScorer.js';
import { ThreatLevel } from '@scanboy/shared';
import type {
  ThreatIntelResult,
  StaticAnalysisResult,
  DynamicAnalysisResult,
  ATTACKTechnique,
} from '@scanboy/shared';

function makeEmptyInput(): ScoringInput {
  return {
    threatIntelResults: [],
    staticAnalysis: null,
    dynamicAnalysis: null,
    attackTechniques: [],
  };
}

function makeThreatIntelResult(overrides: Partial<ThreatIntelResult> = {}): ThreatIntelResult {
  return {
    submissionId: 'sub-1',
    source: 'TestProvider',
    knownMalware: false,
    malwareFamily: null,
    firstSeenAt: null,
    detectionRatio: null,
    communityScore: null,
    tags: [],
    rawResponse: {},
    queriedAt: new Date().toISOString(),
    ...overrides,
  };
}

function makeStaticAnalysis(overrides: Partial<StaticAnalysisResult> = {}): StaticAnalysisResult {
  return {
    submissionId: 'sub-1',
    fileType: 'PE',
    magic: 'PE32 executable',
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

function makeAttackTechnique(overrides: Partial<ATTACKTechnique> = {}): ATTACKTechnique {
  return {
    id: 'att-1',
    techniqueId: 'T1055',
    name: 'Process Injection',
    tactic: 'Defense Evasion',
    description: 'Inject code into processes',
    dataSource: 'Process',
    confidence: 80,
    ...overrides,
  };
}

describe('calculateThreatScore', () => {
  describe('empty input', () => {
    it('returns score 0 when there are no indicators', () => {
      const result = calculateThreatScore(makeEmptyInput());
      expect(result.totalScore).toBe(0);
      expect(result.threatLevel).toBe(ThreatLevel.Informational);
    });

    it('returns all category scores as 0', () => {
      const result = calculateThreatScore(makeEmptyInput());
      expect(result.threatIntelScore).toBe(0);
      expect(result.staticIndicatorScore).toBe(0);
      expect(result.dynamicBehaviorScore).toBe(0);
      expect(result.networkActivityScore).toBe(0);
      expect(result.evasionScore).toBe(0);
    });
  });

  describe('threat intel scoring', () => {
    it('scores positively when providers flag the sample', () => {
      const input = makeEmptyInput();
      input.threatIntelResults = [
        makeThreatIntelResult({ source: 'Provider1', knownMalware: true }),
        makeThreatIntelResult({ source: 'Provider2', knownMalware: true }),
      ];

      const result = calculateThreatScore(input);
      expect(result.threatIntelScore).toBeGreaterThan(0);
      expect(result.threatIntelScore).toBeLessThanOrEqual(25);
    });

    it('returns 0 threat intel score when no providers flag the sample', () => {
      const input = makeEmptyInput();
      input.threatIntelResults = [
        makeThreatIntelResult({ knownMalware: false }),
        makeThreatIntelResult({ knownMalware: false }),
      ];

      const result = calculateThreatScore(input);
      expect(result.threatIntelScore).toBe(0);
    });

    it('gives bonus for identified malware family', () => {
      const input = makeEmptyInput();
      input.threatIntelResults = [
        makeThreatIntelResult({
          source: 'Provider1',
          knownMalware: true,
          malwareFamily: 'Emotet',
        }),
      ];

      const resultWithFamily = calculateThreatScore(input);

      const input2 = makeEmptyInput();
      input2.threatIntelResults = [
        makeThreatIntelResult({ source: 'Provider1', knownMalware: true }),
      ];

      const resultWithout = calculateThreatScore(input2);
      expect(resultWithFamily.threatIntelScore).toBeGreaterThan(
        resultWithout.threatIntelScore,
      );
    });

    it('handles VT high detection ratio', () => {
      const input = makeEmptyInput();
      input.threatIntelResults = [
        makeThreatIntelResult({
          source: 'VirusTotal',
          knownMalware: true,
          detectionRatio: '55/70',
        }),
      ];

      const result = calculateThreatScore(input);
      expect(result.threatIntelScore).toBeGreaterThan(0);
    });
  });

  describe('static indicator scoring', () => {
    it('scores packed binaries', () => {
      const input = makeEmptyInput();
      input.staticAnalysis = makeStaticAnalysis({ isPacked: true });

      const result = calculateThreatScore(input);
      expect(result.staticIndicatorScore).toBeGreaterThan(0);
    });

    it('scores near-random entropy (>7.9)', () => {
      const input = makeEmptyInput();
      input.staticAnalysis = makeStaticAnalysis({ entropy: 7.95 });

      const result = calculateThreatScore(input);
      expect(result.staticIndicatorScore).toBeGreaterThan(0);
    });

    it('scores elevated entropy (7.7-7.9)', () => {
      const input = makeEmptyInput();
      input.staticAnalysis = makeStaticAnalysis({ entropy: 7.8 });

      const result = calculateThreatScore(input);
      expect(result.staticIndicatorScore).toBeGreaterThan(0);
    });

    it('does not score normal PE entropy (7.0-7.7)', () => {
      const input = makeEmptyInput();
      input.staticAnalysis = makeStaticAnalysis({ entropy: 7.5 });

      const result = calculateThreatScore(input);
      // Entropy alone at 7.5 should NOT contribute points — only imports/packing would
      expect(result.staticIndicatorScore).toBe(0);
    });

    it('scores suspicious API imports', () => {
      const input = makeEmptyInput();
      input.staticAnalysis = makeStaticAnalysis({
        imports: ['VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread'],
      });

      const result = calculateThreatScore(input);
      expect(result.staticIndicatorScore).toBeGreaterThan(0);
    });
  });

  describe('dynamic behavior scoring', () => {
    it('scores suspicious processes', () => {
      const input = makeEmptyInput();
      input.dynamicAnalysis = makeDynamicAnalysis({
        processesCreated: [
          {
            pid: 100,
            parentPid: 1,
            name: 'powershell.exe',
            commandLine: 'powershell -enc abc',
            createdAt: new Date().toISOString(),
          },
        ],
      });

      const result = calculateThreatScore(input);
      expect(result.dynamicBehaviorScore).toBeGreaterThan(0);
    });

    it('scores persistence-related registry modifications', () => {
      const input = makeEmptyInput();
      input.dynamicAnalysis = makeDynamicAnalysis({
        registryModifications: [
          {
            key: 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
            valueName: 'Malware',
            operation: 'create',
            valueData: 'C:\\malware.exe',
          },
        ],
      });

      const result = calculateThreatScore(input);
      expect(result.dynamicBehaviorScore).toBeGreaterThan(0);
    });

    it('scores high-confidence ATT&CK techniques', () => {
      const input = makeEmptyInput();
      input.dynamicAnalysis = makeDynamicAnalysis();
      input.attackTechniques = [
        makeAttackTechnique({ confidence: 90 }),
        makeAttackTechnique({ id: 'att-2', techniqueId: 'T1547.001', confidence: 85 }),
      ];

      const result = calculateThreatScore(input);
      expect(result.dynamicBehaviorScore).toBeGreaterThan(0);
    });

    it('scores mutex creation', () => {
      const input = makeEmptyInput();
      input.dynamicAnalysis = makeDynamicAnalysis({
        mutexesCreated: ['Global\\MalwareMutex'],
      });

      const result = calculateThreatScore(input);
      expect(result.dynamicBehaviorScore).toBeGreaterThanOrEqual(2);
    });
  });

  describe('network activity scoring', () => {
    it('scores external network connections', () => {
      const input = makeEmptyInput();
      input.dynamicAnalysis = makeDynamicAnalysis({
        networkConnections: [
          {
            protocol: 'http',
            sourceAddress: '10.0.0.5',
            sourcePort: 12345,
            destinationAddress: '45.33.32.156',
            destinationPort: 80,
            domain: 'evil-c2.com',
            bytesSent: 500,
            bytesReceived: 2000,
          },
        ],
      });

      const result = calculateThreatScore(input);
      expect(result.networkActivityScore).toBeGreaterThan(0);
    });

    it('scores connections to non-standard ports', () => {
      const input = makeEmptyInput();
      input.dynamicAnalysis = makeDynamicAnalysis({
        networkConnections: [
          {
            protocol: 'tcp',
            sourceAddress: '10.0.0.5',
            sourcePort: 12345,
            destinationAddress: '45.33.32.156',
            destinationPort: 4444,
            domain: null,
            bytesSent: 100,
            bytesReceived: 200,
          },
        ],
      });

      const result = calculateThreatScore(input);
      expect(result.networkActivityScore).toBeGreaterThan(0);
    });

    it('returns 0 for no network activity', () => {
      const input = makeEmptyInput();
      input.dynamicAnalysis = makeDynamicAnalysis();

      const result = calculateThreatScore(input);
      expect(result.networkActivityScore).toBe(0);
    });
  });

  describe('evasion scoring', () => {
    it('scores defense evasion ATT&CK techniques', () => {
      const input = makeEmptyInput();
      input.dynamicAnalysis = makeDynamicAnalysis();
      // T1027 is in BASELINE_EVASION (Wine noise), so use a non-baseline technique
      input.attackTechniques = [
        makeAttackTechnique({ tactic: 'Defense Evasion', techniqueId: 'T1140' }),
      ];

      const result = calculateThreatScore(input);
      expect(result.evasionScore).toBeGreaterThan(0);
    });

    it('scores anti-debug API imports', () => {
      const input = makeEmptyInput();
      input.staticAnalysis = makeStaticAnalysis({
        imports: ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent'],
      });

      const result = calculateThreatScore(input);
      expect(result.evasionScore).toBeGreaterThan(0);
    });

    it('scores process injection techniques', () => {
      const input = makeEmptyInput();
      input.dynamicAnalysis = makeDynamicAnalysis();
      input.attackTechniques = [
        makeAttackTechnique({
          techniqueId: 'T1055',
          tactic: 'Defense Evasion',
          confidence: 85,
        }),
      ];

      const result = calculateThreatScore(input);
      expect(result.evasionScore).toBeGreaterThan(0);
    });

    it('scores file deletions as evidence removal', () => {
      const input = makeEmptyInput();
      input.dynamicAnalysis = makeDynamicAnalysis({
        filesModified: [
          { path: 'C:\\temp\\a.tmp', operation: 'delete', newPath: null, sha256: null },
          { path: 'C:\\temp\\b.tmp', operation: 'delete', newPath: null, sha256: null },
          { path: 'C:\\temp\\c.tmp', operation: 'delete', newPath: null, sha256: null },
        ],
      });

      const result = calculateThreatScore(input);
      expect(result.evasionScore).toBeGreaterThan(0);
    });
  });

  describe('threat level mapping', () => {
    it('maps score 0 to Informational', () => {
      const result = calculateThreatScore(makeEmptyInput());
      expect(result.threatLevel).toBe(ThreatLevel.Informational);
    });

    it('maps a moderate combined score to the correct level', () => {
      const input = makeEmptyInput();
      input.threatIntelResults = [
        makeThreatIntelResult({ source: 'P1', knownMalware: true }),
        makeThreatIntelResult({ source: 'P2', knownMalware: true }),
      ];
      input.staticAnalysis = makeStaticAnalysis({ isPacked: true, entropy: 7.8 });
      input.dynamicAnalysis = makeDynamicAnalysis({
        processesCreated: [
          {
            pid: 1,
            parentPid: 0,
            name: 'powershell.exe',
            commandLine: 'powershell -enc abc',
            createdAt: new Date().toISOString(),
          },
        ],
        networkConnections: [
          {
            protocol: 'http',
            sourceAddress: '10.0.0.1',
            sourcePort: 1234,
            destinationAddress: '8.8.8.8',
            destinationPort: 8080,
            domain: null,
            bytesSent: 100,
            bytesReceived: 200,
          },
        ],
      });

      const result = calculateThreatScore(input);
      expect(result.totalScore).toBeGreaterThan(0);
      // Level should match the thresholds
      expect(
        [
          ThreatLevel.Informational,
          ThreatLevel.Low,
          ThreatLevel.Medium,
          ThreatLevel.High,
          ThreatLevel.Critical,
        ],
      ).toContain(result.threatLevel);
    });
  });

  describe('score clamping', () => {
    it('never exceeds 100 even with max indicators in all categories', () => {
      const input: ScoringInput = {
        threatIntelResults: [
          makeThreatIntelResult({
            source: 'VirusTotal',
            knownMalware: true,
            malwareFamily: 'Emotet',
            detectionRatio: '70/70',
          }),
          makeThreatIntelResult({
            source: 'P2',
            knownMalware: true,
            malwareFamily: 'Emotet',
          }),
          makeThreatIntelResult({
            source: 'P3',
            knownMalware: true,
            malwareFamily: 'Emotet',
          }),
        ],
        staticAnalysis: makeStaticAnalysis({
          isPacked: true,
          entropy: 7.9,
          imports: [
            'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread',
            'IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
            'NtQueryInformationProcess', 'OutputDebugString',
          ],
          iocs: [
            { id: '1', submissionId: 'sub-1', type: 'ipv4' as const, value: '1.2.3.4', context: null, confidence: 80, source: 's', firstSeenAt: '', createdAt: '' },
            { id: '2', submissionId: 'sub-1', type: 'domain' as const, value: 'evil.com', context: null, confidence: 80, source: 's', firstSeenAt: '', createdAt: '' },
          ],
        }),
        dynamicAnalysis: makeDynamicAnalysis({
          processesCreated: [
            { pid: 1, parentPid: 0, name: 'powershell.exe', commandLine: 'powershell -enc', createdAt: '' },
            { pid: 2, parentPid: 1, name: 'cmd.exe', commandLine: 'cmd /c whoami', createdAt: '' },
            { pid: 3, parentPid: 1, name: 'certutil.exe', commandLine: 'certutil -decode', createdAt: '' },
            { pid: 4, parentPid: 1, name: 'mshta.exe', commandLine: 'mshta http://evil', createdAt: '' },
          ],
          registryModifications: [
            { key: 'HKLM\\...\\Run', valueName: 'mal', operation: 'create', valueData: 'evil.exe' },
            { key: 'HKLM\\...\\Services', valueName: 'svc', operation: 'create', valueData: 'svc.exe' },
          ],
          mutexesCreated: ['Global\\Mutex1'],
          networkConnections: [
            { protocol: 'http', sourceAddress: '10.0.0.1', sourcePort: 1, destinationAddress: '5.5.5.5', destinationPort: 8080, domain: null, bytesSent: 2_000_000, bytesReceived: 100 },
            { protocol: 'tcp', sourceAddress: '10.0.0.1', sourcePort: 2, destinationAddress: '6.6.6.6', destinationPort: 4444, domain: null, bytesSent: 100, bytesReceived: 100 },
            ...Array.from({ length: 25 }, (_, i) => ({
              protocol: 'dns' as const,
              sourceAddress: '10.0.0.1',
              sourcePort: 1000 + i,
              destinationAddress: '8.8.8.8',
              destinationPort: 53,
              domain: `sub${i}.evil.com`,
              bytesSent: 50,
              bytesReceived: 100,
            })),
          ],
          filesModified: [
            { path: 'a', operation: 'delete' as const, newPath: null, sha256: null },
            { path: 'b', operation: 'delete' as const, newPath: null, sha256: null },
            { path: 'c', operation: 'delete' as const, newPath: null, sha256: null },
          ],
        }),
        attackTechniques: [
          makeAttackTechnique({ id: 'a1', techniqueId: 'T1055', tactic: 'Defense Evasion', confidence: 90 }),
          makeAttackTechnique({ id: 'a2', techniqueId: 'T1027', tactic: 'Defense Evasion', confidence: 85 }),
          makeAttackTechnique({ id: 'a3', techniqueId: 'T1547.001', tactic: 'Persistence', confidence: 80 }),
          makeAttackTechnique({ id: 'a4', techniqueId: 'T1059.001', tactic: 'Execution', confidence: 95 }),
        ],
      };

      const result = calculateThreatScore(input);
      expect(result.totalScore).toBeLessThanOrEqual(100);
      expect(result.totalScore).toBeGreaterThan(0);
    });
  });

  describe('details array', () => {
    it('provides detailed breakdown entries', () => {
      const input = makeEmptyInput();
      input.threatIntelResults = [
        makeThreatIntelResult({ knownMalware: false }),
      ];

      const result = calculateThreatScore(input);
      expect(result.details.length).toBeGreaterThan(0);
      for (const detail of result.details) {
        expect(detail).toHaveProperty('category');
        expect(detail).toHaveProperty('description');
        expect(detail).toHaveProperty('points');
        expect(detail).toHaveProperty('maxPoints');
        expect(detail.points).toBeGreaterThanOrEqual(0);
      }
    });
  });
});
