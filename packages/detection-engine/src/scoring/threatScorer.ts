import type {
  ThreatIntelResult,
  StaticAnalysisResult,
  DynamicAnalysisResult,
  ATTACKTechnique,
  ThreatLevel,
} from '@scanboy/shared';
import { threatLevelFromScore } from '@scanboy/shared';
import { getTrancoTier } from '../domainReputation.js';

/** Breakdown of threat score by category. */
export interface ThreatScoreBreakdown {
  /** Final composite score (0-100). */
  totalScore: number;
  /** Mapped threat level. */
  threatLevel: ThreatLevel;
  /** Points from threat intelligence results (0-25). */
  threatIntelScore: number;
  /** Points from static analysis indicators (0-20). */
  staticIndicatorScore: number;
  /** Points from dynamic behaviour analysis (0-25). */
  dynamicBehaviorScore: number;
  /** Points from network activity (0-15). */
  networkActivityScore: number;
  /** Points from evasion techniques (0-15). */
  evasionScore: number;
  /** Per-category detail. */
  details: ScoreDetail[];
}

export interface ScoreDetail {
  category: string;
  description: string;
  points: number;
  maxPoints: number;
}

/**
 * Input data for threat scoring.
 */
export interface ScoringInput {
  threatIntelResults: ThreatIntelResult[];
  staticAnalysis: StaticAnalysisResult | null;
  dynamicAnalysis: DynamicAnalysisResult | null;
  attackTechniques: ATTACKTechnique[];
}

// ── Category scorers ────────────────────────────────────────────────────────

/**
 * Score threat intelligence results (0-25 points).
 */
function scoreThreatIntel(results: ThreatIntelResult[]): { score: number; details: ScoreDetail[] } {
  const MAX = 25;
  const details: ScoreDetail[] = [];
  let score = 0;

  if (results.length === 0) {
    return { score: 0, details: [{ category: 'Threat Intel', description: 'No threat intel data available', points: 0, maxPoints: MAX }] };
  }

  // Count providers that flagged the sample
  const positiveCount = results.filter((r) => r.knownMalware).length;
  const totalCount = results.length;

  if (positiveCount === 0) {
    details.push({ category: 'Threat Intel', description: `0/${totalCount} providers flagged the sample`, points: 0, maxPoints: MAX });
    return { score: 0, details };
  }

  // Base score from detection ratio
  const ratio = positiveCount / totalCount;
  score += Math.round(ratio * 15);
  details.push({
    category: 'Threat Intel - Detection Ratio',
    description: `${positiveCount}/${totalCount} providers flagged the sample`,
    points: Math.round(ratio * 15),
    maxPoints: 15,
  });

  // Bonus for identified malware family
  const familyCount = results.filter((r) => r.malwareFamily !== null).length;
  if (familyCount > 0) {
    const familyBonus = Math.min(5, familyCount * 2);
    score += familyBonus;
    details.push({
      category: 'Threat Intel - Malware Family',
      description: `${familyCount} provider(s) identified malware family`,
      points: familyBonus,
      maxPoints: 5,
    });
  }

  // VT-specific detection ratio parsing
  const vtResult = results.find((r) => r.source === 'VirusTotal');
  if (vtResult?.detectionRatio) {
    const match = vtResult.detectionRatio.match(/^(\d+)\/(\d+)$/);
    if (match) {
      const detected = parseInt(match[1]!, 10);
      const total = parseInt(match[2]!, 10);
      if (total > 0 && detected / total > 0.5) {
        const vtBonus = Math.min(5, Math.round((detected / total) * 5));
        score += vtBonus;
        details.push({
          category: 'Threat Intel - VT High Detection',
          description: `VirusTotal: ${detected}/${total} detections`,
          points: vtBonus,
          maxPoints: 5,
        });
      }
    }
  }

  return { score: Math.min(MAX, score), details };
}

/**
 * Score static analysis indicators (0-20 points).
 */
function scoreStaticIndicators(staticAnalysis: StaticAnalysisResult | null): { score: number; details: ScoreDetail[] } {
  const MAX = 20;
  const details: ScoreDetail[] = [];

  if (!staticAnalysis) {
    return { score: 0, details: [{ category: 'Static Analysis', description: 'No static analysis data', points: 0, maxPoints: MAX }] };
  }

  let score = 0;

  // Packing detection
  if (staticAnalysis.isPacked) {
    score += 5;
    details.push({
      category: 'Static - Packing',
      description: `Binary is packed${staticAnalysis.packerName ? ` (${staticAnalysis.packerName})` : ''}`,
      points: 5,
      maxPoints: 5,
    });
  }

  // High entropy — only flag near-random entropy (>7.9) that indicates encryption/packing.
  // Normal PE files with compressed resources sit at 7.0-7.8; flagging >7.5 is non-discriminative.
  if (staticAnalysis.entropy > 7.9) {
    score += 4;
    details.push({
      category: 'Static - High Entropy',
      description: `Near-random entropy: ${staticAnalysis.entropy.toFixed(2)} (likely encrypted/packed)`,
      points: 4,
      maxPoints: 4,
    });
  } else if (staticAnalysis.entropy > 7.7) {
    score += 2;
    details.push({
      category: 'Static - Elevated Entropy',
      description: `Elevated entropy: ${staticAnalysis.entropy.toFixed(2)}`,
      points: 2,
      maxPoints: 4,
    });
  }

  // Suspicious imports
  const dangerousApis = [
    'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread',
    'NtWriteVirtualMemory', 'NtUnmapViewOfSection',
    'SetWindowsHookExA', 'SetWindowsHookExW',
    'URLDownloadToFileA', 'InternetOpenA',
  ];
  const matchedApis = dangerousApis.filter((api) =>
    staticAnalysis.imports.some((i) => i.toLowerCase().includes(api.toLowerCase())),
  );
  if (matchedApis.length > 0) {
    const apiScore = Math.min(6, matchedApis.length * 2);
    score += apiScore;
    details.push({
      category: 'Static - Suspicious Imports',
      description: `${matchedApis.length} suspicious API import(s): ${matchedApis.join(', ')}`,
      points: apiScore,
      maxPoints: 6,
    });
  }

  // Suspicious strings (IOCs found in static analysis)
  const iocCount = staticAnalysis.iocs.length;
  if (iocCount > 0) {
    const iocScore = Math.min(5, Math.ceil(iocCount / 2));
    score += iocScore;
    details.push({
      category: 'Static - IOCs',
      description: `${iocCount} IOC(s) extracted from static analysis`,
      points: iocScore,
      maxPoints: 5,
    });
  }

  return { score: Math.min(MAX, score), details };
}

/**
 * Score dynamic behaviour (0-25 points).
 */
function scoreDynamicBehaviors(
  dynamicAnalysis: DynamicAnalysisResult | null,
  attackTechniques: ATTACKTechnique[],
): { score: number; details: ScoreDetail[] } {
  const MAX = 25;
  const details: ScoreDetail[] = [];

  if (!dynamicAnalysis) {
    return { score: 0, details: [{ category: 'Dynamic Analysis', description: 'No dynamic analysis data', points: 0, maxPoints: MAX }] };
  }

  let score = 0;

  // Process creation
  const suspiciousProcs = dynamicAnalysis.processesCreated.filter((p) => {
    const name = p.name.toLowerCase();
    return ['powershell.exe', 'cmd.exe', 'mshta.exe', 'wscript.exe', 'cscript.exe',
      'regsvr32.exe', 'rundll32.exe', 'certutil.exe', 'bitsadmin.exe'].includes(name);
  });
  if (suspiciousProcs.length > 0) {
    const procScore = Math.min(8, suspiciousProcs.length * 2);
    score += procScore;
    details.push({
      category: 'Dynamic - Suspicious Processes',
      description: `${suspiciousProcs.length} suspicious process(es) spawned`,
      points: procScore,
      maxPoints: 8,
    });
  }

  // Registry modifications for persistence
  const persistenceRegKeys = dynamicAnalysis.registryModifications.filter((m) => {
    const key = m.key.toLowerCase();
    return key.includes('\\run') || key.includes('\\runonce') || key.includes('\\services') || key.includes('\\winlogon');
  });
  if (persistenceRegKeys.length > 0) {
    const regScore = Math.min(7, persistenceRegKeys.length * 3);
    score += regScore;
    details.push({
      category: 'Dynamic - Persistence',
      description: `${persistenceRegKeys.length} persistence-related registry modification(s)`,
      points: regScore,
      maxPoints: 7,
    });
  }

  // ATT&CK techniques with high confidence
  // Exclude baseline techniques that appear in ALL Wine-executed PE files (entropy,
  // PE-in-archive, scripting from Wine internals, basic file ops). These provide
  // zero discriminative power between malware and legitimate software.
  const BASELINE_TECHNIQUES = new Set([
    'T1027', 'T1027.002',  // Obfuscated files (high entropy is normal for packed/signed PEs)
    'T1036.008',           // Masquerading (PE-in-archive — common for installers)
    'T1059',               // Command/Scripting — Wine shell invocations
    'T1106',               // Native API — standard Win32 usage
    'T1082',               // System information discovery — basic OS checks
  ]);
  const highConfTechniques = attackTechniques.filter((t) =>
    t.confidence >= 75 && !BASELINE_TECHNIQUES.has(t.techniqueId),
  );
  if (highConfTechniques.length > 0) {
    const techScore = Math.min(10, highConfTechniques.length * 2);
    score += techScore;
    details.push({
      category: 'Dynamic - ATT&CK Techniques',
      description: `${highConfTechniques.length} high-confidence ATT&CK technique(s) detected`,
      points: techScore,
      maxPoints: 10,
    });
  }

  // Mutexes
  if (dynamicAnalysis.mutexesCreated.length > 0) {
    score += 2;
    details.push({
      category: 'Dynamic - Mutexes',
      description: `${dynamicAnalysis.mutexesCreated.length} mutex(es) created`,
      points: 2,
      maxPoints: 2,
    });
  }

  return { score: Math.min(MAX, score), details };
}

/**
 * Score network activity (0-15 points).
 */
function scoreNetworkActivity(dynamicAnalysis: DynamicAnalysisResult | null): { score: number; details: ScoreDetail[] } {
  const MAX = 15;
  const details: ScoreDetail[] = [];

  if (!dynamicAnalysis || dynamicAnalysis.networkConnections.length === 0) {
    return { score: 0, details: [{ category: 'Network', description: 'No network activity', points: 0, maxPoints: MAX }] };
  }

  let score = 0;
  const conns = dynamicAnalysis.networkConnections;

  // Any external connections (exclude trusted Tranco domains)
  const externalConns = conns.filter((c) => {
    const ip = c.destinationAddress;
    if (ip.startsWith('127.') || ip.startsWith('10.') ||
      ip.startsWith('192.168.') || ip.startsWith('172.16.') || ip === '0.0.0.0') return false;
    const tier = c.domain ? getTrancoTier(c.domain) : null;
    if (tier === 'trusted' || tier === 'likely_legit') return false;
    return true;
  });

  if (externalConns.length > 0) {
    const extScore = Math.min(5, Math.ceil(externalConns.length / 2));
    score += extScore;
    details.push({
      category: 'Network - External Connections',
      description: `${externalConns.length} external connection(s) (excluding trusted domains)`,
      points: extScore,
      maxPoints: 5,
    });
  }

  // Non-standard ports
  const standardPorts = new Set([80, 443, 53, 25, 587, 993, 995, 110, 143, 21, 22, 23, 3389]);
  const nonStandardConns = conns.filter((c) => !standardPorts.has(c.destinationPort) && c.destinationPort > 1024);
  if (nonStandardConns.length > 0) {
    const nsScore = Math.min(5, nonStandardConns.length * 2);
    score += nsScore;
    details.push({
      category: 'Network - Non-Standard Ports',
      description: `${nonStandardConns.length} connection(s) to non-standard ports`,
      points: nsScore,
      maxPoints: 5,
    });
  }

  // DNS queries (only count non-trusted domains)
  const dnsConns = conns.filter((c) => {
    if (c.protocol !== 'dns') return false;
    const tier = c.domain ? getTrancoTier(c.domain) : null;
    return tier !== 'trusted' && tier !== 'likely_legit';
  });
  if (dnsConns.length > 20) {
    score += 3;
    details.push({
      category: 'Network - Excessive DNS',
      description: `${dnsConns.length} suspicious DNS queries (possible tunneling or DGA)`,
      points: 3,
      maxPoints: 3,
    });
  }

  // Large data transfer
  const totalBytesSent = conns.reduce((sum, c) => sum + c.bytesSent, 0);
  if (totalBytesSent > 1024 * 1024) { // > 1MB sent
    score += 2;
    details.push({
      category: 'Network - Data Exfiltration',
      description: `${(totalBytesSent / 1024 / 1024).toFixed(2)} MB sent (possible exfiltration)`,
      points: 2,
      maxPoints: 2,
    });
  }

  return { score: Math.min(MAX, score), details };
}

/**
 * Score evasion techniques (0-15 points).
 */
function scoreEvasionTechniques(
  staticAnalysis: StaticAnalysisResult | null,
  dynamicAnalysis: DynamicAnalysisResult | null,
  attackTechniques: ATTACKTechnique[],
): { score: number; details: ScoreDetail[] } {
  const MAX = 15;
  const details: ScoreDetail[] = [];
  let score = 0;

  // Defense evasion ATT&CK techniques (excluding Wine/PE baseline noise)
  const BASELINE_EVASION = new Set(['T1027', 'T1027.002', 'T1036.008', 'T1059', 'T1106']);
  const evasionTechniques = attackTechniques.filter((t) =>
    t.tactic === 'Defense Evasion' && !BASELINE_EVASION.has(t.techniqueId),
  );
  if (evasionTechniques.length > 0) {
    const evasionScore = Math.min(7, evasionTechniques.length * 2);
    score += evasionScore;
    details.push({
      category: 'Evasion - ATT&CK Defense Evasion',
      description: `${evasionTechniques.length} defense evasion technique(s) detected`,
      points: evasionScore,
      maxPoints: 7,
    });
  }

  // Anti-debug imports
  if (staticAnalysis) {
    const antiDebugApis = ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'NtQueryInformationProcess', 'OutputDebugString'];
    const matched = antiDebugApis.filter((api) =>
      staticAnalysis.imports.some((i) => i.toLowerCase().includes(api.toLowerCase())),
    );
    if (matched.length > 0) {
      score += 3;
      details.push({
        category: 'Evasion - Anti-Debug',
        description: `Anti-debug API(s): ${matched.join(', ')}`,
        points: 3,
        maxPoints: 3,
      });
    }
  }

  // File/indicator deletion
  if (dynamicAnalysis) {
    const deletions = dynamicAnalysis.filesModified.filter((f) => f.operation === 'delete');
    if (deletions.length > 2) {
      score += 3;
      details.push({
        category: 'Evasion - Evidence Removal',
        description: `${deletions.length} file deletion(s) observed`,
        points: 3,
        maxPoints: 3,
      });
    }
  }

  // Process injection (also an evasion technique)
  const injectionTechniques = attackTechniques.filter(
    (t) => t.techniqueId.startsWith('T1055') && t.confidence >= 70,
  );
  if (injectionTechniques.length > 0) {
    score += 2;
    details.push({
      category: 'Evasion - Process Injection',
      description: 'Process injection technique(s) detected',
      points: 2,
      maxPoints: 2,
    });
  }

  return { score: Math.min(MAX, score), details };
}

// ── Main scoring function ───────────────────────────────────────────────────

/**
 * Calculate a comprehensive threat score (0-100) from all available analysis data.
 *
 * Score distribution:
 *   - Threat intel results:  0-25 points
 *   - Static indicators:     0-20 points
 *   - Dynamic behaviors:     0-25 points
 *   - Network activity:      0-15 points
 *   - Evasion techniques:    0-15 points
 *
 * Threat level mapping:
 *   -  0-20: informational
 *   - 21-40: low
 *   - 41-60: medium
 *   - 61-80: high
 *   - 81-100: critical
 */
export function calculateThreatScore(input: ScoringInput): ThreatScoreBreakdown {
  const threatIntel = scoreThreatIntel(input.threatIntelResults);
  const staticIndicators = scoreStaticIndicators(input.staticAnalysis);
  const dynamicBehaviors = scoreDynamicBehaviors(input.dynamicAnalysis, input.attackTechniques);
  const networkActivity = scoreNetworkActivity(input.dynamicAnalysis);
  const evasion = scoreEvasionTechniques(input.staticAnalysis, input.dynamicAnalysis, input.attackTechniques);

  const totalScore = Math.min(
    100,
    threatIntel.score +
    staticIndicators.score +
    dynamicBehaviors.score +
    networkActivity.score +
    evasion.score,
  );

  return {
    totalScore,
    threatLevel: threatLevelFromScore(totalScore),
    threatIntelScore: threatIntel.score,
    staticIndicatorScore: staticIndicators.score,
    dynamicBehaviorScore: dynamicBehaviors.score,
    networkActivityScore: networkActivity.score,
    evasionScore: evasion.score,
    details: [
      ...threatIntel.details,
      ...staticIndicators.details,
      ...dynamicBehaviors.details,
      ...networkActivity.details,
      ...evasion.details,
    ],
  };
}
