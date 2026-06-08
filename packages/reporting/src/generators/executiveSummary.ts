import { ThreatLevel } from '@scanboy/shared';
import type { AnalysisReport } from '@scanboy/shared';

// ── Types ──────────────────────────────────────────────────────────────────

export interface ExecutiveSummary {
  overview: string;
  keyFindings: string[];
  riskLevel: RiskLevel;
  recommendedActions: string[];
  generatedAt: string;
}

export interface RiskLevel {
  level: ThreatLevel;
  score: number;
  label: string;
  color: string;
}

// ── Generator ──────────────────────────────────────────────────────────────

export function generateExecutiveSummary(report: AnalysisReport): ExecutiveSummary {
  return {
    overview: buildOverview(report),
    keyFindings: buildKeyFindings(report),
    riskLevel: buildRiskLevel(report),
    recommendedActions: buildRecommendedActions(report),
    generatedAt: new Date().toISOString(),
  };
}

// ── Overview ───────────────────────────────────────────────────────────────

function buildOverview(report: AnalysisReport): string {
  const fileName = report.submission.fileName;
  const threatLevel = report.threatLevel;
  const score = report.threatScore;

  const malwareFamilies = report.threatIntel
    .map((ti) => ti.malwareFamily)
    .filter((f): f is string => f !== null);
  const uniqueFamilies = [...new Set(malwareFamilies)];

  const familyStr =
    uniqueFamilies.length > 0
      ? `, identified as belonging to the ${uniqueFamilies.join(', ')} malware family${uniqueFamilies.length > 1 ? 'ies' : ''}`
      : '';

  const iocCount = report.iocs.length;
  const techniqueCount = report.attackTechniques.length;

  const detectionSources = report.threatIntel.filter((ti) => ti.knownMalware).length;
  const detectionStr =
    detectionSources > 0
      ? ` The sample was flagged as malicious by ${detectionSources} threat intelligence source${detectionSources > 1 ? 's' : ''}.`
      : ' The sample was not previously known to threat intelligence sources.';

  return (
    `The submitted file "${fileName}" has been assessed with a threat level of ${threatLevel} ` +
    `(score: ${score}/100)${familyStr}. Analysis identified ${iocCount} indicator${iocCount !== 1 ? 's' : ''} of compromise ` +
    `and ${techniqueCount} ATT&CK technique${techniqueCount !== 1 ? 's' : ''}.${detectionStr}`
  );
}

// ── Key Findings ───────────────────────────────────────────────────────────

function buildKeyFindings(report: AnalysisReport): string[] {
  const findings: string[] = [];

  // Threat intel findings
  for (const ti of report.threatIntel) {
    if (ti.knownMalware) {
      const family = ti.malwareFamily ? ` (${ti.malwareFamily})` : '';
      const ratio = ti.detectionRatio ? ` with detection ratio ${ti.detectionRatio}` : '';
      findings.push(`Identified as known malware${family} by ${ti.source}${ratio}.`);
    }
  }

  // Static analysis findings
  if (report.staticAnalysis) {
    if (report.staticAnalysis.isPacked) {
      const packer = report.staticAnalysis.packerName
        ? ` (${report.staticAnalysis.packerName})`
        : '';
      findings.push(`Binary is packed${packer}, which is commonly used to evade detection.`);
    }
    // Entropy: only flag >7.9 in executive summary — normal PEs sit 7.0-7.7
    if (report.staticAnalysis.entropy > 7.9) {
      findings.push(
        `Near-random entropy (${report.staticAnalysis.entropy.toFixed(2)}) suggests encrypted or packed content.`,
      );
    }
    if (report.staticAnalysis.certificates.some((c) => !c.isValid)) {
      findings.push('Invalid or expired code signing certificate detected.');
    }
  }

  // Dynamic analysis findings
  if (report.dynamicAnalysis) {
    if (report.dynamicAnalysis.networkConnections.length > 0) {
      const uniqueDests = new Set(
        report.dynamicAnalysis.networkConnections.map((c) => c.destinationAddress),
      );
      findings.push(
        `Established ${report.dynamicAnalysis.networkConnections.length} network connection${report.dynamicAnalysis.networkConnections.length > 1 ? 's' : ''} to ${uniqueDests.size} unique destination${uniqueDests.size > 1 ? 's' : ''}.`,
      );
    }
    if (report.dynamicAnalysis.registryModifications.length > 0) {
      findings.push(
        `Modified ${report.dynamicAnalysis.registryModifications.length} registry key${report.dynamicAnalysis.registryModifications.length > 1 ? 's' : ''}.`,
      );
    }
    if (report.dynamicAnalysis.filesModified.length > 0) {
      const created = report.dynamicAnalysis.filesModified.filter(
        (f) => f.operation === 'create',
      ).length;
      if (created > 0) {
        findings.push(`Created ${created} new file${created > 1 ? 's' : ''} on the filesystem.`);
      }
    }
  }

  // YARA findings
  if (report.yaraMatches.length > 0) {
    findings.push(
      `Matched ${report.yaraMatches.length} YARA rule${report.yaraMatches.length > 1 ? 's' : ''}: ${report.yaraMatches.map((m) => m.ruleName).join(', ')}.`,
    );
  }

  // ATT&CK technique findings
  if (report.attackTechniques.length > 0) {
    const tactics = [...new Set(report.attackTechniques.map((t) => t.tactic))];
    findings.push(
      `Exhibits behavior mapped to ${report.attackTechniques.length} MITRE ATT&CK technique${report.attackTechniques.length > 1 ? 's' : ''} across ${tactics.length} tactic${tactics.length > 1 ? 's' : ''}: ${tactics.join(', ')}.`,
    );
  }

  return findings;
}

// ── Risk Level ─────────────────────────────────────────────────────────────

function buildRiskLevel(report: AnalysisReport): RiskLevel {
  const colorMap: Record<ThreatLevel, string> = {
    [ThreatLevel.Informational]: '#6b7280',
    [ThreatLevel.Low]: '#22c55e',
    [ThreatLevel.Medium]: '#f59e0b',
    [ThreatLevel.High]: '#ef4444',
    [ThreatLevel.Critical]: '#991b1b',
  };

  const labelMap: Record<ThreatLevel, string> = {
    [ThreatLevel.Informational]: 'Informational - No immediate threat detected',
    [ThreatLevel.Low]: 'Low Risk - Minor indicators present, unlikely to be harmful',
    [ThreatLevel.Medium]: 'Medium Risk - Suspicious indicators detected, further review recommended',
    [ThreatLevel.High]: 'High Risk - Strong malicious indicators, immediate action recommended',
    [ThreatLevel.Critical]:
      'Critical Risk - Confirmed malware, immediate containment and remediation required',
  };

  return {
    level: report.threatLevel,
    score: report.threatScore,
    label: labelMap[report.threatLevel],
    color: colorMap[report.threatLevel],
  };
}

// ── Recommended Actions ────────────────────────────────────────────────────

function buildRecommendedActions(report: AnalysisReport): string[] {
  const actions: string[] = [];

  switch (report.threatLevel) {
    case ThreatLevel.Critical:
      actions.push('IMMEDIATE: Isolate affected systems from the network.');
      actions.push('Initiate incident response procedures.');
      actions.push('Block all identified IOCs at network perimeter (firewall, proxy, DNS).');
      actions.push('Scan all endpoints for the identified file hashes.');
      actions.push('Preserve forensic evidence before remediation.');
      actions.push('Notify security leadership and relevant stakeholders.');
      break;

    case ThreatLevel.High:
      actions.push('Quarantine the file and any systems known to have executed it.');
      actions.push('Block identified IOCs at network perimeter.');
      actions.push('Scan environment for related indicators of compromise.');
      actions.push('Review network logs for communication with identified C2 infrastructure.');
      actions.push('Consider engaging incident response team for further investigation.');
      break;

    case ThreatLevel.Medium:
      actions.push('Quarantine the file for further analysis.');
      actions.push('Monitor systems that have been exposed to the file.');
      actions.push('Add identified IOCs to monitoring watchlists.');
      actions.push('Review user activity around the time of submission.');
      break;

    case ThreatLevel.Low:
      actions.push('Add the file hash to monitoring watchlists.');
      actions.push('Review the submission context (source, delivery method).');
      actions.push('No immediate remediation action required.');
      break;

    case ThreatLevel.Informational:
      actions.push('No action required. File appears benign.');
      actions.push('Retain report for reference if future analysis is needed.');
      break;
  }

  // Add IOC-specific actions
  if (report.iocs.length > 0) {
    const domains = report.iocs.filter((i) => i.type === 'domain');
    const ips = report.iocs.filter((i) => i.type === 'ip' || i.type === 'ipv6');
    if (domains.length > 0 || ips.length > 0) {
      actions.push(
        `Update network blocklists with ${domains.length} domain(s) and ${ips.length} IP address(es) identified in analysis.`,
      );
    }
  }

  return actions;
}
