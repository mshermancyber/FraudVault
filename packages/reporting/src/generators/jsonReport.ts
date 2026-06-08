import type {
  AnalysisReport,
  Submission,
  ThreatIntelResult,
  StaticAnalysisResult,
  DynamicAnalysisResult,
  IOC,
  ATTACKTechnique,
  YaraMatch,
  ThreatLevel,
} from '@scanboy/shared';

// ── Types ──────────────────────────────────────────────────────────────────

export interface JsonReport {
  reportVersion: string;
  generatedAt: string;

  submission: {
    id: string;
    fileName: string;
    fileSize: number;
    mimeType: string;
    submittedAt: string;
    completedAt: string | null;
  };

  hashes: {
    md5: string;
    sha1: string;
    sha256: string;
    ssdeep: string | null;
  };

  threatAssessment: {
    threatLevel: ThreatLevel;
    threatScore: number;
    summary: string;
  };

  threatIntel: ThreatIntelSummary[];

  staticAnalysis: StaticAnalysisSummary | null;

  dynamicAnalysis: DynamicAnalysisSummary | null;

  iocs: IOCSummary[];

  attackTechniques: ATTACKTechniqueSummary[];

  yaraMatches: YaraMatchSummary[];

  scoreBreakdown: ScoreBreakdown;
}

export interface ThreatIntelSummary {
  source: string;
  knownMalware: boolean;
  malwareFamily: string | null;
  detectionRatio: string | null;
  communityScore: number | null;
  tags: string[];
}

export interface StaticAnalysisSummary {
  fileType: string;
  entropy: number;
  isPacked: boolean;
  packerName: string | null;
  importCount: number;
  exportCount: number;
  sectionCount: number;
  suspiciousStringsCount: number;
  certificateCount: number;
  iocCount: number;
}

export interface DynamicAnalysisSummary {
  processesCreated: number;
  networkConnections: number;
  filesModified: number;
  registryModifications: number;
  mutexesCreated: number;
  behaviorTags: string[];
  iocCount: number;
}

export interface IOCSummary {
  type: string;
  value: string;
  confidence: number;
  source: string;
  context: string | null;
}

export interface ATTACKTechniqueSummary {
  techniqueId: string;
  name: string;
  tactic: string;
  confidence: number;
}

export interface YaraMatchSummary {
  ruleName: string;
  category: string;
  matchedStrings: string[];
}

export interface ScoreBreakdown {
  totalScore: number;
  components: ScoreComponent[];
}

export interface ScoreComponent {
  name: string;
  score: number;
  maxScore: number;
  details: string;
}

// ── Generator ──────────────────────────────────────────────────────────────

export function generateJsonReport(report: AnalysisReport): JsonReport {
  return {
    reportVersion: '1.0.0',
    generatedAt: new Date().toISOString(),

    submission: buildSubmissionSection(report.submission),
    hashes: buildHashesSection(report.submission),
    threatAssessment: buildThreatAssessment(report),
    threatIntel: buildThreatIntelSection(report.threatIntel),
    staticAnalysis: buildStaticAnalysisSection(report.staticAnalysis),
    dynamicAnalysis: buildDynamicAnalysisSection(report.dynamicAnalysis),
    iocs: buildIOCSection(report.iocs),
    attackTechniques: buildATTACKSection(report.attackTechniques),
    yaraMatches: buildYaraSection(report.yaraMatches),
    scoreBreakdown: buildScoreBreakdown(report),
  };
}

function buildSubmissionSection(submission: Submission) {
  return {
    id: submission.id,
    fileName: submission.fileName,
    fileSize: submission.fileSize,
    mimeType: submission.mimeType,
    submittedAt: submission.submittedAt,
    completedAt: submission.completedAt,
  };
}

function buildHashesSection(submission: Submission) {
  return {
    md5: submission.md5,
    sha1: submission.sha1,
    sha256: submission.sha256,
    ssdeep: submission.ssdeep,
  };
}

function buildThreatAssessment(report: AnalysisReport) {
  return {
    threatLevel: report.threatLevel,
    threatScore: report.threatScore,
    summary: report.summary,
  };
}

function buildThreatIntelSection(results: ThreatIntelResult[]): ThreatIntelSummary[] {
  return results.map((r) => ({
    source: r.source,
    knownMalware: r.knownMalware,
    malwareFamily: r.malwareFamily,
    detectionRatio: r.detectionRatio,
    communityScore: r.communityScore,
    tags: r.tags,
  }));
}

function buildStaticAnalysisSection(
  result: StaticAnalysisResult | null,
): StaticAnalysisSummary | null {
  if (!result) return null;
  return {
    fileType: result.fileType,
    entropy: result.entropy,
    isPacked: result.isPacked,
    packerName: result.packerName,
    importCount: result.imports.length,
    exportCount: result.exports.length,
    sectionCount: result.sections.length,
    suspiciousStringsCount: result.strings.filter((s) => s.category !== null).length,
    certificateCount: result.certificates.length,
    iocCount: result.iocs.length,
  };
}

function buildDynamicAnalysisSection(
  result: DynamicAnalysisResult | null,
): DynamicAnalysisSummary | null {
  if (!result) return null;
  return {
    processesCreated: result.processesCreated.length,
    networkConnections: result.networkConnections.length,
    filesModified: result.filesModified.length,
    registryModifications: result.registryModifications.length,
    mutexesCreated: result.mutexesCreated.length,
    behaviorTags: result.behaviorTags,
    iocCount: result.iocs.length,
  };
}

function buildIOCSection(iocs: IOC[]): IOCSummary[] {
  return iocs.map((ioc) => ({
    type: ioc.type,
    value: ioc.value,
    confidence: ioc.confidence,
    source: ioc.source,
    context: ioc.context,
  }));
}

function buildATTACKSection(techniques: ATTACKTechnique[]): ATTACKTechniqueSummary[] {
  return techniques.map((t) => ({
    techniqueId: t.techniqueId,
    name: t.name,
    tactic: t.tactic,
    confidence: t.confidence,
  }));
}

function buildYaraSection(matches: YaraMatch[]): YaraMatchSummary[] {
  return matches.map((m) => ({
    ruleName: m.ruleName,
    category: m.category,
    matchedStrings: m.matchedStrings,
  }));
}

function buildScoreBreakdown(report: AnalysisReport): ScoreBreakdown {
  const components: ScoreComponent[] = [];

  // Threat intel component
  const tiScore = report.threatIntel.some((ti) => ti.knownMalware) ? 30 : 0;
  components.push({
    name: 'Threat Intelligence',
    score: tiScore,
    maxScore: 30,
    details: report.threatIntel.some((ti) => ti.knownMalware)
      ? `Known malware detected by ${report.threatIntel.filter((ti) => ti.knownMalware).length} source(s)`
      : 'No known malware signatures found',
  });

  // Static analysis component
  let staticScore = 0;
  if (report.staticAnalysis) {
    if (report.staticAnalysis.isPacked) staticScore += 5;
    // Entropy: >7.9 near-random (encrypted/packed), >7.7 elevated. Normal PEs sit 7.0-7.7.
    if (report.staticAnalysis.entropy > 7.9) staticScore += 5;
    else if (report.staticAnalysis.entropy > 7.7) staticScore += 3;
    staticScore += Math.min(report.staticAnalysis.iocs.length * 2, 10);
  }
  components.push({
    name: 'Static Analysis',
    score: staticScore,
    maxScore: 20,
    details: report.staticAnalysis
      ? `${report.staticAnalysis.iocs.length} IOCs extracted, entropy: ${report.staticAnalysis.entropy.toFixed(2)}`
      : 'No static analysis performed',
  });

  // Dynamic analysis component
  let dynamicScore = 0;
  if (report.dynamicAnalysis) {
    dynamicScore += Math.min(report.dynamicAnalysis.networkConnections.length * 2, 10);
    dynamicScore += Math.min(report.dynamicAnalysis.registryModifications.length, 5);
    dynamicScore += Math.min(report.dynamicAnalysis.iocs.length * 2, 10);
  }
  components.push({
    name: 'Dynamic Analysis',
    score: Math.min(dynamicScore, 25),
    maxScore: 25,
    details: report.dynamicAnalysis
      ? `${report.dynamicAnalysis.networkConnections.length} network connections, ${report.dynamicAnalysis.iocs.length} IOCs`
      : 'No dynamic analysis performed',
  });

  // YARA matches component
  const yaraScore = Math.min(report.yaraMatches.length * 5, 15);
  components.push({
    name: 'YARA Rules',
    score: yaraScore,
    maxScore: 15,
    details:
      report.yaraMatches.length > 0
        ? `${report.yaraMatches.length} rule(s) matched`
        : 'No YARA rule matches',
  });

  // ATT&CK techniques component
  const attackScore = Math.min(report.attackTechniques.length * 2, 10);
  components.push({
    name: 'ATT&CK Techniques',
    score: attackScore,
    maxScore: 10,
    details:
      report.attackTechniques.length > 0
        ? `${report.attackTechniques.length} technique(s) identified`
        : 'No ATT&CK techniques identified',
  });

  const totalScore = components.reduce((sum, c) => sum + c.score, 0);

  return { totalScore, components };
}
