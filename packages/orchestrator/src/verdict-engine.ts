// ── Confidence-Rated Verdicts with Evidence Chains ──────────────────────────
//
// Replaces simple numeric scoring with a structured verdict that includes:
// - Weighted evidence aggregation from all analysis sources
// - Confidence rating indicating how certain the classification is
// - Evidence chain showing the reasoning behind the verdict
// - Recommended actions based on classification + confidence

// ── Types ───────────────────────────────────────────────────────────────────

export type Classification = 'malicious' | 'suspicious' | 'benign' | 'inconclusive';
export type RecommendedAction = 'Block' | 'Quarantine' | 'Monitor' | 'Allow';

export interface EvidenceItem {
  source: string;
  finding: string;
  weight: number;
  confidence: number;
  details: Record<string, unknown>;
}

export interface Verdict {
  classification: Classification;
  confidence: number;
  threatScore: number;
  evidenceChain: EvidenceItem[];
  summary: string;
  recommendedAction: RecommendedAction;
}

// ── Evidence Source Weights ──────────────────────────────────────────────────

/**
 * Base reliability weights for different evidence sources.
 * Higher weight = more influence on final verdict.
 */
const SOURCE_BASE_WEIGHTS: Readonly<Record<string, number>> = {
  'virustotal': 30,
  'sandbox': 25,
  'static_analysis': 15,
  'yara': 20,
  'network': 15,
  'signature': 20,
  'behavioral': 18,
  'threat_intel': 22,
  'config_extraction': 25,
  'memory_analysis': 20,
  'certificate': 12,
  'heuristic': 10,
};

// ── Classification Thresholds ───────────────────────────────────────────────

const MALICIOUS_THRESHOLD = 60;
const SUSPICIOUS_THRESHOLD = 30;
const BENIGN_CEILING = 15;

// ── Core Verdict Engine ─────────────────────────────────────────────────────

/**
 * Compute a structured verdict from a collection of evidence items.
 *
 * The algorithm:
 * 1. Normalizes evidence weights by source reliability
 * 2. Separates positive (malicious indicators) and negative (benign indicators)
 * 3. Computes weighted score incorporating confidence of each item
 * 4. Classifies based on score thresholds and evidence agreement
 * 5. Calculates overall confidence based on evidence volume and agreement
 * 6. Generates human-readable summary
 */
export function computeVerdict(evidenceItems: EvidenceItem[]): Verdict {
  if (evidenceItems.length === 0) {
    return {
      classification: 'inconclusive',
      confidence: 0,
      threatScore: 0,
      evidenceChain: [],
      summary: 'No analysis evidence available to determine classification.',
      recommendedAction: 'Monitor',
    };
  }

  // Sort evidence by effective weight (weight * confidence)
  const sortedEvidence = [...evidenceItems].sort(
    (a, b) => (b.weight * b.confidence) - (a.weight * a.confidence),
  );

  // Compute weighted threat score
  const { positiveScore, negativeScore, totalWeight } = computeWeightedScores(sortedEvidence);

  // Net score normalized to 0-100
  const rawScore = totalWeight > 0
    ? Math.round(((positiveScore - negativeScore) / totalWeight) * 100)
    : 0;
  const threatScore = Math.min(100, Math.max(0, rawScore));

  // Classify based on score and evidence patterns
  const classification = classifyFromEvidence(threatScore, sortedEvidence);

  // Compute overall confidence
  const confidence = computeOverallConfidence(sortedEvidence, classification);

  // Determine recommended action
  const recommendedAction = determineAction(classification, confidence, threatScore);

  // Generate summary
  const summary = generateSummary(classification, confidence, threatScore, sortedEvidence);

  return {
    classification,
    confidence,
    threatScore,
    evidenceChain: sortedEvidence,
    summary,
    recommendedAction,
  };
}

// ── Score Computation ───────────────────────────────────────────────────────

interface WeightedScores {
  positiveScore: number;
  negativeScore: number;
  totalWeight: number;
}

function computeWeightedScores(evidence: EvidenceItem[]): WeightedScores {
  let positiveScore = 0;
  let negativeScore = 0;
  let totalWeight = 0;

  for (const item of evidence) {
    const sourceBaseWeight = SOURCE_BASE_WEIGHTS[item.source] ?? 10;
    const effectiveWeight = (item.weight / 100) * (sourceBaseWeight / 30);
    const confidenceFactor = item.confidence / 100;

    totalWeight += Math.abs(effectiveWeight);

    if (item.weight >= 0) {
      positiveScore += effectiveWeight * confidenceFactor;
    } else {
      negativeScore += Math.abs(effectiveWeight) * confidenceFactor;
    }
  }

  return { positiveScore, negativeScore, totalWeight };
}

// ── Classification Logic ────────────────────────────────────────────────────

function classifyFromEvidence(
  threatScore: number,
  evidence: EvidenceItem[],
): Classification {
  // Strong positive signals override score-based classification
  const hasStrongPositive = evidence.some(e =>
    e.source === 'virustotal' && e.confidence >= 80 && e.weight >= 70,
  );
  // Gate on ratio >= 5%: a single 1/71 VT detection with a family name is not
  // sufficient — VT vendors emit speculative family labels at very low ratios,
  // which caused benign files (WinZip, WinRAR) to be classified as malicious.
  const hasKnownFamily = evidence.some(e =>
    e.details['malwareFamily'] !== undefined && e.details['malwareFamily'] !== null
    && e.source === 'virustotal' && (e.details['ratio'] as number ?? 0) >= 0.05,
  );
  const hasConfigExtraction = evidence.some(e =>
    e.source === 'config_extraction' && e.confidence >= 70,
  );

  // Definitive malicious: high VT ratio OR known family + behavioral evidence
  if (hasStrongPositive || (hasKnownFamily && threatScore >= 50)) {
    return 'malicious';
  }
  if (hasConfigExtraction) {
    return 'malicious';
  }

  // Strong benign signals
  const hasValidSignature = evidence.some(e =>
    e.source === 'certificate' && e.confidence >= 80 && e.weight < 0,
  );
  const hasLowVT = evidence.some(e =>
    e.source === 'virustotal' && e.weight < 20 && e.confidence >= 70,
  );

  if (hasValidSignature && hasLowVT && threatScore < SUSPICIOUS_THRESHOLD) {
    return 'benign';
  }

  // Score-based classification
  if (threatScore >= MALICIOUS_THRESHOLD) return 'malicious';
  if (threatScore >= SUSPICIOUS_THRESHOLD) return 'suspicious';
  if (threatScore <= BENIGN_CEILING) return 'benign';

  // Mixed signals
  const highConfidenceItems = evidence.filter(e => e.confidence >= 70);
  if (highConfidenceItems.length < 2) return 'inconclusive';

  const agreementRatio = computeAgreementRatio(evidence);
  if (agreementRatio < 0.5) return 'inconclusive';

  return threatScore > 20 ? 'suspicious' : 'benign';
}

function computeAgreementRatio(evidence: EvidenceItem[]): number {
  if (evidence.length === 0) return 0;

  const positive = evidence.filter(e => e.weight > 0).length;
  const negative = evidence.filter(e => e.weight < 0).length;
  const total = positive + negative;

  if (total === 0) return 0;
  return Math.max(positive, negative) / total;
}

// ── Confidence Computation ──────────────────────────────────────────────────

function computeOverallConfidence(
  evidence: EvidenceItem[],
  classification: Classification,
): number {
  if (evidence.length === 0) return 0;

  // Factor 1: Volume of evidence (more sources = higher confidence)
  const uniqueSources = new Set(evidence.map(e => e.source));
  const volumeFactor = Math.min(uniqueSources.size / 5, 1.0); // Max at 5 sources

  // Factor 2: Agreement between sources
  const agreementFactor = computeAgreementRatio(evidence);

  // Factor 3: Average confidence of individual items
  const avgItemConfidence = evidence.reduce((sum, e) => sum + e.confidence, 0) / evidence.length;

  // Factor 4: Presence of high-confidence definitive evidence
  const hasDefinitiveEvidence = evidence.some(e => e.confidence >= 90 && Math.abs(e.weight) >= 70);
  const definitiveFactor = hasDefinitiveEvidence ? 1.2 : 1.0;

  // Combined confidence
  let confidence = (
    (volumeFactor * 25) +
    (agreementFactor * 30) +
    (avgItemConfidence * 0.35) +
    (hasDefinitiveEvidence ? 10 : 0)
  ) * definitiveFactor;

  // Inconclusive classification inherently has lower confidence
  if (classification === 'inconclusive') {
    confidence = Math.min(confidence, 40);
  }

  return Math.min(100, Math.max(0, Math.round(confidence)));
}

// ── Action Determination ────────────────────────────────────────────────────

function determineAction(
  classification: Classification,
  confidence: number,
  threatScore: number,
): RecommendedAction {
  switch (classification) {
    case 'malicious':
      if (confidence >= 80 || threatScore >= 90) return 'Block';
      if (confidence >= 50) return 'Quarantine';
      return 'Monitor';

    case 'suspicious':
      if (confidence >= 70 && threatScore >= 60) return 'Quarantine';
      return 'Monitor';

    case 'benign':
      return 'Allow';

    case 'inconclusive':
      if (threatScore >= 50) return 'Monitor';
      return 'Allow';
  }
}

// ── Summary Generation ──────────────────────────────────────────────────────

function generateSummary(
  classification: Classification,
  confidence: number,
  threatScore: number,
  evidence: EvidenceItem[],
): string {
  const confidenceLabel = confidence >= 80 ? 'high' : confidence >= 50 ? 'moderate' : 'low';

  // Find the strongest evidence item
  const strongest = evidence[0];
  const strongestDescription = strongest
    ? ` Primary evidence: ${strongest.finding}.`
    : '';

  switch (classification) {
    case 'malicious': {
      const familyEvidence = evidence.find(e => e.details['malwareFamily']);
      const family = familyEvidence
        ? ` Identified as ${String(familyEvidence.details['malwareFamily'])}.`
        : '';
      return `Malicious with ${confidenceLabel} confidence (score: ${threatScore}/100).${family}${strongestDescription}`;
    }

    case 'suspicious':
      return `Suspicious with ${confidenceLabel} confidence (score: ${threatScore}/100). Exhibits potentially malicious behavior but lacks definitive classification.${strongestDescription}`;

    case 'benign':
      return `Benign with ${confidenceLabel} confidence (score: ${threatScore}/100). No significant malicious indicators detected.`;

    case 'inconclusive':
      return `Inconclusive verdict (score: ${threatScore}/100). Insufficient or conflicting evidence to determine classification. Manual review recommended.`;
  }
}

// ── Evidence Builder Helpers ────────────────────────────────────────────────

/**
 * Create an evidence item from VirusTotal results.
 */
export function buildVtEvidence(
  detections: number,
  total: number,
  malwareFamily: string | null,
): EvidenceItem {
  const ratio = total > 0 ? detections / total : 0;
  let weight: number;
  let confidence: number;

  if (ratio > 0.5) {
    weight = 90;
    confidence = 95;
  } else if (ratio > 0.25) {
    weight = 70;
    confidence = 85;
  } else if (ratio > 0.1) {
    weight = 50;
    confidence = 70;
  } else if (ratio > 0.05) {
    weight = 30;
    confidence = 55;
  } else if (detections > 0) {
    weight = 10;
    confidence = 35;
  } else {
    weight = -20;
    confidence = 60;
  }

  return {
    source: 'virustotal',
    finding: `${detections}/${total} engines detected as malicious (${(ratio * 100).toFixed(1)}%)`,
    weight,
    confidence,
    details: {
      detections,
      total,
      ratio,
      malwareFamily,
    },
  };
}

/**
 * Create an evidence item from sandbox behavioral analysis.
 */
export function buildSandboxEvidence(
  riskScore: number,
  indicators: Array<{ category: string; severity: string; description: string }>,
  droppedFiles: number,
  networkConnections: number,
): EvidenceItem {
  const weight = Math.min(riskScore, 80);
  const confidence = indicators.length > 3 ? 80 : indicators.length > 0 ? 65 : 40;

  const criticals = indicators.filter(i => i.severity === 'critical').length;
  const highs = indicators.filter(i => i.severity === 'high').length;

  const findingParts: string[] = [];
  if (criticals > 0) findingParts.push(`${criticals} critical indicators`);
  if (highs > 0) findingParts.push(`${highs} high indicators`);
  if (droppedFiles > 0) findingParts.push(`${droppedFiles} dropped files`);
  if (networkConnections > 0) findingParts.push(`${networkConnections} network connections`);

  return {
    source: 'sandbox',
    finding: findingParts.length > 0
      ? `Behavioral analysis: ${findingParts.join(', ')}`
      : `Behavioral analysis: risk score ${riskScore}/100`,
    weight,
    confidence,
    details: {
      riskScore,
      indicatorCount: indicators.length,
      criticals,
      highs,
      droppedFiles,
      networkConnections,
    },
  };
}

/**
 * Create an evidence item from YARA rule matches.
 */
export function buildYaraEvidence(
  matchedRules: Array<{ name: string; category: string; severity: string }>,
): EvidenceItem {
  if (matchedRules.length === 0) {
    return {
      source: 'yara',
      finding: 'No YARA rules matched',
      weight: -5,
      confidence: 50,
      details: { matchCount: 0 },
    };
  }

  const criticals = matchedRules.filter(r => r.severity === 'critical');
  const highs = matchedRules.filter(r => r.severity === 'high');

  const weight = criticals.length > 0 ? 80
    : highs.length > 0 ? 60
    : Math.min(matchedRules.length * 15, 50);

  const confidence = criticals.length > 0 ? 90
    : highs.length > 0 ? 80
    : 65;

  const topRules = matchedRules.slice(0, 3).map(r => r.name).join(', ');

  return {
    source: 'yara',
    finding: `${matchedRules.length} YARA rules matched: ${topRules}`,
    weight,
    confidence,
    details: {
      matchCount: matchedRules.length,
      rules: matchedRules,
    },
  };
}

/**
 * Create an evidence item from static analysis findings.
 */
export function buildStaticEvidence(
  isPacked: boolean,
  suspiciousImports: string[],
  entropy: number,
  isObfuscated: boolean,
): EvidenceItem {
  let weight = 0;
  if (isPacked) weight += 15;
  if (isObfuscated) weight += 20;
  // Entropy: >7.9 near-random (encrypted/packed), >7.7 elevated. Normal PEs sit 7.0-7.7.
  if (entropy > 7.9) weight += 15;
  else if (entropy > 7.7) weight += 8;
  weight += Math.min(suspiciousImports.length * 5, 25);

  const confidence = weight > 30 ? 70 : weight > 15 ? 55 : 40;

  const findings: string[] = [];
  if (isPacked) findings.push('packed binary');
  if (isObfuscated) findings.push('obfuscated code');
  if (entropy > 7.7) findings.push(`high entropy (${entropy.toFixed(2)})`);
  if (suspiciousImports.length > 0) findings.push(`${suspiciousImports.length} suspicious imports`);

  return {
    source: 'static_analysis',
    finding: findings.length > 0
      ? `Static analysis: ${findings.join(', ')}`
      : 'Static analysis: no suspicious indicators',
    weight: Math.max(weight, 0),
    confidence,
    details: {
      isPacked,
      isObfuscated,
      entropy,
      suspiciousImportCount: suspiciousImports.length,
      suspiciousImports: suspiciousImports.slice(0, 10),
    },
  };
}

/**
 * Create an evidence item from a valid code signing certificate.
 */
export function buildCertificateEvidence(
  hasCertificate: boolean,
  isValidVendor: boolean,
  signer: string,
): EvidenceItem {
  if (!hasCertificate) {
    return {
      source: 'certificate',
      finding: 'No code signing certificate present',
      weight: 5,
      confidence: 50,
      details: { hasCertificate: false },
    };
  }

  if (isValidVendor) {
    return {
      source: 'certificate',
      finding: `Valid code signing certificate from known vendor: ${signer}`,
      weight: -30,
      confidence: 85,
      details: { hasCertificate: true, isValidVendor: true, signer },
    };
  }

  return {
    source: 'certificate',
    finding: `Code signing certificate present but from unknown signer: ${signer}`,
    weight: -5,
    confidence: 40,
    details: { hasCertificate: true, isValidVendor: false, signer },
  };
}

/**
 * Create an evidence item from network behavior during detonation.
 */
export function buildNetworkEvidence(
  externalConnections: number,
  dnsQueries: number,
  c2Indicators: string[],
): EvidenceItem {
  let weight = 0;
  if (c2Indicators.length > 0) weight += 40;
  if (externalConnections > 5) weight += 15;
  else if (externalConnections > 0) weight += 8;
  if (dnsQueries > 10) weight += 10;

  const confidence = c2Indicators.length > 0 ? 80 : externalConnections > 0 ? 60 : 30;

  const findings: string[] = [];
  if (c2Indicators.length > 0) findings.push(`${c2Indicators.length} C2 indicators`);
  if (externalConnections > 0) findings.push(`${externalConnections} external connections`);
  if (dnsQueries > 0) findings.push(`${dnsQueries} DNS queries`);

  return {
    source: 'network',
    finding: findings.length > 0
      ? `Network analysis: ${findings.join(', ')}`
      : 'No network activity observed',
    weight,
    confidence,
    details: {
      externalConnections,
      dnsQueries,
      c2Indicators,
    },
  };
}
