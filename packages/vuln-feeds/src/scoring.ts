// ── Risk scoring: EPSS-amplified, KEV-floored, age-decayed, 0-1000 scale ────
import { RISK_CEILING, KEV_MIN_SCORE } from './config.js';

// ── Types ───────────────────────────────────────────────────────────────────

export interface CveFinding {
  score: number | null;
  severity: string | null;
  epssPercentile: number | null;
  isKev: boolean;
  publishedDate: string | null; // ISO 8601 or null
}

export type Grade = 'A' | 'B' | 'C' | 'D' | 'F';

export interface RiskResult {
  rawTotal: number;
  riskPct: number;
  reportedScore: number; // 0-1000
  grade: Grade;
  perCveScores: number[];
}

// ── Severity fallback map ───────────────────────────────────────────────────

const SEVERITY_POINTS: Record<string, number> = {
  CRITICAL: 90,
  HIGH: 65,
  MEDIUM: 40,
  LOW: 10,
};

// ── Age decay ───────────────────────────────────────────────────────────────

function ageDecay(publishedDate: string | null): number {
  if (!publishedDate) return 1.0;

  const published = new Date(publishedDate);
  if (isNaN(published.getTime())) return 1.0;

  const now = new Date();
  const ageYears = (now.getTime() - published.getTime()) / (365.25 * 24 * 3600 * 1000);

  if (ageYears < 1) return 0.90;
  if (ageYears < 2) return 0.75;
  if (ageYears < 3) return 0.60;
  if (ageYears < 5) return 0.45;
  return 0.30;
}

// ── Per-CVE score ───────────────────────────────────────────────────────────

export function scoreCve(finding: CveFinding): number {
  // Base points
  let basePoints: number;
  if (finding.score !== null && finding.score !== undefined && !isNaN(finding.score)) {
    basePoints = finding.score * 10;
  } else {
    const sev = (finding.severity ?? '').toUpperCase();
    basePoints = SEVERITY_POINTS[sev] ?? 40; // default to MEDIUM
  }

  // Amplifier
  let amplifier: number;
  if (finding.isKev) {
    amplifier = 5.0;
  } else if (finding.epssPercentile !== null && finding.epssPercentile !== undefined) {
    if (finding.epssPercentile >= 0.95) {
      amplifier = 4.0;
    } else if (finding.epssPercentile >= 0.75) {
      amplifier = 2.5;
    } else if (finding.epssPercentile >= 0.50) {
      amplifier = 1.5;
    } else if (finding.epssPercentile >= 0.25) {
      amplifier = 1.0;
    } else {
      // EPSS percentile < 0.25 and NOT KEV — use age decay
      amplifier = ageDecay(finding.publishedDate);
    }
  } else {
    // No EPSS data
    amplifier = 1.0;
  }

  let perCveScore = basePoints * amplifier;

  // KEV floor
  if (finding.isKev) {
    perCveScore = Math.max(perCveScore, KEV_MIN_SCORE);
  }

  return perCveScore;
}

// ── Aggregate scoring ───────────────────────────────────────────────────────

function gradeFromPct(pct: number): Grade {
  if (pct < 15) return 'A';
  if (pct < 30) return 'B';
  if (pct < 50) return 'C';
  if (pct < 70) return 'D';
  return 'F';
}

export function scoreFindings(findings: CveFinding[]): RiskResult {
  const perCveScores = findings.map(scoreCve);
  const rawTotal = perCveScores.reduce((sum, s) => sum + s, 0);

  let riskPct = Math.min(rawTotal / RISK_CEILING, 1.0) * 100;
  const reportedScore = Math.min(rawTotal / RISK_CEILING, 1.0) * 1000;

  // If any KEV finding exists, force minimum grade D (risk_pct >= 50)
  const hasKev = findings.some(f => f.isKev);
  if (hasKev) {
    riskPct = Math.max(riskPct, 50);
  }

  const grade = gradeFromPct(riskPct);

  return {
    rawTotal,
    riskPct,
    reportedScore: Math.round(reportedScore),
    grade,
    perCveScores,
  };
}
