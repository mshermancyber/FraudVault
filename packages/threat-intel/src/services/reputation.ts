import type { Pool } from 'pg';
import type { ThreatIntelResult, ThreatLevel } from '@scanboy/shared';
import { threatLevelFromScore } from '@scanboy/shared';
import type { Logger } from 'pino';

/** Reputation assessment for an indicator. */
export interface ReputationScore {
  /** Composite score 0-100. */
  score: number;
  /** Mapped threat level. */
  threatLevel: ThreatLevel;
  /** Number of providers that returned data. */
  providersQueried: number;
  /** Number of providers that flagged the indicator. */
  providersFlagged: number;
  /** Per-provider breakdown. */
  breakdown: ProviderBreakdown[];
  /** Whether this indicator has been seen in previous submissions. */
  previouslySeen: boolean;
  /** Number of previous submissions that contained this indicator. */
  previousSubmissionCount: number;
}

export interface ProviderBreakdown {
  source: string;
  weight: number;
  knownMalware: boolean;
  communityScore: number | null;
  contributedPoints: number;
}

/**
 * Provider weights for reputation scoring.
 * Higher weight = more trusted provider.
 */
const PROVIDER_WEIGHTS: ReadonlyMap<string, number> = new Map([
  ['VirusTotal', 35],
  ['MalwareBazaar', 25],
  ['AlienVault OTX', 15],
  ['AbuseIPDB', 15],
  ['URLhaus', 10],
]);

const DEFAULT_WEIGHT = 10;

/**
 * Reputation scoring service.
 *
 * Computes a weighted reputation score from all available threat intel results
 * and correlates against historical submissions.
 */
export class ReputationService {
  private readonly db: Pool;
  private readonly log: Logger;

  constructor(db: Pool, log: Logger) {
    this.db = db;
    this.log = log.child({ service: 'reputation' });
  }

  /**
   * Calculate a reputation score for a submission based on stored threat intel results.
   */
  async scoreSubmission(submissionId: string): Promise<ReputationScore> {
    this.log.info({ submissionId }, 'Scoring submission reputation');
    const results = await this.fetchResults(submissionId);
    const previousCount = await this.countPreviousSubmissions(submissionId);

    const score = this.computeScore(results, previousCount);
    this.log.info({ submissionId, score: score.score, level: score.threatLevel }, 'Reputation score calculated');
    return score;
  }

  /**
   * Calculate a reputation score for an arbitrary indicator (hash, IP, domain, URL).
   * Looks up all stored results that match the indicator across any submission.
   */
  async scoreIndicator(indicatorValue: string): Promise<ReputationScore> {
    const results = await this.fetchResultsByIndicator(indicatorValue);
    return this.computeScore(results, 0);
  }

  // ── Private helpers ───────────────────────────────────────────────────

  private computeScore(
    results: ThreatIntelResult[],
    previousSubmissionCount: number,
  ): ReputationScore {
    if (results.length === 0) {
      return {
        score: 0,
        threatLevel: threatLevelFromScore(0),
        providersQueried: 0,
        providersFlagged: 0,
        breakdown: [],
        previouslySeen: previousSubmissionCount > 0,
        previousSubmissionCount,
      };
    }

    const breakdown: ProviderBreakdown[] = [];
    let totalWeight = 0;
    let weightedScore = 0;
    let providersFlagged = 0;

    for (const result of results) {
      const weight = PROVIDER_WEIGHTS.get(result.source) ?? DEFAULT_WEIGHT;
      totalWeight += weight;

      let providerScore = 0;

      if (result.knownMalware) {
        providersFlagged++;
        providerScore = weight;

        // Bonus points for detection ratio (e.g. "45/72" for VT)
        if (result.detectionRatio) {
          const ratioMatch = result.detectionRatio.match(/^(\d+)\/(\d+)$/);
          if (ratioMatch) {
            const detected = parseInt(ratioMatch[1]!, 10);
            const total = parseInt(ratioMatch[2]!, 10);
            if (total > 0) {
              const ratio = detected / total;
              // Scale the weight by detection ratio (higher ratio = more confident)
              providerScore = weight * (0.5 + 0.5 * ratio);
            }
          }
        }

        // Negative community score indicates known bad
        if (result.communityScore !== null && result.communityScore < 0) {
          providerScore *= 1.1; // 10% boost for negative community score
        }
      } else {
        // Provider returned data but did not flag -- slight negative evidence
        providerScore = 0;
      }

      weightedScore += providerScore;
      breakdown.push({
        source: result.source,
        weight,
        knownMalware: result.knownMalware,
        communityScore: result.communityScore,
        contributedPoints: Math.round(providerScore * 10) / 10,
      });
    }

    // Normalise to 0-100
    let rawScore = totalWeight > 0 ? (weightedScore / totalWeight) * 100 : 0;

    // Historical correlation boost: if the indicator was seen in previous
    // submissions that were also flagged, increase score slightly.
    if (previousSubmissionCount > 0) {
      const historyBonus = Math.min(previousSubmissionCount * 2, 10);
      rawScore = Math.min(100, rawScore + historyBonus);
    }

    const score = Math.round(Math.min(100, Math.max(0, rawScore)));

    return {
      score,
      threatLevel: threatLevelFromScore(score),
      providersQueried: results.length,
      providersFlagged,
      breakdown,
      previouslySeen: previousSubmissionCount > 0,
      previousSubmissionCount,
    };
  }

  private mapRow(row: {
    submission_id: string;
    provider: string;
    verdict: string | null;
    detection_count: number | null;
    total_engines: number | null;
    malware_family: string | null;
    first_seen: string | null;
    raw_response: string | null;
    created_at: string;
  }): ThreatIntelResult {
    const detections = row.detection_count ?? 0;
    const total = row.total_engines ?? 0;
    const isKnownMalware = detections > 0 && total > 0 && (detections / total) > 0.05;
    return {
      submissionId: row.submission_id,
      source: row.provider,
      knownMalware: isKnownMalware,
      malwareFamily: row.malware_family,
      firstSeenAt: row.first_seen,
      detectionRatio: total > 0 ? `${detections}/${total}` : null,
      communityScore: null,
      tags: [],
      rawResponse: row.raw_response ? (typeof row.raw_response === 'string' ? JSON.parse(row.raw_response) : row.raw_response) as Record<string, unknown> : {},
      queriedAt: row.created_at,
      detectionCount: row.detection_count,
      totalEngines: row.total_engines,
    };
  }

  /** Fetch all threat intel results for a submission from the database. */
  private async fetchResults(submissionId: string): Promise<ThreatIntelResult[]> {
    const { rows } = await this.db.query<{
      submission_id: string;
      provider: string;
      verdict: string | null;
      detection_count: number | null;
      total_engines: number | null;
      malware_family: string | null;
      first_seen: string | null;
      raw_response: string | null;
      created_at: string;
    }>(
      `SELECT submission_id, provider, verdict, detection_count, total_engines,
              malware_family, first_seen, raw_response, created_at
       FROM threat_intel_results
       WHERE submission_id = $1`,
      [submissionId],
    );

    return rows.map((row) => this.mapRow(row));
  }

  /** Fetch threat intel results across all submissions for a given indicator. */
  private async fetchResultsByIndicator(indicator: string): Promise<ThreatIntelResult[]> {
    const { rows } = await this.db.query<{
      submission_id: string;
      provider: string;
      verdict: string | null;
      detection_count: number | null;
      total_engines: number | null;
      malware_family: string | null;
      first_seen: string | null;
      raw_response: string | null;
      created_at: string;
    }>(
      `SELECT tir.submission_id, tir.provider, tir.verdict, tir.detection_count,
              tir.total_engines, tir.malware_family, tir.first_seen,
              tir.raw_response, tir.created_at
       FROM threat_intel_results tir
       JOIN submissions s ON s.id = tir.submission_id
       WHERE s.sha256 = $1 OR s.sha1 = $1 OR s.md5 = $1
       ORDER BY tir.created_at DESC
       LIMIT 50`,
      [indicator],
    );

    return rows.map((row) => this.mapRow(row));
  }

  /**
   * Count how many previous submissions share a hash with the given submission.
   */
  private async countPreviousSubmissions(submissionId: string): Promise<number> {
    const { rows } = await this.db.query<{ count: string }>(
      `SELECT COUNT(DISTINCT s2.id)::text AS count
       FROM submissions s1
       JOIN submissions s2 ON s2.sha256 = s1.sha256 AND s2.id != s1.id
       WHERE s1.id = $1`,
      [submissionId],
    );

    return parseInt(rows[0]?.count ?? '0', 10);
  }
}
