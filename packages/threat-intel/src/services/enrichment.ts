import type { Pool } from 'pg';
import type { ThreatIntelResult, ThreatLevel } from '@scanboy/shared';
import { threatLevelFromScore } from '@scanboy/shared';
import type { Logger } from 'pino';
import { BaseThreatIntelProvider } from '../providers/base.js';
import { VirusTotalProvider } from '../providers/virustotal.js';
import { MalwareBazaarProvider } from '../providers/malwarebazaar.js';
import { OTXProvider } from '../providers/otx.js';
import { AbuseIPDBProvider } from '../providers/abuseipdb.js';
import { URLhausProvider } from '../providers/urlhaus.js';

/** Consensus verdict aggregated from all provider results. */
export interface EnrichmentVerdict {
  knownMalware: boolean;
  malwareFamily: string | null;
  threatLevel: ThreatLevel;
  threatScore: number;
  positiveProviders: number;
  totalProviders: number;
  results: ThreatIntelResult[];
}

/** Weights used when computing a consensus score from providers. */
const PROVIDER_WEIGHTS: Record<string, number> = {
  VirusTotal: 40,
  MalwareBazaar: 25,
  'AlienVault OTX': 15,
  AbuseIPDB: 10,
  URLhaus: 10,
};

/**
 * Orchestrates all configured threat intelligence providers, runs them in
 * parallel, aggregates their results, and stores them in PostgreSQL.
 */
export class EnrichmentService {
  private readonly providers: BaseThreatIntelProvider[];
  private readonly db: Pool;
  private readonly log: Logger;

  constructor(db: Pool, log: Logger) {
    this.db = db;
    this.log = log.child({ service: 'enrichment' });

    // Instantiate all providers; only configured ones will be used
    this.providers = [
      new VirusTotalProvider(),
      new MalwareBazaarProvider(),
      new OTXProvider(),
      new AbuseIPDBProvider(),
      new URLhausProvider(),
    ];
  }

  /** Returns the subset of providers that are configured. */
  getConfiguredProviders(): BaseThreatIntelProvider[] {
    return this.providers.filter((p) => p.isConfigured());
  }

  /**
   * Enrich a submission by hash.
   * Runs all configured providers in parallel, aggregates results, and stores them.
   */
  async enrichByHash(hash: string, submissionId: string): Promise<EnrichmentVerdict> {
    const configured = this.getConfiguredProviders();
    this.log.info({ hash, submissionId, providers: configured.map((p) => p.name) }, 'Starting hash enrichment');

    const settled = await Promise.allSettled(
      configured.map((provider) =>
        provider.lookup(hash, submissionId).catch((err: unknown) => {
          this.log.warn({ provider: provider.name, err }, 'Provider lookup failed');
          return null;
        }),
      ),
    );

    const results = this.collectResults(settled);
    const verdict = this.computeVerdict(results);

    await this.storeResults(results);

    this.log.info(
      { submissionId, positiveProviders: verdict.positiveProviders, totalProviders: verdict.totalProviders, score: verdict.threatScore },
      'Hash enrichment complete',
    );

    return verdict;
  }

  /**
   * Enrich a submission by URL.
   */
  async enrichByUrl(url: string, submissionId: string): Promise<EnrichmentVerdict> {
    const configured = this.getConfiguredProviders();
    this.log.info({ url, submissionId, providers: configured.map((p) => p.name) }, 'Starting URL enrichment');

    const settled = await Promise.allSettled(
      configured.map((provider) =>
        provider.lookupUrl(url, submissionId).catch((err: unknown) => {
          this.log.warn({ provider: provider.name, err }, 'Provider URL lookup failed');
          return null;
        }),
      ),
    );

    const results = this.collectResults(settled);
    const verdict = this.computeVerdict(results);

    await this.storeResults(results);
    return verdict;
  }

  /**
   * Enrich a submission by IP address.
   */
  async enrichByIp(ip: string, submissionId: string): Promise<EnrichmentVerdict> {
    const configured = this.getConfiguredProviders();
    this.log.info({ ip, submissionId, providers: configured.map((p) => p.name) }, 'Starting IP enrichment');

    const settled = await Promise.allSettled(
      configured.map((provider) =>
        provider.lookupIp(ip, submissionId).catch((err: unknown) => {
          this.log.warn({ provider: provider.name, err }, 'Provider IP lookup failed');
          return null;
        }),
      ),
    );

    const results = this.collectResults(settled);
    const verdict = this.computeVerdict(results);

    await this.storeResults(results);
    return verdict;
  }

  /**
   * Enrich a submission by domain.
   */
  async enrichByDomain(domain: string, submissionId: string): Promise<EnrichmentVerdict> {
    const configured = this.getConfiguredProviders();
    this.log.info({ domain, submissionId, providers: configured.map((p) => p.name) }, 'Starting domain enrichment');

    const settled = await Promise.allSettled(
      configured.map((provider) =>
        provider.lookupDomain(domain, submissionId).catch((err: unknown) => {
          this.log.warn({ provider: provider.name, err }, 'Provider domain lookup failed');
          return null;
        }),
      ),
    );

    const results = this.collectResults(settled);
    const verdict = this.computeVerdict(results);

    await this.storeResults(results);
    return verdict;
  }

  // ── Private helpers ───────────────────────────────────────────────────

  /** Extract fulfilled, non-null ThreatIntelResults from settled promises. */
  private collectResults(settled: PromiseSettledResult<ThreatIntelResult | null>[]): ThreatIntelResult[] {
    const results: ThreatIntelResult[] = [];
    for (const outcome of settled) {
      if (outcome.status === 'fulfilled' && outcome.value !== null) {
        results.push(outcome.value);
      }
    }
    return results;
  }

  /**
   * Compute a consensus verdict from all provider results.
   *
   * The score is a weighted average: each provider that flagged the sample as
   * malicious contributes its weight towards a 0-100 composite score. The
   * weights are normalised to the set of providers that actually returned data.
   */
  private computeVerdict(results: ThreatIntelResult[]): EnrichmentVerdict {
    if (results.length === 0) {
      return {
        knownMalware: false,
        malwareFamily: null,
        threatLevel: threatLevelFromScore(0),
        threatScore: 0,
        positiveProviders: 0,
        totalProviders: 0,
        results,
      };
    }

    // Calculate weighted score
    let totalWeight = 0;
    let positiveWeight = 0;
    let positiveProviders = 0;

    for (const result of results) {
      const weight = PROVIDER_WEIGHTS[result.source] ?? 10;
      totalWeight += weight;
      if (result.knownMalware) {
        positiveWeight += weight;
        positiveProviders++;
      }
    }

    // Normalise to 0-100
    const rawScore = totalWeight > 0 ? (positiveWeight / totalWeight) * 100 : 0;
    const threatScore = Math.round(rawScore);

    // Determine malware family by consensus (most frequently reported)
    const familyCounts = new Map<string, number>();
    for (const result of results) {
      if (result.malwareFamily) {
        const family = result.malwareFamily.toLowerCase();
        familyCounts.set(family, (familyCounts.get(family) ?? 0) + 1);
      }
    }

    let malwareFamily: string | null = null;
    let maxCount = 0;
    for (const [family, count] of familyCounts) {
      if (count > maxCount) {
        maxCount = count;
        malwareFamily = family;
      }
    }

    return {
      knownMalware: positiveProviders > 0,
      malwareFamily,
      threatLevel: threatLevelFromScore(threatScore),
      threatScore,
      positiveProviders,
      totalProviders: results.length,
      results,
    };
  }

  /** Persist each ThreatIntelResult row to the database. */
  private async storeResults(results: ThreatIntelResult[]): Promise<void> {
    if (results.length === 0) return;

    const query = `
      INSERT INTO threat_intel_results (
        submission_id, provider, verdict, detection_count, total_engines,
        malware_family, first_seen, raw_response
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      ON CONFLICT DO NOTHING
    `;

    for (const result of results) {
      try {
        let detections = result.detectionCount ?? 0;
        let total = result.totalEngines ?? 0;
        if (result.detectionRatio) {
          const m = result.detectionRatio.match(/^(\d+)\/(\d+)$/);
          if (m) { detections = parseInt(m[1]!, 10); total = parseInt(m[2]!, 10); }
        }
        const verdict = result.knownMalware ? 'malicious' : 'clean';
        await this.db.query(query, [
          result.submissionId,
          result.source,
          verdict,
          detections,
          total,
          result.malwareFamily,
          result.firstSeenAt,
          JSON.stringify(result.rawResponse),
        ]);
      } catch (err: unknown) {
        this.log.error({ source: result.source, err }, 'Failed to store threat intel result');
      }
    }
  }
}
