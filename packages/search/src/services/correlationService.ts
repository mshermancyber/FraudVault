import type { Client } from '@elastic/elasticsearch';
import { INDEX_SUBMISSIONS, INDEX_IOCS, INDEX_NETWORK_ACTIVITY } from '../elasticsearch.js';

// ── Types ──────────────────────────────────────────────────────────────────

export interface CorrelationResult {
  submissionId: string;
  fileName: string;
  threatLevel: string | null;
  threatScore: number | null;
  correlationType: CorrelationType;
  correlationScore: number;
  sharedIndicators: string[];
}

export type CorrelationType = 'ioc' | 'behavioral' | 'network' | 'family';

export interface CorrelationResponse {
  sourceSubmissionId: string;
  correlations: CorrelationResult[];
  totalCorrelated: number;
}

// ── Service ────────────────────────────────────────────────────────────────

export class CorrelationService {
  constructor(private readonly es: Client) {}

  async correlate(submissionId: string): Promise<CorrelationResponse> {
    const [iocCorrelations, behavioralCorrelations, networkCorrelations, familyCorrelations] =
      await Promise.all([
        this.correlateByIOC(submissionId),
        this.correlateByBehavior(submissionId),
        this.correlateByNetwork(submissionId),
        this.correlateByFamily(submissionId),
      ]);

    // Merge correlations, keeping highest score per submission
    const merged = new Map<string, CorrelationResult>();

    for (const correlations of [
      iocCorrelations,
      behavioralCorrelations,
      networkCorrelations,
      familyCorrelations,
    ]) {
      for (const c of correlations) {
        const existing = merged.get(c.submissionId);
        if (!existing || c.correlationScore > existing.correlationScore) {
          merged.set(c.submissionId, c);
        }
      }
    }

    // Remove self-correlation
    merged.delete(submissionId);

    const correlations = Array.from(merged.values()).sort(
      (a, b) => b.correlationScore - a.correlationScore,
    );

    return {
      sourceSubmissionId: submissionId,
      correlations: correlations.slice(0, 50),
      totalCorrelated: correlations.length,
    };
  }

  /**
   * IOC correlation: find submissions sharing common IOCs.
   */
  private async correlateByIOC(submissionId: string): Promise<CorrelationResult[]> {
    // Step 1: Get IOCs for this submission
    const iocResponse = await this.es.search({
      index: INDEX_IOCS,
      body: {
        query: { term: { submissionId } },
        size: 500,
        _source: ['value', 'type'],
      },
    });

    const iocValues = iocResponse.hits.hits.map(
      (hit) => (hit._source as Record<string, unknown>)['value'] as string,
    );

    if (iocValues.length === 0) return [];

    // Step 2: Find other submissions sharing these IOCs
    const correlatedResponse = await this.es.search({
      index: INDEX_IOCS,
      body: {
        query: {
          bool: {
            must: [{ terms: { 'value.keyword': iocValues } }],
            must_not: [{ term: { submissionId } }],
          },
        },
        size: 0,
        aggs: {
          by_submission: {
            terms: { field: 'submissionId', size: 100 },
            aggs: {
              shared_iocs: {
                terms: { field: 'value.keyword', size: 50 },
              },
            },
          },
        },
      },
    });

    const aggs = correlatedResponse.aggregations as Record<string, unknown> | undefined;
    if (!aggs) return [];

    type IOCBucket = {
      key: string;
      doc_count: number;
      shared_iocs: { buckets: Array<{ key: string }> };
    };

    const buckets = (aggs['by_submission'] as { buckets?: IOCBucket[] })?.buckets ?? [];

    // Step 3: Enrich with submission details
    return this.enrichCorrelations(
      buckets.map((b) => ({
        submissionId: b.key,
        score: Math.min(b.doc_count / iocValues.length, 1.0),
        indicators: b.shared_iocs.buckets.map((ib) => ib.key),
        type: 'ioc' as CorrelationType,
      })),
    );
  }

  /**
   * Behavioral correlation: find submissions with similar ATT&CK techniques.
   */
  private async correlateByBehavior(submissionId: string): Promise<CorrelationResult[]> {
    // Get the source submission's ATT&CK techniques
    const sourceResponse = await this.es.search({
      index: INDEX_SUBMISSIONS,
      body: {
        query: { term: { id: submissionId } },
        size: 1,
        _source: ['attackTechniques'],
      },
    });

    const sourceHit = sourceResponse.hits.hits[0];
    if (!sourceHit) return [];

    const techniques =
      ((sourceHit._source as Record<string, unknown>)['attackTechniques'] as string[]) ?? [];

    if (techniques.length === 0) return [];

    // Find submissions sharing ATT&CK techniques
    const correlatedResponse = await this.es.search({
      index: INDEX_SUBMISSIONS,
      body: {
        query: {
          bool: {
            must: [{ terms: { attackTechniques: techniques } }],
            must_not: [{ term: { id: submissionId } }],
          },
        },
        size: 50,
        _source: ['id', 'fileName', 'threatLevel', 'threatScore', 'attackTechniques'],
      },
    });

    return correlatedResponse.hits.hits.map((hit) => {
      const source = hit._source as Record<string, unknown>;
      const hitTechniques = (source['attackTechniques'] as string[]) ?? [];
      const shared = hitTechniques.filter((t) => techniques.includes(t));

      return {
        submissionId: source['id'] as string,
        fileName: source['fileName'] as string,
        threatLevel: (source['threatLevel'] as string) ?? null,
        threatScore: (source['threatScore'] as number) ?? null,
        correlationType: 'behavioral' as CorrelationType,
        correlationScore: shared.length / techniques.length,
        sharedIndicators: shared,
      };
    });
  }

  /**
   * Network pattern correlation: find submissions contacting the same C2 domains/IPs.
   */
  private async correlateByNetwork(submissionId: string): Promise<CorrelationResult[]> {
    // Get network destinations for this submission
    const netResponse = await this.es.search({
      index: INDEX_NETWORK_ACTIVITY,
      body: {
        query: { term: { submissionId } },
        size: 0,
        aggs: {
          destinations: {
            terms: { field: 'destinationAddress', size: 200 },
          },
          domains: {
            terms: { field: 'domain.keyword', size: 200 },
          },
        },
      },
    });

    const netAggs = netResponse.aggregations as Record<string, unknown> | undefined;
    if (!netAggs) return [];

    type SimpleBucket = { key: string };

    const destIPs =
      (netAggs['destinations'] as { buckets?: SimpleBucket[] })?.buckets?.map((b) => b.key) ?? [];
    const domains =
      (netAggs['domains'] as { buckets?: SimpleBucket[] })?.buckets?.map((b) => b.key) ?? [];

    const allIndicators = [...destIPs, ...domains].filter(Boolean);
    if (allIndicators.length === 0) return [];

    // Find submissions with overlapping network destinations
    const should = [];
    if (destIPs.length > 0) {
      should.push({ terms: { destinationAddress: destIPs } });
    }
    if (domains.length > 0) {
      should.push({ terms: { 'domain.keyword': domains } });
    }

    const correlatedResponse = await this.es.search({
      index: INDEX_NETWORK_ACTIVITY,
      body: {
        query: {
          bool: {
            should,
            minimum_should_match: 1,
            must_not: [{ term: { submissionId } }],
          },
        },
        size: 0,
        aggs: {
          by_submission: {
            terms: { field: 'submissionId', size: 100 },
            aggs: {
              shared_destinations: {
                terms: { field: 'destinationAddress', size: 50 },
              },
              shared_domains: {
                terms: { field: 'domain.keyword', size: 50 },
              },
            },
          },
        },
      },
    });

    const corrAggs = correlatedResponse.aggregations as Record<string, unknown> | undefined;
    if (!corrAggs) return [];

    type NetBucket = {
      key: string;
      doc_count: number;
      shared_destinations: { buckets: SimpleBucket[] };
      shared_domains: { buckets: SimpleBucket[] };
    };

    const buckets = (corrAggs['by_submission'] as { buckets?: NetBucket[] })?.buckets ?? [];

    return this.enrichCorrelations(
      buckets.map((b) => {
        const sharedDests = b.shared_destinations.buckets.map((ib) => ib.key);
        const sharedDoms = b.shared_domains.buckets.map((ib) => ib.key);
        const shared = [...sharedDests, ...sharedDoms];

        return {
          submissionId: b.key,
          score: Math.min(shared.length / allIndicators.length, 1.0),
          indicators: shared,
          type: 'network' as CorrelationType,
        };
      }),
    );
  }

  /**
   * Family correlation: find submissions in the same malware family.
   */
  private async correlateByFamily(submissionId: string): Promise<CorrelationResult[]> {
    // Get the source submission's malware family
    const sourceResponse = await this.es.search({
      index: INDEX_SUBMISSIONS,
      body: {
        query: { term: { id: submissionId } },
        size: 1,
        _source: ['malwareFamily'],
      },
    });

    const sourceHit = sourceResponse.hits.hits[0];
    if (!sourceHit) return [];

    const family = (sourceHit._source as Record<string, unknown>)['malwareFamily'] as
      | string
      | null;
    if (!family) return [];

    // Find other submissions with the same family
    const correlatedResponse = await this.es.search({
      index: INDEX_SUBMISSIONS,
      body: {
        query: {
          bool: {
            must: [{ term: { malwareFamily: family } }],
            must_not: [{ term: { id: submissionId } }],
          },
        },
        size: 50,
        _source: ['id', 'fileName', 'threatLevel', 'threatScore'],
      },
    });

    return correlatedResponse.hits.hits.map((hit) => {
      const source = hit._source as Record<string, unknown>;
      return {
        submissionId: source['id'] as string,
        fileName: source['fileName'] as string,
        threatLevel: (source['threatLevel'] as string) ?? null,
        threatScore: (source['threatScore'] as number) ?? null,
        correlationType: 'family' as CorrelationType,
        correlationScore: 0.9, // Family match is a strong signal
        sharedIndicators: [family],
      };
    });
  }

  /**
   * Enrich raw correlation data with submission details.
   */
  private async enrichCorrelations(
    raw: Array<{
      submissionId: string;
      score: number;
      indicators: string[];
      type: CorrelationType;
    }>,
  ): Promise<CorrelationResult[]> {
    if (raw.length === 0) return [];

    const ids = raw.map((r) => r.submissionId);

    const detailsResponse = await this.es.search({
      index: INDEX_SUBMISSIONS,
      body: {
        query: { terms: { id: ids } },
        size: ids.length,
        _source: ['id', 'fileName', 'threatLevel', 'threatScore'],
      },
    });

    const detailsMap = new Map<string, Record<string, unknown>>();
    for (const hit of detailsResponse.hits.hits) {
      const source = hit._source as Record<string, unknown>;
      detailsMap.set(source['id'] as string, source);
    }

    return raw.map((r) => {
      const details = detailsMap.get(r.submissionId);
      return {
        submissionId: r.submissionId,
        fileName: (details?.['fileName'] as string) ?? 'unknown',
        threatLevel: (details?.['threatLevel'] as string) ?? null,
        threatScore: (details?.['threatScore'] as number) ?? null,
        correlationType: r.type,
        correlationScore: r.score,
        sharedIndicators: r.indicators,
      };
    });
  }
}
