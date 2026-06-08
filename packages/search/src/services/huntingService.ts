import type { Client, estypes } from '@elastic/elasticsearch';
import { INDEX_SUBMISSIONS, INDEX_IOCS } from '../elasticsearch.js';

type QueryDslQueryContainer = estypes.QueryDslQueryContainer;

// ── Types ──────────────────────────────────────────────────────────────────

export interface HuntQuery {
  /** IOC values to hunt for retroactively */
  indicators?: string[];
  /** IOC types to limit the hunt to */
  indicatorTypes?: string[];
  /** Minimum number of shared indicators for campaign grouping */
  campaignThreshold?: number;
  /** Date range start */
  dateFrom?: string;
  /** Date range end */
  dateTo?: string;
  /** Maximum results */
  limit?: number;
}

export interface HuntMatch {
  submissionId: string;
  fileName: string;
  threatLevel: string | null;
  threatScore: number | null;
  matchedIndicators: string[];
  matchCount: number;
  submittedAt: string;
}

export interface CampaignCluster {
  campaignId: string;
  submissions: string[];
  sharedIndicators: string[];
  firstSeen: string;
  lastSeen: string;
  submissionCount: number;
}

export interface HuntResponse {
  matches: HuntMatch[];
  totalMatches: number;
  campaigns: CampaignCluster[];
  took: number;
}

// ── Service ────────────────────────────────────────────────────────────────

export class HuntingService {
  constructor(private readonly es: Client) {}

  /**
   * Execute a threat hunting query. Retroactively searches historical submissions
   * for the given indicators and discovers campaigns.
   */
  async hunt(query: HuntQuery): Promise<HuntResponse> {
    const startTime = Date.now();
    const limit = Math.min(query.limit ?? 100, 500);

    const matches = query.indicators && query.indicators.length > 0
      ? await this.retroactiveIOCSearch(query.indicators, query.indicatorTypes, query.dateFrom, query.dateTo, limit)
      : await this.scanNewIndicators(query.dateFrom, query.dateTo, limit);

    const campaigns =
      query.indicators && query.indicators.length > 0
        ? await this.discoverCampaigns(
            query.indicators,
            query.campaignThreshold ?? 3,
            query.dateFrom,
            query.dateTo,
          )
        : [];

    const took = Date.now() - startTime;

    return {
      matches,
      totalMatches: matches.length,
      campaigns,
      took,
    };
  }

  /**
   * Retroactive IOC search: search historical submissions for specific indicators.
   */
  private async retroactiveIOCSearch(
    indicators: string[],
    indicatorTypes: string[] | undefined,
    dateFrom: string | undefined,
    dateTo: string | undefined,
    limit: number,
  ): Promise<HuntMatch[]> {
    const must: QueryDslQueryContainer[] = [
      { terms: { 'value.keyword': indicators } },
    ];

    if (indicatorTypes && indicatorTypes.length > 0) {
      must.push({ terms: { type: indicatorTypes } });
    }

    if (dateFrom || dateTo) {
      const range: Record<string, string> = {};
      if (dateFrom) range['gte'] = dateFrom;
      if (dateTo) range['lte'] = dateTo;
      must.push({ range: { createdAt: range } });
    }

    const iocResponse = await this.es.search({
      index: INDEX_IOCS,
      body: {
        query: { bool: { must } },
        size: 0,
        aggs: {
          by_submission: {
            terms: { field: 'submissionId', size: limit },
            aggs: {
              matched_values: {
                terms: { field: 'value.keyword', size: 100 },
              },
            },
          },
        },
      },
    });

    const aggs = iocResponse.aggregations as Record<string, unknown> | undefined;
    if (!aggs) return [];

    type HuntBucket = {
      key: string;
      doc_count: number;
      matched_values: { buckets: Array<{ key: string }> };
    };

    const buckets =
      (aggs['by_submission'] as { buckets?: HuntBucket[] })?.buckets ?? [];

    if (buckets.length === 0) return [];

    // Enrich with submission details
    const submissionIds = buckets.map((b) => b.key);
    const submissionsResponse = await this.es.search({
      index: INDEX_SUBMISSIONS,
      body: {
        query: { terms: { id: submissionIds } },
        size: submissionIds.length,
        _source: ['id', 'fileName', 'threatLevel', 'threatScore', 'submittedAt'],
      },
    });

    const detailsMap = new Map<string, Record<string, unknown>>();
    for (const hit of submissionsResponse.hits.hits) {
      const source = hit._source as Record<string, unknown>;
      detailsMap.set(source['id'] as string, source);
    }

    return buckets.map((b) => {
      const details = detailsMap.get(b.key);
      const matchedIndicators = b.matched_values.buckets.map((mv) => mv.key);
      return {
        submissionId: b.key,
        fileName: (details?.['fileName'] as string) ?? 'unknown',
        threatLevel: (details?.['threatLevel'] as string) ?? null,
        threatScore: (details?.['threatScore'] as number) ?? null,
        matchedIndicators,
        matchCount: matchedIndicators.length,
        submittedAt: (details?.['submittedAt'] as string) ?? '',
      };
    });
  }

  /**
   * Scan for newly-seen indicators that appear across multiple submissions.
   * Finds IOCs that have been seen in more than one submission within the date range.
   */
  private async scanNewIndicators(
    dateFrom: string | undefined,
    dateTo: string | undefined,
    limit: number,
  ): Promise<HuntMatch[]> {
    const must: QueryDslQueryContainer[] = [];

    if (dateFrom || dateTo) {
      const range: Record<string, string> = {};
      if (dateFrom) range['gte'] = dateFrom;
      if (dateTo) range['lte'] = dateTo;
      must.push({ range: { firstSeenAt: range } });
    }

    const query: QueryDslQueryContainer =
      must.length > 0 ? { bool: { must } } : { match_all: {} };

    // Find IOCs that appear in multiple submissions
    const iocResponse = await this.es.search({
      index: INDEX_IOCS,
      body: {
        query,
        size: 0,
        aggs: {
          multi_submission_iocs: {
            terms: { field: 'value.keyword', size: 200, min_doc_count: 2 },
            aggs: {
              submissions: {
                terms: { field: 'submissionId', size: 50 },
              },
            },
          },
        },
      },
    });

    const aggs = iocResponse.aggregations as Record<string, unknown> | undefined;
    if (!aggs) return [];

    type MultiIOCBucket = {
      key: string;
      submissions: { buckets: Array<{ key: string }> };
    };

    const iocBuckets =
      (aggs['multi_submission_iocs'] as { buckets?: MultiIOCBucket[] })?.buckets ?? [];

    // Collect unique submissions with their matched indicators
    const submissionIndicators = new Map<string, Set<string>>();
    for (const bucket of iocBuckets) {
      for (const sub of bucket.submissions.buckets) {
        if (!submissionIndicators.has(sub.key)) {
          submissionIndicators.set(sub.key, new Set());
        }
        submissionIndicators.get(sub.key)!.add(bucket.key);
      }
    }

    const submissionIds = Array.from(submissionIndicators.keys()).slice(0, limit);
    if (submissionIds.length === 0) return [];

    // Enrich with details
    const submissionsResponse = await this.es.search({
      index: INDEX_SUBMISSIONS,
      body: {
        query: { terms: { id: submissionIds } },
        size: submissionIds.length,
        _source: ['id', 'fileName', 'threatLevel', 'threatScore', 'submittedAt'],
      },
    });

    const detailsMap = new Map<string, Record<string, unknown>>();
    for (const hit of submissionsResponse.hits.hits) {
      const source = hit._source as Record<string, unknown>;
      detailsMap.set(source['id'] as string, source);
    }

    return submissionIds.map((sid) => {
      const details = detailsMap.get(sid);
      const indicators = Array.from(submissionIndicators.get(sid) ?? []);
      return {
        submissionId: sid,
        fileName: (details?.['fileName'] as string) ?? 'unknown',
        threatLevel: (details?.['threatLevel'] as string) ?? null,
        threatScore: (details?.['threatScore'] as number) ?? null,
        matchedIndicators: indicators,
        matchCount: indicators.length,
        submittedAt: (details?.['submittedAt'] as string) ?? '',
      };
    });
  }

  /**
   * Discover campaigns: cluster submissions that share a threshold number of indicators.
   */
  private async discoverCampaigns(
    indicators: string[],
    threshold: number,
    dateFrom: string | undefined,
    dateTo: string | undefined,
  ): Promise<CampaignCluster[]> {
    const must: QueryDslQueryContainer[] = [
      { terms: { 'value.keyword': indicators } },
    ];

    if (dateFrom || dateTo) {
      const range: Record<string, string> = {};
      if (dateFrom) range['gte'] = dateFrom;
      if (dateTo) range['lte'] = dateTo;
      must.push({ range: { createdAt: range } });
    }

    // Get IOC-to-submission mapping
    const response = await this.es.search({
      index: INDEX_IOCS,
      body: {
        query: { bool: { must } },
        size: 10_000,
        _source: ['submissionId', 'value', 'createdAt'],
      },
    });

    // Build adjacency: group submissions by shared indicator
    const indicatorToSubmissions = new Map<string, Set<string>>();
    const submissionDates = new Map<string, string>();

    for (const hit of response.hits.hits) {
      const source = hit._source as Record<string, unknown>;
      const value = source['value'] as string;
      const subId = source['submissionId'] as string;
      const createdAt = source['createdAt'] as string;

      if (!indicatorToSubmissions.has(value)) {
        indicatorToSubmissions.set(value, new Set());
      }
      indicatorToSubmissions.get(value)!.add(subId);

      const existing = submissionDates.get(subId);
      if (!existing || createdAt < existing) {
        submissionDates.set(subId, createdAt);
      }
    }

    // Simple clustering: group submissions that share >= threshold indicators
    const visited = new Set<string>();
    const campaigns: CampaignCluster[] = [];
    let campaignIndex = 0;

    for (const [_indicator, submissions] of indicatorToSubmissions) {
      for (const seedId of submissions) {
        if (visited.has(seedId)) continue;

        // BFS to find all connected submissions
        const cluster = new Set<string>();
        const clusterIndicators = new Set<string>();
        const queue = [seedId];

        while (queue.length > 0) {
          const current = queue.pop()!;
          if (cluster.has(current)) continue;
          cluster.add(current);

          // Find all indicators shared by this submission
          for (const [ind, subs] of indicatorToSubmissions) {
            if (subs.has(current)) {
              clusterIndicators.add(ind);
              for (const neighbor of subs) {
                if (!cluster.has(neighbor)) {
                  // Check shared indicator count meets threshold
                  let shared = 0;
                  for (const [, checkSubs] of indicatorToSubmissions) {
                    if (checkSubs.has(current) && checkSubs.has(neighbor)) {
                      shared++;
                    }
                  }
                  if (shared >= threshold) {
                    queue.push(neighbor);
                  }
                }
              }
            }
          }
        }

        if (cluster.size >= 2) {
          const dates = Array.from(cluster)
            .map((id) => submissionDates.get(id) ?? '')
            .filter(Boolean)
            .sort();

          campaigns.push({
            campaignId: `campaign-${campaignIndex++}`,
            submissions: Array.from(cluster),
            sharedIndicators: Array.from(clusterIndicators),
            firstSeen: dates[0] ?? '',
            lastSeen: dates[dates.length - 1] ?? '',
            submissionCount: cluster.size,
          });

          for (const id of cluster) {
            visited.add(id);
          }
        } else {
          visited.add(seedId);
        }
      }
    }

    return campaigns.sort((a, b) => b.submissionCount - a.submissionCount);
  }
}
