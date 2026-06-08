import type { Client, estypes } from '@elastic/elasticsearch';

type QueryDslQueryContainer = estypes.QueryDslQueryContainer;
import { INDEX_SUBMISSIONS, INDEX_IOCS } from '../elasticsearch.js';

// ── Types ──────────────────────────────────────────────────────────────────

export interface SearchFilters {
  query?: string;
  md5?: string;
  sha1?: string;
  sha256?: string;
  domain?: string;
  url?: string;
  ip?: string;
  fileName?: string;
  malwareFamily?: string;
  attackTechnique?: string;
  registryKey?: string;
  threatLevel?: string;
  status?: string;
  tag?: string;
  dateFrom?: string;
  dateTo?: string;
  page?: number;
  pageSize?: number;
}

export interface SearchResult {
  id: string;
  score: number;
  source: Record<string, unknown>;
}

export interface SearchResponse {
  results: SearchResult[];
  total: number;
  page: number;
  pageSize: number;
  totalPages: number;
  took: number;
}

// ── Service ────────────────────────────────────────────────────────────────

export class SearchService {
  constructor(private readonly es: Client) {}

  async search(filters: SearchFilters): Promise<SearchResponse> {
    const page = filters.page ?? 1;
    const pageSize = Math.min(filters.pageSize ?? 25, 100);
    const from = (page - 1) * pageSize;

    const must: QueryDslQueryContainer[] = [];
    const filter: QueryDslQueryContainer[] = [];

    // Full-text query across all text fields
    if (filters.query) {
      must.push({
        multi_match: {
          query: filters.query,
          fields: ['fileName', 'tags', 'malwareFamily', 'md5', 'sha1', 'sha256'],
          type: 'best_fields',
          fuzziness: 'AUTO',
        },
      });
    }

    // Hash searches (exact match)
    if (filters.md5) {
      filter.push({ term: { md5: filters.md5.toLowerCase() } });
    }
    if (filters.sha1) {
      filter.push({ term: { sha1: filters.sha1.toLowerCase() } });
    }
    if (filters.sha256) {
      filter.push({ term: { sha256: filters.sha256.toLowerCase() } });
    }

    // Filename (wildcard)
    if (filters.fileName) {
      must.push({
        wildcard: {
          'fileName.keyword': {
            value: `*${filters.fileName.replace(/[*?\\]/g, '\\$&')}*`,
            case_insensitive: true,
          },
        },
      });
    }

    // Malware family
    if (filters.malwareFamily) {
      filter.push({ term: { malwareFamily: filters.malwareFamily } });
    }

    // ATT&CK technique
    if (filters.attackTechnique) {
      filter.push({ term: { attackTechniques: filters.attackTechnique } });
    }

    // Threat level
    if (filters.threatLevel) {
      filter.push({ term: { threatLevel: filters.threatLevel } });
    }

    // Status
    if (filters.status) {
      filter.push({ term: { status: filters.status } });
    }

    // Tag
    if (filters.tag) {
      filter.push({ term: { tags: filters.tag } });
    }

    // Date range
    if (filters.dateFrom || filters.dateTo) {
      const range: Record<string, string> = {};
      if (filters.dateFrom) range['gte'] = filters.dateFrom;
      if (filters.dateTo) range['lte'] = filters.dateTo;
      filter.push({ range: { submittedAt: range } });
    }

    // Search by domain/URL/IP requires cross-index IOC search
    if (filters.domain || filters.url || filters.ip || filters.registryKey) {
      const submissionIds = await this.searchIOCsForSubmissions(filters);
      if (submissionIds.length === 0) {
        return { results: [], total: 0, page, pageSize, totalPages: 0, took: 0 };
      }
      filter.push({ terms: { id: submissionIds } });
    }

    const query: QueryDslQueryContainer =
      must.length > 0 || filter.length > 0
        ? { bool: { must, filter } }
        : { match_all: {} };

    const response = await this.es.search({
      index: INDEX_SUBMISSIONS,
      query,
      from,
      size: pageSize,
      sort: [{ _score: { order: 'desc' } }, { submittedAt: { order: 'desc' } }],
    });

    const total =
      typeof response.hits.total === 'number'
        ? response.hits.total
        : response.hits.total?.value ?? 0;

    const results: SearchResult[] = response.hits.hits.map((hit) => ({
      id: hit._id!,
      score: hit._score ?? 0,
      source: hit._source as Record<string, unknown>,
    }));

    return {
      results,
      total,
      page,
      pageSize,
      totalPages: Math.ceil(total / pageSize),
      took: response.took,
    };
  }

  private async searchIOCsForSubmissions(filters: SearchFilters): Promise<string[]> {
    const iocQueries: QueryDslQueryContainer[] = [];

    if (filters.domain) {
      iocQueries.push({
        bool: {
          must: [
            { term: { type: 'domain' } },
            { term: { 'value.keyword': filters.domain } },
          ],
        },
      });
    }

    if (filters.url) {
      iocQueries.push({
        bool: {
          must: [
            { term: { type: 'url' } },
            { term: { 'value.keyword': filters.url } },
          ],
        },
      });
    }

    if (filters.ip) {
      iocQueries.push({
        bool: {
          must: [
            { terms: { type: ['ipv4', 'ipv6'] } },
            { term: { 'value.keyword': filters.ip } },
          ],
        },
      });
    }

    if (filters.registryKey) {
      iocQueries.push({
        bool: {
          must: [
            { term: { type: 'registry_key' } },
            { term: { 'value.keyword': filters.registryKey } },
          ],
        },
      });
    }

    if (iocQueries.length === 0) return [];

    const response = await this.es.search({
      index: INDEX_IOCS,
      body: {
        query: { bool: { should: iocQueries, minimum_should_match: 1 } },
        size: 0,
        aggs: {
          submission_ids: {
            terms: { field: 'submissionId', size: 10_000 },
          },
        },
      },
    });

    const aggs = response.aggregations as Record<string, unknown> | undefined;
    if (!aggs) return [];

    const buckets = (aggs['submission_ids'] as { buckets?: Array<{ key: string }> })?.buckets;
    return buckets?.map((b) => b.key) ?? [];
  }
}
