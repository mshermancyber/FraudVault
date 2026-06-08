import { describe, it, expect, vi, beforeEach } from 'vitest';
import { CorrelationService } from '../services/correlationService.js';

// Mock the elasticsearch module
vi.mock('../elasticsearch.js', () => ({
  INDEX_SUBMISSIONS: 'scanboy-submissions',
  INDEX_IOCS: 'scanboy-iocs',
  INDEX_NETWORK_ACTIVITY: 'scanboy-network-activity',
}));

/**
 * Since correlate() calls 4 methods in parallel via Promise.all, the order
 * of ES search calls is nondeterministic. We use a smart mock that routes
 * based on the index being queried.
 */
function createRoutingMockEs(handlers: {
  iocs?: Array<Record<string, unknown>>;
  submissions?: Array<Record<string, unknown>>;
  network?: Array<Record<string, unknown>>;
}) {
  const iocCalls: Record<string, unknown>[] = handlers.iocs ?? [];
  const subCalls: Record<string, unknown>[] = handlers.submissions ?? [];
  const netCalls: Record<string, unknown>[] = handlers.network ?? [];

  let iocIdx = 0;
  let subIdx = 0;
  let netIdx = 0;

  const search = vi.fn().mockImplementation((params: { index: string }) => {
    if (params.index === 'scanboy-iocs') {
      return Promise.resolve(iocCalls[iocIdx++] ?? { hits: { hits: [] } });
    }
    if (params.index === 'scanboy-submissions') {
      return Promise.resolve(subCalls[subIdx++] ?? { hits: { hits: [] } });
    }
    if (params.index === 'scanboy-network-activity') {
      return Promise.resolve(netCalls[netIdx++] ?? { hits: { hits: [] }, aggregations: { destinations: { buckets: [] }, domains: { buckets: [] } } });
    }
    return Promise.resolve({ hits: { hits: [] } });
  });

  return { search };
}

describe('CorrelationService', () => {
  describe('IOC overlap calculation', () => {
    it('finds submissions sharing IOCs', async () => {
      const mockEs = createRoutingMockEs({
        iocs: [
          // 1st IOC search: get IOCs for source
          { hits: { hits: [{ _source: { value: '1.2.3.4', type: 'ipv4' } }, { _source: { value: 'evil.com', type: 'domain' } }] } },
          // 2nd IOC search: find correlated submissions
          { hits: { hits: [] }, aggregations: { by_submission: { buckets: [{ key: 'sub-2', doc_count: 2, shared_iocs: { buckets: [{ key: '1.2.3.4' }, { key: 'evil.com' }] } }] } } },
        ],
        submissions: [
          // enrich IOC correlations
          { hits: { hits: [{ _source: { id: 'sub-2', fileName: 'malware.exe', threatLevel: 'high', threatScore: 85 } }] } },
          // behavioral: source techniques
          { hits: { hits: [{ _source: { attackTechniques: [] } }] } },
          // family: source family
          { hits: { hits: [{ _source: { malwareFamily: null } }] } },
        ],
        network: [
          { hits: { hits: [] }, aggregations: { destinations: { buckets: [] }, domains: { buckets: [] } } },
        ],
      });

      const service = new CorrelationService(mockEs as unknown as import('@elastic/elasticsearch').Client);
      const result = await service.correlate('sub-1');

      expect(result.sourceSubmissionId).toBe('sub-1');
      const iocCorrelation = result.correlations.find((c) => c.correlationType === 'ioc');
      expect(iocCorrelation).toBeDefined();
      expect(iocCorrelation!.submissionId).toBe('sub-2');
      expect(iocCorrelation!.correlationScore).toBe(1.0);
      expect(iocCorrelation!.sharedIndicators).toContain('1.2.3.4');
    });

    it('calculates partial overlap correctly', async () => {
      const mockEs = createRoutingMockEs({
        iocs: [
          { hits: { hits: [
            { _source: { value: 'a.com', type: 'domain' } },
            { _source: { value: 'b.com', type: 'domain' } },
            { _source: { value: 'c.com', type: 'domain' } },
            { _source: { value: 'd.com', type: 'domain' } },
          ] } },
          { hits: { hits: [] }, aggregations: { by_submission: { buckets: [{ key: 'sub-3', doc_count: 1, shared_iocs: { buckets: [{ key: 'a.com' }] } }] } } },
        ],
        submissions: [
          { hits: { hits: [{ _source: { id: 'sub-3', fileName: 'test.exe', threatLevel: 'low', threatScore: 10 } }] } },
          { hits: { hits: [{ _source: { attackTechniques: [] } }] } },
          { hits: { hits: [{ _source: { malwareFamily: null } }] } },
        ],
        network: [
          { hits: { hits: [] }, aggregations: { destinations: { buckets: [] }, domains: { buckets: [] } } },
        ],
      });

      const service = new CorrelationService(mockEs as unknown as import('@elastic/elasticsearch').Client);
      const result = await service.correlate('sub-1');
      const corr = result.correlations.find((c) => c.submissionId === 'sub-3');
      expect(corr).toBeDefined();
      expect(corr!.correlationScore).toBeCloseTo(0.25, 2);
    });
  });

  describe('behavioral similarity scoring', () => {
    it('finds submissions with shared ATT&CK techniques', async () => {
      // Use a fine-grained mock that inspects the query body to route responses
      const search = vi.fn().mockImplementation((params: { index: string; body: Record<string, unknown> }) => {
        const body = params.body;
        const queryStr = JSON.stringify(body);

        if (params.index === 'scanboy-iocs') {
          if (queryStr.includes('submissionId')) {
            // correlateByIOC step 1: get IOCs for source -> none
            return Promise.resolve({ hits: { hits: [] } });
          }
          return Promise.resolve({ hits: { hits: [] } });
        }

        if (params.index === 'scanboy-submissions') {
          if (queryStr.includes('attackTechniques') && queryStr.includes('terms')) {
            // correlateByBehavior step 2: find matching submissions
            return Promise.resolve({
              hits: {
                hits: [{
                  _source: {
                    id: 'sub-4',
                    fileName: 'similar.exe',
                    threatLevel: 'high',
                    threatScore: 80,
                    attackTechniques: ['T1055', 'T1059.001'],
                  },
                }],
              },
            });
          }
          if (queryStr.includes('malwareFamily')) {
            // correlateByFamily step 1: get source family
            return Promise.resolve({ hits: { hits: [{ _source: { malwareFamily: null } }] } });
          }
          // correlateByBehavior step 1 or other: get source techniques
          return Promise.resolve({
            hits: {
              hits: [{
                _source: { attackTechniques: ['T1055', 'T1059.001', 'T1547.001'] },
              }],
            },
          });
        }

        if (params.index === 'scanboy-network-activity') {
          return Promise.resolve({
            hits: { hits: [] },
            aggregations: { destinations: { buckets: [] }, domains: { buckets: [] } },
          });
        }

        return Promise.resolve({ hits: { hits: [] } });
      });

      const mockEs = { search };
      const service = new CorrelationService(mockEs as unknown as import('@elastic/elasticsearch').Client);
      const result = await service.correlate('sub-1');
      const behavioral = result.correlations.find((c) => c.correlationType === 'behavioral');
      expect(behavioral).toBeDefined();
      expect(behavioral!.submissionId).toBe('sub-4');
      expect(behavioral!.correlationScore).toBeCloseTo(2 / 3, 2);
      expect(behavioral!.sharedIndicators).toContain('T1055');
      expect(behavioral!.sharedIndicators).toContain('T1059.001');
    });
  });

  describe('empty input handling', () => {
    it('returns empty correlations when no IOCs/techniques found', async () => {
      const mockEs = createRoutingMockEs({
        iocs: [{ hits: { hits: [] } }],
        submissions: [
          { hits: { hits: [] } }, // behavioral: no source
          { hits: { hits: [] } }, // family: no source
        ],
        network: [
          { hits: { hits: [] }, aggregations: { destinations: { buckets: [] }, domains: { buckets: [] } } },
        ],
      });

      const service = new CorrelationService(mockEs as unknown as import('@elastic/elasticsearch').Client);
      const result = await service.correlate('sub-1');
      expect(result.correlations).toEqual([]);
      expect(result.totalCorrelated).toBe(0);
    });

    it('removes self-correlation', async () => {
      const mockEs = createRoutingMockEs({
        iocs: [
          { hits: { hits: [{ _source: { value: '1.2.3.4', type: 'ipv4' } }] } },
          { hits: { hits: [] }, aggregations: { by_submission: { buckets: [{ key: 'sub-1', doc_count: 1, shared_iocs: { buckets: [{ key: '1.2.3.4' }] } }] } } },
        ],
        submissions: [
          { hits: { hits: [{ _source: { id: 'sub-1', fileName: 'self.exe', threatLevel: 'low', threatScore: 5 } }] } },
          { hits: { hits: [{ _source: { attackTechniques: [] } }] } },
          { hits: { hits: [{ _source: { malwareFamily: null } }] } },
        ],
        network: [
          { hits: { hits: [] }, aggregations: { destinations: { buckets: [] }, domains: { buckets: [] } } },
        ],
      });

      const service = new CorrelationService(mockEs as unknown as import('@elastic/elasticsearch').Client);
      const result = await service.correlate('sub-1');
      expect(result.correlations.every((c) => c.submissionId !== 'sub-1')).toBe(true);
    });
  });

  describe('result sorting and limiting', () => {
    it('returns correlations sorted by score descending', async () => {
      const mockEs = createRoutingMockEs({
        iocs: [
          { hits: { hits: [{ _source: { value: 'a.com', type: 'domain' } }, { _source: { value: 'b.com', type: 'domain' } }] } },
          { hits: { hits: [] }, aggregations: { by_submission: { buckets: [
            { key: 'sub-low', doc_count: 1, shared_iocs: { buckets: [{ key: 'a.com' }] } },
            { key: 'sub-high', doc_count: 2, shared_iocs: { buckets: [{ key: 'a.com' }, { key: 'b.com' }] } },
          ] } } },
        ],
        submissions: [
          { hits: { hits: [
            { _source: { id: 'sub-low', fileName: 'low.exe', threatLevel: 'low', threatScore: 10 } },
            { _source: { id: 'sub-high', fileName: 'high.exe', threatLevel: 'high', threatScore: 90 } },
          ] } },
          { hits: { hits: [{ _source: { attackTechniques: [] } }] } },
          { hits: { hits: [{ _source: { malwareFamily: null } }] } },
        ],
        network: [
          { hits: { hits: [] }, aggregations: { destinations: { buckets: [] }, domains: { buckets: [] } } },
        ],
      });

      const service = new CorrelationService(mockEs as unknown as import('@elastic/elasticsearch').Client);
      const result = await service.correlate('sub-1');
      expect(result.correlations.length).toBe(2);
      expect(result.correlations[0]!.correlationScore).toBeGreaterThanOrEqual(
        result.correlations[1]!.correlationScore,
      );
    });
  });
});
