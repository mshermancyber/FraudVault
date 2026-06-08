import { Client } from '@elastic/elasticsearch';
import type { SearchConfig } from './config.js';

let client: Client | null = null;

// ── Index names ────────────────────────────────────────────────────────────

export const INDEX_SUBMISSIONS = 'scanboy-submissions';
export const INDEX_IOCS = 'scanboy-iocs';
export const INDEX_NETWORK_ACTIVITY = 'scanboy-network-activity';

// ── Client management ──────────────────────────────────────────────────────

export function getElasticsearchClient(config: SearchConfig): Client {
  if (!client) {
    const auth =
      config.elasticsearch.username && config.elasticsearch.password
        ? {
            username: config.elasticsearch.username,
            password: config.elasticsearch.password,
          }
        : undefined;

    client = new Client({
      node: config.elasticsearch.node,
      auth,
      maxRetries: config.elasticsearch.maxRetries,
      requestTimeout: config.elasticsearch.requestTimeout,
    });
  }

  return client;
}

export async function closeElasticsearch(): Promise<void> {
  if (client) {
    await client.close();
    client = null;
  }
}

// ── Index mappings ─────────────────────────────────────────────────────────

const submissionsMapping = {
  properties: {
    id: { type: 'keyword' as const },
    userId: { type: 'keyword' as const },
    fileName: { type: 'text' as const, fields: { keyword: { type: 'keyword' as const } } },
    fileSize: { type: 'long' as const },
    mimeType: { type: 'keyword' as const },
    md5: { type: 'keyword' as const },
    sha1: { type: 'keyword' as const },
    sha256: { type: 'keyword' as const },
    ssdeep: { type: 'keyword' as const },
    status: { type: 'keyword' as const },
    threatLevel: { type: 'keyword' as const },
    threatScore: { type: 'float' as const },
    tags: { type: 'keyword' as const },
    malwareFamily: { type: 'keyword' as const },
    attackTechniques: { type: 'keyword' as const },
    submittedAt: { type: 'date' as const },
    completedAt: { type: 'date' as const },
    createdAt: { type: 'date' as const },
    updatedAt: { type: 'date' as const },
  },
};

const iocsMapping = {
  properties: {
    id: { type: 'keyword' as const },
    submissionId: { type: 'keyword' as const },
    type: { type: 'keyword' as const },
    value: { type: 'text' as const, fields: { keyword: { type: 'keyword' as const } } },
    context: { type: 'text' as const },
    confidence: { type: 'float' as const },
    source: { type: 'keyword' as const },
    firstSeenAt: { type: 'date' as const },
    createdAt: { type: 'date' as const },
  },
};

const networkActivityMapping = {
  properties: {
    id: { type: 'keyword' as const },
    submissionId: { type: 'keyword' as const },
    protocol: { type: 'keyword' as const },
    sourceAddress: { type: 'ip' as const },
    sourcePort: { type: 'integer' as const },
    destinationAddress: { type: 'ip' as const },
    destinationPort: { type: 'integer' as const },
    domain: { type: 'text' as const, fields: { keyword: { type: 'keyword' as const } } },
    bytesSent: { type: 'long' as const },
    bytesReceived: { type: 'long' as const },
    timestamp: { type: 'date' as const },
  },
};

// ── Index setup ────────────────────────────────────────────────────────────

export async function ensureIndexes(es: Client): Promise<void> {
  const indexes: Array<{ name: string; mappings: Record<string, unknown> }> = [
    { name: INDEX_SUBMISSIONS, mappings: submissionsMapping },
    { name: INDEX_IOCS, mappings: iocsMapping },
    { name: INDEX_NETWORK_ACTIVITY, mappings: networkActivityMapping },
  ];

  for (const { name, mappings } of indexes) {
    const exists = await es.indices.exists({ index: name });
    if (!exists) {
      await es.indices.create({
        index: name,
        body: {
          settings: {
            number_of_shards: 2,
            number_of_replicas: 1,
            refresh_interval: '5s',
          },
          mappings: mappings,
        },
      });
    }
  }
}

// ── Bulk indexing helpers ───────────────────────────────────────────────────

export interface BulkIndexItem {
  id: string;
  [key: string]: unknown;
}

export async function bulkIndex(
  es: Client,
  indexName: string,
  items: BulkIndexItem[],
): Promise<{ indexed: number; errors: number }> {
  if (items.length === 0) {
    return { indexed: 0, errors: 0 };
  }

  const operations = items.flatMap((item) => [
    { index: { _index: indexName, _id: item.id } },
    item,
  ]);

  const result = await es.bulk({ refresh: true, operations });

  let errors = 0;
  if (result.errors) {
    for (const item of result.items) {
      if (item.index?.error) {
        errors++;
      }
    }
  }

  return { indexed: items.length - errors, errors };
}

export async function indexDocument(
  es: Client,
  indexName: string,
  id: string,
  document: Record<string, unknown>,
): Promise<void> {
  await es.index({
    index: indexName,
    id,
    document,
    refresh: true,
  });
}
