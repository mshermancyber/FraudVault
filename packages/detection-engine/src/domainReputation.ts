import pino from 'pino';

const log = pino({ name: 'domain-reputation' });

const FEEDS_URL = process.env['VULN_FEEDS_URL'] ?? 'http://vuln-feeds:9000';
const INTERNAL_KEY = process.env['INTERNAL_API_KEY'] ?? '';

export type TrancoTier = 'trusted' | 'likely_legit' | 'known' | 'unknown';

let trancoMap = new Map<string, number>();
let loaded = false;

export function isTrancoLoaded(): boolean {
  return loaded;
}

export function getTrancoSize(): number {
  return trancoMap.size;
}

export function getTrancoRank(domain: string): number | null {
  const lower = domain.toLowerCase();
  const direct = trancoMap.get(lower);
  if (direct !== undefined) return direct;

  // Try parent domain (e.g. cdn.example.com -> example.com)
  const parts = lower.split('.');
  if (parts.length > 2) {
    const parent = parts.slice(-2).join('.');
    const parentRank = trancoMap.get(parent);
    if (parentRank !== undefined) return parentRank;
  }

  return null;
}

export function getTrancoTier(domain: string): TrancoTier {
  const rank = getTrancoRank(domain);
  if (rank === null) return 'unknown';
  if (rank <= 50_000) return 'trusted';
  if (rank <= 200_000) return 'likely_legit';
  return 'known';
}

export async function loadTrancoData(): Promise<void> {
  try {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (INTERNAL_KEY) headers['x-internal-api-key'] = INTERNAL_KEY;

    const countRes = await fetch(`${FEEDS_URL}/feeds/tranco/count`, {
      headers,
      signal: AbortSignal.timeout(10_000),
    });
    if (!countRes.ok) {
      log.warn('Tranco count endpoint returned %d — feed may not be populated yet', countRes.status);
      return;
    }
    const countData = await countRes.json() as { count: number };
    if (countData.count === 0) {
      log.info('Tranco feed is empty — skipping load');
      return;
    }

    log.info('Loading %d Tranco domains from vuln-feeds', countData.count);

    const res = await fetch(`${FEEDS_URL}/feeds/tranco/all`, {
      headers,
      signal: AbortSignal.timeout(120_000),
    });
    if (!res.ok) {
      throw new Error(`Tranco all endpoint returned HTTP ${res.status}`);
    }
    const data = await res.json() as { rows: Array<{ rank: number; domain: string }> };

    const newMap = new Map<string, number>();
    for (const row of data.rows) {
      newMap.set(row.domain, row.rank);
    }

    trancoMap = newMap;
    loaded = true;
    log.info('Tranco data loaded: %d domains', trancoMap.size);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    log.error('Failed to load Tranco data: %s', msg);
  }
}
