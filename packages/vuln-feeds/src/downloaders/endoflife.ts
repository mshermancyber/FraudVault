// ── endoflife.date downloader — product version/EOL data for tech debt scoring
import pino from 'pino';
import { stampMeta, replaceEndoflife } from '../db.js';

const log = pino({ name: 'endoflife-downloader' });
const BASE_URL = 'https://endoflife.date/api';
const TIMEOUT = 60_000;

export interface EndoflifeRow {
  product: string;
  cycle: string;
  latest: string;
  eol: string;       // "true", "false", or a date string
  lts: string;
  release_date: string;
}

export async function refreshEndoflife(): Promise<number> {
  log.info('Starting endoflife.date refresh');
  stampMeta('endoflife', 0, 'refreshing', 'Fetching product list');

  try {
    // 1. Get all product slugs
    const listResp = await fetch(`${BASE_URL}/all.json`, {
      signal: AbortSignal.timeout(TIMEOUT),
      headers: { 'User-Agent': 'FraudVault/1.0 vuln-feeds' },
    });
    if (!listResp.ok) throw new Error(`Product list failed: HTTP ${listResp.status}`);

    const products = await listResp.json() as string[];
    log.info('Found %d products on endoflife.date', products.length);

    const rows: EndoflifeRow[] = [];
    let fetched = 0;
    let failed = 0;

    // 2. Fetch each product's version data (batch with small delay to be polite)
    for (const product of products) {
      try {
        const resp = await fetch(`${BASE_URL}/${encodeURIComponent(product)}.json`, {
          signal: AbortSignal.timeout(10_000),
          headers: { 'User-Agent': 'FraudVault/1.0 vuln-feeds' },
        });
        if (!resp.ok) { failed++; continue; }

        const cycles = await resp.json() as Array<Record<string, unknown>>;
        for (const c of cycles) {
          rows.push({
            product,
            cycle: String(c['cycle'] ?? ''),
            latest: String(c['latest'] ?? c['cycle'] ?? ''),
            eol: String(c['eol'] ?? 'false'),
            lts: String(c['lts'] ?? 'false'),
            release_date: String(c['releaseDate'] ?? ''),
          });
        }
        fetched++;

        if (fetched % 50 === 0) {
          stampMeta('endoflife', rows.length, 'refreshing', `${fetched}/${products.length} products`);
        }

        // Small delay every 10 requests to avoid hammering
        if (fetched % 10 === 0) {
          await new Promise(r => setTimeout(r, 200));
        }
      } catch {
        failed++;
      }
    }

    // 3. Wholesale replace
    const count = replaceEndoflife(rows);
    log.info('endoflife.date refresh complete: %d rows from %d products (%d failed)', count, fetched, failed);
    return count;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    log.error('endoflife.date refresh failed: %s', msg);
    stampMeta('endoflife', 0, 'error', msg.slice(0, 300));
    throw err;
  }
}
