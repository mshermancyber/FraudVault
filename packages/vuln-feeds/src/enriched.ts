// ── Build the denormalized cve_enriched table (UNION + LEFT JOIN) ───────────
import pino from 'pino';
import { buildEnrichedTable, stampMeta } from './db.js';

const log = pino({ name: 'enriched' });

export async function refreshEnriched(): Promise<number> {
  log.info('Building enriched table');
  stampMeta('enriched', 0, 'refreshing', 'Building denormalized join');

  try {
    const count = buildEnrichedTable();
    log.info('Enriched table built: %d rows', count);
    return count;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    log.error('Enriched table build failed: %s', msg);
    stampMeta('enriched', 0, 'error', msg.slice(0, 300));
    throw err;
  }
}
