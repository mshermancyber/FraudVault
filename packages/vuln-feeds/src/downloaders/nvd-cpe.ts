// ── Standalone CPE match refresh ─────────────────────────────────────────────
//
// CPE match data is extracted as a side-effect of the NVD/cvelistV5 refresh
// (see nvd.ts). This module exists so the scheduler can treat 'cpe_match' as
// a recognizable feed name. A standalone refresh simply delegates to refreshNvd
// which populates both the nvd AND cpe_match tables in one pass.

import pino from 'pino';
import { getMetaRow, stampMeta } from '../db.js';

const log = pino({ name: 'nvd-cpe-downloader' });

/**
 * Standalone CPE match refresh.
 *
 * Because CPE match rows are extracted during the NVD ZIP parse (refreshNvd),
 * calling this independently just checks whether cpe_match data already exists.
 * A full re-extraction requires running the NVD refresh.
 */
export async function refreshCpeMatch(): Promise<number> {
  const meta = getMetaRow('cpe_match');
  if (meta && meta.row_count > 0 && meta.status === 'ready') {
    log.info('CPE match data already populated (%d rows) — skipping standalone refresh', meta.row_count);
    return meta.row_count;
  }

  // If cpe_match is empty but NVD was already refreshed, we need a full NVD
  // re-parse. Log a warning — the next full refresh cycle will populate it.
  log.warn(
    'CPE match table is empty. It will be populated during the next NVD refresh cycle. ' +
    'Trigger a manual NVD refresh via POST /feeds/refresh?feed=nvd to populate it now.'
  );
  stampMeta('cpe_match', 0, 'empty', 'Awaiting NVD refresh to populate CPE match data');
  return 0;
}
