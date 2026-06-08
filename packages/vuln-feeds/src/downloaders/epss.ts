// ── EPSS downloader + gzip decompress + CSV parser ──────────────────────────
import { gunzipSync } from 'node:zlib';
import pino from 'pino';
import { EPSS_URL, EPSS_TIMEOUT } from '../config.js';
import { replaceEpss, stampMeta, type EpssRow } from '../db.js';

const log = pino({ name: 'epss-downloader' });

export async function refreshEpss(): Promise<number> {
  log.info('Starting EPSS refresh');
  stampMeta('epss', 0, 'refreshing', 'Downloading EPSS scores');

  try {
    const response = await fetch(EPSS_URL, {
      signal: AbortSignal.timeout(EPSS_TIMEOUT),
      headers: { 'User-Agent': 'FraudVault/1.0 vuln-feeds' },
    });

    if (!response.ok) {
      throw new Error(`EPSS download failed: HTTP ${response.status}`);
    }

    const compressed = Buffer.from(await response.arrayBuffer());
    const decompressed = gunzipSync(compressed);
    const text = decompressed.toString('utf-8');

    const rows: EpssRow[] = [];
    const lines = text.split('\n');

    for (const line of lines) {
      // Skip comment lines and empty lines
      if (line.startsWith('#') || line.trim() === '') continue;
      // Skip header row
      if (line.startsWith('cve,') || line.startsWith('CVE-') === false) {
        // Could be the header "cve,epss,percentile" — try to parse anyway
        if (!line.startsWith('CVE-')) continue;
      }

      const parts = line.split(',');
      if (parts.length < 3) continue;

      const cve = parts[0]!.trim();
      const epss = parseFloat(parts[1]!);
      const percentile = parseFloat(parts[2]!);

      if (!cve.startsWith('CVE-') || isNaN(epss) || isNaN(percentile)) continue;

      rows.push({ cve, epss, percentile });
    }

    const count = replaceEpss(rows);
    log.info('EPSS refresh complete: %d entries', count);
    return count;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    log.error('EPSS refresh failed: %s', msg);
    stampMeta('epss', 0, 'error', msg.slice(0, 300));
    throw err;
  }
}
