// ── KEV downloader + parser ──────────────────────────────────────────────────
import pino from 'pino';
import { KEV_URL, KEV_TIMEOUT } from '../config.js';
import { replaceKev, stampMeta, type KevRow } from '../db.js';

const log = pino({ name: 'kev-downloader' });

interface KevVulnerability {
  cveID: string;
  dueDate: string;
  vulnerabilityName: string;
}

interface KevResponse {
  vulnerabilities: KevVulnerability[];
}

export async function refreshKev(): Promise<number> {
  log.info('Starting KEV refresh');
  stampMeta('kev', 0, 'refreshing', 'Downloading KEV catalog');

  try {
    const response = await fetch(KEV_URL, {
      signal: AbortSignal.timeout(KEV_TIMEOUT),
      headers: { 'User-Agent': 'FraudVault/1.0 vuln-feeds' },
    });

    if (!response.ok) {
      throw new Error(`KEV download failed: HTTP ${response.status}`);
    }

    const data = (await response.json()) as KevResponse;
    const vulnerabilities = data.vulnerabilities ?? [];

    const rows: KevRow[] = [];
    for (const v of vulnerabilities) {
      if (typeof v.cveID === 'string' && v.cveID.startsWith('CVE-')) {
        rows.push({
          cve: v.cveID,
          due_date: v.dueDate ?? '',
          name: v.vulnerabilityName ?? '',
        });
      }
    }

    const count = replaceKev(rows);
    log.info('KEV refresh complete: %d entries', count);
    return count;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    log.error('KEV refresh failed: %s', msg);
    stampMeta('kev', 0, 'error', msg.slice(0, 300));
    throw err;
  }
}
