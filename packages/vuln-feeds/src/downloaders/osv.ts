// ── OSV downloader — ecosystems.txt + per-ecosystem ZIP download + atomic replace
import fs from 'node:fs';
import path from 'node:path';

import { randomUUID } from 'node:crypto';
import pino from 'pino';
import { OSV_BUCKET_BASE, OSV_CACHE_DIR, OSV_PER_ZIP_TIMEOUT } from '../config.js';
import { stampMeta } from '../db.js';

const log = pino({ name: 'osv-downloader' });

// Ecosystem name validation — path traversal defense
const ECOSYSTEM_RE = /^[A-Za-z0-9][A-Za-z0-9 ._:-]*$/;

export async function refreshOsv(): Promise<number> {
  log.info('Starting OSV refresh');
  stampMeta('osv', 0, 'refreshing', 'Fetching ecosystems list');

  try {
    // 1. Fetch ecosystems list
    const ecosystemsUrl = `${OSV_BUCKET_BASE}/ecosystems.txt`;
    const response = await fetch(ecosystemsUrl, {
      signal: AbortSignal.timeout(30_000),
      headers: { 'User-Agent': 'FraudVault/1.0 vuln-feeds' },
    });

    if (!response.ok) {
      throw new Error(`Ecosystems list download failed: HTTP ${response.status}`);
    }

    const text = await response.text();
    const ecosystems = text
      .split('\n')
      .map(line => line.trim())
      .filter(line => line.length > 0 && ECOSYSTEM_RE.test(line));

    log.info('Found %d valid ecosystems', ecosystems.length);

    // Ensure cache directory exists (osv-scanner expects ZIPs at <cache>/osv-scanner/<ecosystem>/all.zip)
    const cacheBase = path.join(OSV_CACHE_DIR, 'osv-scanner');
    fs.mkdirSync(cacheBase, { recursive: true });

    let successCount = 0;
    let failCount = 0;

    // 2. Download each ecosystem ZIP
    for (const ecosystem of ecosystems) {
      try {
        const encoded = encodeURIComponent(ecosystem);
        const zipUrl = `${OSV_BUCKET_BASE}/${encoded}/all.zip`;

        stampMeta('osv', successCount, 'refreshing', `Downloading ${ecosystem} (${successCount + 1}/${ecosystems.length})`);

        const zipResponse = await fetch(zipUrl, {
          signal: AbortSignal.timeout(OSV_PER_ZIP_TIMEOUT),
          headers: { 'User-Agent': 'FraudVault/1.0 vuln-feeds' },
        });

        if (!zipResponse.ok) {
          log.warn('OSV download failed for %s: HTTP %d', ecosystem, zipResponse.status);
          failCount++;
          continue;
        }

        const zipData = Buffer.from(await zipResponse.arrayBuffer());

        // 3. Atomic replace: write to temp file, then rename
        const ecosystemDir = path.join(cacheBase, ecosystem);
        fs.mkdirSync(ecosystemDir, { recursive: true });

        const finalPath = path.join(ecosystemDir, 'all.zip');
        const tempPath = path.join(ecosystemDir, `.all-${randomUUID()}.zip.tmp`);

        fs.writeFileSync(tempPath, zipData);
        fs.renameSync(tempPath, finalPath);

        successCount++;
        log.info('OSV: downloaded %s (%d KB)', ecosystem, Math.round(zipData.length / 1024));
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        log.warn('OSV download failed for %s: %s', ecosystem, msg);
        failCount++;
      }
    }

    log.info('OSV refresh complete: %d ecosystems downloaded, %d failed', successCount, failCount);
    stampMeta('osv', successCount, 'ready', `${successCount} ecosystems, ${failCount} failed`);
    return successCount;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    log.error('OSV refresh failed: %s', msg);
    stampMeta('osv', 0, 'error', msg.slice(0, 300));
    throw err;
  }
}
