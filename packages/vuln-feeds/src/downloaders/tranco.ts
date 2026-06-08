import { gunzipSync } from 'node:zlib';
import pino from 'pino';
import { TRANCO_URL, TRANCO_TIMEOUT } from '../config.js';
import { replaceTranco, stampMeta, type TrancoRow } from '../db.js';

const log = pino({ name: 'tranco-downloader' });

export async function refreshTranco(): Promise<number> {
  log.info('Starting Tranco refresh');
  stampMeta('tranco', 0, 'refreshing', 'Downloading Tranco top 1M');

  try {
    const response = await fetch(TRANCO_URL, {
      signal: AbortSignal.timeout(TRANCO_TIMEOUT),
      headers: { 'User-Agent': 'FraudVault/1.0 vuln-feeds' },
    });

    if (!response.ok) {
      throw new Error(`Tranco download failed: HTTP ${response.status}`);
    }

    const zipBuf = Buffer.from(await response.arrayBuffer());

    // The ZIP contains a single CSV file — find and decompress it
    // ZIP local file header: PK\x03\x04, compressed data starts after headers
    // Use a minimal ZIP parser since the archive has one entry using deflate
    let csv = '';
    const localHeaderSig = 0x04034b50;
    const dv = new DataView(zipBuf.buffer, zipBuf.byteOffset, zipBuf.byteLength);

    if (dv.getUint32(0, true) === localHeaderSig) {
      const compressionMethod = dv.getUint16(8, true);
      const compressedSize = dv.getUint32(18, true);
      const fnLen = dv.getUint16(26, true);
      const extraLen = dv.getUint16(28, true);
      const dataOffset = 30 + fnLen + extraLen;
      const compressedData = zipBuf.subarray(dataOffset, dataOffset + compressedSize);

      if (compressionMethod === 8) {
        // Deflate — wrap in zlib raw inflate (negative windowBits)
        const { inflateRawSync } = await import('node:zlib');
        csv = inflateRawSync(compressedData).toString('utf-8');
      } else if (compressionMethod === 0) {
        csv = compressedData.toString('utf-8');
      } else {
        throw new Error(`Unsupported ZIP compression method: ${compressionMethod}`);
      }
    } else {
      // Might be plain gzip or raw CSV
      try {
        csv = gunzipSync(zipBuf).toString('utf-8');
      } catch {
        csv = zipBuf.toString('utf-8');
      }
    }

    const rows: TrancoRow[] = [];
    for (const line of csv.split('\n')) {
      if (!line.trim()) continue;
      const comma = line.indexOf(',');
      if (comma < 0) continue;
      const rank = parseInt(line.slice(0, comma), 10);
      const domain = line.slice(comma + 1).trim().toLowerCase();
      if (isNaN(rank) || !domain || !domain.includes('.')) continue;
      rows.push({ rank, domain });
    }

    const count = replaceTranco(rows);
    log.info('Tranco refresh complete: %d domains', count);
    return count;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    log.error('Tranco refresh failed: %s', msg);
    stampMeta('tranco', 0, 'error', msg.slice(0, 300));
    throw err;
  }
}
