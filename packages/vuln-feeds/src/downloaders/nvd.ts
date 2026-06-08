// ── NVD cvelistV5 ZIP downloader + in-memory streaming + CVE Record 5.x parser
import { inflateRawSync } from 'node:zlib';
import pino from 'pino';
import { NVD_URL, NVD_TIMEOUT } from '../config.js';
import { replaceNvd, replaceCpeMatch, stampMeta, type NvdRow, type CpeMatchRow } from '../db.js';

const log = pino({ name: 'nvd-downloader' });

// ── CVSS metric extraction ──────────────────────────────────────────────────

const METRIC_KEYS: Array<[string, string]> = [
  ['cvssV3_1', '3.1'],
  ['cvssV3_0', '3.0'],
  ['cvssV4_0', '4.0'],
  ['cvssV2_0', '2.0'],
];

interface CvssData {
  baseScore?: number;
  baseSeverity?: string;
  vectorString?: string;
}

interface MetricObj {
  [key: string]: CvssData | undefined;
}

function extractCvss(metrics: MetricObj[]): {
  score: number | null;
  severity: string | null;
  version: string | null;
  vector: string | null;
} | null {
  for (const metricObj of metrics) {
    for (const [key, ver] of METRIC_KEYS) {
      const cvss = metricObj[key] as CvssData | undefined;
      if (cvss) {
        return {
          score: cvss.baseScore ?? null,
          severity: (cvss.baseSeverity ?? '').toUpperCase() || null,
          version: ver,
          vector: cvss.vectorString ?? null,
        };
      }
    }
  }
  return null;
}

// ── CVE Record 5.x parser ───────────────────────────────────────────────────

interface AffectedVersion {
  version?: string;
  lessThan?: string;
  lessThanOrEqual?: string;
  status?: string;
}

interface AffectedEntry {
  vendor?: string;
  product?: string;
  versions?: AffectedVersion[];
}

interface CveRecord {
  cveMetadata?: {
    cveId?: string;
    state?: string;
  };
  containers?: {
    cna?: {
      metrics?: MetricObj[];
      affected?: AffectedEntry[];
      problemTypes?: Array<{
        descriptions?: Array<{ description?: string }>;
      }>;
      references?: Array<{ url?: string }>;
    };
    adp?: Array<{
      metrics?: MetricObj[];
      affected?: AffectedEntry[];
    }>;
  };
}

const CWE_RE = /CWE-\d+/g;

function parseCveRecord(record: CveRecord): NvdRow | null {
  const meta = record.cveMetadata;
  if (!meta?.cveId) return null;
  if (meta.state === 'REJECTED') return null;

  const cve = meta.cveId;
  const cna = record.containers?.cna;

  // Extract CVSS — try CNA first, then ADP
  let cvssResult = cna?.metrics ? extractCvss(cna.metrics) : null;
  if (!cvssResult && record.containers?.adp) {
    for (const adp of record.containers.adp) {
      if (adp.metrics) {
        cvssResult = extractCvss(adp.metrics);
        if (cvssResult) break;
      }
    }
  }

  // Extract CWEs
  const cweSet = new Set<string>();
  if (cna?.problemTypes) {
    for (const pt of cna.problemTypes) {
      for (const desc of pt.descriptions ?? []) {
        const text = desc.description ?? '';
        const matches = text.match(CWE_RE);
        if (matches) {
          for (const m of matches) cweSet.add(m);
        }
      }
    }
  }

  // Extract references (cap at 10)
  const refs: string[] = [];
  if (cna?.references) {
    for (const ref of cna.references) {
      if (ref.url && refs.length < 10) {
        refs.push(ref.url);
      }
    }
  }

  return {
    cve,
    score: cvssResult?.score ?? null,
    severity: cvssResult?.severity ?? null,
    version: cvssResult?.version ?? null,
    vector: cvssResult?.vector ?? null,
    cwes: JSON.stringify([...cweSet]),
    refs: JSON.stringify(refs),
  };
}

// ── CPE match extraction from affected products ────────────────────────────

function normalizeVendor(raw: string): string {
  return raw
    .toLowerCase()
    .replace(/,?\s*(inc\.?|corp\.?|corporation|ltd\.?|llc|systems|software|gmbh|co\.?)$/i, '')
    .replace(/[^a-z0-9\-_]/g, '')
    .trim();
}

function normalizeProduct(raw: string): string {
  return raw
    .toLowerCase()
    .replace(/[^a-z0-9\-_]/g, '_')
    .replace(/_+/g, '_')
    .replace(/^_|_$/g, '')
    .trim();
}

function extractCpeMatches(record: CveRecord): CpeMatchRow[] {
  const cve = record.cveMetadata?.cveId;
  if (!cve) return [];
  if (record.cveMetadata?.state === 'REJECTED') return [];

  const results: CpeMatchRow[] = [];

  // Collect affected entries from CNA and all ADPs
  const affectedSources: AffectedEntry[][] = [];
  if (record.containers?.cna?.affected) {
    affectedSources.push(record.containers.cna.affected);
  }
  if (record.containers?.adp) {
    for (const adp of record.containers.adp) {
      if (adp.affected) {
        affectedSources.push(adp.affected);
      }
    }
  }

  for (const affectedList of affectedSources) {
    for (const entry of affectedList) {
      if (!entry.vendor || !entry.product) continue;

      const vendor = normalizeVendor(entry.vendor);
      const product = normalizeProduct(entry.product);
      if (!vendor || !product) continue;

      const cpePrefix = `cpe:2.3:a:${vendor}:${product}`;

      if (!entry.versions || entry.versions.length === 0) {
        // No version info — the product is broadly affected
        results.push({
          cve,
          cpe_prefix: cpePrefix,
          vendor,
          product,
          version_start: null,
          version_end: null,
          version_exact: null,
        });
        continue;
      }

      for (const ver of entry.versions) {
        if (ver.status === 'unaffected') continue;

        const versionEnd = ver.lessThan ?? ver.lessThanOrEqual ?? null;
        const versionExact = ver.version && !ver.lessThan && !ver.lessThanOrEqual
          ? ver.version
          : null;
        const versionStart = ver.version && (ver.lessThan || ver.lessThanOrEqual)
          ? ver.version
          : null;

        results.push({
          cve,
          cpe_prefix: cpePrefix,
          vendor,
          product,
          version_start: versionStart,
          version_end: versionEnd,
          version_exact: versionExact,
        });
      }
    }
  }

  return results;
}

// ── ZIP processing ──────────────────────────────────────────────────────────

// Minimal ZIP reader that works on a Buffer — reads the central directory
// and extracts individual file entries without writing to disk.

const ZIP_END_SIG = 0x06054b50;
const ZIP64_END_SIG = 0x06064b50;
const ZIP64_LOCATOR_SIG = 0x07064b50;
const ZIP_CD_SIG = 0x02014b50;
const ZIP_LOCAL_SIG = 0x04034b50;

interface ZipEntry {
  fileName: string;
  compressedSize: number;
  uncompressedSize: number;
  compressionMethod: number;
  localHeaderOffset: number;
}

function findEndOfCentralDirectory(buf: Buffer): number {
  // Search backwards for the EOCD signature
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 65557); i--) {
    if (buf.readUInt32LE(i) === ZIP_END_SIG) return i;
  }
  return -1;
}

function readCentralDirectory(buf: Buffer): ZipEntry[] {
  const eocdOffset = findEndOfCentralDirectory(buf);
  if (eocdOffset < 0) throw new Error('Invalid ZIP: EOCD not found');

  let cdOffset: number;
  let totalEntries: number;

  // Check for ZIP64: the EOCD fields may be 0xFFFF/0xFFFFFFFF indicating ZIP64
  const eocdTotalEntries = buf.readUInt16LE(eocdOffset + 10);
  const eocdCdOffset = buf.readUInt32LE(eocdOffset + 16);

  if (eocdTotalEntries === 0xFFFF || eocdCdOffset === 0xFFFFFFFF) {
    // ZIP64 — look for the ZIP64 End of Central Directory Locator (20 bytes before EOCD)
    const zip64LocatorOffset = eocdOffset - 20;
    if (zip64LocatorOffset >= 0 && buf.readUInt32LE(zip64LocatorOffset) === ZIP64_LOCATOR_SIG) {
      // ZIP64 locator contains the offset to the ZIP64 EOCD record
      // Offset is at bytes 8-15 (8 bytes), but for buffers < 4GB we can use 32-bit read
      const zip64EocdOffset = Number(buf.readBigUInt64LE(zip64LocatorOffset + 8));
      if (buf.readUInt32LE(zip64EocdOffset) === ZIP64_END_SIG) {
        totalEntries = Number(buf.readBigUInt64LE(zip64EocdOffset + 32));
        cdOffset = Number(buf.readBigUInt64LE(zip64EocdOffset + 48));
      } else {
        throw new Error('Invalid ZIP64: EOCD64 signature not found');
      }
    } else {
      throw new Error('Invalid ZIP64: locator not found');
    }
  } else {
    totalEntries = eocdTotalEntries;
    cdOffset = eocdCdOffset;
  }

  const entries: ZipEntry[] = [];
  let pos = cdOffset;

  for (let i = 0; i < totalEntries && pos + 46 <= buf.length; i++) {
    if (buf.readUInt32LE(pos) !== ZIP_CD_SIG) break;

    const compressionMethod = buf.readUInt16LE(pos + 10);
    let compressedSize = buf.readUInt32LE(pos + 20);
    let uncompressedSize = buf.readUInt32LE(pos + 24);
    const fileNameLen = buf.readUInt16LE(pos + 28);
    const extraLen = buf.readUInt16LE(pos + 30);
    const commentLen = buf.readUInt16LE(pos + 32);
    let localHeaderOffset = buf.readUInt32LE(pos + 42);

    const fileName = buf.toString('utf-8', pos + 46, pos + 46 + fileNameLen);

    // Parse ZIP64 extra field if any sizes are 0xFFFFFFFF
    if (compressedSize === 0xFFFFFFFF || uncompressedSize === 0xFFFFFFFF || localHeaderOffset === 0xFFFFFFFF) {
      const extraStart = pos + 46 + fileNameLen;
      let ePos = extraStart;
      const extraEnd = extraStart + extraLen;
      while (ePos + 4 <= extraEnd) {
        const headerId = buf.readUInt16LE(ePos);
        const dataSize = buf.readUInt16LE(ePos + 2);
        if (headerId === 0x0001) {
          // ZIP64 extended information
          let fieldOffset = ePos + 4;
          if (uncompressedSize === 0xFFFFFFFF) {
            uncompressedSize = Number(buf.readBigUInt64LE(fieldOffset));
            fieldOffset += 8;
          }
          if (compressedSize === 0xFFFFFFFF) {
            compressedSize = Number(buf.readBigUInt64LE(fieldOffset));
            fieldOffset += 8;
          }
          if (localHeaderOffset === 0xFFFFFFFF) {
            localHeaderOffset = Number(buf.readBigUInt64LE(fieldOffset));
          }
          break;
        }
        ePos += 4 + dataSize;
      }
    }

    entries.push({
      fileName,
      compressedSize,
      uncompressedSize,
      compressionMethod,
      localHeaderOffset,
    });

    pos += 46 + fileNameLen + extraLen + commentLen;
  }

  return entries;
}

function extractEntry(buf: Buffer, entry: ZipEntry): Buffer {
  const localOffset = entry.localHeaderOffset;
  if (buf.readUInt32LE(localOffset) !== ZIP_LOCAL_SIG) {
    throw new Error(`Invalid local header for ${entry.fileName}`);
  }

  const fileNameLen = buf.readUInt16LE(localOffset + 26);
  const extraLen = buf.readUInt16LE(localOffset + 28);
  const dataOffset = localOffset + 30 + fileNameLen + extraLen;

  const compressedData = buf.subarray(dataOffset, dataOffset + entry.compressedSize);

  if (entry.compressionMethod === 0) {
    // Stored (no compression)
    return compressedData;
  } else if (entry.compressionMethod === 8) {
    // Deflated — use raw inflate (no header)
    return inflateRawSync(compressedData);
  } else {
    throw new Error(`Unsupported compression method ${entry.compressionMethod} for ${entry.fileName}`);
  }
}

// ── Main refresh ────────────────────────────────────────────────────────────

export async function refreshNvd(): Promise<number> {
  log.info('Starting NVD/cvelistV5 refresh (this may take several minutes)');
  stampMeta('nvd', 0, 'refreshing', 'Downloading cvelistV5 ZIP (~200MB)');

  try {
    const response = await fetch(NVD_URL, {
      signal: AbortSignal.timeout(NVD_TIMEOUT),
      headers: { 'User-Agent': 'FraudVault/1.0 vuln-feeds' },
    });

    if (!response.ok) {
      throw new Error(`NVD download failed: HTTP ${response.status}`);
    }

    log.info('NVD ZIP download complete, reading into memory');
    stampMeta('nvd', 0, 'refreshing', 'Parsing cvelistV5 ZIP entries');

    const MAX_NVD_SIZE = 2 * 1024 * 1024 * 1024;
    const arrayBuf = await response.arrayBuffer();
    if (arrayBuf.byteLength > MAX_NVD_SIZE) {
      throw new Error(`NVD ZIP exceeds maximum size: ${arrayBuf.byteLength} bytes`);
    }
    const zipBuffer = Buffer.from(arrayBuf);
    log.info('NVD ZIP size: %d MB', Math.round(zipBuffer.length / 1024 / 1024));

    const entries = readCentralDirectory(zipBuffer);
    log.info('NVD ZIP contains %d entries', entries.length);

    const rows: NvdRow[] = [];
    const cpeRows: CpeMatchRow[] = [];
    let parsed = 0;
    let skipped = 0;

    for (const entry of entries) {
      // Only process JSON files containing CVE-
      if (!entry.fileName.endsWith('.json') || !entry.fileName.includes('CVE-')) {
        continue;
      }

      try {
        const content = extractEntry(zipBuffer, entry);
        const record = JSON.parse(content.toString('utf-8')) as CveRecord;
        const row = parseCveRecord(record);
        if (row) {
          rows.push(row);
          parsed++;

          // Also extract CPE match entries from affected products
          const matches = extractCpeMatches(record);
          for (const m of matches) {
            cpeRows.push(m);
          }
        } else {
          skipped++;
        }
      } catch {
        skipped++;
      }

      if ((parsed + skipped) % 50000 === 0) {
        log.info('NVD progress: %d parsed, %d skipped', parsed, skipped);
      }
    }

    log.info('NVD parsing complete: %d CVEs parsed, %d skipped, %d CPE match entries', parsed, skipped, cpeRows.length);
    stampMeta('nvd', 0, 'refreshing', 'Writing NVD data to database');

    const count = replaceNvd(rows);
    log.info('NVD refresh complete: %d entries stored', count);

    // Store CPE match data
    stampMeta('cpe_match', 0, 'refreshing', 'Writing CPE match data to database');
    const cpeCount = replaceCpeMatch(cpeRows);
    log.info('CPE match refresh complete: %d entries stored', cpeCount);

    return count;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    log.error('NVD refresh failed: %s', msg);
    stampMeta('nvd', 0, 'error', msg.slice(0, 300));
    throw err;
  }
}
