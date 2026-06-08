// ── SQLite setup, WAL mode, schema creation, batch lookups ──────────────────
import Database from 'better-sqlite3';
import path from 'node:path';
import fs from 'node:fs';
import pino from 'pino';
import { DB_PATH, BUSY_TIMEOUT_MS, FEED_NAMES, type FeedName, type FeedStatus } from './config.js';

const log = pino({ name: 'db' });

function safeJsonArray(val: string | null | undefined): string[] {
  try {
    const parsed = JSON.parse(val ?? '[]');
    return Array.isArray(parsed) ? parsed : [];
  } catch { return []; }
}

// Ensure directory exists
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

const db: InstanceType<typeof Database> = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('synchronous = NORMAL');
db.pragma(`busy_timeout = ${BUSY_TIMEOUT_MS}`);

// ── Schema creation ─────────────────────────────────────────────────────────

db.exec(`
  CREATE TABLE IF NOT EXISTS kev (
    cve TEXT PRIMARY KEY,
    due_date TEXT,
    name TEXT
  );

  CREATE TABLE IF NOT EXISTS epss (
    cve TEXT PRIMARY KEY,
    epss REAL,
    percentile REAL
  );

  CREATE TABLE IF NOT EXISTS nvd (
    cve TEXT PRIMARY KEY,
    score REAL,
    severity TEXT,
    version TEXT,
    vector TEXT,
    cwes TEXT,
    refs TEXT
  );

  CREATE TABLE IF NOT EXISTS meta (
    feed TEXT PRIMARY KEY,
    updated_at TEXT,
    row_count INTEGER,
    status TEXT,
    detail TEXT
  );

  CREATE TABLE IF NOT EXISTS cve_enriched (
    cve TEXT PRIMARY KEY,
    kev INTEGER NOT NULL DEFAULT 0,
    kev_due_date TEXT,
    epss REAL,
    epss_percentile REAL,
    score REAL,
    severity TEXT,
    version TEXT,
    vector TEXT,
    cwes TEXT,
    refs TEXT
  );

  CREATE TABLE IF NOT EXISTS cpe_match (
    cve TEXT NOT NULL,
    cpe_prefix TEXT NOT NULL,
    vendor TEXT,
    product TEXT,
    version_start TEXT,
    version_end TEXT,
    version_exact TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_cpe_match_prefix ON cpe_match(cpe_prefix);
  CREATE INDEX IF NOT EXISTS idx_cpe_match_cve ON cpe_match(cve);
  CREATE INDEX IF NOT EXISTS idx_cpe_match_vendor_product ON cpe_match(vendor, product);

  CREATE TABLE IF NOT EXISTS endoflife (
    product TEXT NOT NULL,
    cycle TEXT NOT NULL,
    latest TEXT,
    eol TEXT,
    lts TEXT,
    release_date TEXT,
    PRIMARY KEY (product, cycle)
  );
  CREATE INDEX IF NOT EXISTS idx_endoflife_product ON endoflife(product);

  CREATE TABLE IF NOT EXISTS tranco (
    rank INTEGER NOT NULL,
    domain TEXT PRIMARY KEY
  );
  CREATE INDEX IF NOT EXISTS idx_tranco_rank ON tranco(rank);

  CREATE TABLE IF NOT EXISTS yara_rules_feed (
    name TEXT NOT NULL,
    source TEXT NOT NULL,
    category TEXT,
    severity TEXT,
    rule_text TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (name, source)
  );
  CREATE INDEX IF NOT EXISTS idx_yara_feed_source ON yara_rules_feed(source);
  CREATE INDEX IF NOT EXISTS idx_yara_feed_enabled ON yara_rules_feed(enabled);
`);

// Seed meta rows
const upsertMeta = db.prepare(
  `INSERT OR IGNORE INTO meta (feed, updated_at, row_count, status, detail)
   VALUES (?, NULL, 0, 'empty', NULL)`
);
for (const name of FEED_NAMES) {
  upsertMeta.run(name);
}

log.info('Database initialized at %s', DB_PATH);

// ── Meta helpers ────────────────────────────────────────────────────────────

export interface MetaRow {
  feed: string;
  updated_at: string | null;
  row_count: number;
  status: FeedStatus;
  detail: string | null;
}

const getMeta = db.prepare<[string], MetaRow>('SELECT * FROM meta WHERE feed = ?');
const getAllMeta = db.prepare<[], MetaRow>('SELECT * FROM meta ORDER BY feed');
const setMetaStmt = db.prepare<[string, number, string, string | null, string]>(
  `UPDATE meta SET updated_at = ?, row_count = ?, status = ?, detail = ? WHERE feed = ?`
);

export function getMetaRow(feed: FeedName): MetaRow | undefined {
  return getMeta.get(feed);
}

export function getAllMetaRows(): MetaRow[] {
  return getAllMeta.all();
}

export function stampMeta(feed: FeedName, rowCount: number, status: FeedStatus, detail?: string): void {
  setMetaStmt.run(new Date().toISOString(), rowCount, status, detail ?? null, feed);
}

// ── Wholesale replace helpers ───────────────────────────────────────────────

export interface KevRow {
  cve: string;
  due_date: string;
  name: string;
}

export interface EpssRow {
  cve: string;
  epss: number;
  percentile: number;
}

export interface NvdRow {
  cve: string;
  score: number | null;
  severity: string | null;
  version: string | null;
  vector: string | null;
  cwes: string | null;
  refs: string | null;
}

export interface CpeMatchRow {
  cve: string;
  cpe_prefix: string;
  vendor: string | null;
  product: string | null;
  version_start: string | null;
  version_end: string | null;
  version_exact: string | null;
}

export function replaceCpeMatch(rows: CpeMatchRow[]): number {
  const insert = db.prepare(
    'INSERT INTO cpe_match (cve, cpe_prefix, vendor, product, version_start, version_end, version_exact) VALUES (?, ?, ?, ?, ?, ?, ?)'
  );
  const tx = db.transaction(() => {
    db.exec('DELETE FROM cpe_match');
    for (const r of rows) {
      insert.run(r.cve, r.cpe_prefix, r.vendor, r.product, r.version_start, r.version_end, r.version_exact);
    }
    stampMeta('cpe_match', rows.length, 'ready');
  });
  tx();
  return rows.length;
}

export function replaceKev(rows: KevRow[]): number {
  const insert = db.prepare('INSERT INTO kev (cve, due_date, name) VALUES (?, ?, ?)');
  const tx = db.transaction(() => {
    db.exec('DELETE FROM kev');
    for (const r of rows) {
      insert.run(r.cve, r.due_date, r.name);
    }
    stampMeta('kev', rows.length, 'ready');
  });
  tx();
  return rows.length;
}

export function replaceEpss(rows: EpssRow[]): number {
  const insert = db.prepare('INSERT INTO epss (cve, epss, percentile) VALUES (?, ?, ?)');
  const tx = db.transaction(() => {
    db.exec('DELETE FROM epss');
    for (const r of rows) {
      insert.run(r.cve, r.epss, r.percentile);
    }
    stampMeta('epss', rows.length, 'ready');
  });
  tx();
  return rows.length;
}

export function replaceNvd(rows: NvdRow[]): number {
  const insert = db.prepare(
    'INSERT INTO nvd (cve, score, severity, version, vector, cwes, refs) VALUES (?, ?, ?, ?, ?, ?, ?)'
  );
  const tx = db.transaction(() => {
    db.exec('DELETE FROM nvd');
    for (const r of rows) {
      insert.run(r.cve, r.score, r.severity, r.version, r.vector, r.cwes, r.refs);
    }
    stampMeta('nvd', rows.length, 'ready');
  });
  tx();
  return rows.length;
}

export interface EndoflifeRow {
  product: string;
  cycle: string;
  latest: string;
  eol: string;
  lts: string;
  release_date: string;
}

export function replaceEndoflife(rows: EndoflifeRow[]): number {
  const insert = db.prepare('INSERT OR REPLACE INTO endoflife (product, cycle, latest, eol, lts, release_date) VALUES (?, ?, ?, ?, ?, ?)');
  const tx = db.transaction(() => {
    db.exec('DELETE FROM endoflife');
    for (const r of rows) {
      insert.run(r.product, r.cycle, r.latest, r.eol, r.lts, r.release_date);
    }
    stampMeta('endoflife', rows.length, 'ready');
  });
  tx();
  return rows.length;
}

interface EndoflifeQueryRow {
  product: string;
  cycle: string;
  latest: string;
  eol: string;
  lts: string;
  release_date: string;
}

export function lookupEndoflife(product: string): EndoflifeQueryRow[] {
  return db.prepare<[string], EndoflifeQueryRow>(
    'SELECT * FROM endoflife WHERE product = ? ORDER BY release_date DESC'
  ).all(product);
}

// ── Enriched table build ────────────────────────────────────────────────────

export function buildEnrichedTable(): number {
  const tx = db.transaction(() => {
    db.exec('DELETE FROM cve_enriched');
    db.exec(`
      INSERT INTO cve_enriched (cve, kev, kev_due_date, epss, epss_percentile, score, severity, version, vector, cwes, refs)
      SELECT
        c.cve,
        CASE WHEN k.cve IS NOT NULL THEN 1 ELSE 0 END,
        k.due_date,
        e.epss,
        e.percentile,
        n.score,
        n.severity,
        n.version,
        n.vector,
        n.cwes,
        n.refs
      FROM (
        SELECT cve FROM nvd
        UNION
        SELECT cve FROM epss
        UNION
        SELECT cve FROM kev
      ) c
      LEFT JOIN kev k ON k.cve = c.cve
      LEFT JOIN epss e ON e.cve = c.cve
      LEFT JOIN nvd n ON n.cve = c.cve
    `);
    const countRow = db.prepare<[], { cnt: number }>('SELECT COUNT(*) AS cnt FROM cve_enriched').get();
    const count = countRow?.cnt ?? 0;
    stampMeta('enriched', count, 'ready');
    return count;
  });
  return tx();
}

// ── Batch lookups with 900-item chunking ────────────────────────────────────

function chunked<T>(arr: T[], size: number): T[][] {
  const result: T[][] = [];
  for (let i = 0; i < arr.length; i += size) {
    result.push(arr.slice(i, i + size));
  }
  return result;
}

const CHUNK_SIZE = 900;

export interface EnrichedResult {
  kev: boolean;
  kevDueDate: string | null;
  epss: number | null;
  percentile: number | null;
  score: number | null;
  severity: string | null;
  version: string | null;
  vector: string | null;
  cwes: string[];
  refs: string[];
}

interface EnrichedRow {
  cve: string;
  kev: number;
  kev_due_date: string | null;
  epss: number | null;
  epss_percentile: number | null;
  score: number | null;
  severity: string | null;
  version: string | null;
  vector: string | null;
  cwes: string | null;
  refs: string | null;
}

export function lookupEnriched(cves: string[]): Record<string, EnrichedResult> {
  const results: Record<string, EnrichedResult> = {};
  for (const chunk of chunked(cves, CHUNK_SIZE)) {
    const placeholders = chunk.map(() => '?').join(',');
    const rows = db.prepare<string[], EnrichedRow>(
      `SELECT * FROM cve_enriched WHERE cve IN (${placeholders})`
    ).all(...chunk);
    for (const row of rows) {
      results[row.cve] = {
        kev: row.kev === 1,
        kevDueDate: row.kev_due_date,
        epss: row.epss,
        percentile: row.epss_percentile,
        score: row.score,
        severity: row.severity,
        version: row.version,
        vector: row.vector,
        cwes: safeJsonArray(row.cwes),
        refs: safeJsonArray(row.refs),
      };
    }
  }
  return results;
}

export function lookupKev(cves: string[]): string[] {
  const results: string[] = [];
  for (const chunk of chunked(cves, CHUNK_SIZE)) {
    const placeholders = chunk.map(() => '?').join(',');
    const rows = db.prepare<string[], { cve: string }>(
      `SELECT cve FROM kev WHERE cve IN (${placeholders})`
    ).all(...chunk);
    for (const row of rows) {
      results.push(row.cve);
    }
  }
  return results;
}

interface EpssResult {
  epss: number;
  percentile: number;
}

export function lookupEpss(cves: string[]): Record<string, EpssResult> {
  const results: Record<string, EpssResult> = {};
  for (const chunk of chunked(cves, CHUNK_SIZE)) {
    const placeholders = chunk.map(() => '?').join(',');
    const rows = db.prepare<string[], { cve: string; epss: number; percentile: number }>(
      `SELECT cve, epss, percentile FROM epss WHERE cve IN (${placeholders})`
    ).all(...chunk);
    for (const row of rows) {
      results[row.cve] = { epss: row.epss, percentile: row.percentile };
    }
  }
  return results;
}

interface NvdResult {
  score: number | null;
  severity: string | null;
  version: string | null;
  vector: string | null;
  cwes: string[];
  refs: string[];
}

export function lookupNvd(cves: string[]): Record<string, NvdResult> {
  const results: Record<string, NvdResult> = {};
  for (const chunk of chunked(cves, CHUNK_SIZE)) {
    const placeholders = chunk.map(() => '?').join(',');
    const rows = db.prepare<string[], NvdRow>(
      `SELECT * FROM nvd WHERE cve IN (${placeholders})`
    ).all(...chunk);
    for (const row of rows) {
      results[row.cve] = {
        score: row.score,
        severity: row.severity,
        version: row.version,
        vector: row.vector,
        cwes: safeJsonArray(row.cwes),
        refs: safeJsonArray(row.refs),
      };
    }
  }
  return results;
}

// ── CPE match lookup ───────────────────────────────────────────────────────

export interface CpeLookupResult {
  cve: string;
  score: number | null;
  severity: string | null;
  kev: boolean;
  kevDueDate: string | null;
  epss: number | null;
  epssPercentile: number | null;
  version: string | null;
  vector: string | null;
  cwes: string[];
  refs: string[];
  versionStart: string | null;
  versionEnd: string | null;
  versionExact: string | null;
}

interface CpeLookupRow {
  cve: string;
  score: number | null;
  severity: string | null;
  kev: number;
  kev_due_date: string | null;
  epss: number | null;
  epss_percentile: number | null;
  version: string | null;
  vector: string | null;
  cwes: string | null;
  refs: string | null;
  version_start: string | null;
  version_end: string | null;
  version_exact: string | null;
}

/**
 * Lookup CVEs matching a vendor+product from the cpe_match table,
 * joined with cve_enriched for full severity/KEV/EPSS details.
 */
export function lookupCpeMatch(vendor: string, product: string): CpeLookupResult[] {
  let rows = db.prepare<[string, string], CpeLookupRow>(`
    SELECT
      cm.cve,
      ce.score,
      ce.severity,
      COALESCE(ce.kev, 0) AS kev,
      ce.kev_due_date,
      ce.epss,
      ce.epss_percentile,
      ce.version,
      ce.vector,
      ce.cwes,
      ce.refs,
      cm.version_start,
      cm.version_end,
      cm.version_exact
    FROM cpe_match cm
    LEFT JOIN cve_enriched ce ON ce.cve = cm.cve
    WHERE cm.vendor = ? AND cm.product = ?
  `).all(vendor, product);

  if (rows.length === 0) {
    rows = db.prepare<[string], CpeLookupRow>(`
      SELECT
        cm.cve,
        ce.score,
        ce.severity,
        COALESCE(ce.kev, 0) AS kev,
        ce.kev_due_date,
        ce.epss,
        ce.epss_percentile,
        ce.version,
        ce.vector,
        ce.cwes,
        ce.refs,
        cm.version_start,
        cm.version_end,
        cm.version_exact
      FROM cpe_match cm
      LEFT JOIN cve_enriched ce ON ce.cve = cm.cve
      WHERE cm.product = ?
    `).all(product);
  }

  return rows.map((row: any) => ({
    cve: row.cve,
    score: row.score,
    severity: row.severity,
    kev: row.kev === 1,
    kevDueDate: row.kev_due_date,
    epss: row.epss,
    epssPercentile: row.epss_percentile,
    version: row.version,
    vector: row.vector,
    cwes: safeJsonArray(row.cwes),
    refs: safeJsonArray(row.refs),
    versionStart: row.version_start,
    versionEnd: row.version_end,
    versionExact: row.version_exact,
  }));
}

// ── YARA rules feed ─────────────────────────────────────────────────────────

export interface YaraRuleFeedRow {
  name: string;
  source: string;
  category: string | null;
  severity: string | null;
  rule_text: string;
  enabled: number;
}

export function replaceYaraRulesForSource(source: string, rules: Array<{ name: string; category: string | null; severity: string | null; ruleText: string }>): number {
  const insert = db.prepare(
    'INSERT OR REPLACE INTO yara_rules_feed (name, source, category, severity, rule_text, enabled) VALUES (?, ?, ?, ?, ?, 1)'
  );
  const tx = db.transaction(() => {
    db.prepare('DELETE FROM yara_rules_feed WHERE source = ?').run(source);
    for (const r of rules) {
      insert.run(r.name, source, r.category, r.severity, r.ruleText);
    }
  });
  tx();
  return rules.length;
}

export function getYaraRuleFeedCount(): number {
  const row = db.prepare('SELECT count(*) as cnt FROM yara_rules_feed WHERE enabled = 1').get() as { cnt: number } | undefined;
  return row?.cnt ?? 0;
}

export function getYaraRuleFeedStats(): Array<{ source: string; count: number }> {
  return db.prepare('SELECT source, count(*) as count FROM yara_rules_feed WHERE enabled = 1 GROUP BY source ORDER BY count DESC').all() as Array<{ source: string; count: number }>;
}

export function getAllEnabledYaraRules(): Array<{ name: string; source: string; ruleText: string }> {
  return db.prepare('SELECT name, source, rule_text as ruleText FROM yara_rules_feed WHERE enabled = 1').all() as Array<{ name: string; source: string; ruleText: string }>;
}

export function toggleYaraRule(name: string, source: string, enabled: boolean): void {
  db.prepare('UPDATE yara_rules_feed SET enabled = ? WHERE name = ? AND source = ?').run(enabled ? 1 : 0, name, source);
}

export function purgeStaleYaraSources(activeSources: string[]): number {
  const placeholders = activeSources.map(() => '?').join(',');
  const result = db.prepare(`DELETE FROM yara_rules_feed WHERE source NOT IN (${placeholders})`).run(...activeSources);
  return result.changes;
}

// ── Tranco domain popularity ───────────────────────────────────────────────

export interface TrancoRow {
  rank: number;
  domain: string;
}

export function replaceTranco(rows: TrancoRow[]): number {
  const insert = db.prepare('INSERT INTO tranco (rank, domain) VALUES (?, ?)');
  const tx = db.transaction(() => {
    db.exec('DELETE FROM tranco');
    for (const r of rows) {
      insert.run(r.rank, r.domain);
    }
    stampMeta('tranco', rows.length, 'ready');
  });
  tx();
  return rows.length;
}

export function lookupTrancoBatch(domains: string[]): Record<string, number> {
  const results: Record<string, number> = {};
  for (const chunk of chunked(domains, CHUNK_SIZE)) {
    const placeholders = chunk.map(() => '?').join(',');
    const rows = db.prepare<string[], { domain: string; rank: number }>(
      `SELECT domain, rank FROM tranco WHERE domain IN (${placeholders})`
    ).all(...chunk);
    for (const row of rows) {
      results[row.domain] = row.rank;
    }
  }
  return results;
}

export function getTrancoAll(): TrancoRow[] {
  return db.prepare<[], TrancoRow>('SELECT domain, rank FROM tranco ORDER BY rank').all();
}

export function getTrancoCount(): number {
  const row = db.prepare<[], { cnt: number }>('SELECT count(*) as cnt FROM tranco').get();
  return row?.cnt ?? 0;
}

export { db };
