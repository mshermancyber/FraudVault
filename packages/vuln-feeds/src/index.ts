// ── Express server with all API endpoints ───────────────────────────────────
import express, { type Request, type Response } from 'express';
import pino from 'pino';
import { FEEDS_PORT, DAILY_REFRESH_TIME, FEED_NAMES, type FeedName } from './config.js';
import { getAllMetaRows, lookupEnriched, lookupKev, lookupEpss, lookupNvd, lookupCpeMatch, getYaraRuleFeedStats, getAllEnabledYaraRules, toggleYaraRule, lookupTrancoBatch, getTrancoAll, getTrancoCount, type CpeLookupResult } from './db.js';
import { startScheduler, checkStartupStaleness, refreshAll, refreshSingle, isRefreshing, getNextRunTime } from './scheduler.js';
import { scoreFindings, type CveFinding } from './scoring.js';

const log = pino({ name: 'vuln-feeds' });
const app = express();

app.use(express.json({ limit: '10mb' }));

// Only gate destructive actions (refresh triggers downloads).
// Read-only endpoints are already behind the API gateway's user auth.
const INTERNAL_KEY = process.env['INTERNAL_API_KEY'];
app.use((req: Request, res: Response, next: () => void) => {
  if (req.path === '/feeds/health' || req.path === '/feeds/status') return next();
  if (!INTERNAL_KEY || req.headers['x-internal-api-key'] !== INTERNAL_KEY) {
    res.status(401).json({ error: 'Unauthorized' });
    return;
  }
  next();
});

// ── GET /feeds/health ───────────────────────────────────────────────────────

app.get('/feeds/health', (_req: Request, res: Response) => {
  res.json({ status: 'ok' });
});

// ── GET /feeds/status ───────────────────────────────────────────────────────

app.get('/feeds/status', (_req: Request, res: Response) => {
  const metaRows = getAllMetaRows();
  const feeds = metaRows.map(row => ({
    name: row.feed,
    updatedAt: row.updated_at,
    rowCount: row.row_count,
    status: row.status,
    detail: row.detail,
  }));

  res.json({
    feeds,
    scheduler: {
      dailyAt: DAILY_REFRESH_TIME,
      nextRun: getNextRunTime(),
      refreshing: isRefreshing(),
    },
  });
});

// ── POST /feeds/kev — batch KEV lookup ──────────────────────────────────────

interface CvesBody {
  cves: string[];
}

const MAX_BATCH_CVES = 500;

const CVE_FORMAT_RE = /^CVE-\d{4}-\d{4,}$/;

function validateCveBatch(body: CvesBody, res: Response): string[] | null {
  const cves = body?.cves;
  if (!Array.isArray(cves)) {
    res.status(400).json({ error: 'Request body must include "cves" array' });
    return null;
  }
  if (cves.length > MAX_BATCH_CVES) {
    res.status(400).json({ error: `Maximum ${MAX_BATCH_CVES} CVEs per batch request` });
    return null;
  }
  for (const cve of cves) {
    if (typeof cve !== 'string' || !CVE_FORMAT_RE.test(cve)) {
      res.status(400).json({ error: `Invalid CVE format: ${String(cve).slice(0, 40)}` });
      return null;
    }
  }
  return cves;
}

app.post('/feeds/kev', (req: Request, res: Response) => {
  const cves = validateCveBatch(req.body as CvesBody, res);
  if (!cves) return;

  const result = lookupKev(cves);
  res.json({ kev: result });
});

// ── POST /feeds/epss — batch EPSS lookup ────────────────────────────────────

app.post('/feeds/epss', (req: Request, res: Response) => {
  const cves = validateCveBatch(req.body as CvesBody, res);
  if (!cves) return;

  const results = lookupEpss(cves);
  res.json({ results });
});

// ── POST /feeds/nvd — batch NVD lookup ──────────────────────────────────────

app.post('/feeds/nvd', (req: Request, res: Response) => {
  const cves = validateCveBatch(req.body as CvesBody, res);
  if (!cves) return;

  const results = lookupNvd(cves);
  res.json({ results });
});

// ── POST /feeds/enriched — batch enriched lookup ────────────────────────────

app.post('/feeds/enriched', (req: Request, res: Response) => {
  const cves = validateCveBatch(req.body as CvesBody, res);
  if (!cves) return;

  const results = lookupEnriched(cves);
  res.json({ results });
});

// ── POST /feeds/cpe-lookup — CPE-based vulnerability lookup ────────────────

interface CpeLookupBody {
  vendor: string;
  product: string;
  version?: string;
}

/**
 * Compare two dot-separated version strings.
 * Returns -1 if a < b, 0 if a == b, 1 if a > b.
 */
function compareVersions(a: string, b: string): number {
  const aParts = a.split('.').map(p => {
    const n = parseInt(p, 10);
    return isNaN(n) ? 0 : n;
  });
  const bParts = b.split('.').map(p => {
    const n = parseInt(p, 10);
    return isNaN(n) ? 0 : n;
  });

  const maxLen = Math.max(aParts.length, bParts.length);
  for (let i = 0; i < maxLen; i++) {
    const av = aParts[i] ?? 0;
    const bv = bParts[i] ?? 0;
    if (av < bv) return -1;
    if (av > bv) return 1;
  }
  return 0;
}

function versionMatchesCpe(submittedVersion: string, result: CpeLookupResult): boolean {
  // If no version constraints, the entry matches all versions
  if (!result.versionExact && !result.versionStart && !result.versionEnd) {
    return true;
  }

  // Exact version match
  if (result.versionExact) {
    return compareVersions(submittedVersion, result.versionExact) === 0;
  }

  // Range match: version_start <= submitted < version_end
  if (result.versionStart) {
    if (compareVersions(submittedVersion, result.versionStart) < 0) {
      return false;
    }
  }
  if (result.versionEnd) {
    if (compareVersions(submittedVersion, result.versionEnd) >= 0) {
      return false;
    }
  }

  return true;
}

// ── Endoflife / Tech Debt lookup ────────────────────────────────────────────

app.post('/feeds/endoflife', (req: Request, res: Response) => {
  const body = req.body as { product?: string };
  if (!body?.product) {
    res.status(400).json({ error: 'Request body must include "product" string' });
    return;
  }

  const { lookupEndoflife } = require('./db.js') as { lookupEndoflife: (p: string) => Array<{ product: string; cycle: string; latest: string; eol: string; lts: string; release_date: string }> };
  const rows = lookupEndoflife(body.product);

  if (rows.length === 0) {
    res.json({ found: false, product: body.product, cycles: [] });
    return;
  }

  const cycles = rows.map(r => ({
    cycle: r.cycle,
    latest: r.latest,
    eol: r.eol === 'true' ? true : r.eol === 'false' ? false : r.eol,
    lts: r.lts === 'true',
    releaseDate: r.release_date,
  }));

  res.json({ found: true, product: body.product, latestVersion: rows[0]?.latest ?? null, cycles });
});

// ── CPE Lookup ────────────────────────────────────────────────────────────────

app.post('/feeds/cpe-lookup', (req: Request, res: Response) => {
  const body = req.body as CpeLookupBody;
  if (!body?.vendor || !body?.product) {
    res.status(400).json({ error: 'Request body must include "vendor" and "product" strings' });
    return;
  }

  const vendor = body.vendor.toLowerCase().trim();
  const product = body.product.toLowerCase().trim();
  const submittedVersion = body.version?.trim() ?? null;

  let results = lookupCpeMatch(vendor, product);

  // Filter by version if provided
  if (submittedVersion) {
    results = results.filter(r => versionMatchesCpe(submittedVersion, r));
  }

  // Deduplicate by CVE (same CVE may appear from multiple cpe_match rows)
  const seen = new Set<string>();
  const deduped: CpeLookupResult[] = [];
  for (const r of results) {
    if (!seen.has(r.cve)) {
      seen.add(r.cve);
      deduped.push(r);
    }
  }

  // Sort by severity: CRITICAL > HIGH > MEDIUM > LOW > unknown, then by score desc
  const severityOrder: Record<string, number> = {
    CRITICAL: 0,
    HIGH: 1,
    MEDIUM: 2,
    LOW: 3,
  };
  deduped.sort((a, b) => {
    const aOrd = severityOrder[(a.severity ?? '').toUpperCase()] ?? 4;
    const bOrd = severityOrder[(b.severity ?? '').toUpperCase()] ?? 4;
    if (aOrd !== bOrd) return aOrd - bOrd;
    return (b.score ?? 0) - (a.score ?? 0);
  });

  res.json({
    results: deduped.map(r => ({
      cve: r.cve,
      score: r.score,
      severity: r.severity,
      kev: r.kev,
      kevDueDate: r.kevDueDate,
      epss: r.epss,
      epssPercentile: r.epssPercentile,
      version: r.version,
      vector: r.vector,
      cwes: r.cwes,
      refs: r.refs,
    })),
  });
});

// ── GET /feeds/yara — YARA rule stats and rules ────────────────────────────

app.get('/feeds/yara/stats', (_req: Request, res: Response) => {
  const stats = getYaraRuleFeedStats();
  const total = stats.reduce((sum, s) => sum + s.count, 0);
  res.json({ total, sources: stats });
});

app.get('/feeds/yara/rules', (_req: Request, res: Response) => {
  const rules = getAllEnabledYaraRules();
  res.json({ count: rules.length, rules });
});

app.post('/feeds/yara/toggle', (req: Request, res: Response) => {
  const { name, source, enabled } = req.body as { name?: string; source?: string; enabled?: boolean };
  if (!name || !source || typeof enabled !== 'boolean') {
    res.status(400).json({ error: 'name, source, and enabled required' });
    return;
  }
  toggleYaraRule(name, source, enabled);
  res.json({ ok: true });
});

// ── POST /feeds/tranco — batch Tranco domain lookup ────────────────────────

app.post('/feeds/tranco', (req: Request, res: Response) => {
  const body = req.body as { domains?: string[] };
  if (!Array.isArray(body?.domains)) {
    res.status(400).json({ error: 'Request body must include "domains" array' });
    return;
  }
  if (body.domains.length > 1000) {
    res.status(400).json({ error: 'Maximum 1000 domains per batch request' });
    return;
  }
  const results = lookupTrancoBatch(body.domains);
  res.json({ results });
});

// ── GET /feeds/tranco/count — Tranco row count ─────────────────────────────

app.get('/feeds/tranco/count', (_req: Request, res: Response) => {
  res.json({ count: getTrancoCount() });
});

// ── GET /feeds/tranco/all — full Tranco dump ───────────────────────────────

app.get('/feeds/tranco/all', (_req: Request, res: Response) => {
  const rows = getTrancoAll();
  res.json({ count: rows.length, rows });
});

// ── POST /feeds/refresh — manual trigger ────────────────────────────────────

const VALID_FEEDS = new Set<string>([...FEED_NAMES, 'all']);

app.post('/feeds/refresh', (req: Request, res: Response) => {
  const feed = (req.query['feed'] as string) ?? 'all';

  if (!VALID_FEEDS.has(feed)) {
    res.status(400).json({ error: `Invalid feed: ${feed}. Must be one of: ${[...VALID_FEEDS].join(', ')}` });
    return;
  }

  if (isRefreshing()) {
    res.status(409).json({ started: false, reason: 'Refresh already in progress' });
    return;
  }

  // Fire and forget
  if (feed === 'all') {
    refreshAll().catch(err => {
      const msg = err instanceof Error ? err.message : String(err);
      log.error('Manual full refresh failed: %s', msg);
    });
  } else {
    refreshSingle(feed as FeedName).catch(err => {
      const msg = err instanceof Error ? err.message : String(err);
      log.error('Manual %s refresh failed: %s', feed, msg);
    });
  }

  res.json({ started: true });
});

// ── POST /feeds/score — risk scoring ────────────────────────────────────────

interface ScoreBody {
  findings: CveFinding[];
}

app.post('/feeds/score', (req: Request, res: Response) => {
  const body = req.body as ScoreBody;
  const findings = body?.findings;
  if (!Array.isArray(findings)) {
    res.status(400).json({ error: 'Request body must include "findings" array' });
    return;
  }

  const result = scoreFindings(findings);
  res.json(result);
});

// ── Start server ────────────────────────────────────────────────────────────

app.listen(FEEDS_PORT, '0.0.0.0', () => {
  log.info('Vulnerability feeds service listening on port %d', FEEDS_PORT);

  // Start the daily scheduler
  startScheduler();

  // Check staleness and trigger background refresh if needed (non-blocking)
  checkStartupStaleness();
});
