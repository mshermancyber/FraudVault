// ── Daily refresh, startup staleness check, serialized execution with mutex ─
import cron from 'node-cron';
import pino from 'pino';
import { DAILY_REFRESH_TIME, YARA_REFRESH_CRON, STALE_HOURS, type FeedName } from './config.js';
import { getMetaRow } from './db.js';
import { refreshKev } from './downloaders/kev.js';
import { refreshEpss } from './downloaders/epss.js';
import { refreshNvd } from './downloaders/nvd.js';
import { refreshOsv } from './downloaders/osv.js';
import { refreshCpeMatch } from './downloaders/nvd-cpe.js';
import { refreshEndoflife } from './downloaders/endoflife.js';
import { refreshEnriched } from './enriched.js';
import { refreshYaraRules } from './downloaders/yara.js';
import { refreshTranco } from './downloaders/tranco.js';

const log = pino({ name: 'scheduler' });

// ── Mutex ───────────────────────────────────────────────────────────────────

let refreshInProgress = false;

export function isRefreshing(): boolean {
  return refreshInProgress;
}

// ── Staleness detection ─────────────────────────────────────────────────────

function isStale(feed: FeedName): boolean {
  const meta = getMetaRow(feed);
  if (!meta || meta.row_count === 0) return true;
  if (!meta.updated_at) return true;
  const age = Date.now() - new Date(meta.updated_at).getTime();
  return age > STALE_HOURS * 3600 * 1000;
}

// ── Refresh runners ─────────────────────────────────────────────────────────

type FeedRefresher = () => Promise<number>;

const FEED_REFRESHERS: Record<string, FeedRefresher> = {
  kev: refreshKev,
  epss: refreshEpss,
  nvd: refreshNvd,
  osv: refreshOsv,
  cpe_match: refreshCpeMatch,
  endoflife: refreshEndoflife,
  enriched: refreshEnriched,
  yara_rules: async () => { await refreshYaraRules(); return 0; },
  tranco: refreshTranco,
};

async function runRefresh(feed: FeedName): Promise<void> {
  const refresher = FEED_REFRESHERS[feed];
  if (!refresher) {
    log.warn('Unknown feed: %s', feed);
    return;
  }

  try {
    await refresher();
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    log.error('Feed %s refresh failed: %s', feed, msg);
    // Error already stamped in individual refreshers — do not crash
  }
}

export async function refreshAll(): Promise<void> {
  if (refreshInProgress) {
    log.warn('Refresh already in progress, skipping');
    return;
  }

  refreshInProgress = true;
  try {
    log.info('Starting full refresh cycle');
    // Refresh in order: kev, epss, nvd (also populates cpe_match), osv, then enriched last
    await runRefresh('kev');
    await runRefresh('epss');
    await runRefresh('nvd');
    await runRefresh('cpe_match');
    await runRefresh('osv');
    await runRefresh('endoflife');
    await runRefresh('tranco');
    await runRefresh('enriched');
    log.info('Full refresh cycle complete');
  } finally {
    refreshInProgress = false;
  }
}

export async function refreshSingle(feed: FeedName): Promise<void> {
  if (refreshInProgress) {
    log.warn('Refresh already in progress, skipping %s', feed);
    return;
  }

  refreshInProgress = true;
  try {
    await runRefresh(feed);
    // If we just refreshed kev/epss/nvd, also rebuild enriched
    if (feed !== 'osv' && feed !== 'enriched') {
      await runRefresh('enriched');
    }
  } finally {
    refreshInProgress = false;
  }
}

// ── Startup staleness check ─────────────────────────────────────────────────

export function checkStartupStaleness(): void {
  const anyStale = isStale('kev') || isStale('epss') || isStale('nvd') || isStale('osv');
  if (anyStale) {
    log.info('Stale feeds detected at startup — triggering background refresh');
    // Fire and forget — do NOT block startup
    refreshAll().catch(err => {
      const msg = err instanceof Error ? err.message : String(err);
      log.error('Background startup refresh failed: %s', msg);
    });
  } else {
    log.info('All feeds are fresh — no startup refresh needed');
  }
}

// ── Daily schedule ──────────────────────────────────────────────────────────

export function startScheduler(): void {
  // Parse HH:MM
  const parts = DAILY_REFRESH_TIME.split(':');
  const hour = parts[0] ?? '3';
  const minute = parts[1] ?? '15';

  // node-cron format: minute hour * * *
  const cronExpr = `${minute} ${hour} * * *`;

  log.info('Scheduling daily refresh at %s (cron: %s)', DAILY_REFRESH_TIME, cronExpr);

  cron.schedule(cronExpr, () => {
    log.info('Daily scheduled refresh triggered');
    refreshAll().catch(err => {
      const msg = err instanceof Error ? err.message : String(err);
      log.error('Scheduled refresh failed: %s', msg);
    });
  });

  // Weekly YARA rule refresh
  log.info('Scheduling weekly YARA refresh (cron: %s)', YARA_REFRESH_CRON);
  cron.schedule(YARA_REFRESH_CRON, () => {
    log.info('Weekly YARA refresh triggered');
    refreshYaraRules().catch(err => {
      const msg = err instanceof Error ? err.message : String(err);
      log.error('YARA refresh failed: %s', msg);
    });
  });
}

export function getNextRunTime(): string {
  const now = new Date();
  const parts = DAILY_REFRESH_TIME.split(':');
  const hour = parseInt(parts[0] ?? '3', 10);
  const minute = parseInt(parts[1] ?? '15', 10);

  const next = new Date(now);
  next.setHours(hour, minute, 0, 0);

  // If the time has already passed today, schedule for tomorrow
  if (next.getTime() <= now.getTime()) {
    next.setDate(next.getDate() + 1);
  }

  return next.toISOString();
}
