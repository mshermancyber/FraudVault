// ── Configuration constants ──────────────────────────────────────────────────

// Download timeouts (milliseconds)
export const KEV_TIMEOUT = 30_000;
export const EPSS_TIMEOUT = 60_000;
export const NVD_TIMEOUT = 600_000;
export const OSV_PER_ZIP_TIMEOUT = 600_000;

// Scheduler
export const DAILY_REFRESH_TIME = process.env['DAILY_REFRESH_TIME'] ?? '03:15';
export const STALE_HOURS = Number(process.env['STALE_HOURS'] ?? '24');

// SQLite
export const DB_PATH = process.env['DB_PATH'] ?? '/data/feeds.db';
export const BUSY_TIMEOUT_MS = 30_000;

// OSV
export const OSV_CACHE_DIR = process.env['OSV_CACHE_DIR'] ?? '/data/osv-cache';
export const OSV_BUCKET_BASE = 'https://osv-vulnerabilities.storage.googleapis.com';

// Feeds API
export const FEEDS_PORT = Number(process.env['FEEDS_PORT'] ?? '9000');

// Risk scoring
export const RISK_CEILING = 2000;
export const KEV_MIN_SCORE = 250;

// Feed source URLs
export const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
export const EPSS_URL = 'https://epss.cyentia.com/epss_scores-current.csv.gz';
export const NVD_URL = 'https://github.com/CVEProject/cvelistV5/archive/refs/heads/main.zip';

// YARA rule sources — gold-standard rulesets only
export const YARA_SOURCES = [
  { name: 'yara-forge', url: 'https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip', subdir: '' },
  { name: 'elastic', url: 'https://github.com/elastic/protections-artifacts/archive/refs/heads/main.zip', subdir: 'yara' },
  { name: 'eset', url: 'https://github.com/eset/malware-ioc/archive/refs/heads/master.zip', subdir: '' },
  { name: 'reversinglabs', url: 'https://github.com/reversinglabs/reversinglabs-yara-rules/archive/refs/heads/develop.zip', subdir: 'yara' },
  { name: 'mandiant', url: 'https://github.com/mandiant/red_team_tool_countermeasures/archive/refs/heads/master.zip', subdir: 'rules' },
];
export const YARA_TIMEOUT = 120_000;
export const YARA_REFRESH_CRON = process.env['YARA_REFRESH_CRON'] ?? '0 4 * * 0'; // Weekly Sunday 4am

// Tranco domain popularity list
export const TRANCO_URL = process.env['TRANCO_URL'] ?? 'https://tranco-list.eu/top-1m.csv.zip';
export const TRANCO_TIMEOUT = 120_000;

// Feed names
export const FEED_NAMES = ['kev', 'epss', 'nvd', 'osv', 'cpe_match', 'endoflife', 'enriched', 'yara_rules', 'tranco'] as const;
export type FeedName = (typeof FEED_NAMES)[number];
export type FeedStatus = 'empty' | 'refreshing' | 'ready' | 'error';
