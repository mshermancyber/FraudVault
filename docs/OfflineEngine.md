# OfflineEngine.md — Implementation spec for offline vulnerability data pipeline

This document is written for LLM coding agents. It describes the implemented system at `packages/vuln-feeds/`. Build compatible services using this spec; do not copy code directly.

---

## What this system does

Downloads six public vulnerability/exploit data sources to local SQLite storage on a daily schedule, joins them into a single denormalized lookup table, and exposes batch HTTP endpoints so the scanner can enrich findings with zero live network calls at scan time.

---

## Data sources

| Source | What it is | URL | Format | Approx Size |
|--------|-----------|-----|--------|-------------|
| **KEV** | CISA Known Exploited Vulnerabilities catalog | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | JSON | ~50 KB |
| **EPSS** | Exploit Prediction Scoring System (daily scores) | `https://epss.cyentia.com/epss_scores-current.csv.gz` | gzipped CSV | ~100 MB uncompressed |
| **NVD/cvelistV5** | Full CVE corpus (MITRE CVE Record 5.x format) | `https://github.com/CVEProject/cvelistV5/archive/refs/heads/main.zip` | ZIP of ~354k JSON files | ~560 MB compressed |
| **CPE Match** | Vendor/product/version-to-CVE mapping | Extracted from cvelistV5 `containers.cna.affected[]` and `containers.adp[].affected[]` | Derived during NVD parse | ~1M rows |
| **OSV** | Open Source Vulnerabilities (per-ecosystem mirrors) | `https://osv-vulnerabilities.storage.googleapis.com/<ecosystem>/all.zip` | ZIP per ecosystem, list at `https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt` | ~1.2 GB total (~45 ecosystems) |
| **Enriched** | Denormalized join of KEV + EPSS + NVD | Derived via SQL JOIN | SQLite table | ~337k rows |

---

## Technology stack

- **Runtime**: Node.js 22 (TypeScript, strict mode)
- **Database**: SQLite via `better-sqlite3` (synchronous, WAL mode)
- **HTTP server**: Express on port 9000
- **Scheduler**: `node-cron` for daily refresh
- **Logging**: pino
- **Container**: Docker (node:22-alpine + python3/make/g++ for better-sqlite3 native build)

---

## Storage layer — SQLite with WAL

Single SQLite database. WAL mode lets readers query while a refresh writes.

```sql
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA busy_timeout=30000;
```

### Schema (6 tables + meta)

```sql
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
    version TEXT,       -- "2.0", "3.0", "3.1", "4.0"
    vector TEXT,
    cwes TEXT,           -- JSON array of strings
    refs TEXT            -- JSON array of URL strings (capped at 10)
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

CREATE TABLE IF NOT EXISTS meta (
    feed TEXT PRIMARY KEY,
    updated_at TEXT,     -- ISO 8601 UTC
    row_count INTEGER,
    status TEXT,         -- "empty" | "refreshing" | "ready" | "error"
    detail TEXT
);
```

Feed names: `kev`, `epss`, `nvd`, `cpe_match`, `osv`, `enriched`. Meta rows seeded on init with `status='empty'`, `row_count=0`.

### Write strategy: wholesale replace

Every refresh does a full replace inside one transaction:
```
BEGIN;
DELETE FROM <table>;
INSERT INTO <table> VALUES (...), (...), ...;
UPDATE meta SET updated_at=<now>, row_count=<count>, status='ready' WHERE feed='<name>';
COMMIT;
```
On error: ROLLBACK, set `meta.status='error'`, `meta.detail=<first 300 chars>`.

### Read strategy: batch lookup with chunking

SQLite has a 999-parameter limit per query. Chunk lookups into groups of 900.

---

## Downloaders — one per source

### KEV downloader
1. HTTP GET the KEV URL. Timeout: 30s.
2. Parse JSON: `{"vulnerabilities": [{"cveID": "CVE-...", "dueDate": "YYYY-MM-DD", "vulnerabilityName": "..."}]}`.
3. Wholesale replace into `kev` table.

### EPSS downloader
1. HTTP GET the gzipped CSV. Timeout: 60s.
2. Gunzip via `zlib.gunzipSync()`.
3. Parse CSV. Skip comment lines (`#`) and header row. Columns: `cve,epss,percentile`.
4. Wholesale replace into `epss` table.

### NVD/cvelistV5 downloader (also populates cpe_match)
1. HTTP GET the cvelistV5 ZIP (~560 MB). Timeout: 600s.
2. Read entire ZIP into a Buffer. Parse using a custom ZIP reader that handles ZIP64 (>65535 entries).
3. For each `.json` file containing `CVE-`:
   a. Parse JSON. Structure: `{"cveMetadata": {...}, "containers": {"cna": {...}, "adp": [...]}}`.
   b. Skip if `cveMetadata.state == "REJECTED"`.
   c. Extract CVE ID from `cveMetadata.cveId`.
   d. Extract CVSS: search `containers.cna.metrics[]` then `containers.adp[].metrics[]`. Preference: v3.1 > v3.0 > v4.0 > v2.0. Each metric has key like `cvssV3_1` containing `{baseScore, baseSeverity, vectorString}`.
   e. Extract CWEs via regex `CWE-\d+` from `containers.cna.problemTypes[].descriptions[].description`.
   f. Extract first 10 reference URLs from `containers.cna.references[].url`.
   g. **Extract CPE match data**: walk `containers.cna.affected[]` and `containers.adp[].affected[]`. For each affected entry, extract `vendor`, `product`, and `versions[].version` / `versions[].lessThan` / `versions[].lessThanOrEqual`. Build `cpe_match` rows with normalized vendor/product.
4. Wholesale replace into `nvd` table AND `cpe_match` table.

### OSV downloader
1. HTTP GET `https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt`. Parse into ecosystem names.
2. Validate names: `^[A-Za-z0-9][A-Za-z0-9 ._:-]*$` (path traversal defense).
3. For each ecosystem: download `https://osv-vulnerabilities.storage.googleapis.com/<encoded_name>/all.zip`.
4. Atomic file replace: write to temp file **in the same directory** as the final path (avoids EXDEV cross-device rename errors), then `fs.renameSync(temp, final)`.
5. ZIPs stored at `<OSV_CACHE_DIR>/osv-scanner/<ecosystem>/all.zip`.

### Building the enriched table
After refreshing kev, epss, and nvd:
```sql
INSERT INTO cve_enriched (...)
SELECT c.cve, ...
FROM (SELECT cve FROM nvd UNION SELECT cve FROM epss UNION SELECT cve FROM kev) c
LEFT JOIN kev k ON k.cve = c.cve
LEFT JOIN epss e ON e.cve = c.cve
LEFT JOIN nvd n ON n.cve = c.cve;
```

---

## Scheduler

### Implementation: `node-cron` + mutex + startup check

```typescript
let refreshInProgress = false;  // Simple boolean mutex

async function refreshAll(): Promise<void> {
  if (refreshInProgress) return;  // Reject concurrent runs
  refreshInProgress = true;
  try {
    // Order matters — enriched must come last
    await runRefresh('kev');
    await runRefresh('epss');
    await runRefresh('nvd');       // Also populates cpe_match as side-effect
    await runRefresh('cpe_match'); // No-op if nvd already populated it
    await runRefresh('osv');
    await runRefresh('enriched');  // Must come last — joins fresh data
  } finally {
    refreshInProgress = false;
  }
}
```

### Daily schedule
- Runs once daily at configurable time (default: `03:15` local).
- Uses `node-cron` with expression `${minute} ${hour} * * *`.
- Fire-and-forget: scheduled callback calls `refreshAll().catch(log.error)`.

### Startup behavior
- On service start, check each feed's `meta` row.
- If any feed has `row_count=0` OR `updated_at` older than `STALE_HOURS` (default 24):
  - Trigger `refreshAll()` in the background (non-blocking).
  - Service responds to HTTP queries immediately (returns empty results until data arrives).
- If all feeds are fresh, skip startup refresh.

### Staleness detection
```typescript
function isStale(feed: FeedName): boolean {
  const meta = getMetaRow(feed);
  if (!meta || meta.row_count === 0) return true;
  if (!meta.updated_at) return true;
  const age = Date.now() - new Date(meta.updated_at).getTime();
  return age > STALE_HOURS * 3600 * 1000;
}
```

### Single feed refresh
- `refreshSingle(feed)` refreshes one feed, then rebuilds `enriched` if the feed was kev/epss/nvd/cpe_match (not osv).
- Also guarded by the mutex.

---

## API endpoints

Express server on port 9000 (configurable via `FEEDS_PORT` env var).

```
GET  /feeds/health    → {"status": "ok"}

GET  /feeds/status    → {
  "feeds": [
    {"name": "kev",       "updatedAt": "...", "rowCount": 1610,    "status": "ready", "detail": null},
    {"name": "epss",      "updatedAt": "...", "rowCount": 337285,  "status": "ready", "detail": null},
    {"name": "nvd",       "updatedAt": "...", "rowCount": 337479,  "status": "ready", "detail": null},
    {"name": "cpe_match", "updatedAt": "...", "rowCount": 1064390, "status": "ready", "detail": null},
    {"name": "osv",       "updatedAt": "...", "rowCount": 45,      "status": "ready", "detail": "45 ecosystems, 0 failed"},
    {"name": "enriched",  "updatedAt": "...", "rowCount": 337481,  "status": "ready", "detail": null}
  ],
  "scheduler": {"dailyAt": "03:15", "nextRun": "2026-06-04T03:15:00.000Z"}
}

POST /feeds/kev        {cves: ["CVE-2024-1234", ...]}
  → {kev: ["CVE-2024-1234"]}

POST /feeds/epss       {cves: [...]}
  → {results: {"CVE-...": {epss: 0.94, percentile: 0.99}}}

POST /feeds/nvd        {cves: [...]}
  → {results: {"CVE-...": {score: 9.8, severity: "CRITICAL", version: "3.1", vector: "...", cwes: [...], refs: [...]}}}

POST /feeds/enriched   {cves: [...]}
  → {results: {"CVE-...": {kev: true, kevDueDate: "...", epss: 0.94, percentile: 0.99, score: 9.8, severity: "CRITICAL", ...}}}

POST /feeds/cpe-lookup {vendor: "cisco", product: "webex", version: "21.33.0"}
  → {results: [{cve: "CVE-2024-20338", score: 7.3, severity: "HIGH", kev: false, epss: 0.00087, ...}]}

POST /feeds/refresh    ?feed=all|kev|epss|nvd|osv|cpe_match|enriched
  → {started: true} or {started: false, reason: "Refresh already in progress"}

POST /feeds/score      {cves: ["CVE-2024-1234", ...]}
  → {score: 450, grade: "C", riskPct: 22.5, breakdown: [...]}
```

### CPE lookup flow
1. Accept `vendor`, `product`, optional `version`.
2. Query `cpe_match` table: `WHERE vendor = ? AND product = ?`.
3. If `version` provided, filter by version ranges (application-layer comparison).
4. JOIN with `cve_enriched` to get full CVE details.
5. Deduplicate by CVE ID, sort by severity then score.

---

## Risk scoring model

### Per-CVE score
```
base_points = cvss_score * 10      (if numeric score available)
            = {CRITICAL: 90, HIGH: 65, MEDIUM: 40, LOW: 10}[severity]  (fallback)

amplifier   = 5.0   (if CVE is in KEV)
            = 4.0   (if EPSS percentile >= 0.95)
            = 2.5   (if EPSS percentile >= 0.75)
            = 1.5   (if EPSS percentile >= 0.50)
            = 1.0   (if EPSS percentile >= 0.25)
            = age_decay  (if EPSS percentile < 0.25 and NOT KEV)
            = 1.0   (if no EPSS data)

age_decay   = 0.90  (< 1 year old)
            = 0.75  (1-2 years)
            = 0.60  (2-3 years)
            = 0.45  (3-5 years)
            = 0.30  (> 5 years)

per_cve_score = base_points * amplifier
```

### KEV floor
Any CVE in KEV: `per_cve_score = max(per_cve_score, 250)`.

### Normalization
```
raw_total      = sum(per_cve_score for all findings)
risk_pct       = min(raw_total / 2000, 1.0) * 100
reported_score = min(raw_total / 2000, 1.0) * 1000   // 0-1000 scale
```

### Grading
```
A: risk_pct < 15
B: risk_pct < 30
C: risk_pct < 50
D: risk_pct < 70
F: risk_pct >= 70
```
If any KEV finding exists, force minimum grade D (`risk_pct = max(risk_pct, 50)`).

---

## Enrichment data flow

### For commercial PE files (CPE path)
```
PE metadata → CompanyName + ProductName + FileVersion
  → normalize vendor ("Cisco Systems, Inc" → "cisco")
  → normalize product ("Webex" → "webex")
  → POST /feeds/cpe-lookup {vendor, product, version}
  → SQL: cpe_match WHERE vendor=? AND product=? → CVE IDs
  → version range filtering
  → JOIN cve_enriched → full details (score, severity, KEV, EPSS)
```

### For open-source packages (OSV path)
```
SBOM packages → ecosystem + name + version
  → osv-scanner binary with --offline-vulnerabilities flag
  → reads ZIPs from <OSV_CACHE_DIR>/osv-scanner/<ecosystem>/all.zip
  → returns CVE IDs
  → POST /feeds/enriched {cves: [...]} → KEV + EPSS overlay
```

### For any CVE ID list
```
CVE IDs → POST /feeds/enriched {cves: [...]}
  → batch lookup with 900-item chunking
  → returns: {kev, kevDueDate, epss, percentile, score, severity, vector, cwes, refs}
```

---

## Configuration (env vars with defaults)

```
# Download timeouts (ms)
KEV_TIMEOUT          = 30000
EPSS_TIMEOUT         = 60000
NVD_TIMEOUT          = 600000
OSV_PER_ZIP_TIMEOUT  = 600000

# Scheduler
DAILY_REFRESH_TIME   = "03:15"     # HH:MM local time
STALE_HOURS          = 24

# SQLite
DB_PATH              = "/data/feeds.db"

# OSV
OSV_CACHE_DIR        = "/data/osv-cache"

# Server
FEEDS_PORT           = 9000

# Risk scoring
RISK_CEILING         = 2000
KEV_MIN_SCORE        = 250
```

---

## Docker deployment

```yaml
vuln-feeds:
  build:
    context: .
    dockerfile: packages/vuln-feeds/Dockerfile
  environment:
    DB_PATH: /feeds/feeds.db
    OSV_CACHE_DIR: /feeds/osv-cache
  volumes:
    - ./techdebtdata:/feeds    # bind mount to host — persistent across rebuilds
  networks:
    - backend-net
  restart: unless-stopped
```

Dockerfile uses multi-stage: node:22-alpine with python3/make/g++ for better-sqlite3 native compilation.

Data persists in `./techdebtdata/` on the host (bind mount). Total disk: ~2GB (SQLite ~450MB + OSV cache ~1.2GB + WAL ~200MB).

---

## Error handling principles

1. **Never crash on a single feed failure.** Log error, set `meta.status='error'`, continue with other feeds.
2. **Readers never block on writers.** WAL mode ensures this.
3. **Empty is not error.** A feed with `row_count=0, status='empty'` returns empty results.
4. **Atomic file writes for OSV.** Temp file in same directory as final path (avoids EXDEV), then `rename()`.
5. **No live API calls at scan time.** Scanner queries local SQLite only. If feeds are stale, results are stale — the daily scheduler will refresh.
6. **Mutex on refresh.** Only one refresh cycle runs at a time. Concurrent requests are rejected.
7. **Non-blocking startup.** Service starts serving HTTP immediately. Background refresh fires if data is stale.
