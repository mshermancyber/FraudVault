# FraudVault Architecture

## System Overview

FraudVault is an enterprise malware and container security analysis platform. It accepts suspicious files (PE executables, ELF binaries, scripts, documents, archives, container images), detonates them in isolated Docker sandbox containers, applies static and dynamic analysis, correlates results against threat intelligence, and produces actionable detection reports with MITRE ATT&CK mapping.

The system is composed of 17 Docker Compose services organized around four operational domains:

- **Ingestion & Routing** -- TLS termination, authentication, rate limiting, REST routing
- **Orchestration & Analysis** -- job orchestration, static analysis, dynamic sandbox detonation, threat intel enrichment
- **Detection & Reporting** -- ATT&CK mapping, rule generation, scoring, PDF/STIX/CSV export
- **Infrastructure** -- PostgreSQL, Redis, MinIO, Elasticsearch

Each service communicates over REST (HTTP) or asynchronous Redis pub/sub and BullMQ job queues.

## Service Topology

```
                              Internet
                                 |
                          [ Port 443 ]
                                 |
                      +----------v-----------+
                      |       nginx          |
                      | (TLS termination,    |
                      |  reverse proxy)      |
                      +----+------------+----+
                           |            |
              frontend-net |            | api-net
                           |            |
                +----------v--+   +-----v-----------+
                |  frontend   |   |  api-gateway    |
                |  (React SPA)|   |  (auth, routes, |
                |             |   |   rate limit)    |
                +-----------+-+   +-----+-----------+
                                        |
                                   backend-net
                                        |
         +----------+----------+--------+--------+----------+----------+
         |          |          |        |        |          |          |
    +----v---+ +----v----+ +--v-----+ +v------+ +--v-----+ +--v-----+ |
    | orch-  | | static- | | dyn-   | |threat-| |detect- | | vuln-  | |
    | estr-  | | analy-  | | amic-  | |intel  | |ion-    | | feeds  | |
    | ator   | | sis     | | analy- | |       | |engine  | | (9000) | |
    |(BullMQ)| |(BullMQ) | | sis    | |(HTTP) | |(HTTP)  | |        | |
    +----+---+ +---------+ |(BullMQ)| +-------+ +--------+ +--------+ |
         |                  +---+----+                                  |
         |                      |                                      |
         |               +------v-------+                              |
         |               | sandbox-mgr  |     sandbox-net              |
         |               | (3008)       |     (internal: true)         |
         |               +------+-------+                              |
         |                      |                                      |
         |              +-------v--------+                             |
         |              | scanboy-sandbox |                            |
         |              | (throwaway     |                             |
         |              |  containers)   |                             |
         |              +----------------+                             |
         |                                                             |
         +------+----------+----------+-----------+                    |
                |          |          |           |                    |
          +-----v---+ +---v------+ +-v--------+ +v---------+  +------v------+
          |reporting| | search   | |telemetry | |postgres   |  |    redis    |
          |(HTTP)   | | (HTTP)   | |(HTTP)    | |(5432)     |  |   (6379)    |
          +---------+ +----+-----+ +----------+ +-----------+  +-------------+
                           |
                     +-----v--------+       +-------------+
                     |elasticsearch |       |    minio    |
                     |  (9200)      |       | (9000/9001) |
                     +--------------+       +-------------+
```

## Service Descriptions

### nginx

Reverse proxy and TLS termination. Serves HTTPS on port 443 with a self-signed certificate (HTTP on port 80 redirects to HTTPS). Routes `/api/*` to api-gateway and all other requests to frontend. No WAF, no CDN.

- Listens on port 443 (HTTPS, self-signed TLS) and port 80 (HTTP redirect to HTTPS)
- Connected to `frontend-net` and `api-net`
- Proxies API traffic to api-gateway on port 3000
- Serves frontend SPA via the frontend container

### Frontend

React single-page application built with Vite and TailwindCSS. Dark theme with teal accent color. Served by the `serve` static file server inside the container.

- React + TypeScript + Vite + TailwindCSS
- Connected to `frontend-net` only (reaches backend exclusively through nginx)
- Build: `cd packages/frontend && npx vite build` (must cd into directory or Tailwind content glob fails)

### API Gateway (port 3000)

Entry point for all external API traffic. Handles authentication, rate limiting, REST routing, and Swagger UI documentation. User management (accounts, RBAC) is built into this service -- there is no separate user management service.

- Authentication: JWT with HS256 algorithm pinning, 15-minute expiry
- Refresh token rotation via Redis SETNX (atomic, prevents replay)
- RBAC roles: `viewer`, `analyst`, `admin`
- Rate limiting: configurable per endpoint
- Swagger UI at `/api-docs`
- Local accounts only (bcrypt password hashing); no SAML, OIDC, or SSO
- Connected to `api-net` and `backend-net`

### Orchestrator (BullMQ worker)

Central coordinator for the analysis lifecycle. Listens on Redis pub/sub channel `scanboy:submissions:new`, creates BullMQ jobs, dispatches work to analysis services, and assembles final results. Contains three independent scoring engines that must agree.

- Routes submissions to one of two workflows based on `options.analysisWorkflow`:
  - **Malware workflow** (8 steps): hash verify, threat intel, static analysis, YARA scanning, dynamic sandbox detonation, detection engine, scoring, reporting
  - **Container workflow** (3 steps): sandbox extraction, SBOM vulnerability scan (CPE to OSV/NVD via local feeds), container-specific scoring (7 sub-scores)
- Three independent scorers with cross-check reconciliation:
  1. Primary scorer (`computeThreatScore` in submissionWorkflow.ts)
  2. Detection engine scorer (`calculateThreatScore` in threatScorer.ts)
  3. Verdict engine (verdict-engine.ts)
- 55+ malware family config extractors
- Persists job state and results to PostgreSQL
- Connected to `backend-net`

### Static Analysis (BullMQ worker)

Analyzes submitted files without execution. Extracts metadata, identifies file types, unpacks archives, and applies pattern matching.

- File identification: magic bytes, MIME type, entropy analysis
- PE analysis: imports, exports, sections, resources, authenticode signatures
- ELF analysis: headers, sections, symbols
- Script analysis: PowerShell, VBScript, JavaScript, batch
- Document analysis: macro extraction (Office), JavaScript extraction (PDF)
- Archive handling: recursive unpacking; password-protected archives tried with common passwords (infected, malware, virus, dangerous, password, 123456, test)
- String extraction and classification (URLs, IPs, registry keys, mutexes)
- Connected to `backend-net`

### Dynamic Analysis (BullMQ worker)

Drives detonation inside throwaway Docker sandbox containers. Instruments the sandbox to capture behavioral artifacts during execution.

- Creates disposable `scanboy-sandbox:latest` containers via Docker socket
- Wine for PE execution, strace for syscall tracing, inotifywait for filesystem monitoring, tcpdump for network capture
- Two-layer YARA pipeline:
  1. Built-in pattern scanner (`yara-pattern-scanner.ts`, ~30 rules for ransomware/RATs/anti-debug) runs as Python inside sandbox at step g5
  2. Community rules (8,841+ from vuln-feeds service, 4 GitHub sources refreshed weekly) run via `yara` binary at step g6
- Container security scanning via `container-security-scan.py` (Python, runs inside sandbox as sandbox user)
- CycloneDX 1.6 SBOM generation via syft binary inside sandbox
- Artifacts collected via `docker exec` + `docker cp` (not hypervisor snapshots)
- Requires `docker-cli` installed in container (`apk add --no-cache docker-cli` after recreate)
- Connected to `backend-net`

### Threat Intel (HTTP service)

Enriches submissions and analysis artifacts with external threat intelligence.

- VirusTotal lookups (uses extracted executable hash, NOT archive hash)
- MalwareBazaar lookups
- Caches results in Redis
- Connected to `backend-net` and `sandbox-net`

### Detection Engine (HTTP service)

Applies detection logic to combined static and dynamic analysis results. Produces ATT&CK mappings and generates detection rules.

- ATT&CK technique mapping with baseline exclusions for Wine noise (T1027, T1027.002, T1036.008, T1059, T1106, T1082 in `BASELINE_TECHNIQUES` / `BASELINE_EVASION` sets)
- Generates Sigma, Suricata, Snort, and YARA rules from analysis results
- Independent threat scorer (`calculateThreatScore`) that must agree with orchestrator's primary scorer and verdict engine
- Requires `x-internal-api-key` header for all inbound requests
- Connected to `backend-net`

### Search (HTTP service)

Full-text search over historical analyses, backed by Elasticsearch.

- Indexes submissions, IOCs, behavioral indicators, detection results
- Correlation queries across submissions (e.g., all submissions contacting a given C2 domain)
- Connected to `backend-net`

### Reporting (HTTP service)

Generates structured reports from analysis results.

- PDF export via WeasyPrint (Python, runs inside the reporting container)
- STIX 2.1 structured threat intelligence export
- CSV export
- Connected to `backend-net`

### Telemetry (HTTP service)

Platform operational metrics and health monitoring.

- Submission volume, analysis duration, verdict distribution, queue depth
- Service health checks
- Connected to `backend-net`

### Sandbox Manager (port 3008)

Manages the lifecycle of throwaway sandbox Docker containers.

- Provisions fresh `scanboy-sandbox:latest` containers per detonation (no container reuse)
- Container security hardening:
  - `--read-only` rootfs
  - `--cap-drop ALL`, adds only `SYS_PTRACE` + `NET_RAW`
  - `--network none` (default; network enabled only when explicitly requested)
  - `no-new-privileges` security option
  - seccomp default profile
  - PID limits
- DNS isolation: fake resolv.conf with 8.8.8.8/4.4.4.4 mounted read-only
- Dangerous binaries removed: nsenter, mount, umount
- SUID bits stripped: su, passwd, chfn, chsh, gpasswd, newgrp
- Destroys container and associated storage on completion or timeout
- Connected to `backend-net` and `sandbox-net`

### Vuln-Feeds (port 9000)

Offline vulnerability feed aggregator. Provides local SQLite database of vulnerability data for container security scanning. No live API queries during scan jobs.

- 6 feed sources downloaded by daily scheduler: KEV, EPSS, cvelistV5, OSV, NVD CPE dictionary, NVD CVE data
- 20,000+ YARA rules from 4 GitHub sources, refreshed weekly
- All vulnerability enrichment at scan time comes from local SQLite only
- If a feed is stale or empty, returns empty results (never falls back to online APIs)
- Feed data stored in `techdebtdata/` (bind-mounted as `/feeds` in container)
- Requires `x-internal-api-key` header for all inbound requests
- Connected to `backend-net`

### PostgreSQL (port 5432)

PostgreSQL 16 relational database. 25 tables, 105 indexes. Shared credentials (`POSTGRES_USER` / `POSTGRES_PASSWORD`).

- Stores: submissions, analysis results, detection results, user accounts, RBAC, job state
- Accessed via raw SQL using the `pg` library (no ORM)
- Note: `file_activity` column in `dynamic_analysis_results` can be 30MB+ (Wine noise) and is excluded from API responses
- Connected to `backend-net`

### Redis (port 6379)

Redis 7 with `noeviction` policy, 256MB max memory.

- BullMQ job queues (at-least-once delivery)
- Pub/sub event bus (primary channel: `scanboy:submissions:new`)
- File cache: uploaded samples stored as base64 with 1-hour TTL, keyed as `scanboy:file:<submissionId>`
- Session data and refresh token storage
- Threat intel result caching
- Connected to `backend-net`

### MinIO (ports 9000/9001)

S3-compatible object storage for analysis artifacts.

- Stores: PCAPs, screenshots, reports, extracted artifacts
- Port 9000: S3 API; port 9001: web console
- Connected to `backend-net`

### Elasticsearch (port 9200)

Elasticsearch 8 with X-Pack security enabled. Full-text search index for submissions and IOCs.

- Connected to `backend-net`

### Optional Services

- **Ollama** (profile: `ai`): Local LLM inference for AI-assisted analysis features
- **scanboy-sandbox** (profile: build-only): Build target for the sandbox container image

## Data Flow

### Malware Submission Flow

```
User / API Client
     |
     | POST /api/v1/submissions (file upload)
     v
nginx (port 443, HTTPS)
     |
     | reverse proxy
     v
API Gateway (port 3000)
     |
     | JWT auth check, rate limit, route
     |
     | 1. Store file in Redis as base64 (key: scanboy:file:<id>, TTL: 1hr)
     | 2. Create submission record in PostgreSQL
     | 3. Publish to Redis pub/sub channel: scanboy:submissions:new
     v
Orchestrator (listening on scanboy:submissions:new)
     |
     | Step 1: Hash verification
     | Step 2: Threat Intel lookup (VirusTotal, MalwareBazaar)
     | Step 3: Static analysis (BullMQ job)
     | Step 4: YARA scanning (built-in + community rules)
     | Step 5: Dynamic sandbox detonation (BullMQ job)
     |              |
     |              v
     |         Sandbox Manager provisions container
     |              |
     |              v
     |         scanboy-sandbox:latest (throwaway)
     |           - Wine executes PE sample
     |           - strace captures syscalls
     |           - inotifywait monitors filesystem
     |           - tcpdump captures network
     |           - YARA pattern scanner runs
     |              |
     |              v
     |         Artifacts collected via docker exec/cp
     |         Container destroyed
     |
     | Step 6: Detection engine (ATT&CK mapping, rule generation)
     | Step 7: Scoring (three independent scorers + cross-check)
     |           - Primary scorer (computeThreatScore)
     |           - Detection engine scorer (calculateThreatScore)
     |           - Verdict engine
     | Step 8: Reporting (PDF, STIX 2.1, CSV)
     |
     | Results written to PostgreSQL
     v
Frontend (queries API Gateway -> PostgreSQL)
```

### Container Submission Flow

```
User / API Client
     |
     | POST /api/v1/submissions (container image, analysisWorkflow: "container")
     v
nginx -> API Gateway -> Redis + PostgreSQL -> Orchestrator
     |
     | Step 1: Sandbox extraction (unpack container layers)
     | Step 2: SBOM vulnerability scan
     |           - CycloneDX 1.6 SBOM via syft
     |           - CPE matching against local SQLite feeds (OSV, NVD)
     |           - No live API calls (all data from vuln-feeds service)
     | Step 3: Container-specific scoring (7 sub-scores)
     |
     | Results written to PostgreSQL
     v
Frontend
```

### Event and Job Flow

```
+------------------+     +------------------+     +------------------+
| API Gateway      |---->|      Redis       |---->| Orchestrator     |
| (publisher)      |     |    Pub/Sub       |     | (subscriber)     |
+------------------+     +------------------+     +------------------+

Primary pub/sub channel:
  scanboy:submissions:new  ->  Orchestrator picks up new submissions

+------------------+     +------------------+     +------------------+
| Orchestrator     |---->|      Redis       |---->| Analysis Workers |
| (job creator)    |     |  BullMQ Queues   |     | (job processors) |
+------------------+     +------------------+     +------------------+

BullMQ queues:
  static-analysis    ->  Static Analysis workers
  dynamic-analysis   ->  Dynamic Analysis workers
  (other job types dispatched as needed)
```

## Docker Network Segmentation

The platform uses four Docker networks to enforce service isolation:

```
+=================================================================+
|                        INTERNET                                 |
|  (users connect via HTTPS on port 443)                          |
+==========================+======================================+
                           | self-signed TLS
+==========================v======================================+
|                     frontend-net                                |
|  nginx <-> frontend                                             |
+==========================+======================================+
                           |
+==========================v======================================+
|                       api-net                                   |
|  nginx <-> api-gateway                                          |
+==========================+======================================+
                           |
+==========================v======================================+
|                     backend-net                                 |
|  All backend services:                                          |
|    orchestrator, static-analysis, dynamic-analysis,             |
|    threat-intel, detection-engine, search, reporting,           |
|    telemetry, sandbox-manager, vuln-feeds                       |
|  All datastores:                                                |
|    postgres, redis, minio, elasticsearch                        |
+==================+==============================================+
                   |
+==================v==============================================+
|                  sandbox-net (internal: true)                   |
|  sandbox-manager, threat-intel                                  |
|  No external network access                                     |
|  Throwaway sandbox containers run with --network none           |
+=================================================================+
```

Key isolation properties:
- `frontend-net`: Only nginx and frontend can communicate
- `api-net`: Only nginx and api-gateway can communicate
- `backend-net`: All backend services and datastores; no direct external access
- `sandbox-net`: Marked `internal: true` (Docker blocks external routing); sandbox containers themselves run with `--network none` by default

## Technology Stack

| Layer | Technology | Details |
|---|---|---|
| Backend services | TypeScript / Node.js 22 LTS | All services except frontend and some Python components |
| Frontend | React + TypeScript + Vite + TailwindCSS | Dark theme, teal accent, served by `serve` |
| Relational DB | PostgreSQL 16 | 25 tables, 105 indexes, raw SQL via `pg` library (no ORM) |
| Cache / Queue / Pub/Sub | Redis 7 (standalone, noeviction, 256MB) | BullMQ queues, pub/sub, file cache, sessions |
| Artifact Storage | MinIO | S3-compatible, self-hosted |
| Search | Elasticsearch 8 | X-Pack security enabled, full-text indexing |
| Sandbox | Docker containers (`scanboy-sandbox:latest`) | Throwaway, hardened, Wine + strace + tcpdump + inotifywait |
| Container analysis | Python (`container-security-scan.py`) + syft | CycloneDX 1.6 SBOM, CPE-based vuln matching |
| PDF generation | WeasyPrint (Python) | Runs inside reporting container |
| YARA | Built-in rules (~30) + community rules (20,000+) | Two-layer pipeline, community rules refreshed weekly |
| Vuln feeds | SQLite | 6 feed sources, daily refresh, offline-only at scan time |
| Reverse proxy | nginx | Self-signed TLS on port 443 |
| Deployment | Docker Compose | Single-node, 17 services, 4 networks |

## Communication Patterns

### Synchronous (REST over HTTP)

All inter-service communication uses plain HTTP (not HTTP/2, not mTLS). Services resolve each other by Docker Compose DNS names. Internal endpoints require the `x-internal-api-key` header (fail-closed -- missing header returns 401).

- nginx -> api-gateway: reverse proxy (port 3000)
- nginx -> frontend: static file serving
- api-gateway -> backend services: REST calls for submission, results, search, reports
- orchestrator -> threat-intel: hash lookups
- orchestrator -> detection-engine: ATT&CK mapping, rule generation
- orchestrator -> vuln-feeds: vulnerability data for container scanning
- dynamic-analysis -> sandbox-manager: container provisioning and lifecycle

### Asynchronous (Redis Pub/Sub + BullMQ)

**Pub/Sub** (notifications):
- `scanboy:submissions:new` -- API Gateway publishes, Orchestrator subscribes and begins analysis

**BullMQ Queues** (reliable job dispatch, at-least-once delivery):
- Static analysis jobs
- Dynamic analysis jobs
- Additional job types as needed per workflow step

### Authentication

**External (user-facing):**
- JWT tokens with HS256 algorithm pinning
- 15-minute token expiry
- Refresh token rotation via Redis SETNX (atomic check-and-set prevents replay)
- Local accounts only (bcrypt), no SSO/SAML/OIDC

**Internal (service-to-service):**
- `x-internal-api-key` header on all inter-service HTTP calls
- Shared key from `INTERNAL_API_KEY` environment variable
- Fail-closed: missing or invalid key returns 401

## Deployment

### Single-Node Docker Compose

FraudVault deploys as a single Docker Compose stack. All 17 services run as containers on one host.

```
docker-compose.yml
  services:
    # Ingress
    nginx:              ports: ["80:80", "443:443"]

    # Frontend
    frontend:           (served by 'serve', connected to frontend-net)

    # API
    api-gateway:        port 3000 (internal), connected to api-net + backend-net

    # Analysis
    orchestrator:       BullMQ worker, connected to backend-net
    static-analysis:    BullMQ worker, connected to backend-net
    dynamic-analysis:   BullMQ worker, connected to backend-net
                        volumes: ["/var/run/docker.sock:/var/run/docker.sock"]
    sandbox-manager:    port 3008, connected to backend-net + sandbox-net
    threat-intel:       HTTP service, connected to backend-net + sandbox-net
    detection-engine:   HTTP service, connected to backend-net
    vuln-feeds:         port 9000, connected to backend-net

    # Support
    search:             HTTP service, connected to backend-net
    reporting:          HTTP service, connected to backend-net
    telemetry:          HTTP service, connected to backend-net

    # Infrastructure
    postgres:           image: postgres:16, port 5432
    redis:              image: redis:7-alpine, port 6379
    minio:              image: minio/minio, ports 9000/9001
    elasticsearch:      image: elasticsearch:8, port 9200

  # Optional (profiles)
    ollama:             profile: ai
    scanboy-sandbox:    profile: build-only (image build target)

  networks:
    frontend-net:
    api-net:
    backend-net:
    sandbox-net:        internal: true
```

### Deployment Operations

- **Compile**: `npx tsc --project packages/<pkg>/tsconfig.json` (requires Node.js 22.x on PATH)
- **Deploy to container**: `docker cp packages/<pkg>/dist/. scan-boy-<service>-1:/app/packages/<pkg>/dist/`
- **Restart**: `docker compose restart <service>` (not `docker compose up -d`, which recreates)
- **Frontend**: Must `cd packages/frontend && npx vite build` first, then copy and restart frontend + nginx

### Environment

- Node.js 22 LTS required (for local TypeScript compilation)
- Docker data-root should point to a large data partition (200GB+ recommended)
- HTTPS on port 443 via nginx (self-signed TLS, HTTP on port 80 redirects to HTTPS)
- Configuration via environment variables in `.env` file
- Shared PostgreSQL credentials across all services
