# FraudVault Trust Boundaries

## Overview

FraudVault runs as a single-server Docker Compose deployment with 17 containers across 4 bridge networks. Trust is segmented by Docker network isolation and application-layer authentication. There are 5 trust boundaries.

The fundamental security property: **malware executing inside a throwaway sandbox container must not reach backend services, storage, or the host.** Sandbox containers run with `--network none`, `--read-only`, and `--cap-drop ALL` by default. Everything else is defense-in-depth.

```
+=================================================================+
|                                                                 |
|   INTERNET (Untrusted)                                          |
|   Users, analysts, browsers                                     |
|                                                                 |
+============================+====================================+
                             | B1: Internet -> Nginx
                             | HTTPS (self-signed TLS, port 443)
                             | No WAF, no IP allowlist
+============================v====================================+
|                                                                 |
|   frontend-net (Docker bridge)                                  |
|   nginx <-> frontend (React SPA, Vite dev server)               |
|                                                                 |
|   api-net (Docker bridge)                                       |
|   nginx <-> api-gateway                                         |
|                                                                 |
+============================+====================================+
                             | B2: Nginx -> API Gateway
                             | JWT HS256, RBAC, rate limiting
+============================v====================================+
|                                                                 |
|   backend-net (Docker bridge)                                   |
|   orchestrator, static-analysis, dynamic-analysis,              |
|   detection-engine, search, reporting, telemetry,               |
|   sandbox-manager, vuln-feeds, threat-intel                     |
|                                                                 |
+=======+=================+=======================================+
        |                 |
        | B5: Storage     | B4: Sandbox
        | Boundary        | Boundary
        |                 |
+=======v=========+   +===v===================================+
| backend-net     |   | Throwaway containers                  |
| (same network)  |   | scanboy-sandbox:latest                |
|                 |   | --network none (default)               |
| PostgreSQL      |   | --read-only rootfs                    |
| Redis           |   | --cap-drop ALL (+SYS_PTRACE, +NET_RAW)|
| MinIO           |   | seccomp profile, PID limit             |
| Elasticsearch   |   |                                       |
+-----------------+   +=======================================+

   sandbox-net (Docker bridge, internal: true)
   sandbox-manager <-> threat-intel
   No external connectivity
```

### Docker Network Map

| Network | Type | Services | External Access |
|---------|------|----------|-----------------|
| **frontend-net** | bridge | nginx, frontend | Yes (ports 80/443 on nginx) |
| **api-net** | bridge | nginx, api-gateway | No (nginx proxies inbound) |
| **backend-net** | bridge | api-gateway, orchestrator, static-analysis, dynamic-analysis, detection-engine, search, reporting, telemetry, sandbox-manager, vuln-feeds, threat-intel, postgres, redis, minio, elasticsearch | No |
| **sandbox-net** | bridge, `internal: true` | sandbox-manager, threat-intel | No (Docker internal flag blocks all egress) |

### Service Inventory (17 containers)

| Container | Network(s) | Special Mounts |
|-----------|-----------|----------------|
| nginx | frontend-net, api-net | TLS certs |
| frontend | frontend-net | -- |
| api-gateway | api-net, backend-net | -- |
| orchestrator | backend-net | -- |
| static-analysis | backend-net | -- |
| dynamic-analysis | backend-net | `/var/run/docker.sock:ro` |
| sandbox-manager | backend-net, sandbox-net | `/var/run/docker.sock:ro`, `cap_add: NET_ADMIN` |
| detection-engine | backend-net | -- |
| search | backend-net | -- |
| reporting | backend-net | -- |
| telemetry | backend-net | -- |
| threat-intel | backend-net, sandbox-net | -- |
| vuln-feeds | backend-net | `./techdebtdata:/feeds` |
| postgres | backend-net | named volume `postgres-data` |
| redis | backend-net | -- |
| minio | backend-net | named volume `minio-data` |
| elasticsearch | backend-net | named volume `es-data` |

---

## B1: Internet Boundary

### Definition

The boundary between the public internet and the FraudVault platform. All external traffic enters through nginx on ports 80 (HTTP redirect) and 443 (HTTPS).

### Location

Between external clients and the nginx reverse proxy. Single entry point.

### Traffic Allowed

| Direction | Source | Destination | Protocol | Port | Purpose |
|-----------|--------|-------------|----------|------|---------|
| Inbound | Any | nginx | HTTPS | 443 | Web UI, API requests, WebSocket |
| Outbound | threat-intel | External APIs | HTTPS | 443 | VirusTotal, AbuseIPDB, MalwareBazaar, OTX, HybridAnalysis |
| Outbound | vuln-feeds | External feeds | HTTPS | 443 | KEV, EPSS, cvelistV5, OSV (daily scheduler only) |

### Controls

| Control | Implementation | Verification |
|---------|----------------|--------------|
| TLS 1.2/1.3 | nginx `ssl_protocols TLSv1.2 TLSv1.3;` with ECDHE cipher suites | `openssl s_client -connect host:443` |
| Self-signed certificate | Generated at deploy time, HSTS header set (`max-age=31536000`) | Check cert in browser or `curl -vk` |
| Security headers | `X-Frame-Options: SAMEORIGIN`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, `Content-Security-Policy` (default-src 'self') | `curl -I https://host` |
| Server identity hidden | `server_tokens off;` | Response headers lack nginx version |
| Upload size limit | `client_max_body_size 500m` (600s timeout for upload endpoint) | Upload a file >500 MB, expect 413 |
| No WAF | Not deployed | -- |
| No IP allowlist | Not deployed (single-server, not multi-tenant) | -- |

### What Is NOT Present

- No WAF (ModSecurity, AWS WAF, or equivalent)
- No IP allowlist or geo-blocking
- No DDoS mitigation (no fail2ban, no cloud L3/L4 protection)
- No certificate pinning
- Not TLS 1.3-only (TLS 1.2 also accepted)

---

## B2: User Boundary (Nginx -> API Gateway)

### Definition

The boundary between unauthenticated external requests and the authenticated backend. Requests crossing this boundary have a valid JWT and an authorized role.

### Location

Between nginx (which proxies to api-gateway on `api-net`) and the api-gateway's auth middleware.

### Authentication

| Method | Details | Expiry |
|--------|---------|--------|
| JWT Bearer Token | **HS256** signed with `JWT_SECRET` env var | 15 minutes (configurable via `JWT_EXPIRY`) |
| Refresh Token | **HS256** signed with `JWT_REFRESH_SECRET`, one-time use, stored server-side in Redis | 7 days |
| Password hashing | bcrypt, 12 rounds | -- |

### Authorization Model

```
Single-tenant deployment (no tenant isolation)

Role Hierarchy (lowest to highest):
  viewer   -> read submissions, view results
  analyst  -> read/write submissions, manage rules
  admin    -> manage users, platform settings
  super_admin -> full platform access
```

There is no multi-tenant scoping. No `tenant_id` in JWTs. No cross-tenant query filtering. This is a single-organization deployment.

### Controls

| Control | Implementation | Verification |
|---------|----------------|--------------|
| JWT validation | Every request: verify HS256 signature, check expiry, extract claims | Send expired/malformed token, expect 401 |
| Role enforcement | `requireRole()` middleware checks user role against endpoint minimum | Request admin endpoint as viewer, expect 403 |
| Rate limiting | 100 requests per 15-minute window (configurable via `RATE_LIMIT_WINDOW_MS`, `RATE_LIMIT_MAX_REQUESTS`) | Send 101 requests in 15 min, expect 429 |
| Refresh token rotation | One-time use; old token invalidated on refresh | Reuse a refresh token, expect 401 |
| Password hashing | bcrypt with 12 rounds | -- |
| CORS | Configurable origins via `CORS_ORIGINS` env var | Check `Access-Control-Allow-Origin` header |
| WebSocket auth | JWT validated on WebSocket upgrade at `/ws` | Connect without token, expect rejection |

### What Is NOT Present

- No RS256 (asymmetric) JWT signing -- uses HS256 (symmetric shared secret)
- No MFA
- No account lockout after failed attempts
- No session binding (refresh tokens not bound to user-agent or IP)
- No API key authentication (JWT only)
- No tenant isolation

---

## B3: Inter-Service Boundary (API Gateway -> Backend)

### Definition

The boundary between the API gateway and all backend microservices. Backend services authenticate each other using a shared `x-internal-api-key` header.

### Location

Between api-gateway (on both `api-net` and `backend-net`) and all services on `backend-net`. Communication is plain HTTP over Docker bridge networking using Docker DNS names.

### Authentication

All inter-service calls include the `x-internal-api-key` header. Services that enforce it (confirmed in code):

| Service | Enforcement |
|---------|-------------|
| detection-engine | Rejects requests if header missing or mismatched (401) |
| vuln-feeds | Rejects requests if header missing or mismatched (401) |
| api-gateway (outbound) | Attaches header to requests to detection-engine, vuln-feeds |
| orchestrator (outbound) | Attaches header to requests to detection-engine, vuln-feeds |

Services communicate via Docker DNS (e.g., `http://orchestrator:3001`, `http://detection-engine:3005`, `http://vuln-feeds:3010`).

### Controls

| Control | Implementation | Verification |
|---------|----------------|--------------|
| Shared API key | `INTERNAL_API_KEY` env var, checked via `x-internal-api-key` header | `curl` a backend service without header, expect 401 |
| Fail-closed | If `INTERNAL_API_KEY` is set and header is missing/wrong, request is rejected | Misconfigure key, observe rejection in logs |
| Docker network isolation | Backend services only reachable from `backend-net`; not exposed on host ports | `docker network inspect backend-net` |
| Redis pub/sub | Orchestrator listens on `scanboy:submissions:new` for new submissions | Check Redis `PUBSUB CHANNELS` |

### What Is NOT Present

- No mTLS between services (plain HTTP on Docker bridge)
- No per-service authentication (single shared key for all services)
- No request signing or replay protection
- No service mesh (no Istio, no Linkerd)

---

## B4: Sandbox Boundary (Backend -> Throwaway Containers)

### Definition

The most critical security boundary. Malware executes inside throwaway `scanboy-sandbox:latest` Docker containers. These containers must not be able to reach the host, backend services, storage, or the internet.

### Location

Between `dynamic-analysis` / `sandbox-manager` (which have `docker.sock` mounted read-only) and the throwaway sandbox containers they create.

### Isolation Model

```
+---------------------------------------------------------------------+
|  HOST (Docker jail container itself)                                 |
|                                                                     |
|  dynamic-analysis                sandbox-manager                    |
|  (docker.sock:ro)                (docker.sock:ro, cap: NET_ADMIN)   |
|       |                                |                            |
|       | docker run ...                 | manages sandbox lifecycle   |
|       v                                v                            |
|  +------------------------+  +------------------------+             |
|  | sandbox-abc123         |  | sandbox-def456         |  ...        |
|  | --network none         |  | --network none         |             |
|  | --read-only            |  | --read-only            |             |
|  | --cap-drop ALL         |  | --cap-drop ALL         |             |
|  | --cap-add SYS_PTRACE   |  | --cap-add SYS_PTRACE   |             |
|  | --cap-add NET_RAW      |  | --cap-add NET_RAW      |             |
|  | --security-opt         |  | --security-opt         |             |
|  |   no-new-privileges    |  |   no-new-privileges    |             |
|  | --security-opt         |  | --security-opt         |             |
|  |   seccomp=profile.json |  |   seccomp=profile.json |             |
|  | --memory 512m          |  | --memory 512m          |             |
|  | --memory-swap 512m     |  | --memory-swap 512m     |             |
|  | --pids-limit 256       |  | --pids-limit 256       |             |
|  | --cpus 1.0             |  | --cpus 1.0             |             |
|  | tmpfs /tmp,/run,       |  | tmpfs /tmp,/run,       |             |
|  |   /opt/scanboy,/home   |  |   /opt/scanboy,/home   |             |
|  +------------------------+  +------------------------+             |
+---------------------------------------------------------------------+
```

### Sandbox Container Security Controls

| Control | Implementation | Verification |
|---------|----------------|--------------|
| Network isolation | `--network none` by default; configurable via `SANDBOX_ALLOW_NETWORK` env var | `docker exec <sandbox> ping 8.8.8.8` fails |
| Read-only rootfs | `--read-only` flag; writable tmpfs at `/tmp` (256m), `/run` (16m), `/opt/scanboy` (64m), `/home/sandbox` (128m) | `docker exec <sandbox> touch /etc/test` fails |
| Capability drop | `--cap-drop ALL`, then `--cap-add SYS_PTRACE` (for strace) and `--cap-add NET_RAW` (for packet capture) | `docker exec <sandbox> capsh --print` |
| No privilege escalation | `--security-opt no-new-privileges` | Attempt setuid binary, fails |
| Seccomp profile | Custom seccomp JSON at `/app/packages/dynamic-analysis/seccomp-sandbox.json` (default-deny with syscall allowlist) | Attempt blocked syscall, observe EPERM |
| Memory limit | 512 MB hard limit, no swap (`--memory 512m --memory-swap 512m`) | OOM killer fires at 512 MB |
| CPU limit | 1.0 CPU (`--cpus 1.0`) | `docker stats` shows limit |
| PID limit | 256 processes (`--pids-limit 256`) | Fork bomb hits limit |
| Execution timeout | Default 120 seconds, max 600 seconds; hard kill | Container auto-removed after timeout |
| Dangerous binaries removed | `nsenter`, `mount`, `umount` deleted from sandbox image | `which nsenter` returns nothing |
| SUID stripped | `chmod u-s` on `su`, `passwd`, `chfn`, `chsh`, `gpasswd`, `newgrp` | `find / -perm -4000` returns nothing |
| Fake DNS | `/etc/resolv.conf` set to `nameserver 127.0.0.1` inside container (irrelevant with `--network none`, but defense-in-depth) | `cat /etc/resolv.conf` inside sandbox |
| No container reuse | Fresh container per detonation, destroyed after | `docker ps -a` shows no lingering sandbox containers |

### Artifact Collection

Artifacts are collected from sandbox containers using Docker primitives, not hypervisor snapshots:

| Artifact | Collection Method |
|----------|-------------------|
| Process trees, API calls, file activity | `docker exec` runs collection scripts inside sandbox as `sandbox` user |
| Extracted files, SBOM, YARA results | `docker cp` copies from container tmpfs to host |
| Network activity | Synthetic PCAP generated from strace `connect()` syscall traces (with `--network none`, no real traffic occurs) |
| Screenshots | Not available (no display server; Wine runs headless) |
| Memory dumps | Not available (no hypervisor-level memory capture) |

### Risk: docker.sock Access

Both `dynamic-analysis` and `sandbox-manager` mount `/var/run/docker.sock:ro`. This grants them the ability to create, inspect, and manage containers on the host Docker daemon. A compromise of either service could lead to container escape via the Docker API. The `:ro` flag prevents writing to the socket file itself but does not restrict Docker API operations (container creation, exec, etc.).

### What Is NOT Present

- No VMs or hypervisor isolation (Docker containers only, namespace/cgroup isolation)
- No SELinux (not enforcing, not available in Docker jail)
- No hardware-assisted virtualization (no VT-x/AMD-V, no KVM/QEMU)
- No VM snapshot signing
- No Squid monitoring proxy for sandbox egress
- No real network capture (synthetic PCAP only, since `--network none`)
- No memory forensics (no hypervisor-level memory dump)

---

## B5: Storage Boundary

### Definition

The boundary between backend services and persistence stores. All storage runs on `backend-net` with no ports exposed to the host or internet.

### Location

PostgreSQL, Redis, MinIO, and Elasticsearch are all on `backend-net`, accessible to all backend services on that network.

### Access Control

```
All backend services (same shared credentials)
        |
        | Single POSTGRES_USER/PASSWORD for all services
        | Single REDIS_PASSWORD for all services
        | Single MINIO_ACCESS_KEY/SECRET_KEY for all services
        | Single elastic/ELASTICSEARCH_PASSWORD for all services
        v
+-------------------------------+
|  backend-net (no host ports)  |
|                               |
|  PostgreSQL  :5432            |
|  Redis       :6379            |
|  MinIO       :9000            |
|  Elasticsearch :9200          |
+-------------------------------+
```

### Controls

| Control | Implementation | Verification |
|---------|----------------|--------------|
| Network isolation | Storage ports accessible only from `backend-net`; not published to host | `docker network inspect backend-net`; `nmap localhost -p 5432` from host shows closed |
| PostgreSQL auth | `POSTGRES_USER`/`POSTGRES_PASSWORD` (shared across all services) | Attempt connection without password, expect rejection |
| Redis auth | `--requirepass` flag, `REDIS_PASSWORD` env var | `redis-cli` without AUTH, expect NOAUTH |
| Redis memory policy | `--maxmemory 256mb --maxmemory-policy noeviction` | `redis-cli INFO memory` |
| Elasticsearch auth | X-Pack security enabled, `elastic` user with `ELASTIC_PASSWORD` | `curl http://elasticsearch:9200` without auth, expect 401 |
| MinIO auth | `MINIO_ROOT_USER`/`MINIO_ROOT_PASSWORD` (same as `MINIO_ACCESS_KEY`/`SECRET_KEY`) | Attempt S3 API call without credentials |
| Malware in Redis only | Uploaded samples stored as base64 in Redis with 1-hour TTL (`scanboy:file:<submissionId>`), never written to host filesystem | Check Redis TTL on file keys |

### Data Classification

| Store | Data | Sensitivity | Retention |
|-------|------|-------------|-----------|
| PostgreSQL | Users, submissions, analysis results, rules | HIGH | Indefinite |
| Redis | File uploads (base64, TTL 1h), job queues, pub/sub, session state | MEDIUM | Ephemeral (TTL-based) |
| MinIO | Reports, extracted artifacts, PCAPs | HIGH | Configurable |
| Elasticsearch | Search indices, IOC data, telemetry | MEDIUM | Configurable |

### What Is NOT Present

- No per-service database credentials (single shared user for all services)
- No row-level security in PostgreSQL
- No encryption at rest (no TDE, no SSE, no encrypted volumes)
- No encryption in transit between services and storage (plain TCP on Docker bridge)
- No backup encryption
- No Redis command restriction (`FLUSHALL`, `CONFIG`, `DEBUG` are available)
- No MinIO per-service bucket policies

---

## What Does NOT Exist

This section explicitly lists security controls described in other documentation or commonly expected in production platforms that are **not present** in the current FraudVault deployment.

| Missing Control | Category | Notes |
|----------------|----------|-------|
| Management zone / admin network | Network | No separate admin network; admin actions go through the same API gateway and JWT auth |
| VPN / bastion host | Network | No VPN required for admin access; the platform is accessed directly on port 443 |
| mTLS between services | Network | Plain HTTP over Docker bridge; inter-service auth is a shared API key header |
| WAF | Network | No ModSecurity, no cloud WAF |
| Monitoring proxy (Squid) | Sandbox | Sandbox has `--network none`; no monitored egress path exists |
| Per-service database credentials | Storage | All services share one PostgreSQL user, one Redis password, one MinIO key |
| Encryption at rest | Storage | No TDE, no SSE, no LUKS, no encrypted Docker volumes |
| Encryption in transit (internal) | Storage | No TLS between services and databases on Docker bridge |
| SELinux | Host | Not available in Docker jail environment |
| Image signing | Supply chain | No Docker Content Trust, no cosign, no Notary |
| Infrastructure-as-code | Operations | No Terraform, no Helm, no GitOps; deployed via `docker compose` |
| MFA | Authentication | Single-factor (password + JWT) only |
| Account lockout | Authentication | No lockout after failed login attempts |
| Audit logging | Operations | No dedicated audit log for admin actions |
| Secret rotation | Operations | No automated rotation of database passwords or API keys |
| Cloud metadata protection | Network | Not applicable (bare metal Docker jail, no cloud metadata endpoint) |

---

## Boundary Enforcement Verification

| Boundary | What to Verify | How to Verify |
|----------|---------------|---------------|
| B1: Internet | Only ports 80 and 443 are reachable from outside | `nmap -p- <host>` from external machine |
| B1: Internet | TLS is enforced, HTTP redirects to HTTPS | `curl http://host` (should 301 redirect to HTTPS) |
| B2: User | Unauthenticated requests are rejected | `curl https://host/api/v1/submissions` without JWT, expect 401 |
| B2: User | Role enforcement works | Authenticate as viewer, attempt admin endpoint, expect 403 |
| B2: User | Rate limiting triggers | Send 101 requests in 15 minutes, expect 429 on 101st |
| B3: Inter-service | Missing API key is rejected | `curl http://detection-engine:3005/...` from inside backend-net without `x-internal-api-key` header |
| B4: Sandbox | No network from sandbox | `docker exec <sandbox> ping 8.8.8.8` (expect failure with `--network none`) |
| B4: Sandbox | Read-only rootfs | `docker exec <sandbox> touch /etc/test` (expect EROFS) |
| B4: Sandbox | PID limit enforced | Fork bomb inside sandbox hits 256 process limit |
| B4: Sandbox | Memory limit enforced | Allocate >512 MB inside sandbox, observe OOM kill |
| B4: Sandbox | No dangerous binaries | `docker exec <sandbox> which nsenter mount umount` returns nothing |
| B4: Sandbox | No SUID binaries | `docker exec <sandbox> find / -perm -4000 -type f 2>/dev/null` returns nothing |
| B5: Storage | Storage not exposed on host | `curl http://localhost:5432` from host, expect connection refused |
| B5: Storage | Redis requires auth | `redis-cli -h localhost -p 6379 PING` without AUTH, expect NOAUTH error |
