# FraudVault Threat Model

## Scope

This threat model covers the FraudVault malware and container analysis platform. It identifies assets, threat actors, attack paths, and mitigations for the system as deployed: a single-server Docker Compose deployment with 17+ containerized services, Docker-based sandboxing (not VMs), and self-signed TLS via nginx.

Methodology: STRIDE-per-element, supplemented with attack trees for container escape.

## Assets

### Critical Assets

| ID | Asset | Description | Confidentiality | Integrity | Availability |
|----|-------|-------------|-----------------|-----------|--------------|
| A1 | Submitted malware samples | Files uploaded for analysis, stored as base64 in Redis (1hr TTL) | HIGH (may contain client IP, internal docs) | CRITICAL (tampering invalidates analysis) | MEDIUM |
| A2 | Analysis results & verdicts | Detection outcomes, behavioral data, threat scores | HIGH (reveals detection capabilities) | CRITICAL (false verdicts = missed threats or false alarms) | HIGH |
| A3 | Threat intel data | YARA rules (20,000+ from 4 sources), vulnerability feeds (KEV, EPSS, OSV, NVD), IOC databases | HIGH (reveals detection posture) | CRITICAL | HIGH |
| A4 | User credentials & secrets | JWT signing keys, bcrypt password hashes, INTERNAL_API_KEY, VT API key | CRITICAL | CRITICAL | HIGH |
| A5 | Platform infrastructure | Service code, configs, Docker images, host Docker socket | CRITICAL | CRITICAL | CRITICAL |
| A6 | Sandbox containers | Disposable `scanboy-sandbox:latest` Docker containers running malware via Wine | LOW (disposable) | CRITICAL (compromised container = escape vector) | HIGH |

### Supporting Assets

| ID | Asset | Description |
|----|-------|-------------|
| A7 | PostgreSQL 16 database | Job state, user records, analysis results (raw SQL via `pg` library) |
| A8 | Redis instance | Sample storage (base64), session data, refresh token revocation, login lockout counters, pub/sub |
| A9 | Vulnerability feeds SQLite | Local KEV, EPSS, cvelistV5, OSV data refreshed daily by vuln-feeds service |
| A10 | Docker networks | 4 bridge networks: frontend-net, api-net, backend-net, sandbox-net (internal: true) |

## Trust Boundaries

```
+---------------------------------------------------------------+
|                      INTERNET (untrusted)                     |
|  Threat actors, C2 servers, malware authors                   |
+---------------------------+-----------------------------------+
                            | B1: Internet Boundary
                            | (nginx reverse proxy, self-signed TLS, port 443)
+---------------------------v-----------------------------------+
|                   FRONTEND-NET                                |
|  nginx (TLS termination, CSP headers)                         |
|  Frontend SPA (static files)                                  |
+---------------------------+-----------------------------------+
                            | B2: User Boundary (JWT HS256 authn/authz)
+---------------------------v-----------------------------------+
|                   API-NET                                     |
|  API Gateway (auth, rate limiting, input validation)          |
+---------------------------+-----------------------------------+
                            | B3: Internal API Boundary (INTERNAL_API_KEY)
+---------------------------v-----------------------------------+
|                   BACKEND-NET                                 |
|  Orchestrator, Static Analysis, Dynamic Analysis,             |
|  Detection Engine, Threat Intel, Vuln Feeds,                  |
|  Reporting, Telemetry, Sandbox Manager, Search                |
|  PostgreSQL, Redis, Elasticsearch, Ollama                     |
+----------------+---------------------------------------------+
                 | B4: Sandbox Boundary
+---------v------------------------+
|        SANDBOX-NET               |
|  (internal: true, no egress)     |
|  Disposable Docker containers    |
|  Actively running malware        |
|  --read-only, --cap-drop ALL,    |
|  --network none (default),       |
|  no-new-privileges, seccomp,     |
|  PID limit 256                   |
+----------------------------------+
```

## Threat Actors

### TA1: Submitted Malware (automated threat)

**Capability:** Code execution inside a sandbox Docker container via Wine (PE files) or native Linux execution. May be purpose-built to attack analysis platforms (anti-sandbox, container-escape exploits).

**Motivation:** Evade detection, escape container to compromise platform, destroy evidence of analysis, fingerprint the platform to adapt future samples.

**Access:** Code execution inside a hardened Docker container. No direct access to backend services or storage. Default network mode is `--network none`.

### TA2: Malicious Authenticated User (insider threat)

**Capability:** Valid credentials for the platform. May be a compromised analyst account or a rogue user.

**Motivation:** Exfiltrate other users' submissions, poison detection rules, retrieve threat intel data, abuse platform resources.

**Access:** Authenticated API access scoped to their role (viewer, analyst, admin, super_admin). No tenant isolation -- single-tenant deployment.

### TA3: External Attacker (network threat)

**Capability:** Can reach the nginx reverse proxy from the network. May exploit web application vulnerabilities, credential stuffing, or API abuse.

**Motivation:** Compromise platform to access submitted samples (which may contain sensitive documents), pivot to internal networks, use infrastructure for cryptomining.

**Access:** Unauthenticated network access to nginx on ports 80/443. No direct access to internal services (Docker network isolation).

### TA4: Supply Chain Attacker

**Capability:** Compromise of a dependency (npm package, Docker base image, YARA rule source, vulnerability feed data).

**Motivation:** Backdoor the platform, exfiltrate data, introduce false negatives in detection.

**Access:** Code execution within the compromised service at build or runtime.

## Attack Paths

### AP1: Container Escape from Sandbox

**Threat actor:** TA1 (Submitted Malware)
**Target assets:** A5 (Platform infrastructure), A1 (Other submissions)

```
Malware executes in sandbox container (via Wine or native)
     |
     +---> Exploit container runtime vulnerability (runc, containerd)
     |         |
     |         +---> Gain write access to host filesystem
     |         |         |
     |         |         +---> Access Docker socket [CRITICAL]
     |         |         +---> Access backend service containers
     |         |         +---> Read host environment variables (secrets)
     |         |
     |         +---> Escape via kernel exploit (shared kernel with host)
     |                   |
     |                   +---> Full host compromise [CRITICAL]
     |
     +---> Abuse mounted volumes or docker exec channel
     |         |
     |         +---> Inject crafted output into artifact collection [blocked: read-only fs]
     |         +---> Exploit docker exec stdin/stdout parsing
     |
     +---> Exploit seccomp bypass or capability escalation
               |
               +---> Abuse SYS_PTRACE to attach to other processes in container
               +---> Abuse NET_RAW for raw socket operations [limited: --network none]
```

**Mitigations:**

| Control | Description | Residual Risk |
|---------|-------------|---------------|
| `--read-only` filesystem | Container root filesystem is read-only; malware cannot write to arbitrary paths | tmpfs mounts still writable |
| `--cap-drop ALL` + selective add | Only SYS_PTRACE (for strace monitoring) and NET_RAW added back | SYS_PTRACE enables ptrace-based attacks within the container |
| `--network none` (default) | No network access from sandbox; eliminates network-based escape vectors | Can be overridden to simulated network for specific analyses |
| `no-new-privileges` security option | Prevents privilege escalation via setuid/setgid binaries | None for this path |
| seccomp profile | Custom seccomp profile restricts available syscalls (`seccomp-sandbox.json`) | Profile bypass via allowed syscalls |
| PID limit (256) | `--pids-limit 256` prevents fork bombs and resource exhaustion | None for this path |
| Fresh container per analysis | Each detonation gets a new container; no persistence between analyses | None for this path |
| No Docker socket mount | Sandbox containers have no access to `/var/run/docker.sock` | None for this path |
| No host volume mounts | Sample data piped via `docker exec` stdin, artifacts collected via `docker cp` | docker exec channel is an attack surface |
| Sandbox-net (internal: true) | Docker network marked internal; no external routing | Containers on same network can communicate |

### AP2: Privilege Escalation via API

**Threat actor:** TA2 (Malicious User), TA3 (External Attacker)
**Target assets:** A4 (Credentials), A1 (Other users' data)

```
Attacker obtains valid low-privilege token
     |
     +---> JWT manipulation
     |         |
     |         +---> Forge token with elevated role [blocked: HS256 algorithm pinning]
     |         +---> Exploit alg=none or key confusion [blocked: algorithms whitelist]
     |         +---> Steal JWT signing secret from environment [requires host access]
     |
     +---> RBAC bypass
     |         |
     |         +---> Access admin routes with viewer/analyst token [blocked: requireRole middleware]
     |         +---> Modify role field in request body [blocked: role extracted from JWT claims]
     |
     +---> API parameter injection
     |         |
     |         +---> SQL injection in queries [blocked: parameterized queries via pg library]
     |         +---> Path traversal in artifact download [blocked: UUID-based paths, regex validation]
     |
     +---> Credential stuffing / brute force
               |
               +---> Automated login attempts [rate-limited: 15 req/15min on auth endpoints]
               +---> Account lockout bypass [blocked: Redis INCR atomic counter with TTL]
```

**Mitigations:**

| Control | Description |
|---------|-------------|
| HS256 JWT with algorithm pinning | `algorithms: ['HS256']` whitelist on all verify calls prevents alg=none and algorithm confusion attacks |
| Refresh token single-use rotation | Redis SETNX (NX flag) ensures each refresh token can only be used once; replay detected and rejected |
| Login lockout via Redis INCR | Atomic counter with TTL; account locked after repeated failures for configurable minutes |
| Parameterized SQL queries | All database access uses `pg` library with parameterized queries (`$1`, `$2`, ...); no string interpolation |
| Manual input validation | UUID format checks, hash format checks (regex), path traversal prevention on API routes |
| RBAC with 4 roles | viewer < analyst < admin < super_admin; `requireRole` middleware enforces minimum role per route |
| Rate limiting | Global: 100 req/15min window; Auth endpoints: 15 req/15min window (express-rate-limit) |

### AP3: Data Exfiltration from Sandbox

**Threat actor:** TA1 (Submitted Malware)
**Target assets:** A5 (Infrastructure secrets), A1 (Other submissions)

```
Malware in sandbox container
     |
     +---> Read environment/metadata
     |         |
     |         +---> Container environment variables [minimal: only sample-related vars passed]
     |         +---> Host filesystem [blocked: no volume mounts, read-only rootfs]
     |         +---> Other containers' data [blocked: --network none, no shared volumes]
     |         +---> Cloud metadata endpoint [N/A: no cloud, single server deployment]
     |
     +---> Exfiltrate via network
     |         |
     |         +---> Any network egress [blocked: --network none by default]
     |         +---> DNS exfiltration [blocked: fake resolv.conf mounted read-only with 8.8.8.8/4.4.4.4]
     |
     +---> Exfiltrate via side channel
               |
               +---> Encode data in analysis artifacts (process names, file names)
               +---> Timing-based covert channel
```

**Mitigations:**

| Control | Description |
|---------|-------------|
| `--network none` default | Sandbox has no network stack by default; no TCP/UDP/ICMP egress possible |
| No sensitive data in sandbox | Containers receive only the sample under analysis; no platform secrets, no other samples, no credentials |
| No shared storage | Sandbox containers have no mounts to host or service filesystems |
| No cloud metadata endpoint | Single-server deployment; no cloud metadata service (169.254.169.254) exists |
| DNS isolation | Fake resolv.conf with 8.8.8.8/4.4.4.4 mounted read-only; DNS queries go nowhere when network is none |
| Read-only root filesystem | `--read-only` prevents writing markers or staging data for exfiltration |
| Ephemeral sample storage | Samples exist only in Redis (1hr TTL) and inside the disposable container; never written to host filesystem |

### AP4: Supply Chain Compromise

**Threat actor:** TA4 (Supply Chain Attacker)
**Target assets:** A5 (Platform code), A2 (Analysis results)

```
Compromised dependency
     |
     +---> npm package with backdoor
     |         |
     |         +---> Exfiltrate environment variables (JWT secrets, API keys)
     |         +---> Introduce false negatives in detection
     |         +---> Open reverse shell from a backend service
     |
     +---> Compromised Docker base image
     |         |
     |         +---> Rootkit in base image
     |         +---> Modified binaries (Wine, strace, file, strings)
     |
     +---> Poisoned YARA rules (from 4 GitHub sources)
     |         |
     |         +---> Rules that whitelist specific malware families
     |         +---> Rules with ReDoS patterns (denial of service)
     |
     +---> Poisoned vulnerability feed data
               |
               +---> False CVE entries causing false positives/negatives
               +---> Malicious data in local SQLite feeds database
```

**Mitigations:**

| Control | Description |
|---------|-------------|
| Lock files | `package-lock.json` pinned; dependency changes are reviewable |
| Minimal base images | `node:20-slim` for services; Alpine-based sandbox image |
| YARA rule weekly refresh | Rules refreshed from 4 known GitHub sources by vuln-feeds service on weekly schedule |
| Local-only vulnerability data | Vulnerability enrichment reads only from local SQLite feeds; no live API calls during scans |
| Docker network isolation | Backend services on backend-net cannot reach internet directly; sandbox-net is internal-only |
| Fail-closed internal auth | All inter-service calls require `INTERNAL_API_KEY` header; missing key = 401 rejection |

### AP5: Denial of Service

**Threat actor:** TA2, TA3
**Target assets:** A6 (Sandbox availability), A5 (Platform availability)

```
Attacker
     |
     +---> Submit large volume of samples
     |         |
     |         +---> Exhaust sandbox container pool
     |         +---> Fill Redis memory with base64 samples
     |         +---> Overwhelm analysis pipeline (Redis pub/sub queue)
     |
     +---> Submit crafted files
     |         |
     |         +---> Zip bomb (recursive decompression)
     |         +---> File that triggers OOM in static analysis
     |         +---> Sample that causes sandbox container to hang indefinitely
     |         +---> Password-protected archive that exhausts retry attempts
     |
     +---> API abuse
               |
               +---> Expensive search queries
               +---> Repeated report generation
               +---> Auth endpoint flooding
```

**Mitigations:**

| Control | Description |
|---------|-------------|
| Rate limiting | Global: 100 req/15min; Auth: 15 req/15min |
| File size limits | Multer `fileSize` limit enforced at API Gateway (memory storage) |
| Analysis timeouts | Hard timeout per sandbox detonation (configurable, default 120s) |
| PID limits | `--pids-limit 256` prevents fork bombs inside sandbox containers |
| Container resource limits | Docker memory/CPU limits; OOM killer terminates runaway processes |
| Redis TTL | Samples auto-expire from Redis after 1 hour |
| Fresh container per analysis | Hung containers are killed and replaced; no impact on other analyses |
| Archive password list | Limited to 8 common passwords; does not retry indefinitely |
| Login lockout | Redis-based lockout prevents auth endpoint abuse |

### AP6: Inter-Service Compromise

**Threat actor:** TA3 (via API vulnerability), TA4 (via supply chain)
**Target assets:** A5 (Platform infrastructure), A2 (Analysis results)

```
Attacker compromises one service
     |
     +---> Lateral movement to other services
     |         |
     |         +---> Forge requests with INTERNAL_API_KEY [requires key extraction]
     |         +---> Access services on same Docker network directly
     |         +---> Reach PostgreSQL/Redis if on backend-net
     |
     +---> Tamper with analysis results
     |         |
     |         +---> Modify detection engine scoring
     |         +---> Poison YARA rules via vuln-feeds service
     |         +---> Alter threat intel lookups
     |
     +---> Access secrets
               |
               +---> Read environment variables (JWT secret, VT API key, DB credentials)
               +---> Access Redis data (samples, sessions, refresh tokens)
```

**Mitigations:**

| Control | Description |
|---------|-------------|
| INTERNAL_API_KEY on all services | Fail-closed: vuln-feeds, detection-engine, threat-intel, reporting, telemetry, static-analysis, dynamic-analysis, sandbox-manager all reject requests without valid key |
| Docker network segmentation | 4 separate networks limit blast radius; sandbox-net is internal-only |
| Single shared API key | All services use the same INTERNAL_API_KEY (limitation: compromise of one key compromises all inter-service auth) |

## Security Controls Matrix

| Control Category | Control | Applies To | Threats Mitigated |
|---|---|---|---|
| **Authentication** | JWT (HS256 with algorithm pinning) | API Gateway | TA2, TA3 |
| | Refresh token single-use rotation (Redis NX) | API Gateway | TA2, TA3 |
| | Login lockout (Redis INCR + TTL) | API Gateway | TA3 |
| | MFA (TOTP, supported but not enforced) | API Gateway | TA2, TA3 |
| **Authorization** | RBAC (4 roles: viewer, analyst, admin, super_admin) | API Gateway, admin routes | TA2 |
| | INTERNAL_API_KEY (fail-closed) | All backend services | TA3 |
| **Network** | Docker network segmentation (4 bridge networks) | All services | TA1, TA3 |
| | sandbox-net (internal: true) | Sandbox zone | TA1 |
| | `--network none` (default for sandbox containers) | Sandbox containers | TA1 |
| | DNS isolation (fake resolv.conf, read-only mount) | Sandbox containers | TA1 |
| **Container Isolation** | `--read-only` root filesystem | Sandbox containers | TA1 |
| | `--cap-drop ALL` + SYS_PTRACE + NET_RAW | Sandbox containers | TA1 |
| | `no-new-privileges` | Sandbox containers | TA1 |
| | Custom seccomp profile | Sandbox containers | TA1 |
| | `--pids-limit 256` | Sandbox containers | TA1 |
| | Fresh container per analysis | Sandbox zone | TA1 |
| | No Docker socket mount | Sandbox containers | TA1 |
| | No host volume mounts | Sandbox containers | TA1 |
| **Input Validation** | Manual regex validation (UUID, hash, path traversal checks) | API routes | TA2, TA3 |
| | File size limits (Multer) | API Gateway | TA2, TA3 |
| | Parameterized SQL queries (pg library) | PostgreSQL access | TA2, TA3 |
| | Shell injection prevention (base64 encoding, filename sanitization, command blocklist) | Sandbox execution | TA1 |
| **HTTP Security** | Helmet middleware (default headers) | API Gateway | TA3 |
| | CSP: `script-src 'self'` (no unsafe-inline, no unsafe-eval) | nginx | TA3 |
| | Swagger UI CDN pinned to version 5.17.14 | API Gateway | TA4 |
| **Sample Handling** | Redis-only storage (base64, 1hr TTL) | API Gateway, Orchestrator | TA1, TA3 |
| | Never written to host filesystem | All services | TA1 |
| | Ephemeral sandbox containers | Dynamic Analysis | TA1 |
| **Rate Limiting** | Global: 100 req/15min | API Gateway | TA2, TA3 |
| | Auth: 15 req/15min | API Gateway | TA3 |
| **Supply Chain** | Locked dependencies (package-lock.json) | Build pipeline | TA4 |
| | Local-only vulnerability feeds (no live API calls at scan time) | Vuln-feeds service | TA4 |
| | YARA rules from 4 curated GitHub sources | Vuln-feeds service | TA4 |
| **Availability** | Analysis timeouts | Sandbox containers | TA1, TA2, TA3 |
| | Container resource limits | All containers | TA1, TA4 |
| | Redis TTL on samples | Redis | TA2, TA3 |

## Residual Risks

These risks are accepted or require ongoing management:

1. **Container runtime 0-day (runc/containerd):** A vulnerability in the container runtime could allow sandbox escape. Unlike VM-based isolation, containers share the host kernel -- a kernel exploit from inside the container could compromise the host. Mitigated by: `--cap-drop ALL`, seccomp profile, `no-new-privileges`, `--read-only`, and no Docker socket access. The residual risk is higher than hypervisor-based isolation but acceptable given the defense-in-depth controls.

2. **Shared kernel attack surface:** All sandbox containers share the Linux kernel with the host and all backend services. A kernel privilege escalation exploit from inside a sandbox container could bypass all container-level controls. Mitigated by: seccomp filtering to reduce kernel attack surface, `--cap-drop ALL` to limit available operations, and PID limits to constrain resource usage.

3. **Single INTERNAL_API_KEY for all services:** All inter-service authentication uses the same shared key. Compromise of any single service's environment exposes the key for all services. There are no per-service credentials or fine-grained service-to-service authorization.

4. **No tenant isolation:** The platform is single-tenant. All authenticated users share the same data space. A compromised analyst account can access all submissions and results. Mitigated by RBAC role hierarchy, but no row-level data isolation exists.

5. **SYS_PTRACE capability in sandbox:** Required for strace-based behavioral monitoring, but SYS_PTRACE allows ptrace operations within the container. Malware could use this to inspect or manipulate the monitoring processes running inside the same container.

6. **Detection rule gaps:** Malware families not covered by YARA rules (20,000+ from 4 sources) or behavioral heuristics will produce false negatives. Mitigated by continuous weekly rule updates and multi-layer scoring (three independent scorers with cross-check reconciliation), but novel malware may evade detection until rules are written.

7. **Self-signed TLS:** The nginx reverse proxy uses self-signed certificates. Clients must accept the certificate manually, and there is no certificate chain validation. This is acceptable for the current single-server deployment but would need CA-signed certificates for production internet exposure.

8. **MFA not enforced:** TOTP-based MFA is supported but not required. Users can operate with password-only authentication, leaving accounts vulnerable to credential compromise.

## Review Schedule

This threat model must be reviewed:

- Quarterly (scheduled)
- When a new service is added
- When the sandbox isolation model changes (e.g., adding network access modes)
- When a new threat actor category is identified
- After any security incident
