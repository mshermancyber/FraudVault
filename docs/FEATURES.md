# FraudVault Features

## Submission & Intake

- **5 submission types** — Upload Suspicious File, Link to Suspicious File, Suspicious Email, Upload Container Image, Link to Container Image
- **File upload** — drag-and-drop, up to 500MB
- **URL submission** — detonates URLs via curl in sandbox
- **Archive handling** — zip, rar, 7z, tar.gz with automatic password cracking (infected, malware, virus, etc.)
- **Container image upload** — Docker/OCI tar images routed to dedicated container analysis workflow
- **Configurable timeout** — 30s, 60s, 2m, 5m per submission
- **Network mode selection** — isolated (default), simulated internet (FakeNet), controlled (disabled by default via `SANDBOX_ALLOW_NETWORK`)

## Static Analysis

- **PE parsing** — headers, imports, exports, sections with per-section entropy
- **ELF analysis** — libraries, symbols, sections, security features (RELRO, NX, PIE, Fortify)
- **Office macro extraction** — OLE/OOXML with auto-execution trigger detection
- **PDF analysis** — JavaScript, embedded files, actions
- **Script analysis** — PowerShell, Bash, Python, JavaScript, VBScript, Batch (100+ detection patterns per language)
- **Entropy analysis** — overall + per-section, packer detection (UPX, ASPack, Themida, VMProtect)
- **String extraction** — ASCII/Unicode with URL, IP, domain, email, registry key extraction
- **PE metadata** — ProductName, FileVersion, CompanyName, OriginalFilename, LegalCopyright
- **Digital signature verification** — valid vendor certs (DigiCert, GlobalSign, etc.), unknown issuers, forged, unsigned
- **Compile timestamp** extraction from PE header
- **Imphash** — import table hash for malware family clustering
- **SSDEEP/TLSH** fuzzy hashing
- **PDB debug path** extraction

## Deep PE Analysis

- **Section analysis** — virtual vs raw size ratios, section name anomaly detection, per-section entropy
- **Rich header** — full decode of MSVC/linker versions and object file counts (build environment fingerprint)
- **Load Config** — SEH handler count, Guard CF function count, security cookie verification
- **PE checksum** verification (detect post-signing tampering)
- **IAT entropy** — obfuscated import address table detection
- **.NET CLR** — runtime version extraction from CLR header
- **Resource language** extraction (attacker locale identification)
- **Manifest parsing** — requested execution level (asInvoker vs requireAdministrator)
- **Format analysis** — polyglot detection, ZIP bomb detection, embedded file carving
- **Byte-level entropy histogram** — chi-squared distribution analysis
- **XOR brute-force** — 1-byte key scanning on high-entropy regions

## Dynamic Analysis (Docker Sandbox)

- **Throwaway containers** — fresh `scanboy-sandbox:latest` per analysis, destroyed after
- **Hardened jail** — `--read-only`, `--cap-drop ALL`, `--network none`, `no-new-privileges`, seccomp default-deny profile, PID 1 FDs to /dev/null. 30-vector pentest verified: zero host file-write primitives
- **Analysis tools** — python3, strace, inotifywait, tcpdump, file, strings, readelf, objdump, xxd, wine, 7z, unrar
- **Wine PE execution** — runs Windows executables under Wine with strace monitoring
- **strace syscall tracing** — tracks open, connect, execve, clone, write, unlink, chmod, mkdir, and 20+ syscalls
- **inotifywait filesystem monitoring** — real-time file creation/modification/deletion tracking
- **tcpdump network capture** — DNS, HTTP, TCP connections (when network enabled)
- **Wine registry diffing** — before/after comparison of system.reg and user.reg
- **Process tree construction** — parent-child relationships, command lines
- **Network simulation (FakeNet)** — DNS responder + HTTP server inside sandbox for C2 observation
- **PCAP capture** — downloadable network capture file (capped at 10MB)
- **False positive filtering** — sandbox infrastructure (exec scripts, benign DLLs) excluded from indicators
- **Packing deduplication** — entropy + section names + YARA consolidated into single indicator

## Threat Intelligence

- **VirusTotal integration** — looks up extracted executable hash (not archive hash), returns detection ratio, malware family, engine results, alternative names, tags, first/last seen
- **VT link** — direct link to full VirusTotal report
- **Detection engine breakdown** — which AV engines flagged it and what they called it
- **Domain trust scoring** — data-driven from PE signer/issuer, known CA domains, and vendor domain mapping. Trusted domains score confidence 10%, untrusted 65-75%
- **Search with VT enrichment** — search results show VT detection ratio, malware family, and link

## Vulnerability Analysis (Offline Feeds)

- **CVE lookup** — MITRE cvelistV5 corpus (337k+ CVEs) stored locally in SQLite
- **CPE matching** — 1M+ CPE-to-CVE mappings from NVD data
- **CISA KEV** — 1,610+ Known Exploited Vulnerabilities with due dates
- **EPSS scores** — 337k+ Exploit Prediction Scoring System probabilities
- **OSV** — 45 ecosystem vulnerability databases
- **Tech debt** — endoflife.date with 700+ products, version comparison
- **Application classification** — CPE dictionary lookup (120+ product mappings)
- **Daily refresh** — all feeds update at 03:15 daily via cron scheduler
- **Zero live API calls at scan time** — all enrichment from local SQLite feeds database
- **Feeds dashboard** — record counts, last pull dates, status, manual refresh buttons

## YARA Scanning

- **20,000+ YARA rules** — 391 inline rules plus 20,000+ community rules from 4 public GitHub sources (signature-base, YARA-Rules, ReversingLabs, bartblaze)
- **Binary YARA scanning** — actual `yara` binary execution inside sandbox on sample and extracted files
- **Custom rules** — RedBoot_Ransomware, MBR_Wiper_Generic, AutoIt_Ransomware_Generic, Ransomware_File_Encryptor
- **Weekly refresh** — community rules pulled from GitHub repositories on a weekly schedule
- **YARA Rules management page** — browse sources, search rules, view rule content
- **Rule coverage**: UPX, ASPack, Themida, VMProtect, WannaCry, LockBit, Cobalt Strike, Meterpreter, Remcos, AsyncRAT, njRAT, Agent Tesla, Emotet, QakBot, RedLine, Mimikatz, and more

## Container Image Analysis

- **CycloneDX 1.6 SBOM generation** — via syft binary inside sandbox, downloadable JSON
- **SBOM vulnerability scanning** — each package checked against local OSV/NVD feeds
- **22-capability security scanner** — Python script running inside jailed sandbox:
  - OS detection (Alpine APK, Debian DPKG)
  - Secrets scan (passwords, API keys, AWS AKIA tokens, private keys, GitHub tokens) with config template exclusions
  - Setuid binary detection (flags abnormal setuid beyond system defaults)
  - ELF binary analysis (readelf: packed sections, suspicious imports, RPATH injection, static linking)
  - User/permission analysis (UID-0 aliases, empty shadow passwords, world-writable root files, runs-as-root)
  - Entrypoint/CMD analysis (eval injection, curl/wget at startup, sshd in entrypoint)
  - Sensitive file detection (.bash_history, .aws/credentials, .kube/config, .docker/config.json, .env, SSH keys)
  - Network config analysis (/etc/hosts aliasing, LD_PRELOAD injection)
  - CIS Docker Benchmark image-level checks
  - Configuration file auditing (nginx, sshd, redis, pg_hba, PHP)
  - Certificate/TLS analysis (self-signed, expired, private keys bundled with certs)
  - Capability-dependent binary detection (nsenter, mount, strace, tcpdump)
  - Nested archive/container detection
  - Multi-stage build leak detection (compilers, SDKs, .git directories)
  - Dockerfile reconstruction from image history
  - Base image identification and fingerprinting
  - Cron job analysis (scheduled callbacks, cryptominer crons)
  - Supply chain verification (forged keys, unofficial repos, unsigned packages, dependency confusion)
  - Backdoor/cryptominer/beacon detection
  - Symlink/hardlink escape vector detection (CVE-2024-21626 class)
  - Trojan layer detection (binary modified across layers)
  - Layer-by-layer filesystem diffs
  - Writable path analysis
- **Expert-designed container scoring model** — 7 sub-scores with quadratic CVSS scaling, diminishing returns, synergy bonus, mandatory floors

### Container Scoring Model

| Sub-Score | Cap | Key Signals |
|-----------|-----|-------------|
| Vulnerability | 45 | Quadratic CVSS scaling, KEV 2.5x amplifier, EPSS percentile multiplier, diminishing returns decay |
| Configuration | 20 | Runs as root, CIS benchmark failures/warnings |
| Supply Chain | 20 | Forged keys, unofficial sources, unsigned packages |
| Malicious | 30 | Cryptominers, backdoors, beacons |
| Hygiene | 15 | Sensitive files, compilers in prod, .git dirs, capability binaries, private keys |
| Structural | 30 | Symlink escapes, trojan layers, abnormal setuid |
| Secrets | 25 | Exposed passwords, API keys, private keys |

**Mandatory floors**: KEV present = 70, backdoor = 90, cryptominer = 90, trojan layer = 85, symlink escape = 80, forged keys = 70.

## Config Extraction

55+ malware family configuration extractors:
- **Cobalt Strike** — XOR-decoded C2 URLs, beacon interval, watermark, public key
- **Emotet** — RSA key + C2 IP:port list
- **Agent Tesla** — SMTP/FTP credentials, Telegram tokens
- **Remcos RAT** — RC4 encrypted config with C2 addresses
- **AsyncRAT** — AES encrypted host/port from .NET resources
- **QakBot** — RC4 C2 list with campaign ID
- **LockBit, BlackCat/ALPHV, Conti, REvil** — ransomware C2 and encryption configs
- **IcedID, BumbleBee, Raccoon, RedLine, Vidar** — stealer/loader configs
- **Sliver, Havoc, Mythic, BruteRatel** — C2 framework configs
- And 40+ more families including njRAT, DarkComet, NanoCore, Poison Ivy, Gh0st, PlugX, ShadowPad, Trickbot, Dridex, Gozi, Ursnif, ZLoader, FormBook, XLoader, LokiBot, Amadey, SmokeLoader, SystemBC, Tofsee, Phorpiex, Sality, Virut, Ramnit, Zbot, Danabot, AZORult, Predator, NetWire, BitRAT, DcRAT, Warzone, Orcus

## Deobfuscation

- **PowerShell** — base64, GZip, XOR, char code, string reversal, IEX unwrapping
- **JavaScript** — eval/Function hooking via Node.js sandbox
- **Office macros** — Chr() concatenation, StrReverse, Shell command extraction
- **.NET decompilation** — IL disassembly via monodis, method/string extraction

## MITRE ATT&CK

- **Automatic technique mapping** from observed behaviors
- **Kill chain visualization** — techniques grouped by tactic phase
- **Global ATT&CK matrix** — heat map across all submissions
- **Links to MITRE website** for each technique

## Malware Scoring Model

### Verdict Engine (Evidence-Chain Classification)

The verdict engine produces structured verdicts with confidence ratings and evidence chains:

- **Classification**: malicious, suspicious, benign, or inconclusive
- **Confidence**: 0-100 based on evidence volume, source agreement, and definitive signals
- **Evidence chain**: weighted items from 12 source types (virustotal, sandbox, static_analysis, yara, network, signature, behavioral, threat_intel, config_extraction, memory_analysis, certificate, heuristic)
- **Recommended action**: Block, Quarantine, Monitor, or Allow

**Classification thresholds**: malicious ≥ 60, suspicious ≥ 30, benign ≤ 15. Overrides: high VT ratio (≥80% confidence, ≥70 weight) or known malware family + score ≥ 50 → malicious. Config extraction with ≥70 confidence → malicious. Valid vendor certificate + low VT + score below suspicious → benign.

### Component Scoring

Expert-reviewed multi-component scoring (0-100) with CTI and data science validation:

- **VirusTotal** (up to 70 pts) — 7-tier ratio scoring, malware family severity weighting (ransomware/trojan +15, adware +3), 75%+ near-unanimous tier
- **YARA** (up to 50 pts) — severity-weighted with novelty multiplier when VT absent
- **Sandbox behavioral** (up to 65 pts) — risk score + indicator severity with per-category caps and dedup. Category floors: ransomware=65, C2=45, reverse_shell=60
- **Static analysis** (up to 25 pts) — packing, entropy, imports, obfuscation, keyword clusters
- **Vulnerability** (up to 35 pts) — KEV=25, CVSS-scaled, EPSS stacking, tech debt

**Trust adjustments:**
- **Vendor signature tiered cap** — clean behavior → cap at 10; moderate behavior → cap at 30; critical behavior → no cap (supply chain detection)
- **Novelty multiplier** — 1.4x sandbox/YARA weight when VT has no coverage (zero-day amplification)
- **Behavioral override floor** — ransomware/C2/reverse_shell categories guarantee MEDIUM minimum (55)
- **KEV floor** — known-exploited vulns = automatic HIGH (70); KEV + high EPSS = 75
- **Domain trust** — data-driven reduction when extracted domains match vendor/CA infrastructure
- **Clean VT conditional** — penalty only when sandbox is also quiet (protects zero-days)

## Reporting

- **PDF report** — professional FraudVault-branded document via WeasyPrint with all analysis sections
- **STIX 2.1 export** — threat intelligence sharing format
- **Sigma rule generation** — from observed behaviors
- **Suricata/Snort rules** — from observed network traffic
- **Auto-generated YARA rules** — from unique sample characteristics
- **CycloneDX SBOM download** — for container image submissions

## Integrations

- **SIEM forwarding** — Splunk HEC, Azure Sentinel, Elasticsearch, QRadar, generic webhook
- **Slack/Teams alerts** — on critical findings
- **EDR hash push** — CrowdStrike, Microsoft Defender, SentinelOne blacklisting

## Infrastructure

- **17 containerized services** on Docker Compose
- **Nginx HTTPS** on port 443 (HTTP on port 80 redirects to HTTPS)
- **PostgreSQL 16** — 25 tables with full indexing
- **Redis 7** — queues, pub/sub, file storage cache (1-hour TTL)
- **Elasticsearch 8** — full-text search and correlation
- **MinIO** — S3-compatible artifact storage
- **BullMQ** — 8-queue job orchestration pipeline
- **Swagger UI** — interactive API documentation at `/api/v1/docs`
- **Inter-service authentication** — shared INTERNAL_API_KEY on all internal services

## Security

- **5 rounds of security scanning** — ~80 vulnerabilities found and fixed across all 13 packages
- **Parameterized SQL** — zero SQL injection vectors
- **JWT HS256 pinned** — algorithm whitelist prevents confusion attacks; separate JWT_REFRESH_SECRET for refresh tokens
- **RBAC + ownership** — all submission routes enforce user_id ownership
- **Error message containment** — generic errors to clients, details only in structured logs
- **Sandbox pentest** — 30+ escape vectors tested across multiple rounds, zero host writes possible
- **Malware isolation** — samples stay in Redis (ephemeral) and disposable containers only, never on host disk
- **DNS isolation** — fake resolv.conf with 8.8.8.8/4.4.4.4 mounted read-only, prevents host DNS leakage
- **Binary hardening** — nsenter, mount, umount removed; SUID stripped from su, passwd, chfn, chsh, gpasswd, newgrp
- **Atomic lockout** — login fail counter via Redis INCR (race-condition-free), MFA brute-force rate limiting (5 attempts/session)
- **Inter-service auth** — INTERNAL_API_KEY required on all internal services, fail-closed pattern (missing key = reject)
- **CSP hardened** — `script-src 'self'` (no unsafe-inline, no unsafe-eval)
- **Soft delete** — users set to `disabled` status, never hard-deleted from database
- **Last super_admin guard** — prevents deletion of the sole super_admin account
- **Token revocation** — frontend logout calls backend to invalidate refresh tokens; refresh tokens single-use via Redis SETNX
- **SSRF protection** — DNS pinning (resolve → check IP → pin resolved IP into URL), private IP blocking (RFC 1918, IPv6 ::1, link-local), redirect chain validation with per-hop DNS re-check
- **Seccomp profile** — default-deny syscall filter on all sandbox containers
- **RFC 1918 validation** — private IP ranges parsed numerically (172.16-31.x.x second octet check, IPv6 bracket detection)
- **Shell injection prevention** — base64 encoding for data passed to sandbox scripts, filename sanitization, command character blocklist
- **Swagger CDN pinned** — Swagger UI CSS/JS pinned to specific version (5.17.14), no floating `@5` tags
- **NaN propagation guards** — Number.isFinite checks on all CVSS/score arithmetic paths
- **Trusted domain scoring** — PE signer/issuer domains and known CA infrastructure (DigiCert, GlobalSign, Sectigo CRL/OCSP endpoints, Microsoft update domains) automatically scored at low confidence (5-10%) to separate vendor noise from genuinely suspicious IOCs; untrusted domains scored at 65-75%
- **Container IOC filtering** — known-good base image domains (alpine, debian, ubuntu package repos) downgraded via domain pattern matching, not blanket suppression

## Administration

- **RBAC** — super_admin, admin, analyst, viewer roles
- **User management** — create, disable, role assignment
- **Audit logging** — all actions recorded
- **Purge script** — `scripts/purge.sh` for cache/data cleanup
- **Health checks** — all services expose `/health`
