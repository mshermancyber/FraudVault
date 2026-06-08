# FraudVault

**Contain. Analyze. Convict.**

Enterprise malware detonation, threat intelligence, and behavioral analysis platform.

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

## Quick Start

```bash
# Generate TLS certs
bash nginx/generate-certs.sh

# Configure
cp .env.example .env
# Edit .env — fill in all required secrets (see .env.example comments)
# Generate secrets with: openssl rand -hex 32

# Build the sandbox image (required for dynamic analysis)
docker compose --profile build-only build scanboy-sandbox

# Start all 17 services
docker compose up -d

# Access
open https://localhost
# Default login: admin@scanboy.local
# Set the admin password — see First Login below
```

### First Login

The admin account is created on first boot with a placeholder password hash. You must set a real password before logging in:

```bash
# Generate a bcrypt hash for your chosen password
docker compose exec api-gateway node -e "require('bcrypt').hash('YOUR_PASSWORD_HERE',12).then(h=>console.log(h))"

# Update the admin user
docker compose exec postgres psql -U scanboy -d scanboy -c \
  "UPDATE users SET password_hash = '<paste-hash-here>' WHERE email = 'admin@scanboy.local';"
```

## What It Does

FraudVault accepts suspicious files, detonates them in hardened throwaway Docker containers, and produces actionable intelligence: threat scores, IOCs, MITRE ATT&CK mappings, detection rules, and exportable reports.

### Malware Analysis

- **Dynamic sandbox** -- Wine-based PE execution with strace, inotifywait, tcpdump, strings, readelf, objdump, xxd, unrar in disposable containers
- **Deep PE analysis** -- sections, Rich header, Load Config, .NET CLR, IAT entropy, resource languages, manifest
- **Config extraction** -- 55+ malware family extractors (Cobalt Strike, Emotet, LockBit, BlackCat, Agent Tesla, Remcos, AsyncRAT, QakBot, and more)
- **YARA rule matching** -- 20,000+ rules from 4 public GitHub sources plus custom rules
- **VirusTotal integration** -- hash lookups on extracted executables
- **MITRE ATT&CK mapping** -- techniques and tactics from observed behaviors
- **IOC extraction** -- network indicators, file artifacts, registry changes with trusted domain scoring (vendor/CA infrastructure automatically separated from suspicious IOCs)
- **Detection rule generation** -- Sigma, Suricata, and Snort rules
- **Report export** -- PDF and STIX 2.1

### Container Image Analysis

- **CycloneDX 1.6 SBOM** -- generated via syft inside sandbox, downloadable and validated
- **SBOM vulnerability scan** -- every package checked against local OSV/NVD feeds with CVSS, EPSS, and KEV enrichment
- **22-capability security scanner** -- layer diffs, trojan layer detection, symlink escape vectors, ELF binary analysis, CIS benchmark checks, entrypoint analysis, Dockerfile reconstruction, certificate analysis, secrets scan, supply chain verification
- **Expert-designed scoring model** -- 7 sub-scores (vulnerability, configuration, supply chain, malicious, hygiene, structural, secrets) with quadratic CVSS scaling, KEV/cryptominer/backdoor floors
- **Separate workflow** -- 3-step pipeline (sandbox extraction, SBOM vuln scan, container scoring) independent from malware scoring

### Scoring Model

Two expert-reviewed scoring models, both driven by a verdict engine that produces structured classifications (malicious/suspicious/benign/inconclusive) with confidence ratings and evidence chains:

- **Malware**: 12 evidence source types weighted by reliability. VT detections (vendor tiered trust), YARA hits, sandbox behavioral signals (override floors), static analysis, CVE/KEV/EPSS correlation (novelty multiplier), config extraction, network behavior, certificate validation, supply chain detection. Domain trust scoring separates vendor/CA infrastructure from suspicious IOCs. Classification thresholds: malicious >= 60, suspicious >= 30, benign <= 15.
- **Container**: 7 sub-scores with quadratic CVSS scaling, diminishing returns decay, synergy bonus, mandatory floors (KEV=70, cryptominer=90, trojan=85, backdoor=90). Known-good base image domains (package repos) downgraded via pattern matching.

### Offline Vulnerability Feeds

All enrichment runs against local SQLite feeds -- no live API calls during scans.

| Feed | Coverage |
|------|----------|
| CISA KEV | 1,610 known exploited vulnerabilities |
| EPSS | 337k exploit probability scores |
| NVD / cvelistV5 | 337k CVEs |
| CPE Match | 1M+ product-to-CVE mappings |
| OSV | 45 ecosystem advisory databases |
| endoflife.date | 700+ product lifecycle records |

Feeds refresh daily via background scheduler.

## Architecture

```
                ┌───────────┐
                │   Nginx   │ :443 (HTTPS) / :80 -> 443 redirect
                └─────┬─────┘
           ┌──────────┼──────────┐
      ┌────▼───┐ ┌────▼────┐ ┌──▼────────┐
      │Frontend│ │API Gate-│ │Swagger UI │
      │ React  │ │  way    │ │ /api/docs │
      └────────┘ └────┬────┘ └───────────┘
        ┌──────────────┼──────────────┐
   ┌────▼─────┐  ┌─────▼──────┐ ┌────▼───────────┐
   │Orchestr- │  │Static      │ │Dynamic Analysis│
   │ator      │  │Analysis    │ │(Docker Sandbox)│
   │(BullMQ)  │  │(PE/ELF)   │ │(strace/wine)   │
   └────┬─────┘  └────────────┘ └────────────────┘
   ┌────┼─────────────┬──────────────┐
┌──▼───┐ ┌──▼────┐ ┌──▼────────┐ ┌──▼────────┐
│Redis │ │Postgr-│ │Elastic-   │ │MinIO      │
│  7   │ │eSQL 16│ │search 8   │ │(artifacts)│
└──────┘ └───────┘ └───────────┘ └───────────┘
```

17 containerized services. Inter-service auth via `INTERNAL_API_KEY`. All communication over Docker internal networks. **Stack**: PostgreSQL 16, Redis 7, Elasticsearch 8, MinIO, BullMQ, React + Vite + TailwindCSS (dark theme, teal accent).

### Sandbox Security

Every sandbox container runs with defense-in-depth isolation:

| Control | Setting |
|---------|---------|
| Filesystem | `--read-only` rootfs |
| Capabilities | `--cap-drop ALL`, add only `SYS_PTRACE` + `NET_RAW` |
| Network | `--network none` (default) |
| Privileges | `--security-opt no-new-privileges` |
| Syscalls | seccomp profile applied |
| Init | PID 1 FDs redirected to `/dev/null` |
| DNS isolation | Fake resolv.conf (8.8.8.8/4.4.4.4) mounted read-only |
| Binaries removed | nsenter, mount, umount |
| SUID stripped | su, passwd, chfn, chsh, gpasswd, newgrp |

Verified through 30+ pentest scenarios across 5 rounds of security scanning (~80 fixes), all clean.

## Configuration

### Required: `.env`

Copy `.env.example` to `.env` and fill in all required secrets. At minimum:

```bash
# Generate all required secrets
openssl rand -hex 32    # Use for JWT_SECRET, JWT_REFRESH_SECRET, INTERNAL_API_KEY
openssl rand -hex 16    # Use for POSTGRES_PASSWORD, REDIS_PASSWORD, etc.

# Optional but recommended
VIRUSTOTAL_API_KEY=your-key-here    # Free tier: 4 lookups/min
```

### Sandbox Network Containment

```bash
# Default: false (all sandboxes fully isolated, --network none)
SANDBOX_ALLOW_NETWORK=false
```

When `false` (default), every sandbox runs with `--network none` regardless of UI selection. Set to `true` only to observe C2 callback behavior in a controlled environment.

### Optional Integrations

```bash
# AI-assisted analysis (pick one)
OPENAI_COMPATIBLE_URL=http://localhost:11434    # Ollama
OPENAI_COMPATIBLE_MODEL=llama3
ANTHROPIC_API_KEY=                              # Claude
OPENAI_API_KEY=                                 # GPT-4

# SIEM forwarding
FRAUDVAULT_WEBHOOK_URL=https://hooks.slack.com/...
FRAUDVAULT_SIEM_TYPE=splunk       # splunk|sentinel|elasticsearch|webhook
FRAUDVAULT_SIEM_ENDPOINT=https://splunk:8088
FRAUDVAULT_SIEM_API_KEY=

# EDR hash blacklisting
FRAUDVAULT_EDR_TYPE=crowdstrike   # crowdstrike|defender|sentinelone
FRAUDVAULT_EDR_ENDPOINT=https://api.crowdstrike.com
FRAUDVAULT_EDR_API_KEY=
```

### Advanced Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `JWT_SECRET` | (required) | JWT signing secret -- use 64+ char random string |
| `JWT_REFRESH_SECRET` | (required) | Separate secret for refresh tokens |
| `JWT_EXPIRY` | `15m` | Access token lifetime |
| `JWT_REFRESH_EXPIRY` | `7d` | Refresh token lifetime |
| `WORKER_CONCURRENCY` | `5` | Max parallel analysis jobs |
| `SANDBOX_TIMEOUT_SECONDS` | `300` | Default sandbox execution timeout |

VirusTotal free tier: 4 req/min, 500 req/day. FraudVault rate-limits VT calls with 16s delays. For high volume, use a premium key.

## System Requirements

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU | 4 cores | 8+ cores |
| RAM | 16 GB | 32 GB |
| Disk | 100 GB | 500 GB (SSD) |
| OS | Linux (Docker host) | Ubuntu 22.04+ / Debian 12+ |
| Docker | 24+ | 29+ |
| Docker Compose | v2+ | v2.20+ |

## Maintenance

```bash
# Purge uploaded files only (keep reports)
bash scripts/purge.sh

# Purge everything (files + analysis data)
bash scripts/purge.sh --all

# Factory reset (including users)
bash scripts/purge.sh --nuke

# View logs
docker compose logs -f orchestrator
docker compose logs -f dynamic-analysis

# Restart a service
docker compose restart api-gateway
```

## Documentation

| Document | Description |
|----------|-------------|
| [User Guide](docs/USER.md) | How to use the platform |
| [Data Model](docs/MODEL.md) | Database schema and data flow |
| [Interactive Diagram](docs/database/data-model-diagram.html) | Visual database schema explorer |
| [Features](docs/FEATURES.md) | Complete feature list |
| [Architecture](docs/architecture/ARCHITECTURE.md) | System design |
| [Threat Model](docs/security/THREAT_MODEL.md) | Security analysis |
| [Trust Boundaries](docs/security/TRUST_BOUNDARIES.md) | Network segmentation and trust zones |
| [Security Review](Scan.md) | 5-round security audit report (68 findings, all fixed) |
| [Offline Feeds](docs/OfflineEngine.md) | Vulnerability feed pipeline spec |
| [Troubleshooting](docs/INSTALL-TROUBLESHOOTING.md) | Install and troubleshooting guide |
| [Gap Analysis](docs/GAP_ANALYSIS.md) | Remaining gaps and tech debt |
| [Deployment Guide](docs/operations/DEPLOYMENT_GUIDE.md) | Installation |
| [Runbook](docs/operations/RUNBOOK.md) | Operations procedures |
| [Disaster Recovery](docs/operations/DISASTER_RECOVERY.md) | DR plan |
| [API Docs](https://localhost/api/v1/docs) | Interactive Swagger UI |
| [Roadmap](docs/ROADMAP.md) | Development roadmap |

## Contributing

FraudVault is maintained by [Mark Sherman](https://github.com/mshermancyber) ([LinkedIn](https://www.linkedin.com/in/mshermancyber)).

Contributions are welcome. Please open an issue or pull request on [GitHub](https://github.com/mshermancyber/FraudVault).

## License

Copyright (C) 2026 Mark Sherman

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the [GNU General Public License](LICENSE) for more details.
