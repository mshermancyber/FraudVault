# FraudVault User Guide

## Getting Started

### First Login
- Navigate to `https://your-server`
- Default credentials: `admin@scanboy.local` / (configured password)
- Change your password immediately after first login

### Submitting a Sample

1. Click **Submit** in the sidebar
2. Choose submission type:
   - **Upload Suspicious File** — drag and drop or browse (max 500MB), runs malware analysis workflow
   - **Link to Suspicious File** — provide a URL to download and analyze
   - **Suspicious Email** — upload EML/MSG file for analysis
   - **Upload Container Image** — upload Docker/OCI tar image, runs container analysis workflow
   - **Link to Container Image** — provide a URL to a container image
3. Configure analysis options:
   - **Network Mode**: Isolated (default), Simulated Internet, or Controlled Internet
   - **Execution Timeout**: 30s, 60s, 2m, or 5m
4. Click **Submit for Analysis**

### Supported File Types

| Category | Extensions |
|----------|-----------|
| Executables | .exe, .dll, .msi, .sys, .scr |
| Linux | ELF binaries, .so |
| Scripts | .ps1, .sh, .py, .js, .vbs, .bat, .cmd |
| Documents | .pdf, .doc, .docx, .xls, .xlsx, .ppt, .pptx, .rtf |
| Archives | .zip, .rar, .7z, .tar, .tar.gz, .tgz |
| Containers | .tar (Docker/OCI image exports) |

Password-protected archives are automatically cracked using common malware passwords (infected, malware, virus, dangerous, password, 123456, test).

### Understanding the Report

#### Threat Score (0-100)
| Range | Level | Meaning |
|-------|-------|---------|
| 0-9 | Informational | No significant indicators |
| 10-39 | Low | Minor suspicious indicators |
| 40-69 | Medium | Multiple suspicious indicators or behavioral anomalies |
| 70-89 | High | Strong malicious indicators or known-exploited vulnerability |
| 90-100 | Critical | Confirmed malicious with high confidence |

The score is computed by the verdict engine, which aggregates weighted evidence from up to 12 sources (VirusTotal, YARA rules, sandbox behavioral analysis, static analysis, vulnerability data, network behavior, certificates, config extraction, and more) into a structured verdict with classification (malicious/suspicious/benign/inconclusive), confidence rating, and recommended action. A CTI expert and data scientist validated the model — details in the Scoring Model section.

#### Key Badges (next to threat score)
- **CISA KEV** — red badge means the software has vulnerabilities actively exploited in the wild
- **CVSS** — color-coded severity of the highest-scoring CVE
- **EPSS** — probability the vulnerability will be exploited (percentage)

#### Digital Signature Banner
- **Green**: Valid signature from a known Certificate Authority
- **Yellow**: Certificate present but unknown issuer
- **Red**: Invalid or forged signature
- **Gray**: Unsigned binary

#### Threat Intelligence
Shows VirusTotal detection ratio, malware family name, detection engine results, and a direct link to the full VT report. Only the extracted executable hash is looked up (not the archive wrapper). Search results also include VT data inline.

#### Vulnerability Section
If the binary contains PE version metadata, FraudVault checks local vulnerability feeds for known CVEs, cross-references CISA KEV, and shows EPSS exploitation probability. Application classification and CPE data are shown when available.

#### Tech Debt
Compares the installed software version against the latest release from endoflife.date. Shows version gap, end-of-life status, and release date.

#### Deep Analysis
Five tabbed views for PE/ELF binaries:
- **Binary Hardening** — ASLR/DEP/CFG flags, security cookie, Load Config
- **Section Analysis** — per-section entropy, virtual vs raw size ratios
- **Format Analysis** — polyglot detection, embedded files, XOR brute-force results, byte histogram
- **Runtime Behavior** — enhanced strace analysis, /proc extraction, Wine deep tracing
- **Network Intelligence** — JA3 hashes, SNI extraction, SYN packets, DNS timing

#### MITRE ATT&CK Techniques
Techniques mapped to kill chain phases. Each technique links to the official MITRE ATT&CK page.

#### IOCs (Indicators of Compromise)
Grouped by type: domains, URLs, IPs, hashes, registry keys, mutexes, file paths. Trusted infrastructure domains (certificate CRLs, OCSP endpoints, vendor update domains like DigiCert, GlobalSign, Sectigo, Microsoft) are automatically scored at low confidence (5-10%) to separate vendor noise from genuinely suspicious IOCs. Untrusted domains are scored at 65-75% confidence. For container submissions, known-good base image domains (Alpine, Debian, Ubuntu package repos) are similarly downgraded via domain pattern matching rather than blanket suppression.

### Exporting Results

From the submission detail page:
- **Download Report** — Professional PDF report (FraudVault-branded via WeasyPrint)
- **Export STIX** — STIX 2.1 bundle for threat intelligence sharing
- **Generate Sigma Rules** — Detection rules from observed behaviors
- **Generate YARA Rules** — Auto-generated YARA rules from sample characteristics
- **Download PCAP** — Network capture from sandbox (if available)
- **Download SBOM** — CycloneDX 1.6 SBOM (container submissions only)

### Container Image Reports

Container submissions run a separate 3-step workflow: sandbox extraction, SBOM vulnerability scan, and container-specific scoring. The report includes:

- **CycloneDX SBOM** — full package inventory with downloadable JSON
- **Vulnerability findings** — each CVE with CVSS score, severity, KEV status, and EPSS probability
- **Security scan results** — secrets, setuid binaries, suspicious files, supply chain issues, CIS benchmark checks
- **Container score** — 7 sub-score breakdown (vulnerability, configuration, supply chain, malicious, hygiene, structural, secrets) with mandatory floors for critical findings

Container images are analyzed inside the same hardened sandbox jail as malware samples.

### Search

Search by hash, domain, URL, IP, filename, malware family, ATT&CK technique, or registry key. Each result shows the VT detection ratio, malware family, threat level, and a direct link to the VT report.

### Feeds Dashboard

Navigate to **Feeds** in the sidebar to view:
- Record counts per feed (KEV, EPSS, NVD, CPE Match, OSV, endoflife)
- Last pull date and next scheduled refresh
- Feed health status
- Manual refresh buttons per feed

All feeds refresh daily at 03:15. No live API calls are made during scans — all vulnerability enrichment comes from the local SQLite feeds database.

### ATT&CK Matrix

The global ATT&CK matrix at `/attack-matrix` shows all techniques observed across all submissions, organized by tactic.

### Dashboard

Submission trends, threat level distribution, top malware families, and recent critical/high detections.

### API Access

Interactive API documentation at `/api/v1/docs` (Swagger UI). All endpoints require JWT authentication via Bearer token.

### User Roles

| Role | Permissions |
|------|------------|
| Super Admin | Full access, user management, system settings, cannot be deleted when sole super_admin |
| Admin | Full access, user management, system settings |
| Analyst | Submit, analyze, full reports, search |
| Viewer | View reports only |
