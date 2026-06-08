# FraudVault Data Model

**[Open Interactive Diagram](database/data-model-diagram.html)** -- pan, zoom, click to expand tables, right-click to highlight relationships, double-click for full details.

## Database: PostgreSQL 16

### Entity Relationship Overview

```
users ──┬── sessions
        ├── api_keys
        ├── audit_log
        └── submissions ──┬── analysis_jobs
                          ├── static_analysis_results
                          ├── dynamic_analysis_results
                          ├── threat_intel_results
                          ├── iocs ── ioc_correlations
                          ├── attack_techniques
                          ├── generated_rules
                          ├── yara_scan_results
                          ├── network_captures
                          ├── memory_analysis_results
                          ├── submission_notes
                          ├── submission_tags
                          ├── detonation_sessions
                          └── family_memberships ── malware_families
                                                    behavioral_clusters

sandbox_environments ── detonation_sessions
yara_rules ── yara_scan_results
```

### Core Tables

#### `users`
| Column | Type | Description |
|--------|------|-------------|
| id | uuid (PK) | Auto-generated |
| email | varchar(255) | Unique, login identifier |
| username | varchar(128) | Login identifier |
| display_name | varchar(256) | Display name |
| password_hash | varchar(512) | bcrypt hashed |
| role | enum | viewer, analyst, admin, super_admin |
| status | enum | active, disabled, locked |
| mfa_enabled | boolean | TOTP MFA flag |
| failed_login_attempts | integer | Legacy column (lockout now tracked via atomic Redis INCR) |

#### `submissions`
| Column | Type | Description |
|--------|------|-------------|
| id | uuid (PK) | Auto-generated |
| user_id | uuid (FK→users) | Who submitted |
| filename | varchar(1024) | Original filename |
| file_size | bigint | Bytes |
| file_type | varchar(256) | Extension |
| mime_type | varchar(256) | Detected MIME |
| md5 | char(32) | Hash |
| sha1 | char(40) | Hash |
| sha256 | char(64) | Hash |
| sha512 | char(128) | Hash |
| submission_type | enum | file, url, email, container |
| source_url | text | For URL submissions |
| status | enum | submitted, queued, analyzing, review, escalated, confirmed_malicious, benign, closed |
| threat_score | smallint | 0-100 |
| threat_level | enum | informational, low, medium, high, critical |

#### `analysis_jobs`
| Column | Type | Description |
|--------|------|-------------|
| id | uuid (PK) | |
| submission_id | uuid (FK→submissions) | |
| job_type | enum | static, dynamic, threat_intel, yara, network, memory |
| status | enum | pending, running, completed, failed, timeout |
| started_at | timestamptz | |
| completed_at | timestamptz | |
| error_message | text | On failure |

#### `static_analysis_results`
| Column | Type | Description |
|--------|------|-------------|
| submission_id | uuid (FK) | |
| file_metadata | jsonb | File type, magic, packer info |
| strings | jsonb | Extracted strings array |
| entropy_data | jsonb | Overall + per-section entropy |
| pe_analysis | jsonb | Imports, exports, sections, suspicious imports |
| elf_analysis | jsonb | Libraries, symbols, sections |
| office_analysis | jsonb | Macros, OLE objects |
| pdf_analysis | jsonb | JavaScript, actions, embedded content |
| script_analysis | jsonb | Obfuscation indicators |
| certificates | jsonb | Digital signature info |

#### `dynamic_analysis_results`
| Column | Type | Description |
|--------|------|-------------|
| submission_id | uuid (FK) | |
| sandbox_id | uuid (FK→sandbox_environments) | |
| processes | jsonb | Process tree, command lines |
| file_activity | jsonb | Created/modified/deleted files (can be 30MB+ from wine) |
| registry_activity | jsonb | Wine registry changes |
| network_activity | jsonb | Connections, DNS, HTTP |
| memory_activity | jsonb | Suspicious indicators, risk score, extracted files, YARA matches |
| duration_seconds | integer | Execution time |

#### `threat_intel_results`
| Column | Type | Description |
|--------|------|-------------|
| submission_id | uuid (FK) | |
| provider | varchar | virustotal-extracted-sha256, cve-lookup, tech-debt, cpe-classification, config-extraction |
| verdict | varchar | malicious, clean, suspicious |
| detection_count | integer | Engines detecting |
| total_engines | integer | Total engines scanned |
| malware_family | varchar | Family name if identified |
| first_seen | timestamptz | |
| last_seen | timestamptz | |
| raw_response | jsonb | Full provider response (VT engines, CVE details, etc.) |

#### `iocs`
| Column | Type | Description |
|--------|------|-------------|
| submission_id | uuid (FK) | |
| type | enum | domain, url, ip, hash_md5, hash_sha1, hash_sha256, registry_key, file_path, mutex, service, certificate, email |
| value | text | The IOC value |
| context | text | Where/how it was found |
| confidence | smallint | 0-100 |

#### `attack_techniques`
| Column | Type | Description |
|--------|------|-------------|
| submission_id | uuid (FK) | |
| tactic_id | varchar | Kill chain phase (defense-evasion, execution, etc.) |
| technique_id | varchar | MITRE ID (T1027.002, T1059, etc.) |
| evidence | jsonb | What triggered the mapping |
| confidence | smallint | 0-100 |

#### `yara_rules` / `yara_scan_results`
Rules table stores rule definitions. Scan results link rules to submissions with match details.

#### `malware_families` / `family_memberships` / `behavioral_clusters`
Clustering infrastructure for grouping related samples by behavior.

### Indexes

105 indexes including:
- Hash lookups (md5, sha1, sha256, sha512, ssdeep, tlsh)
- GIN indexes on all JSONB columns for JSON path queries
- Status, threat_level, submission_type for filtering
- Foreign key indexes for JOIN performance

### Enum Types

11 custom PostgreSQL enums: user_role, user_status, submission_type, submission_status, threat_level, analysis_job_type, analysis_job_status, ioc_type, sandbox_status, internet_mode, generated_rule_type

### Data Flow

```
Upload → Redis (base64, 1hr TTL)
       → PostgreSQL (submission record)
       → Redis pub/sub (trigger orchestrator)
       → Orchestrator creates analysis_jobs
       → Services write results to PostgreSQL
       → Verdict engine aggregates evidence → classification + confidence
       → Frontend queries PostgreSQL via API Gateway
```

File bytes live in Redis for 1 hour only. Analysis results persist in PostgreSQL indefinitely. The `file_activity` column in dynamic_analysis_results is excluded from API responses (can be 30MB+ from wine temp file noise).

### Authentication State in Redis

Login lockout tracking uses atomic Redis operations rather than the database column:
- `scanboy:session:fail_count:<userId>` — atomic INCR per failed login (TTL = lockout window)
- `scanboy:session:mfa_attempts:<mfaSessionId>` — MFA brute-force rate limiting (5 max, 300s TTL)
- Refresh tokens stored with atomic SETNX for single-use rotation
