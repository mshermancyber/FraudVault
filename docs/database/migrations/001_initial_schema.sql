-- =============================================================================
-- FraudVault - Enterprise Malware Detonation Platform
-- Migration 001: Initial Schema
-- =============================================================================
--
-- Description: Creates the complete initial database schema including all
--              tables, types, indexes, constraints, and triggers.
--
-- Apply:   psql -d scanboy -f 001_initial_schema.sql
-- Verify:  SELECT count(*) FROM information_schema.tables
--          WHERE table_schema = 'public';
--          -- Expected: 24 tables
--
-- =============================================================================

BEGIN;

-- ---------------------------------------------------------------------------
-- Migration tracking table (created first so we can record this migration)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS schema_migrations (
    version     INTEGER PRIMARY KEY,
    name        VARCHAR(256) NOT NULL,
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Guard against re-application
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM schema_migrations WHERE version = 1) THEN
        RAISE EXCEPTION 'Migration 001 has already been applied.';
    END IF;
END
$$;

-- ---------------------------------------------------------------------------
-- Extensions
-- ---------------------------------------------------------------------------
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ---------------------------------------------------------------------------
-- Custom Types
-- ---------------------------------------------------------------------------
CREATE TYPE user_role AS ENUM (
    'admin',
    'malware_researcher',
    'threat_hunter',
    'soc_analyst',
    'incident_responder',
    'read_only'
);

CREATE TYPE user_status AS ENUM (
    'active',
    'disabled',
    'locked'
);

CREATE TYPE submission_type AS ENUM (
    'file',
    'url',
    'email',
    'container'
);

CREATE TYPE submission_status AS ENUM (
    'submitted',
    'queued',
    'analyzing',
    'review',
    'escalated',
    'confirmed_malicious',
    'benign',
    'closed'
);

CREATE TYPE threat_level AS ENUM (
    'informational',
    'low',
    'medium',
    'high',
    'critical'
);

CREATE TYPE analysis_job_type AS ENUM (
    'static',
    'dynamic',
    'threat_intel',
    'yara',
    'network',
    'memory'
);

CREATE TYPE analysis_job_status AS ENUM (
    'pending',
    'running',
    'completed',
    'failed',
    'timeout'
);

CREATE TYPE ioc_type AS ENUM (
    'domain',
    'url',
    'ip',
    'hash_md5',
    'hash_sha1',
    'hash_sha256',
    'registry_key',
    'file_path',
    'mutex',
    'service',
    'certificate',
    'email'
);

CREATE TYPE generated_rule_type AS ENUM (
    'sigma',
    'suricata',
    'snort',
    'yara'
);

CREATE TYPE sandbox_status AS ENUM (
    'available',
    'in_use',
    'provisioning',
    'destroying',
    'error'
);

CREATE TYPE internet_mode AS ENUM (
    'isolated',
    'simulated',
    'controlled'
);

-- ---------------------------------------------------------------------------
-- Utility: updated_at trigger function
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ===========================================================================
-- CORE TABLES
-- ===========================================================================

-- ---------------------------------------------------------------------------
-- users
-- ---------------------------------------------------------------------------
CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email           VARCHAR(255) NOT NULL,
    username        VARCHAR(128) NOT NULL,
    display_name    VARCHAR(256),
    password_hash   VARCHAR(512) NOT NULL,
    mfa_secret      VARCHAR(256),
    mfa_enabled     BOOLEAN NOT NULL DEFAULT FALSE,
    role            user_role NOT NULL DEFAULT 'read_only',
    status          user_status NOT NULL DEFAULT 'active',
    failed_login_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until    TIMESTAMPTZ,
    last_login_at   TIMESTAMPTZ,
    password_changed_at TIMESTAMPTZ,
    force_password_change BOOLEAN NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_users_email    UNIQUE (email),
    CONSTRAINT uq_users_username UNIQUE (username),
    CONSTRAINT chk_users_failed_login_attempts CHECK (failed_login_attempts >= 0)
);

COMMENT ON TABLE users IS 'Platform user accounts with RBAC and MFA support.';

CREATE TRIGGER trg_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE INDEX idx_users_email    ON users (email);
CREATE INDEX idx_users_username ON users (username);
CREATE INDEX idx_users_role     ON users (role);
CREATE INDEX idx_users_status   ON users (status);

-- ---------------------------------------------------------------------------
-- sessions
-- ---------------------------------------------------------------------------
CREATE TABLE sessions (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id     UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token_hash  VARCHAR(512) NOT NULL,
    ip_address  INET NOT NULL,
    user_agent  TEXT,
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_sessions_token_hash UNIQUE (token_hash)
);

COMMENT ON TABLE sessions IS 'Active user sessions with expiry tracking.';

CREATE INDEX idx_sessions_user_id    ON sessions (user_id);
CREATE INDEX idx_sessions_token_hash ON sessions (token_hash);
CREATE INDEX idx_sessions_expires_at ON sessions (expires_at);

-- ---------------------------------------------------------------------------
-- audit_log
-- ---------------------------------------------------------------------------
CREATE TABLE audit_log (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id       UUID REFERENCES users (id) ON DELETE SET NULL,
    action        VARCHAR(128) NOT NULL,
    resource_type VARCHAR(128),
    resource_id   VARCHAR(256),
    details       JSONB,
    ip_address    INET,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE audit_log IS 'Immutable audit trail of all security-relevant actions.';

CREATE OR REPLACE FUNCTION prevent_audit_modification()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Audit log records cannot be modified or deleted';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_audit_log_immutable
    BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();

CREATE INDEX idx_audit_log_user_id       ON audit_log (user_id);
CREATE INDEX idx_audit_log_action        ON audit_log (action);
CREATE INDEX idx_audit_log_resource_type ON audit_log (resource_type);
CREATE INDEX idx_audit_log_resource_id   ON audit_log (resource_id);
CREATE INDEX idx_audit_log_created_at    ON audit_log (created_at);
CREATE INDEX idx_audit_log_details       ON audit_log USING GIN (details);

-- ---------------------------------------------------------------------------
-- api_keys
-- ---------------------------------------------------------------------------
CREATE TABLE api_keys (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id     UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    name        VARCHAR(256) NOT NULL,
    key_hash    VARCHAR(512) NOT NULL,
    permissions JSONB NOT NULL DEFAULT '[]'::jsonb,
    last_used_at TIMESTAMPTZ,
    expires_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_api_keys_key_hash UNIQUE (key_hash)
);

COMMENT ON TABLE api_keys IS 'API keys for programmatic access with granular permissions.';

CREATE INDEX idx_api_keys_user_id  ON api_keys (user_id);
CREATE INDEX idx_api_keys_key_hash ON api_keys (key_hash);
CREATE INDEX idx_api_keys_permissions ON api_keys USING GIN (permissions);

-- ===========================================================================
-- SUBMISSION TABLES
-- ===========================================================================

-- ---------------------------------------------------------------------------
-- submissions
-- ---------------------------------------------------------------------------
CREATE TABLE submissions (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id             UUID NOT NULL REFERENCES users (id) ON DELETE RESTRICT,
    filename            VARCHAR(1024),
    file_size           BIGINT,
    file_type           VARCHAR(256),
    mime_type           VARCHAR(256),
    md5                 CHAR(32),
    sha1                CHAR(40),
    sha256              CHAR(64),
    sha512              CHAR(128),
    tlsh                VARCHAR(128),
    ssdeep              VARCHAR(256),
    submission_type     submission_type NOT NULL,
    source_url          TEXT,
    status              submission_status NOT NULL DEFAULT 'submitted',
    threat_score        SMALLINT,
    threat_level        threat_level,
    assigned_analyst_id UUID REFERENCES users (id) ON DELETE SET NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_submissions_threat_score CHECK (threat_score IS NULL OR (threat_score >= 0 AND threat_score <= 100)),
    CONSTRAINT chk_submissions_file_size    CHECK (file_size IS NULL OR file_size >= 0)
);

COMMENT ON TABLE submissions IS 'Malware samples and URLs submitted for analysis.';

CREATE TRIGGER trg_submissions_updated_at
    BEFORE UPDATE ON submissions
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE INDEX idx_submissions_user_id    ON submissions (user_id);
CREATE INDEX idx_submissions_md5        ON submissions (md5);
CREATE INDEX idx_submissions_sha1       ON submissions (sha1);
CREATE INDEX idx_submissions_sha256     ON submissions (sha256);
CREATE INDEX idx_submissions_sha512     ON submissions (sha512);
CREATE INDEX idx_submissions_tlsh       ON submissions (tlsh);
CREATE INDEX idx_submissions_ssdeep     ON submissions (ssdeep);
CREATE INDEX idx_submissions_status     ON submissions (status);
CREATE INDEX idx_submissions_threat_level   ON submissions (threat_level);
CREATE INDEX idx_submissions_threat_score   ON submissions (threat_score);
CREATE INDEX idx_submissions_submission_type ON submissions (submission_type);
CREATE INDEX idx_submissions_assigned_analyst ON submissions (assigned_analyst_id);
CREATE INDEX idx_submissions_created_at ON submissions (created_at);

-- ---------------------------------------------------------------------------
-- submission_tags
-- ---------------------------------------------------------------------------
CREATE TABLE submission_tags (
    submission_id UUID NOT NULL REFERENCES submissions (id) ON DELETE CASCADE,
    tag           VARCHAR(128) NOT NULL,

    PRIMARY KEY (submission_id, tag)
);

COMMENT ON TABLE submission_tags IS 'Freeform tags associated with submissions for categorization.';

CREATE INDEX idx_submission_tags_tag ON submission_tags (tag);

-- ---------------------------------------------------------------------------
-- submission_notes
-- ---------------------------------------------------------------------------
CREATE TABLE submission_notes (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    submission_id UUID NOT NULL REFERENCES submissions (id) ON DELETE CASCADE,
    user_id       UUID NOT NULL REFERENCES users (id) ON DELETE RESTRICT,
    content       TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE submission_notes IS 'Analyst notes and commentary attached to submissions.';

CREATE TRIGGER trg_submission_notes_updated_at
    BEFORE UPDATE ON submission_notes
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE INDEX idx_submission_notes_submission_id ON submission_notes (submission_id);
CREATE INDEX idx_submission_notes_user_id       ON submission_notes (user_id);
CREATE INDEX idx_submission_notes_created_at    ON submission_notes (created_at);

-- ===========================================================================
-- ANALYSIS TABLES
-- ===========================================================================

-- ---------------------------------------------------------------------------
-- analysis_jobs
-- ---------------------------------------------------------------------------
CREATE TABLE analysis_jobs (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    submission_id UUID NOT NULL REFERENCES submissions (id) ON DELETE CASCADE,
    job_type      analysis_job_type NOT NULL,
    status        analysis_job_status NOT NULL DEFAULT 'pending',
    worker_id     VARCHAR(256),
    started_at    TIMESTAMPTZ,
    completed_at  TIMESTAMPTZ,
    error_message TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_analysis_jobs_times CHECK (
        completed_at IS NULL OR started_at IS NULL OR completed_at >= started_at
    )
);

COMMENT ON TABLE analysis_jobs IS 'Individual analysis tasks dispatched for each submission.';

CREATE INDEX idx_analysis_jobs_submission_id ON analysis_jobs (submission_id);
CREATE INDEX idx_analysis_jobs_status        ON analysis_jobs (status);
CREATE INDEX idx_analysis_jobs_job_type      ON analysis_jobs (job_type);
CREATE INDEX idx_analysis_jobs_worker_id     ON analysis_jobs (worker_id);
CREATE INDEX idx_analysis_jobs_created_at    ON analysis_jobs (created_at);

-- ---------------------------------------------------------------------------
-- static_analysis_results
-- ---------------------------------------------------------------------------
CREATE TABLE static_analysis_results (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    submission_id       UUID NOT NULL REFERENCES submissions (id) ON DELETE CASCADE,
    file_metadata       JSONB,
    strings             JSONB,
    entropy_data        JSONB,
    pe_analysis         JSONB,
    elf_analysis        JSONB,
    office_analysis     JSONB,
    pdf_analysis        JSONB,
    script_analysis     JSONB,
    container_analysis  JSONB,
    certificates        JSONB,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_static_analysis_submission UNIQUE (submission_id)
);

COMMENT ON TABLE static_analysis_results IS 'Results of static file analysis including PE, ELF, document, and script parsing.';

CREATE INDEX idx_static_analysis_submission_id   ON static_analysis_results (submission_id);
CREATE INDEX idx_static_analysis_file_metadata   ON static_analysis_results USING GIN (file_metadata);
CREATE INDEX idx_static_analysis_strings         ON static_analysis_results USING GIN (strings);
CREATE INDEX idx_static_analysis_pe_analysis     ON static_analysis_results USING GIN (pe_analysis);
CREATE INDEX idx_static_analysis_elf_analysis    ON static_analysis_results USING GIN (elf_analysis);
CREATE INDEX idx_static_analysis_office_analysis ON static_analysis_results USING GIN (office_analysis);
CREATE INDEX idx_static_analysis_certificates    ON static_analysis_results USING GIN (certificates);

-- ---------------------------------------------------------------------------
-- dynamic_analysis_results
-- ---------------------------------------------------------------------------
CREATE TABLE dynamic_analysis_results (
    id                UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    submission_id     UUID NOT NULL REFERENCES submissions (id) ON DELETE CASCADE,
    sandbox_id        UUID,
    processes         JSONB,
    file_activity     JSONB,
    registry_activity JSONB,
    network_activity  JSONB,
    memory_activity   JSONB,
    services          JSONB,
    scheduled_tasks   JSONB,
    user_activity     JSONB,
    screenshots       JSONB,
    duration_seconds  INTEGER,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_dynamic_analysis_duration CHECK (duration_seconds IS NULL OR duration_seconds >= 0)
);

COMMENT ON TABLE dynamic_analysis_results IS 'Behavioral analysis results captured during sandbox detonation.';

CREATE INDEX idx_dynamic_analysis_submission_id   ON dynamic_analysis_results (submission_id);
CREATE INDEX idx_dynamic_analysis_sandbox_id      ON dynamic_analysis_results (sandbox_id);
CREATE INDEX idx_dynamic_analysis_processes       ON dynamic_analysis_results USING GIN (processes);

CREATE INDEX idx_dynamic_analysis_registry        ON dynamic_analysis_results USING GIN (registry_activity);
CREATE INDEX idx_dynamic_analysis_network         ON dynamic_analysis_results USING GIN (network_activity);
CREATE INDEX idx_dynamic_analysis_memory          ON dynamic_analysis_results USING GIN (memory_activity);

-- ---------------------------------------------------------------------------
-- network_captures
-- ---------------------------------------------------------------------------
CREATE TABLE network_captures (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    submission_id   UUID NOT NULL REFERENCES submissions (id) ON DELETE CASCADE,
    dns_queries     JSONB,
    http_requests   JSONB,
    tls_connections JSONB,
    connections     JSONB,
    pcap_path       VARCHAR(1024),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE network_captures IS 'Network traffic captured during dynamic analysis.';

CREATE INDEX idx_network_captures_submission_id  ON network_captures (submission_id);
CREATE INDEX idx_network_captures_dns_queries    ON network_captures USING GIN (dns_queries);
CREATE INDEX idx_network_captures_http_requests  ON network_captures USING GIN (http_requests);
CREATE INDEX idx_network_captures_tls_connections ON network_captures USING GIN (tls_connections);
CREATE INDEX idx_network_captures_connections    ON network_captures USING GIN (connections);

-- ---------------------------------------------------------------------------
-- memory_analysis_results
-- ---------------------------------------------------------------------------
CREATE TABLE memory_analysis_results (
    id                 UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    submission_id      UUID NOT NULL REFERENCES submissions (id) ON DELETE CASCADE,
    process_dumps      JSONB,
    injected_modules   JSONB,
    suspicious_regions JSONB,
    extracted_strings  JSONB,
    extracted_iocs     JSONB,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE memory_analysis_results IS 'Memory forensics results from sandbox detonation sessions.';

CREATE INDEX idx_memory_analysis_submission_id    ON memory_analysis_results (submission_id);
CREATE INDEX idx_memory_analysis_process_dumps    ON memory_analysis_results USING GIN (process_dumps);
CREATE INDEX idx_memory_analysis_injected_modules ON memory_analysis_results USING GIN (injected_modules);
CREATE INDEX idx_memory_analysis_suspicious       ON memory_analysis_results USING GIN (suspicious_regions);
CREATE INDEX idx_memory_analysis_extracted_iocs   ON memory_analysis_results USING GIN (extracted_iocs);

-- ===========================================================================
-- THREAT INTELLIGENCE TABLES
-- ===========================================================================

-- ---------------------------------------------------------------------------
-- threat_intel_results
-- ---------------------------------------------------------------------------
CREATE TABLE threat_intel_results (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    submission_id   UUID NOT NULL REFERENCES submissions (id) ON DELETE CASCADE,
    provider        VARCHAR(128) NOT NULL,
    verdict         VARCHAR(64),
    detection_count INTEGER,
    total_engines   INTEGER,
    malware_family  VARCHAR(256),
    threat_actors   JSONB,
    campaigns       JSONB,
    first_seen      TIMESTAMPTZ,
    last_seen       TIMESTAMPTZ,
    raw_response    JSONB,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_threat_intel_detections CHECK (
        detection_count IS NULL OR total_engines IS NULL OR detection_count <= total_engines
    ),
    CONSTRAINT chk_threat_intel_counts_positive CHECK (
        (detection_count IS NULL OR detection_count >= 0) AND
        (total_engines IS NULL OR total_engines >= 0)
    )
);

COMMENT ON TABLE threat_intel_results IS 'Enrichment results from external threat intelligence providers.';

CREATE INDEX idx_threat_intel_submission_id  ON threat_intel_results (submission_id);
CREATE INDEX idx_threat_intel_provider       ON threat_intel_results (provider);
CREATE INDEX idx_threat_intel_malware_family ON threat_intel_results (malware_family);
CREATE INDEX idx_threat_intel_verdict        ON threat_intel_results (verdict);
CREATE INDEX idx_threat_intel_threat_actors  ON threat_intel_results USING GIN (threat_actors);
CREATE INDEX idx_threat_intel_campaigns      ON threat_intel_results USING GIN (campaigns);
CREATE INDEX idx_threat_intel_raw_response   ON threat_intel_results USING GIN (raw_response);

-- ---------------------------------------------------------------------------
-- iocs (Indicators of Compromise)
-- ---------------------------------------------------------------------------
CREATE TABLE iocs (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    submission_id UUID NOT NULL REFERENCES submissions (id) ON DELETE CASCADE,
    type          ioc_type NOT NULL,
    value         TEXT NOT NULL,
    context       TEXT,
    confidence    SMALLINT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_iocs_confidence CHECK (confidence IS NULL OR (confidence >= 0 AND confidence <= 100)),
    CONSTRAINT chk_iocs_value_length CHECK (LENGTH(value) <= 4096)
);

COMMENT ON TABLE iocs IS 'Indicators of compromise extracted from analysis results.';

CREATE INDEX idx_iocs_submission_id ON iocs (submission_id);
CREATE INDEX idx_iocs_type          ON iocs (type);
CREATE INDEX idx_iocs_value         ON iocs (value);
CREATE INDEX idx_iocs_confidence    ON iocs (confidence);
CREATE INDEX idx_iocs_type_value    ON iocs (type, value);

-- ---------------------------------------------------------------------------
-- ioc_correlations
-- ---------------------------------------------------------------------------
CREATE TABLE ioc_correlations (
    id                    UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    ioc_id                UUID NOT NULL REFERENCES iocs (id) ON DELETE CASCADE,
    related_submission_id UUID NOT NULL REFERENCES submissions (id) ON DELETE CASCADE,
    correlation_type      VARCHAR(128) NOT NULL,
    confidence            SMALLINT,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_ioc_correlations_confidence CHECK (confidence IS NULL OR (confidence >= 0 AND confidence <= 100))
);

COMMENT ON TABLE ioc_correlations IS 'Cross-submission correlations linking shared IOCs.';

CREATE INDEX idx_ioc_correlations_ioc_id     ON ioc_correlations (ioc_id);
CREATE INDEX idx_ioc_correlations_related_sub ON ioc_correlations (related_submission_id);
CREATE INDEX idx_ioc_correlations_type        ON ioc_correlations (correlation_type);

-- ===========================================================================
-- DETECTION TABLES
-- ===========================================================================

-- ---------------------------------------------------------------------------
-- attack_techniques (MITRE ATT&CK mapping)
-- ---------------------------------------------------------------------------
CREATE TABLE attack_techniques (
    id               UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    submission_id    UUID NOT NULL REFERENCES submissions (id) ON DELETE CASCADE,
    tactic_id        VARCHAR(32) NOT NULL,
    technique_id     VARCHAR(32) NOT NULL,
    sub_technique_id VARCHAR(32),
    evidence         JSONB,
    confidence       SMALLINT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_attack_techniques_confidence CHECK (confidence IS NULL OR (confidence >= 0 AND confidence <= 100))
);

COMMENT ON TABLE attack_techniques IS 'MITRE ATT&CK technique mappings identified during analysis.';

CREATE INDEX idx_attack_techniques_submission_id  ON attack_techniques (submission_id);
CREATE INDEX idx_attack_techniques_tactic         ON attack_techniques (tactic_id);
CREATE INDEX idx_attack_techniques_technique      ON attack_techniques (technique_id);
CREATE INDEX idx_attack_techniques_sub_technique  ON attack_techniques (sub_technique_id);
CREATE INDEX idx_attack_techniques_evidence       ON attack_techniques USING GIN (evidence);

-- ---------------------------------------------------------------------------
-- generated_rules
-- ---------------------------------------------------------------------------
CREATE TABLE generated_rules (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    submission_id UUID NOT NULL REFERENCES submissions (id) ON DELETE CASCADE,
    rule_type     generated_rule_type NOT NULL,
    rule_content  TEXT NOT NULL,
    description   TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE generated_rules IS 'Auto-generated detection rules (Sigma, Suricata, Snort, YARA) from analysis results.';

CREATE INDEX idx_generated_rules_submission_id ON generated_rules (submission_id);
CREATE INDEX idx_generated_rules_rule_type     ON generated_rules (rule_type);

-- ---------------------------------------------------------------------------
-- yara_rules
-- ---------------------------------------------------------------------------
CREATE TABLE yara_rules (
    id             UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name           VARCHAR(256) NOT NULL,
    description    TEXT,
    content        TEXT NOT NULL,
    category       VARCHAR(128),
    author         VARCHAR(256),
    version        INTEGER NOT NULL DEFAULT 1,
    is_active      BOOLEAN NOT NULL DEFAULT TRUE,
    performance_ms INTEGER,
    match_count    BIGINT NOT NULL DEFAULT 0,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_yara_rules_name UNIQUE (name),
    CONSTRAINT chk_yara_rules_version CHECK (version >= 1),
    CONSTRAINT chk_yara_rules_performance CHECK (performance_ms IS NULL OR performance_ms >= 0),
    CONSTRAINT chk_yara_rules_match_count CHECK (match_count >= 0)
);

COMMENT ON TABLE yara_rules IS 'YARA rule library for malware detection and classification.';

CREATE TRIGGER trg_yara_rules_updated_at
    BEFORE UPDATE ON yara_rules
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE INDEX idx_yara_rules_name      ON yara_rules (name);
CREATE INDEX idx_yara_rules_category  ON yara_rules (category);
CREATE INDEX idx_yara_rules_is_active ON yara_rules (is_active);
CREATE INDEX idx_yara_rules_author    ON yara_rules (author);

-- ---------------------------------------------------------------------------
-- yara_scan_results
-- ---------------------------------------------------------------------------
CREATE TABLE yara_scan_results (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    submission_id UUID NOT NULL REFERENCES submissions (id) ON DELETE CASCADE,
    rule_id       UUID NOT NULL REFERENCES yara_rules (id) ON DELETE CASCADE,
    matched       BOOLEAN NOT NULL,
    match_details JSONB,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE yara_scan_results IS 'Results of YARA rule scans against submitted samples.';

CREATE INDEX idx_yara_scan_submission_id ON yara_scan_results (submission_id);
CREATE INDEX idx_yara_scan_rule_id       ON yara_scan_results (rule_id);
CREATE INDEX idx_yara_scan_matched       ON yara_scan_results (matched);
CREATE INDEX idx_yara_scan_match_details ON yara_scan_results USING GIN (match_details);

-- ---------------------------------------------------------------------------
-- detection_results
-- ---------------------------------------------------------------------------
CREATE TABLE detection_results (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    submission_id       UUID NOT NULL REFERENCES submissions (id) ON DELETE CASCADE,
    score_breakdown     JSONB,
    sigma_rules         JSONB,
    suricata_rules      JSONB,
    snort_rules         JSONB,
    yara_recommendations JSONB,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_detection_results_submission UNIQUE (submission_id)
);

CREATE INDEX idx_detection_results_submission_id ON detection_results (submission_id);

-- ===========================================================================
-- CLUSTERING TABLES
-- ===========================================================================

-- ---------------------------------------------------------------------------
-- malware_families
-- ---------------------------------------------------------------------------
CREATE TABLE malware_families (
    id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name         VARCHAR(256) NOT NULL,
    description  TEXT,
    first_seen   TIMESTAMPTZ,
    last_seen    TIMESTAMPTZ,
    sample_count BIGINT NOT NULL DEFAULT 0,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_malware_families_name UNIQUE (name),
    CONSTRAINT chk_malware_families_sample_count CHECK (sample_count >= 0)
);

COMMENT ON TABLE malware_families IS 'Known malware family classifications for clustering analysis.';

CREATE TRIGGER trg_malware_families_updated_at
    BEFORE UPDATE ON malware_families
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE INDEX idx_malware_families_name ON malware_families (name);

-- ---------------------------------------------------------------------------
-- family_memberships
-- ---------------------------------------------------------------------------
CREATE TABLE family_memberships (
    submission_id     UUID NOT NULL REFERENCES submissions (id) ON DELETE CASCADE,
    family_id         UUID NOT NULL REFERENCES malware_families (id) ON DELETE CASCADE,
    confidence        SMALLINT,
    clustering_method VARCHAR(128),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (submission_id, family_id),
    CONSTRAINT chk_family_memberships_confidence CHECK (confidence IS NULL OR (confidence >= 0 AND confidence <= 100))
);

COMMENT ON TABLE family_memberships IS 'Maps submissions to malware family classifications with confidence scores.';

CREATE INDEX idx_family_memberships_family_id ON family_memberships (family_id);
CREATE INDEX idx_family_memberships_confidence ON family_memberships (confidence);

-- ---------------------------------------------------------------------------
-- behavioral_clusters
-- ---------------------------------------------------------------------------
CREATE TABLE behavioral_clusters (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    cluster_vector      JSONB,
    techniques          JSONB,
    network_patterns    JSONB,
    persistence_methods JSONB,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE behavioral_clusters IS 'Behavioral similarity clusters derived from dynamic analysis features.';

CREATE INDEX idx_behavioral_clusters_vector      ON behavioral_clusters USING GIN (cluster_vector);
CREATE INDEX idx_behavioral_clusters_techniques  ON behavioral_clusters USING GIN (techniques);
CREATE INDEX idx_behavioral_clusters_network     ON behavioral_clusters USING GIN (network_patterns);
CREATE INDEX idx_behavioral_clusters_persistence ON behavioral_clusters USING GIN (persistence_methods);

-- ===========================================================================
-- SANDBOX TABLES
-- ===========================================================================

-- ---------------------------------------------------------------------------
-- sandbox_environments
-- ---------------------------------------------------------------------------
CREATE TABLE sandbox_environments (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name        VARCHAR(256) NOT NULL,
    os_type     VARCHAR(64) NOT NULL,
    os_version  VARCHAR(128),
    status      sandbox_status NOT NULL DEFAULT 'available',
    vm_id       VARCHAR(256),
    snapshot_id VARCHAR(256),
    last_used_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_sandbox_environments_name UNIQUE (name)
);

COMMENT ON TABLE sandbox_environments IS 'Managed sandbox VMs for malware detonation.';

CREATE INDEX idx_sandbox_environments_status  ON sandbox_environments (status);
CREATE INDEX idx_sandbox_environments_os_type ON sandbox_environments (os_type);

-- ---------------------------------------------------------------------------
-- detonation_sessions
-- ---------------------------------------------------------------------------
CREATE TABLE detonation_sessions (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    submission_id UUID NOT NULL REFERENCES submissions (id) ON DELETE CASCADE,
    sandbox_id    UUID NOT NULL REFERENCES sandbox_environments (id) ON DELETE RESTRICT,
    internet_mode internet_mode NOT NULL DEFAULT 'isolated',
    started_at    TIMESTAMPTZ,
    ended_at      TIMESTAMPTZ,
    status        analysis_job_status NOT NULL DEFAULT 'pending',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_detonation_sessions_times CHECK (
        ended_at IS NULL OR started_at IS NULL OR ended_at >= started_at
    )
);

COMMENT ON TABLE detonation_sessions IS 'Individual sandbox detonation runs linking submissions to sandbox environments.';

CREATE INDEX idx_detonation_sessions_submission_id ON detonation_sessions (submission_id);
CREATE INDEX idx_detonation_sessions_sandbox_id    ON detonation_sessions (sandbox_id);
CREATE INDEX idx_detonation_sessions_status        ON detonation_sessions (status);
CREATE INDEX idx_detonation_sessions_started_at    ON detonation_sessions (started_at);

-- ===========================================================================
-- Add sandbox_id FK on dynamic_analysis_results now that sandbox_environments exists
-- ===========================================================================
ALTER TABLE dynamic_analysis_results
    ADD CONSTRAINT fk_dynamic_analysis_sandbox
    FOREIGN KEY (sandbox_id) REFERENCES sandbox_environments (id) ON DELETE SET NULL;

-- ===========================================================================
-- Record this migration
-- ===========================================================================
INSERT INTO schema_migrations (version, name) VALUES (1, '001_initial_schema');

COMMIT;
