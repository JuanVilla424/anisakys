-- Schema produced by the runtime DDL that Anisakys executed on every start
-- before Alembic revision 003 (commit 729d038), in the order Engine.__init__
-- ran it, followed by ReportTracker's column back-fill. No alembic_version
-- table: these databases were never migrated by Alembic.
--
-- Used by tests/database/test_migrations.py to prove that
-- `alembic upgrade head` converts such a database without losing data.

-- DatabaseManager.init_db
CREATE TABLE IF NOT EXISTS scan_results (
    id SERIAL PRIMARY KEY,
    url TEXT UNIQUE,
    first_seen TIMESTAMP,
    last_seen TIMESTAMP,
    response_code INTEGER,
    found_keywords TEXT,
    count INTEGER
);

-- DatabaseManager.init_phishing_db (no GSB columns: migrate_gsb_columns was
-- never called at runtime)
CREATE TABLE IF NOT EXISTS phishing_sites (
    id SERIAL PRIMARY KEY,
    url TEXT UNIQUE,
    manual_flag INTEGER DEFAULT 0,
    auto_detected INTEGER DEFAULT 0,
    first_seen TIMESTAMP,
    last_seen TIMESTAMP,
    whois_info TEXT,
    abuse_email TEXT,
    reported INTEGER DEFAULT 0,
    abuse_report_sent INTEGER DEFAULT 0,
    site_status TEXT DEFAULT 'up',
    takedown_date TIMESTAMP,
    last_report_sent TIMESTAMP,
    resolved_ip TEXT,
    asn_provider TEXT,
    is_cloudflare INTEGER,
    provider_abuse_email TEXT,
    source TEXT DEFAULT 'manual',
    priority TEXT DEFAULT 'medium',
    description TEXT,
    asn TEXT,
    asn_abuse_email TEXT,
    hosting_provider TEXT,
    all_abuse_emails TEXT,
    virustotal_result TEXT,
    urlvoid_result TEXT,
    phishtank_result TEXT,
    multi_api_threat_level TEXT,
    api_confidence_score INTEGER,
    auto_analysis_status TEXT DEFAULT 'pending',
    auto_analysis_timestamp TIMESTAMP,
    detection_keywords TEXT,
    auto_report_eligible INTEGER DEFAULT 0,
    requires_manual_review INTEGER DEFAULT 0,
    manual_emails INTEGER DEFAULT 0,
    registration_date TIMESTAMP,
    registrar_name TEXT,
    registrant_org TEXT,
    domain_age_days INTEGER,
    status TEXT DEFAULT 'new',
    assigned_to TEXT
);
ALTER TABLE phishing_sites ADD COLUMN IF NOT EXISTS detected_kit_type TEXT;
ALTER TABLE phishing_sites ADD COLUMN IF NOT EXISTS kit_confidence INTEGER;
ALTER TABLE phishing_sites ADD COLUMN IF NOT EXISTS kit_indicators TEXT;

-- src.api.phishing_api.upgrade_phishing_db: abuse_reports (API variant,
-- without site_id / screenshot_path / attachment_count) ...
CREATE TABLE IF NOT EXISTS abuse_reports (
    id SERIAL PRIMARY KEY,
    site_url TEXT NOT NULL,
    report_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    recipients TEXT NOT NULL,
    cc_recipients TEXT,
    subject TEXT,
    report_id TEXT UNIQUE,
    status TEXT DEFAULT 'sent',
    response_received INTEGER DEFAULT 0,
    response_date TIMESTAMP,
    response_content TEXT,
    sla_deadline TIMESTAMP,
    icann_compliant INTEGER DEFAULT 1,
    screenshot_included INTEGER DEFAULT 0,
    multi_api_results TEXT,
    confidence_score INTEGER,
    threat_level TEXT,
    follow_up_required INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
-- ... and the phishing_sites columns that init_phishing_db did not create.
ALTER TABLE phishing_sites ADD COLUMN registrar TEXT;
ALTER TABLE phishing_sites ADD COLUMN screenshot_taken INTEGER DEFAULT 0;
ALTER TABLE phishing_sites ADD COLUMN screenshot_path TEXT;
ALTER TABLE phishing_sites ADD COLUMN screenshot_timestamp TIMESTAMP;

-- DatabaseManager.init_registrar_abuse_db
CREATE TABLE IF NOT EXISTS registrar_abuse (
    id SERIAL PRIMARY KEY,
    registrar_name TEXT UNIQUE NOT NULL,
    abuse_emails TEXT,
    verified INTEGER DEFAULT 0,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    notes TEXT,
    manual_override INTEGER DEFAULT 0
);

-- DatabaseManager.init_hosting_abuse_db
CREATE TABLE IF NOT EXISTS hosting_abuse (
    id SERIAL PRIMARY KEY,
    provider_name TEXT NOT NULL,
    asn TEXT,
    abuse_emails TEXT,
    verified INTEGER DEFAULT 0,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    notes TEXT,
    manual_override INTEGER DEFAULT 0,
    UNIQUE(provider_name, asn)
);

-- DatabaseManager.init_threads_db
CREATE TABLE IF NOT EXISTS analysis_threads (
    id SERIAL PRIMARY KEY,
    thread_type VARCHAR(50) NOT NULL,
    label VARCHAR(255),
    account_id VARCHAR(20),
    status VARCHAR(20) NOT NULL,
    started_at TIMESTAMP NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMP,
    results_count INTEGER NOT NULL DEFAULT 0,
    details JSONB,
    error_message TEXT,
    image_s3_key VARCHAR(500),
    original_filename VARCHAR(255),
    content_type VARCHAR(100),
    file_size_bytes INTEGER,
    search_interval_hours INTEGER,
    last_searched_at TIMESTAMP
);
CREATE TABLE IF NOT EXISTS thread_results (
    id SERIAL PRIMARY KEY,
    thread_id INTEGER NOT NULL REFERENCES analysis_threads(id),
    result_type VARCHAR(50) NOT NULL,
    found_url VARCHAR(2000),
    title VARCHAR(500),
    confidence REAL,
    thumbnail_url VARCHAR(2000),
    source VARCHAR(100),
    first_detected_at TIMESTAMP NOT NULL DEFAULT NOW(),
    last_detected_at TIMESTAMP NOT NULL DEFAULT NOW(),
    status VARCHAR(20) NOT NULL DEFAULT 'new',
    assigned_to VARCHAR(100),
    details JSONB
);
CREATE INDEX IF NOT EXISTS idx_threads_type ON analysis_threads(thread_type);
CREATE INDEX IF NOT EXISTS idx_threads_status ON analysis_threads(status);
CREATE INDEX IF NOT EXISTS idx_results_thread ON thread_results(thread_id);
CREATE INDEX IF NOT EXISTS idx_results_status ON thread_results(status);
CREATE TABLE IF NOT EXISTS thread_executions (
    id SERIAL PRIMARY KEY,
    thread_id INTEGER NOT NULL REFERENCES analysis_threads(id),
    execution_type VARCHAR(50) NOT NULL,
    started_at TIMESTAMP DEFAULT NOW(),
    completed_at TIMESTAMP,
    status VARCHAR(20) NOT NULL DEFAULT 'running',
    results_count INTEGER NOT NULL DEFAULT 0,
    error_message TEXT,
    details JSONB
);
CREATE INDEX IF NOT EXISTS idx_executions_thread ON thread_executions(thread_id);
CREATE INDEX IF NOT EXISTS idx_executions_status ON thread_executions(status);
ALTER TABLE thread_results ADD COLUMN IF NOT EXISTS execution_id INTEGER REFERENCES thread_executions(id);
CREATE INDEX IF NOT EXISTS idx_results_execution ON thread_results(execution_id);
ALTER TABLE thread_results ADD COLUMN IF NOT EXISTS extra_data JSONB;
ALTER TABLE thread_results ADD COLUMN IF NOT EXISTS source_type VARCHAR(20);

-- DatabaseManager._init_email_reputation_db (called by init_threads_db)
CREATE TABLE IF NOT EXISTS email_sender_reputation (
    id SERIAL PRIMARY KEY,
    sender_email VARCHAR(320) NOT NULL,
    sender_domain VARCHAR(255) NOT NULL,
    display_name VARCHAR(255),
    report_count INTEGER NOT NULL DEFAULT 0,
    automated_count INTEGER NOT NULL DEFAULT 0,
    threat_score_avg REAL NOT NULL DEFAULT 0,
    threat_score_max REAL NOT NULL DEFAULT 0,
    first_seen_at TIMESTAMP NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMP NOT NULL DEFAULT NOW(),
    blocked BOOLEAN NOT NULL DEFAULT FALSE,
    blocked_at TIMESTAMP,
    block_reason TEXT,
    UNIQUE(sender_email)
);
CREATE TABLE IF NOT EXISTS email_domain_reputation (
    id SERIAL PRIMARY KEY,
    domain VARCHAR(255) NOT NULL,
    sender_count INTEGER NOT NULL DEFAULT 0,
    report_count INTEGER NOT NULL DEFAULT 0,
    automated_count INTEGER NOT NULL DEFAULT 0,
    threat_score_avg REAL NOT NULL DEFAULT 0,
    first_seen_at TIMESTAMP NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMP NOT NULL DEFAULT NOW(),
    blocked BOOLEAN NOT NULL DEFAULT FALSE,
    blocked_at TIMESTAMP,
    block_reason TEXT,
    UNIQUE(domain)
);
CREATE INDEX IF NOT EXISTS idx_sender_rep_domain ON email_sender_reputation(sender_domain);
CREATE INDEX IF NOT EXISTS idx_sender_rep_blocked ON email_sender_reputation(blocked);
CREATE INDEX IF NOT EXISTS idx_domain_rep_blocked ON email_domain_reputation(blocked);
ALTER TABLE email_sender_reputation ADD COLUMN IF NOT EXISTS whitelisted BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE email_sender_reputation ADD COLUMN IF NOT EXISTS whitelisted_at TIMESTAMP;
ALTER TABLE email_sender_reputation ADD COLUMN IF NOT EXISTS whitelist_reason TEXT;

-- DatabaseManager.init_blocklist_db
CREATE TABLE IF NOT EXISTS blocklist (
    id SERIAL PRIMARY KEY,
    entry TEXT NOT NULL,
    entry_type TEXT NOT NULL CHECK (entry_type IN ('email', 'domain')),
    policy_name TEXT,
    alert_id TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(entry)
);

-- ReportTracker._add_missing_columns (no foreign key on site_id)
ALTER TABLE abuse_reports ADD COLUMN site_id INTEGER;
ALTER TABLE abuse_reports ADD COLUMN screenshot_path TEXT;
ALTER TABLE abuse_reports ADD COLUMN attachment_count INTEGER DEFAULT 0;

-- AbuseReportManager._save_followup_time
CREATE TABLE IF NOT EXISTS system_status (
    task_name VARCHAR(100) PRIMARY KEY,
    last_run TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
