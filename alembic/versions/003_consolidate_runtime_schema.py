"""Consolidate every runtime-created table, column and index into Alembic.

Revision ID: 003
Revises: 002
Create Date: 2026-10-03

Until this revision the schema was spread across Alembic (001/002) and
DDL executed at runtime by ``DatabaseManager.init_*``,
``src.api.phishing_api.upgrade_phishing_db`` and ``ReportTracker``. Those
paths disagreed with each other (three different ``abuse_reports``
definitions) and one table (``redirect_chains``) was written to without any
DDL at all.

This revision declares the canonical schema once and brings ANY existing
database to it:

* a fresh database (after 001/002);
* a database built by the old runtime DDL, with or without an
  ``alembic_version`` row;
* a database stamped at 002 whose tables were never created by 001.

Every statement is idempotent (``IF NOT EXISTS`` or guarded ``DO`` blocks), so
running it on an up-to-date database is a no-op. Existing column types are
NOT changed here (normalisation to TIMESTAMPTZ/BOOLEAN/JSONB is phase 6);
only the new ``redirect_chains`` table uses the target types.

Downgrade drops only what is certainly new in this revision
(``redirect_chains`` and the indexes introduced here). Tables and columns
that the old runtime DDL may already have created are left in place on
purpose: dropping them could destroy production data that predates 003.
"""

from typing import Dict, List, Sequence, Tuple, Union

from alembic import op

revision: str = "003"
down_revision: Union[str, None] = "002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# ---------------------------------------------------------------------------
# Canonical schema
# ---------------------------------------------------------------------------
# Each table maps to (columns, table_constraints). Column definitions are
# used verbatim both in CREATE TABLE and in ALTER TABLE ... ADD COLUMN IF NOT
# EXISTS, so a table that exists with fewer columns converges to the same
# shape as a freshly created one. Tables are listed in foreign-key order.

Column = Tuple[str, str]
TableSpec = Tuple[List[Column], List[str]]

SCHEMA: Dict[str, TableSpec] = {
    "scan_results": (
        [
            ("id", "SERIAL PRIMARY KEY"),
            ("url", "TEXT UNIQUE"),
            ("first_seen", "TIMESTAMP"),
            ("last_seen", "TIMESTAMP"),
            ("response_code", "INTEGER"),
            ("found_keywords", "TEXT"),
            ("count", "INTEGER"),
        ],
        [],
    ),
    "phishing_sites": (
        [
            ("id", "SERIAL PRIMARY KEY"),
            ("url", "TEXT UNIQUE"),
            ("manual_flag", "INTEGER DEFAULT 0"),
            ("auto_detected", "INTEGER DEFAULT 0"),
            ("first_seen", "TIMESTAMP"),
            ("last_seen", "TIMESTAMP"),
            ("whois_info", "TEXT"),
            ("abuse_email", "TEXT"),
            ("reported", "INTEGER DEFAULT 0"),
            ("abuse_report_sent", "INTEGER DEFAULT 0"),
            ("site_status", "TEXT DEFAULT 'up'"),
            ("takedown_date", "TIMESTAMP"),
            ("last_report_sent", "TIMESTAMP"),
            ("resolved_ip", "TEXT"),
            ("asn_provider", "TEXT"),
            ("is_cloudflare", "INTEGER"),
            ("provider_abuse_email", "TEXT"),
            ("source", "TEXT DEFAULT 'manual'"),
            ("priority", "TEXT DEFAULT 'medium'"),
            ("description", "TEXT"),
            ("asn", "TEXT"),
            ("asn_abuse_email", "TEXT"),
            ("hosting_provider", "TEXT"),
            ("all_abuse_emails", "TEXT"),
            # Written by AbuseReportManager (manual WHOIS processing); only the
            # old runtime upgrade created it, 001 did not.
            ("registrar", "TEXT"),
            ("virustotal_result", "TEXT"),
            ("urlvoid_result", "TEXT"),
            ("phishtank_result", "TEXT"),
            ("multi_api_threat_level", "TEXT"),
            ("api_confidence_score", "INTEGER"),
            ("auto_analysis_status", "TEXT DEFAULT 'pending'"),
            ("auto_analysis_timestamp", "TIMESTAMP"),
            ("detection_keywords", "TEXT"),
            ("auto_report_eligible", "INTEGER DEFAULT 0"),
            ("requires_manual_review", "INTEGER DEFAULT 0"),
            ("screenshot_taken", "INTEGER DEFAULT 0"),
            ("screenshot_path", "TEXT"),
            ("screenshot_timestamp", "TIMESTAMP"),
            ("manual_emails", "INTEGER DEFAULT 0"),
            ("registration_date", "TIMESTAMP"),
            ("registrar_name", "TEXT"),
            ("registrant_org", "TEXT"),
            ("domain_age_days", "INTEGER"),
            ("status", "TEXT DEFAULT 'new'"),
            ("assigned_to", "TEXT"),
            ("gsb_result", "TEXT"),
            ("gsb_threat_type", "TEXT"),
            ("gsb_last_check", "TIMESTAMP"),
            ("gsb_safe", "INTEGER DEFAULT 1"),
            ("detected_kit_type", "TEXT"),
            ("kit_confidence", "INTEGER"),
            ("kit_indicators", "TEXT"),
        ],
        [],
    ),
    "registrar_abuse": (
        [
            ("id", "SERIAL PRIMARY KEY"),
            ("registrar_name", "TEXT UNIQUE NOT NULL"),
            ("abuse_emails", "TEXT"),
            ("verified", "INTEGER DEFAULT 0"),
            ("last_updated", "TIMESTAMP DEFAULT CURRENT_TIMESTAMP"),
            ("notes", "TEXT"),
            ("manual_override", "INTEGER DEFAULT 0"),
        ],
        [],
    ),
    "hosting_abuse": (
        [
            ("id", "SERIAL PRIMARY KEY"),
            ("provider_name", "TEXT NOT NULL"),
            ("asn", "TEXT"),
            ("abuse_emails", "TEXT"),
            ("verified", "INTEGER DEFAULT 0"),
            ("last_updated", "TIMESTAMP DEFAULT CURRENT_TIMESTAMP"),
            ("notes", "TEXT"),
            ("manual_override", "INTEGER DEFAULT 0"),
        ],
        ["UNIQUE(provider_name, asn)"],
    ),
    "analysis_threads": (
        [
            ("id", "SERIAL PRIMARY KEY"),
            ("thread_type", "VARCHAR(50) NOT NULL"),
            ("label", "VARCHAR(255)"),
            ("account_id", "VARCHAR(20)"),
            ("status", "VARCHAR(20) NOT NULL"),
            ("started_at", "TIMESTAMP NOT NULL DEFAULT NOW()"),
            ("completed_at", "TIMESTAMP"),
            ("results_count", "INTEGER NOT NULL DEFAULT 0"),
            ("details", "JSONB"),
            ("error_message", "TEXT"),
            ("image_s3_key", "VARCHAR(500)"),
            ("original_filename", "VARCHAR(255)"),
            ("content_type", "VARCHAR(100)"),
            ("file_size_bytes", "INTEGER"),
            ("search_interval_hours", "INTEGER"),
            ("last_searched_at", "TIMESTAMP"),
        ],
        [],
    ),
    "thread_executions": (
        [
            ("id", "SERIAL PRIMARY KEY"),
            ("thread_id", "INTEGER NOT NULL REFERENCES analysis_threads(id)"),
            ("execution_type", "VARCHAR(50) NOT NULL"),
            ("started_at", "TIMESTAMP DEFAULT NOW()"),
            ("completed_at", "TIMESTAMP"),
            ("status", "VARCHAR(20) NOT NULL DEFAULT 'running'"),
            ("results_count", "INTEGER NOT NULL DEFAULT 0"),
            ("error_message", "TEXT"),
            ("details", "JSONB"),
        ],
        [],
    ),
    "thread_results": (
        [
            ("id", "SERIAL PRIMARY KEY"),
            ("thread_id", "INTEGER NOT NULL REFERENCES analysis_threads(id)"),
            ("result_type", "VARCHAR(50) NOT NULL"),
            ("found_url", "VARCHAR(2000)"),
            ("title", "VARCHAR(500)"),
            ("confidence", "REAL"),
            ("thumbnail_url", "VARCHAR(2000)"),
            ("source", "VARCHAR(100)"),
            ("first_detected_at", "TIMESTAMP NOT NULL DEFAULT NOW()"),
            ("last_detected_at", "TIMESTAMP NOT NULL DEFAULT NOW()"),
            ("status", "VARCHAR(20) NOT NULL DEFAULT 'new'"),
            ("assigned_to", "VARCHAR(100)"),
            ("details", "JSONB"),
            ("execution_id", "INTEGER REFERENCES thread_executions(id)"),
            ("extra_data", "JSONB"),
            ("source_type", "VARCHAR(20)"),
        ],
        [],
    ),
    # Superset of the three historical definitions (001, the API's runtime
    # CREATE and ReportTracker's self-healing CREATE): every column that any
    # code path reads or writes is kept.
    "abuse_reports": (
        [
            ("id", "SERIAL PRIMARY KEY"),
            ("site_url", "TEXT NOT NULL"),
            ("site_id", "INTEGER REFERENCES phishing_sites(id)"),
            ("report_date", "TIMESTAMP DEFAULT CURRENT_TIMESTAMP"),
            ("recipients", "TEXT NOT NULL"),
            ("cc_recipients", "TEXT"),
            ("subject", "TEXT"),
            ("report_id", "TEXT UNIQUE"),
            ("status", "TEXT DEFAULT 'sent'"),
            ("response_received", "INTEGER DEFAULT 0"),
            ("response_date", "TIMESTAMP"),
            ("response_content", "TEXT"),
            ("sla_deadline", "TIMESTAMP"),
            ("icann_compliant", "INTEGER DEFAULT 1"),
            ("screenshot_included", "INTEGER DEFAULT 0"),
            ("screenshot_path", "TEXT"),
            ("attachment_count", "INTEGER DEFAULT 0"),
            ("multi_api_results", "TEXT"),
            ("confidence_score", "INTEGER"),
            ("threat_level", "TEXT"),
            ("follow_up_required", "INTEGER DEFAULT 0"),
            ("created_at", "TIMESTAMP DEFAULT CURRENT_TIMESTAMP"),
            ("updated_at", "TIMESTAMP DEFAULT CURRENT_TIMESTAMP"),
        ],
        [],
    ),
    "system_status": (
        [
            ("task_name", "VARCHAR(100) PRIMARY KEY"),
            ("last_run", "TIMESTAMP"),
            ("updated_at", "TIMESTAMP DEFAULT CURRENT_TIMESTAMP"),
        ],
        [],
    ),
    "api_keys": (
        [
            ("id", "SERIAL PRIMARY KEY"),
            ("key_hash", "VARCHAR(64) NOT NULL UNIQUE"),
            ("key_prefix", "VARCHAR(12) NOT NULL"),
            ("name", "VARCHAR(100) NOT NULL"),
            ("scopes", "TEXT NOT NULL DEFAULT 'read'"),
            ("allowed_ips", "TEXT"),
            ("active", "BOOLEAN NOT NULL DEFAULT TRUE"),
            ("created_at", "TIMESTAMP NOT NULL DEFAULT NOW()"),
            ("last_used_at", "TIMESTAMP"),
            ("revoked_at", "TIMESTAMP"),
            ("description", "TEXT"),
        ],
        [],
    ),
    "blocklist": (
        [
            ("id", "SERIAL PRIMARY KEY"),
            ("entry", "TEXT NOT NULL"),
            ("entry_type", "TEXT NOT NULL CHECK (entry_type IN ('email', 'domain'))"),
            ("policy_name", "TEXT"),
            ("alert_id", "TEXT"),
            ("created_at", "TIMESTAMP DEFAULT NOW()"),
        ],
        ["UNIQUE(entry)"],
    ),
    "email_sender_reputation": (
        [
            ("id", "SERIAL PRIMARY KEY"),
            ("sender_email", "VARCHAR(320) NOT NULL"),
            ("sender_domain", "VARCHAR(255) NOT NULL"),
            ("display_name", "VARCHAR(255)"),
            ("report_count", "INTEGER NOT NULL DEFAULT 0"),
            ("automated_count", "INTEGER NOT NULL DEFAULT 0"),
            ("threat_score_avg", "REAL NOT NULL DEFAULT 0"),
            ("threat_score_max", "REAL NOT NULL DEFAULT 0"),
            ("first_seen_at", "TIMESTAMP NOT NULL DEFAULT NOW()"),
            ("last_seen_at", "TIMESTAMP NOT NULL DEFAULT NOW()"),
            ("blocked", "BOOLEAN NOT NULL DEFAULT FALSE"),
            ("blocked_at", "TIMESTAMP"),
            ("block_reason", "TEXT"),
            ("whitelisted", "BOOLEAN NOT NULL DEFAULT FALSE"),
            ("whitelisted_at", "TIMESTAMP"),
            ("whitelist_reason", "TEXT"),
        ],
        ["UNIQUE(sender_email)"],
    ),
    "email_domain_reputation": (
        [
            ("id", "SERIAL PRIMARY KEY"),
            ("domain", "VARCHAR(255) NOT NULL"),
            ("sender_count", "INTEGER NOT NULL DEFAULT 0"),
            ("report_count", "INTEGER NOT NULL DEFAULT 0"),
            ("automated_count", "INTEGER NOT NULL DEFAULT 0"),
            ("threat_score_avg", "REAL NOT NULL DEFAULT 0"),
            ("first_seen_at", "TIMESTAMP NOT NULL DEFAULT NOW()"),
            ("last_seen_at", "TIMESTAMP NOT NULL DEFAULT NOW()"),
            ("blocked", "BOOLEAN NOT NULL DEFAULT FALSE"),
            ("blocked_at", "TIMESTAMP"),
            ("block_reason", "TEXT"),
        ],
        ["UNIQUE(domain)"],
    ),
    # New in 003: the scanner has always INSERTed here (src/detection/scanner.py)
    # but no DDL ever created it, so every redirect chain was silently lost.
    "redirect_chains": (
        [
            ("id", "SERIAL PRIMARY KEY"),
            ("site_id", "INTEGER NOT NULL REFERENCES phishing_sites(id) ON DELETE CASCADE"),
            ("original_url", "TEXT NOT NULL"),
            ("final_url", "TEXT"),
            ("hop_count", "INTEGER NOT NULL DEFAULT 0"),
            ("chain_urls", "JSONB NOT NULL DEFAULT '[]'::jsonb"),
            ("status_codes", "JSONB NOT NULL DEFAULT '[]'::jsonb"),
            ("risk_score", "INTEGER NOT NULL DEFAULT 0"),
            ("has_cloudflare", "BOOLEAN NOT NULL DEFAULT FALSE"),
            ("has_suspicious_tld", "BOOLEAN NOT NULL DEFAULT FALSE"),
            ("has_url_shortener", "BOOLEAN NOT NULL DEFAULT FALSE"),
            ("has_cross_domain", "BOOLEAN NOT NULL DEFAULT FALSE"),
            ("has_loop", "BOOLEAN NOT NULL DEFAULT FALSE"),
            ("total_time_ms", "DOUBLE PRECISION"),
            ("analyzed_at", "TIMESTAMPTZ NOT NULL DEFAULT NOW()"),
        ],
        [],
    ),
}

# Indexes that already existed before 003 (created by 001 or by the old
# runtime DDL). Re-declared so that stamped or partially built databases
# converge; never dropped by downgrade().
EXISTING_INDEXES: List[Tuple[str, str, str]] = [
    ("idx_threads_type", "analysis_threads", "thread_type"),
    ("idx_threads_status", "analysis_threads", "status"),
    ("idx_executions_thread", "thread_executions", "thread_id"),
    ("idx_executions_status", "thread_executions", "status"),
    ("idx_results_thread", "thread_results", "thread_id"),
    ("idx_results_status", "thread_results", "status"),
    ("idx_results_execution", "thread_results", "execution_id"),
    ("idx_api_keys_hash", "api_keys", "key_hash"),
    ("idx_api_keys_active", "api_keys", "active"),
    ("idx_sender_rep_domain", "email_sender_reputation", "sender_domain"),
    ("idx_sender_rep_blocked", "email_sender_reputation", "blocked"),
    ("idx_domain_rep_blocked", "email_domain_reputation", "blocked"),
]

# Indexes introduced by 003 for the hot WHERE / ORDER BY clauses of the API,
# the reporting loop and the monitors. Dropped by downgrade().
NEW_INDEXES: List[Tuple[str, str, str]] = [
    ("idx_phishing_sites_site_status", "phishing_sites", "site_status"),
    ("idx_phishing_sites_abuse_report_sent", "phishing_sites", "abuse_report_sent"),
    ("idx_phishing_sites_auto_report_eligible", "phishing_sites", "auto_report_eligible"),
    ("idx_phishing_sites_manual_flag", "phishing_sites", "manual_flag"),
    ("idx_phishing_sites_auto_analysis_status", "phishing_sites", "auto_analysis_status"),
    ("idx_phishing_sites_registrar_name", "phishing_sites", "registrar_name"),
    ("idx_phishing_sites_first_seen", "phishing_sites", "first_seen"),
    ("idx_phishing_sites_last_seen", "phishing_sites", "last_seen"),
    ("idx_phishing_sites_takedown_date", "phishing_sites", "takedown_date"),
    ("idx_abuse_reports_site_url", "abuse_reports", "site_url"),
    ("idx_abuse_reports_status", "abuse_reports", "status"),
    ("idx_abuse_reports_report_date", "abuse_reports", "report_date"),
    ("idx_abuse_reports_sla_deadline", "abuse_reports", "sla_deadline"),
    ("idx_results_thread_found_url", "thread_results", "thread_id, found_url"),
    ("idx_results_result_type", "thread_results", "result_type"),
    ("idx_results_last_detected_at", "thread_results", "last_detected_at"),
    ("idx_threads_started_at", "analysis_threads", "started_at"),
    ("idx_executions_started_at", "thread_executions", "started_at"),
    ("idx_redirect_chains_site_id", "redirect_chains", "site_id"),
]

# Tables that no revision before 003 creates. Only redirect_chains is safe
# to drop on downgrade: the others may hold data written by the old runtime
# DDL before this revision existed.
TABLES_NEW_IN_003_SAFE_TO_DROP = ("redirect_chains",)


def _create_table_sql(table: str, spec: TableSpec) -> str:
    """Render the CREATE TABLE IF NOT EXISTS statement for a table.

    Args:
        table: Table name.
        spec: Column definitions and table-level constraints.

    Returns:
        The DDL statement.
    """
    columns, constraints = spec
    body = [f"{name} {definition}" for name, definition in columns] + constraints
    joined = ",\n    ".join(body)
    return f"CREATE TABLE IF NOT EXISTS {table} (\n    {joined}\n)"


def _add_missing_columns(table: str, spec: TableSpec) -> None:
    """Add every canonical column that an existing table lacks.

    Primary-key columns are skipped: a table without its primary key is not a
    shape this migration can repair, and PostgreSQL would reject a second
    primary key anyway. A ``NOT NULL`` column without a default fails loudly
    on a non-empty table, which is the intended behaviour: it means the table
    is not one this application created.

    Args:
        table: Table name.
        spec: Column definitions and table-level constraints.
    """
    columns, _ = spec
    for name, definition in columns:
        if "PRIMARY KEY" in definition:
            continue
        op.execute(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {name} {definition}")


def _repair_legacy_constraints() -> None:
    """Bring legacy constraint variants in line with the canonical schema.

    * ``phishing_sites.api_confidence_score``: a historical bug created it as
      ``NUMERIC(5,4)``, which cannot hold 0-100 scores. The old runtime
      upgrade fixed it to ``INTEGER`` on every start; that exact repair is
      carried over so it is not lost with the runtime DDL. Any other type is
      left untouched (type normalisation is phase 6).
    * ``abuse_reports.report_id``: ReportTracker's fallback table had no
      UNIQUE constraint. It is added; duplicate ids abort the migration with
      an explicit message instead of being silently merged.
    * ``abuse_reports.site_id``: columns added by ReportTracker lacked the
      foreign key. It is added as ``NOT VALID`` and validated right away when
      no orphaned row exists; otherwise it stays ``NOT VALID`` (new writes are
      enforced, historical orphans do not block the upgrade).
    """
    op.execute("""
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_schema = current_schema()
                  AND table_name = 'phishing_sites'
                  AND column_name = 'api_confidence_score'
                  AND data_type = 'numeric'
                  AND numeric_precision = 5
                  AND numeric_scale = 4
            ) THEN
                ALTER TABLE phishing_sites
                    ALTER COLUMN api_confidence_score TYPE INTEGER;
            END IF;
        END
        $$;
        """)
    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1
                FROM pg_index i
                JOIN pg_attribute a
                  ON a.attrelid = i.indrelid AND a.attnum = ANY (i.indkey)
                WHERE i.indrelid = 'abuse_reports'::regclass
                  AND i.indisunique
                  AND i.indnatts = 1
                  AND a.attname = 'report_id'
            ) THEN
                IF EXISTS (
                    SELECT report_id FROM abuse_reports
                    WHERE report_id IS NOT NULL
                    GROUP BY report_id HAVING COUNT(*) > 1
                ) THEN
                    RAISE EXCEPTION
                        'abuse_reports.report_id has duplicate values; deduplicate them '
                        '(SELECT report_id FROM abuse_reports GROUP BY report_id '
                        'HAVING COUNT(*) > 1) and re-run alembic upgrade head';
                END IF;
                ALTER TABLE abuse_reports
                    ADD CONSTRAINT abuse_reports_report_id_key UNIQUE (report_id);
            END IF;
        END
        $$;
        """)
    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1
                FROM pg_constraint c
                JOIN pg_attribute a
                  ON a.attrelid = c.conrelid AND a.attnum = ANY (c.conkey)
                WHERE c.conrelid = 'abuse_reports'::regclass
                  AND c.contype = 'f'
                  AND a.attname = 'site_id'
            ) THEN
                ALTER TABLE abuse_reports
                    ADD CONSTRAINT abuse_reports_site_id_fkey
                    FOREIGN KEY (site_id) REFERENCES phishing_sites(id) NOT VALID;
                IF NOT EXISTS (
                    SELECT 1 FROM abuse_reports ar
                    WHERE ar.site_id IS NOT NULL
                      AND NOT EXISTS (SELECT 1 FROM phishing_sites ps WHERE ps.id = ar.site_id)
                ) THEN
                    ALTER TABLE abuse_reports VALIDATE CONSTRAINT abuse_reports_site_id_fkey;
                END IF;
            END IF;
        END
        $$;
        """)


def upgrade() -> None:
    """Create or complete every table, constraint and index of the schema."""
    for table, spec in SCHEMA.items():
        op.execute(_create_table_sql(table, spec))
        _add_missing_columns(table, spec)

    _repair_legacy_constraints()

    for name, table, columns in EXISTING_INDEXES + NEW_INDEXES:
        op.execute(f"CREATE INDEX IF NOT EXISTS {name} ON {table} ({columns})")


def downgrade() -> None:
    """Drop the objects that certainly did not exist before 003.

    Columns and tables that the old runtime DDL may have created before this
    revision (email reputation, blocklist, extra phishing_sites columns, ...)
    are intentionally kept: there is no way to tell whether 003 or the legacy
    code created them, and dropping them could destroy production data.
    """
    for name, _table, _columns in reversed(NEW_INDEXES):
        op.execute(f"DROP INDEX IF EXISTS {name}")
    for table in TABLES_NEW_IN_003_SAFE_TO_DROP:
        op.execute(f"DROP TABLE IF EXISTS {table}")
