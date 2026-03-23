"""Baseline schema — all 9 tables as they exist in production.

Revision ID: 001
Revises:
Create Date: 2026-03-22

This migration is a no-op on existing databases (all statements use
IF NOT EXISTS / IF EXISTS) and creates the full schema on fresh databases.
"""

from typing import Sequence, Union
from alembic import op

# revision identifiers
revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ------------------------------------------------------------------
    # scan_results
    # ------------------------------------------------------------------
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS scan_results (
            id SERIAL PRIMARY KEY,
            url TEXT UNIQUE,
            first_seen TIMESTAMP,
            last_seen TIMESTAMP,
            response_code INTEGER,
            found_keywords TEXT,
            count INTEGER
        )
        """
    )

    # ------------------------------------------------------------------
    # phishing_sites (full schema including registration + GSB columns)
    # ------------------------------------------------------------------
    op.execute(
        """
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
            assigned_to TEXT,
            gsb_result TEXT,
            gsb_threat_type TEXT,
            gsb_last_check TIMESTAMP,
            gsb_safe INTEGER DEFAULT 1
        )
        """
    )

    # ------------------------------------------------------------------
    # registrar_abuse
    # ------------------------------------------------------------------
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS registrar_abuse (
            id SERIAL PRIMARY KEY,
            registrar_name TEXT UNIQUE NOT NULL,
            abuse_emails TEXT,
            verified INTEGER DEFAULT 0,
            last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            notes TEXT,
            manual_override INTEGER DEFAULT 0
        )
        """
    )

    # ------------------------------------------------------------------
    # hosting_abuse
    # ------------------------------------------------------------------
    op.execute(
        """
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
        )
        """
    )

    # ------------------------------------------------------------------
    # analysis_threads
    # ------------------------------------------------------------------
    op.execute(
        """
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
        )
        """
    )

    op.execute("CREATE INDEX IF NOT EXISTS idx_threads_type ON analysis_threads(thread_type)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_threads_status ON analysis_threads(status)")

    # ------------------------------------------------------------------
    # thread_executions (must exist before thread_results references it)
    # ------------------------------------------------------------------
    op.execute(
        """
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
        )
        """
    )

    op.execute("CREATE INDEX IF NOT EXISTS idx_executions_thread ON thread_executions(thread_id)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_executions_status ON thread_executions(status)")

    # ------------------------------------------------------------------
    # thread_results
    # ------------------------------------------------------------------
    op.execute(
        """
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
            details JSONB,
            execution_id INTEGER REFERENCES thread_executions(id)
        )
        """
    )

    op.execute("CREATE INDEX IF NOT EXISTS idx_results_thread ON thread_results(thread_id)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_results_status ON thread_results(status)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_results_execution ON thread_results(execution_id)")

    # ------------------------------------------------------------------
    # abuse_reports
    # ------------------------------------------------------------------
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS abuse_reports (
            id SERIAL PRIMARY KEY,
            site_url TEXT NOT NULL,
            site_id INTEGER REFERENCES phishing_sites(id),
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
            screenshot_path TEXT,
            attachment_count INTEGER DEFAULT 0,
            follow_up_required INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    # ------------------------------------------------------------------
    # system_status
    # ------------------------------------------------------------------
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS system_status (
            task_name VARCHAR(100) PRIMARY KEY,
            last_run TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )


def downgrade() -> None:
    # Drop in reverse dependency order
    op.execute("DROP TABLE IF EXISTS system_status")
    op.execute("DROP TABLE IF EXISTS abuse_reports")
    op.execute("DROP TABLE IF EXISTS thread_results")
    op.execute("DROP TABLE IF EXISTS thread_executions")
    op.execute("DROP TABLE IF EXISTS analysis_threads")
    op.execute("DROP TABLE IF EXISTS hosting_abuse")
    op.execute("DROP TABLE IF EXISTS registrar_abuse")
    op.execute("DROP TABLE IF EXISTS phishing_sites")
    op.execute("DROP TABLE IF EXISTS scan_results")
