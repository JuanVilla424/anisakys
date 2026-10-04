"""Tests for the Alembic migrations and the startup schema guard.

Alembic is the single owner of the schema (revision 003 consolidated every
table, column and index that used to be created at runtime). These tests run
the real migrations against throw-away PostgreSQL databases:

* a fresh database upgraded to head has the full expected schema;
* a database built by the old runtime DDL converges to exactly the same
  schema without losing data;
* the 003 downgrade only removes what 003 introduced;
* ``ensure_schema_is_current`` refuses stale or unknown databases.
"""

from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Dict, FrozenSet, Iterator, Set, Tuple

import pytest
from alembic import command
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

from src.database.schema import (
    BEHIND_MESSAGE,
    ensure_schema_is_current,
    get_alembic_config,
    reset_schema_check_cache,
)

pytestmark = pytest.mark.slow

PROJECT_ROOT = Path(__file__).resolve().parents[2]
LEGACY_SQL = Path(__file__).parent / "fixtures" / "legacy_runtime_schema.sql"
SCANNER_SOURCE = PROJECT_ROOT / "src" / "detection" / "scanner.py"

# Hand-written on purpose (not derived from the migration) so that a column
# silently dropped from the migration makes this test fail.
EXPECTED_COLUMNS: Dict[str, Set[str]] = {
    "scan_results": {
        "id",
        "url",
        "first_seen",
        "last_seen",
        "response_code",
        "found_keywords",
        "count",
    },
    "phishing_sites": {
        "id",
        "url",
        "manual_flag",
        "auto_detected",
        "first_seen",
        "last_seen",
        "whois_info",
        "abuse_email",
        "reported",
        "abuse_report_sent",
        "site_status",
        "takedown_date",
        "last_report_sent",
        "resolved_ip",
        "asn_provider",
        "is_cloudflare",
        "provider_abuse_email",
        "source",
        "priority",
        "description",
        "asn",
        "asn_abuse_email",
        "hosting_provider",
        "all_abuse_emails",
        "registrar",
        "virustotal_result",
        "urlvoid_result",
        "phishtank_result",
        "multi_api_threat_level",
        "api_confidence_score",
        "auto_analysis_status",
        "auto_analysis_timestamp",
        "detection_keywords",
        "auto_report_eligible",
        "requires_manual_review",
        "screenshot_taken",
        "screenshot_path",
        "screenshot_timestamp",
        "manual_emails",
        "registration_date",
        "registrar_name",
        "registrant_org",
        "domain_age_days",
        "status",
        "assigned_to",
        "gsb_result",
        "gsb_threat_type",
        "gsb_last_check",
        "gsb_safe",
        "detected_kit_type",
        "kit_confidence",
        "kit_indicators",
    },
    "registrar_abuse": {
        "id",
        "registrar_name",
        "abuse_emails",
        "verified",
        "last_updated",
        "notes",
        "manual_override",
    },
    "hosting_abuse": {
        "id",
        "provider_name",
        "asn",
        "abuse_emails",
        "verified",
        "last_updated",
        "notes",
        "manual_override",
    },
    "analysis_threads": {
        "id",
        "thread_type",
        "label",
        "account_id",
        "status",
        "started_at",
        "completed_at",
        "results_count",
        "details",
        "error_message",
        "image_s3_key",
        "original_filename",
        "content_type",
        "file_size_bytes",
        "search_interval_hours",
        "last_searched_at",
    },
    "thread_executions": {
        "id",
        "thread_id",
        "execution_type",
        "started_at",
        "completed_at",
        "status",
        "results_count",
        "error_message",
        "details",
    },
    "thread_results": {
        "id",
        "thread_id",
        "result_type",
        "found_url",
        "title",
        "confidence",
        "thumbnail_url",
        "source",
        "first_detected_at",
        "last_detected_at",
        "status",
        "assigned_to",
        "details",
        "execution_id",
        "extra_data",
        "source_type",
    },
    "abuse_reports": {
        "id",
        "site_url",
        "site_id",
        "report_date",
        "recipients",
        "cc_recipients",
        "subject",
        "report_id",
        "status",
        "response_received",
        "response_date",
        "response_content",
        "sla_deadline",
        "icann_compliant",
        "screenshot_included",
        "screenshot_path",
        "attachment_count",
        "multi_api_results",
        "confidence_score",
        "threat_level",
        "follow_up_required",
        "created_at",
        "updated_at",
    },
    "system_status": {"task_name", "last_run", "updated_at"},
    "api_keys": {
        "id",
        "key_hash",
        "key_prefix",
        "name",
        "scopes",
        "allowed_ips",
        "active",
        "created_at",
        "last_used_at",
        "revoked_at",
        "description",
    },
    "blocklist": {"id", "entry", "entry_type", "policy_name", "alert_id", "created_at"},
    "email_sender_reputation": {
        "id",
        "sender_email",
        "sender_domain",
        "display_name",
        "report_count",
        "automated_count",
        "threat_score_avg",
        "threat_score_max",
        "first_seen_at",
        "last_seen_at",
        "blocked",
        "blocked_at",
        "block_reason",
        "whitelisted",
        "whitelisted_at",
        "whitelist_reason",
    },
    "email_domain_reputation": {
        "id",
        "domain",
        "sender_count",
        "report_count",
        "automated_count",
        "threat_score_avg",
        "first_seen_at",
        "last_seen_at",
        "blocked",
        "blocked_at",
        "block_reason",
    },
    "redirect_chains": {
        "id",
        "site_id",
        "original_url",
        "final_url",
        "hop_count",
        "chain_urls",
        "status_codes",
        "risk_score",
        "has_cloudflare",
        "has_suspicious_tld",
        "has_url_shortener",
        "has_cross_domain",
        "has_loop",
        "total_time_ms",
        "analyzed_at",
    },
}

NEW_INDEXES_IN_003 = {
    "idx_phishing_sites_site_status",
    "idx_phishing_sites_abuse_report_sent",
    "idx_phishing_sites_auto_report_eligible",
    "idx_phishing_sites_manual_flag",
    "idx_phishing_sites_auto_analysis_status",
    "idx_phishing_sites_registrar_name",
    "idx_phishing_sites_first_seen",
    "idx_phishing_sites_last_seen",
    "idx_phishing_sites_takedown_date",
    "idx_abuse_reports_site_url",
    "idx_abuse_reports_status",
    "idx_abuse_reports_report_date",
    "idx_abuse_reports_sla_deadline",
    "idx_results_thread_found_url",
    "idx_results_result_type",
    "idx_results_last_detected_at",
    "idx_threads_started_at",
    "idx_executions_started_at",
    "idx_redirect_chains_site_id",
}

SchemaSignature = Tuple[FrozenSet[tuple], FrozenSet[tuple], FrozenSet[tuple]]


@pytest.fixture
def make_engine() -> Iterator:
    """Create engines for scratch databases and dispose them at teardown."""
    engines = []

    def _make(url: str) -> Engine:
        engine = create_engine(url)
        engines.append(engine)
        return engine

    yield _make
    for engine in engines:
        engine.dispose()


@pytest.fixture(autouse=True)
def _fresh_schema_guard_cache() -> Iterator[None]:
    """Isolate the process-wide cache of ensure_schema_is_current."""
    reset_schema_check_cache()
    yield
    reset_schema_check_cache()


def upgrade(url: str, revision: str = "head") -> None:
    """Run ``alembic upgrade`` against ``url``."""
    command.upgrade(get_alembic_config(url), revision)


def script_head() -> str:
    """Return the newest revision id in ``alembic/versions``."""
    head = ScriptDirectory.from_config(get_alembic_config("postgresql://unused")).get_current_head()
    assert head is not None, "alembic/versions has no head revision"
    return head


def downgrade(url: str, revision: str) -> None:
    """Run ``alembic downgrade`` against ``url``."""
    command.downgrade(get_alembic_config(url), revision)


def load_legacy_schema(engine: Engine) -> None:
    """Build the schema the pre-003 runtime DDL produced."""
    with engine.begin() as conn:
        conn.exec_driver_sql(LEGACY_SQL.read_text())


def table_columns(engine: Engine) -> Dict[str, Set[str]]:
    """Return ``{table: {columns}}`` for the public schema."""
    with engine.connect() as conn:
        rows = conn.execute(text("""
                SELECT table_name, column_name FROM information_schema.columns
                WHERE table_schema = 'public' AND table_name <> 'alembic_version'
                """)).fetchall()
    result: Dict[str, Set[str]] = {}
    for table, column in rows:
        result.setdefault(table, set()).add(column)
    return result


def index_names(engine: Engine) -> Set[str]:
    """Return the names of every index in the public schema."""
    with engine.connect() as conn:
        return {
            row[0]
            for row in conn.execute(
                text("SELECT indexname FROM pg_indexes WHERE schemaname = 'public'")
            )
        }


def schema_signature(engine: Engine) -> SchemaSignature:
    """Describe columns, indexes and constraints independently of column order."""
    with engine.connect() as conn:
        columns = conn.execute(text("""
                SELECT table_name, column_name, data_type, character_maximum_length,
                       numeric_precision, is_nullable, column_default
                FROM information_schema.columns
                WHERE table_schema = 'public'
                """)).fetchall()
        indexes = conn.execute(
            text("SELECT indexname, indexdef FROM pg_indexes WHERE schemaname = 'public'")
        ).fetchall()
        constraints = conn.execute(text("""
                SELECT conrelid::regclass::text, conname, pg_get_constraintdef(oid), convalidated
                FROM pg_constraint
                WHERE connamespace = 'public'::regnamespace
                """)).fetchall()
    return (
        frozenset(tuple(r) for r in columns),
        frozenset(tuple(r) for r in indexes),
        frozenset(tuple(r) for r in constraints),
    )


def scanner_redirect_chain_insert() -> str:
    """Return the scanner's own ``INSERT INTO redirect_chains`` statement."""
    tree = ast.parse(SCANNER_SOURCE.read_text())
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and "INSERT INTO redirect_chains" in node.value
        ):
            return node.value
    raise AssertionError("scanner.py no longer inserts into redirect_chains")


class TestFreshDatabase:
    """``alembic upgrade head`` on an empty database."""

    def test_upgrade_to_003_creates_every_table_and_column(self, scratch_database, make_engine):
        """EXPECTED_COLUMNS is the schema of revision 003; later revisions add to it."""
        url = scratch_database()
        upgrade(url, "003")

        assert table_columns(make_engine(url)) == EXPECTED_COLUMNS

    def test_upgrade_head_keeps_every_003_column(self, scratch_database, make_engine):
        url = scratch_database()
        upgrade(url)

        columns = table_columns(make_engine(url))
        for table, expected in EXPECTED_COLUMNS.items():
            assert expected <= columns.get(table, set()), table

    def test_upgrade_head_creates_hot_filter_indexes(self, scratch_database, make_engine):
        url = scratch_database()
        upgrade(url)

        assert NEW_INDEXES_IN_003 <= index_names(make_engine(url))

    def test_scanner_redirect_chain_insert_is_stored(self, scratch_database, make_engine):
        """Regression: redirect_chains had no DDL, so every chain INSERT failed."""
        url = scratch_database()
        upgrade(url)
        engine = make_engine(url)

        with engine.begin() as conn:
            site_id = conn.execute(
                text("INSERT INTO phishing_sites (url) VALUES ('https://chain.test') RETURNING id")
            ).scalar_one()
            conn.execute(
                text(scanner_redirect_chain_insert()),
                {
                    "site_id": site_id,
                    "original_url": "https://short.test/x",
                    "final_url": "https://chain.test",
                    "hop_count": 2,
                    "chain_urls": json.dumps(["https://short.test/x", "https://chain.test"]),
                    "status_codes": json.dumps([301, 200]),
                    "risk_score": 40,
                    "has_cloudflare": False,
                    "has_suspicious_tld": True,
                    "has_url_shortener": True,
                    "has_cross_domain": True,
                    "has_loop": False,
                    "total_time_ms": 123.5,
                },
            )

        with engine.connect() as conn:
            row = conn.execute(
                text("SELECT chain_urls, status_codes, has_url_shortener FROM redirect_chains")
            ).one()
        assert row.chain_urls == ["https://short.test/x", "https://chain.test"]
        assert row.status_codes == [301, 200]
        assert row.has_url_shortener is True

        with engine.begin() as conn:
            conn.execute(text("DELETE FROM phishing_sites WHERE id = :id"), {"id": site_id})
            remaining = conn.execute(text("SELECT COUNT(*) FROM redirect_chains")).scalar_one()
        assert remaining == 0, "redirect_chains must cascade with its phishing site"

    def test_upgrade_head_is_idempotent(self, scratch_database, make_engine):
        url = scratch_database()
        upgrade(url)
        engine = make_engine(url)
        before = schema_signature(engine)

        upgrade(url)
        downgrade(url, "002")
        upgrade(url)

        assert schema_signature(engine) == before

    def test_database_stamped_at_002_without_tables_is_completed(
        self, scratch_database, make_engine
    ):
        """003 must not depend on 001 having run (stamped legacy databases)."""
        url = scratch_database()
        command.stamp(get_alembic_config(url), "002")

        upgrade(url, "003")

        assert table_columns(make_engine(url)) == EXPECTED_COLUMNS


class TestLegacyRuntimeDatabase:
    """Databases built by the runtime DDL that existed before revision 003."""

    def test_upgrade_converges_to_fresh_schema_and_keeps_data(self, scratch_database, make_engine):
        fresh_url = scratch_database()
        upgrade(fresh_url)

        legacy_url = scratch_database()
        legacy = make_engine(legacy_url)
        load_legacy_schema(legacy)
        with legacy.begin() as conn:
            site_id = conn.execute(text("""
                    INSERT INTO phishing_sites
                        (url, manual_flag, registrar, detected_kit_type, api_confidence_score)
                    VALUES ('https://legacy.test', 1, 'Legacy Registrar', 'kit-x', 87)
                    RETURNING id
                    """)).scalar_one()
            conn.execute(
                text("""
                    INSERT INTO abuse_reports
                        (site_url, recipients, report_id, threat_level, site_id)
                    VALUES ('https://legacy.test', 'abuse@registrar.test', 'R-1', 'high', :sid)
                    """),
                {"sid": site_id},
            )
            thread_id = conn.execute(text("""
                    INSERT INTO analysis_threads (thread_type, status)
                    VALUES ('email_scan', 'completed') RETURNING id
                    """)).scalar_one()
            conn.execute(
                text("""
                    INSERT INTO thread_results (thread_id, result_type, found_url, extra_data)
                    VALUES (:tid, 'email_threat', 'https://legacy.test', '{"k": 1}')
                    """),
                {"tid": thread_id},
            )
            conn.execute(text("""
                    INSERT INTO email_sender_reputation (sender_email, sender_domain, whitelisted)
                    VALUES ('bad@legacy.test', 'legacy.test', TRUE)
                    """))
            conn.execute(text("""
                    INSERT INTO blocklist (entry, entry_type) VALUES ('legacy.test', 'domain')
                    """))

        upgrade(legacy_url)

        assert schema_signature(legacy) == schema_signature(make_engine(fresh_url))
        with legacy.connect() as conn:
            site = conn.execute(text("""
                    SELECT manual_flag, registrar, detected_kit_type, api_confidence_score,
                           gsb_safe
                    FROM phishing_sites WHERE url = 'https://legacy.test'
                    """)).one()
            report = conn.execute(
                text("SELECT threat_level, site_id, attachment_count FROM abuse_reports")
            ).one()
            extra = conn.execute(text("SELECT extra_data FROM thread_results")).scalar_one()
            whitelisted = conn.execute(
                text("SELECT whitelisted FROM email_sender_reputation")
            ).scalar_one()
            blocked = conn.execute(text("SELECT entry FROM blocklist")).scalar_one()
        assert tuple(site) == (1, "Legacy Registrar", "kit-x", 87, 1)
        assert tuple(report) == ("high", site_id, 0)
        assert extra == {"k": 1}
        assert whitelisted is True
        assert blocked == "legacy.test"

    def test_upgrade_repairs_legacy_numeric_confidence_score(self, scratch_database, make_engine):
        url = scratch_database()
        engine = make_engine(url)
        with engine.begin() as conn:
            conn.execute(text("""
                    CREATE TABLE phishing_sites (
                        id SERIAL PRIMARY KEY, url TEXT UNIQUE,
                        api_confidence_score NUMERIC(5, 4)
                    )
                    """))
            conn.execute(text("""
                    INSERT INTO phishing_sites (url, api_confidence_score)
                    VALUES ('https://n.test', 0.85)
                    """))

        upgrade(url)

        with engine.connect() as conn:
            data_type = conn.execute(text("""
                    SELECT data_type FROM information_schema.columns
                    WHERE table_name = 'phishing_sites' AND column_name = 'api_confidence_score'
                    """)).scalar_one()
        assert data_type == "integer"

    def test_minimal_abuse_reports_table_gets_unique_report_id(self, scratch_database, make_engine):
        """ReportTracker's fallback table had no UNIQUE(report_id)."""
        url = scratch_database()
        engine = make_engine(url)
        with engine.begin() as conn:
            conn.execute(text("CREATE TABLE phishing_sites (id SERIAL PRIMARY KEY, url TEXT)"))
            conn.execute(text("""
                    CREATE TABLE abuse_reports (
                        id SERIAL PRIMARY KEY, site_url TEXT NOT NULL,
                        recipients TEXT NOT NULL, report_id TEXT,
                        status TEXT DEFAULT 'sent',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                    """))
            conn.execute(text("""
                    INSERT INTO abuse_reports (site_url, recipients, report_id)
                    VALUES ('https://a.test', 'x@y.test', 'R-1')
                    """))

        upgrade(url)

        with engine.begin() as conn:
            with pytest.raises(Exception, match="abuse_reports_report_id_key"):
                conn.execute(text("""
                        INSERT INTO abuse_reports (site_url, recipients, report_id)
                        VALUES ('https://b.test', 'x@y.test', 'R-1')
                        """))

    def test_duplicate_report_ids_abort_the_upgrade_loudly(self, scratch_database, make_engine):
        url = scratch_database()
        engine = make_engine(url)
        with engine.begin() as conn:
            conn.execute(text("CREATE TABLE phishing_sites (id SERIAL PRIMARY KEY, url TEXT)"))
            conn.execute(text("""
                    CREATE TABLE abuse_reports (
                        id SERIAL PRIMARY KEY, site_url TEXT NOT NULL,
                        recipients TEXT NOT NULL, report_id TEXT
                    )
                    """))
            conn.execute(text("""
                    INSERT INTO abuse_reports (site_url, recipients, report_id)
                    VALUES ('https://a.test', 'x', 'DUP'), ('https://b.test', 'x', 'DUP')
                    """))

        with pytest.raises(Exception, match="duplicate values"):
            upgrade(url)

        assert "alembic_version" not in table_columns(engine), "upgrade must be atomic"

    def test_orphaned_site_ids_keep_foreign_key_not_valid(self, scratch_database, make_engine):
        url = scratch_database()
        engine = make_engine(url)
        load_legacy_schema(engine)
        with engine.begin() as conn:
            conn.execute(text("""
                    INSERT INTO abuse_reports (site_url, recipients, report_id, site_id)
                    VALUES ('https://gone.test', 'x@y.test', 'R-9', 9999)
                    """))

        upgrade(url)

        with engine.connect() as conn:
            validated = conn.execute(text("""
                    SELECT convalidated FROM pg_constraint
                    WHERE conname = 'abuse_reports_site_id_fkey'
                    """)).scalar_one()
        assert validated is False


class TestDowngrade:
    """``alembic downgrade 002`` from 003."""

    def test_downgrade_drops_only_objects_new_in_003(self, scratch_database, make_engine):
        url = scratch_database()
        engine = make_engine(url)
        load_legacy_schema(engine)
        with engine.begin() as conn:
            conn.execute(text("""
                    INSERT INTO email_sender_reputation (sender_email, sender_domain)
                    VALUES ('keep@legacy.test', 'legacy.test')
                    """))
        upgrade(url)

        downgrade(url, "002")

        tables = table_columns(engine)
        assert "redirect_chains" not in tables
        assert not NEW_INDEXES_IN_003 & index_names(engine)
        assert "email_sender_reputation" in tables, "pre-existing runtime tables are kept"
        with engine.connect() as conn:
            kept = conn.execute(
                text("SELECT sender_email FROM email_sender_reputation")
            ).scalar_one()
            version = conn.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
        assert kept == "keep@legacy.test"
        assert version == "002"

        upgrade(url)
        assert "redirect_chains" in table_columns(engine)


class TestSchemaGuard:
    """``ensure_schema_is_current`` at application startup."""

    def test_current_database_passes(self, scratch_database, make_engine):
        url = scratch_database()
        upgrade(url)

        ensure_schema_is_current(make_engine(url))

    def test_database_behind_head_is_rejected(self, scratch_database, make_engine):
        url = scratch_database()
        upgrade(url, "002")

        with pytest.raises(RuntimeError, match="Database schema is behind") as excinfo:
            ensure_schema_is_current(make_engine(url))
        assert BEHIND_MESSAGE in str(excinfo.value)
        assert "002" in str(excinfo.value)

    def test_never_migrated_database_is_rejected(self, scratch_database, make_engine):
        url = scratch_database()
        engine = make_engine(url)
        load_legacy_schema(engine)

        with pytest.raises(RuntimeError, match="alembic_version missing"):
            ensure_schema_is_current(engine)

    def test_unknown_revision_is_rejected(self, scratch_database, make_engine):
        url = scratch_database()
        upgrade(url)
        engine = make_engine(url)
        with engine.begin() as conn:
            conn.execute(text("UPDATE alembic_version SET version_num = '999'"))

        with pytest.raises(RuntimeError, match="999, which this code does not know"):
            ensure_schema_is_current(engine)


class TestAlembicCli:
    """URL resolution of ``alembic/env.py`` when run from the command line."""

    @staticmethod
    def _run_alembic(env: Dict[str, str]) -> subprocess.CompletedProcess:
        base = {k: v for k, v in os.environ.items() if k not in {"DATABASE_URL"}}
        base.update(env)
        return subprocess.run(
            [sys.executable, "-m", "alembic", "current"],
            cwd=PROJECT_ROOT,
            env=base,
            capture_output=True,
            text=True,
            timeout=60,
        )

    def test_reads_database_url_from_active_env_file(self, scratch_database, tmp_path):
        url = scratch_database()
        upgrade(url)
        env_file = tmp_path / "custom.env"
        env_file.write_text(f"DATABASE_URL={url}\n")

        result = self._run_alembic({"ANISAKYS_ENV_FILE": str(env_file)})

        assert result.returncode == 0, result.stderr
        assert f"{script_head()} (head)" in result.stdout

    def test_environment_variable_wins_over_env_file(self, scratch_database, tmp_path):
        url = scratch_database()
        upgrade(url)
        env_file = tmp_path / "custom.env"
        env_file.write_text("DATABASE_URL=postgresql://nobody@127.0.0.1:1/nothing\n")

        result = self._run_alembic({"ANISAKYS_ENV_FILE": str(env_file), "DATABASE_URL": url})

        assert result.returncode == 0, result.stderr
        assert f"{script_head()} (head)" in result.stdout

    def test_missing_url_fails_loudly(self, tmp_path):
        result = self._run_alembic({"ANISAKYS_ENV_FILE": str(tmp_path / "missing.env")})

        assert result.returncode != 0
        assert "DATABASE_URL is not set" in result.stderr
