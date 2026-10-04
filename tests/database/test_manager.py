"""
Tests for src/database/manager.py - DatabaseManager
"""

from unittest.mock import patch, MagicMock

import pytest
from sqlalchemy import text

from src.database.manager import DatabaseManager, DATABASE_URL, db_engine


class TestDatabaseManager:
    """Tests for DatabaseManager class."""

    def test_database_url_is_set(self):
        """DATABASE_URL should be configured."""
        assert DATABASE_URL is not None
        assert "postgresql" in DATABASE_URL

    def test_db_engine_is_created(self):
        """Global db_engine should be created."""
        assert db_engine is not None

    def test_init_with_default_url(self):
        """Should use default DATABASE_URL when none provided."""
        manager = DatabaseManager()
        assert manager.db_url == DATABASE_URL

    def test_init_with_custom_url(self):
        """Should accept custom database URL."""
        custom_url = "postgresql://test:test@localhost/test"
        manager = DatabaseManager(db_url=custom_url)
        assert manager.db_url == custom_url

    def test_engine_is_shared(self):
        """Manager should use shared global engine."""
        manager = DatabaseManager()
        assert manager.engine == db_engine


class TestDatabaseManagerHasNoRuntimeDdl:
    """The schema is owned by Alembic; DatabaseManager must not create tables."""

    @pytest.mark.parametrize(
        "method",
        [
            "init_db",
            "init_phishing_db",
            "migrate_phishing_db",
            "migrate_gsb_columns",
            "init_registrar_abuse_db",
            "init_hosting_abuse_db",
            "init_threads_db",
            "init_blocklist_db",
            "_init_email_reputation_db",
        ],
    )
    def test_runtime_ddl_methods_are_gone(self, method):
        assert not hasattr(DatabaseManager, method)

    def test_migrated_test_database_has_core_tables(self):
        """conftest builds the schema with `alembic upgrade head`."""
        manager = DatabaseManager()
        with manager.engine.connect() as conn:
            tables = {
                row[0]
                for row in conn.execute(
                    text(
                        "SELECT table_name FROM information_schema.tables "
                        "WHERE table_schema = 'public'"
                    )
                )
            }
        assert {"scan_results", "phishing_sites", "hosting_abuse", "alembic_version"} <= tables


class TestDatabaseManagerOperations:
    """Tests for database operations."""

    @pytest.fixture
    def manager(self):
        """Create a DatabaseManager instance."""
        return DatabaseManager()

    def test_get_pending_analysis_sites_returns_list(self, manager):
        """get_pending_analysis_sites should return a list."""
        result = manager.get_pending_analysis_sites()
        assert isinstance(result, list)

    def test_get_auto_report_eligible_sites_returns_list(self, manager):
        """get_auto_report_eligible_sites should return a list."""
        result = manager.get_auto_report_eligible_sites()
        assert isinstance(result, list)

    def test_get_registrar_abuse_emails_returns_none_for_empty(self, manager):
        """get_registrar_abuse_emails should return None for empty input."""
        result = manager.get_registrar_abuse_emails("")
        assert result is None

    def test_get_registrar_abuse_emails_returns_none_for_none(self, manager):
        """get_registrar_abuse_emails should return None for None input."""
        result = manager.get_registrar_abuse_emails(None)
        assert result is None

    def test_get_registrar_abuse_emails_queries_database(self):
        """get_registrar_abuse_emails should query the database."""

        manager = DatabaseManager()

        # Mock the engine connection to simulate database query.
        # manager.engine is the SHARED global db_engine — patch.object restores
        # it afterwards; a bare assignment would poison every later test.
        mock_conn = MagicMock()
        mock_conn.execute.return_value.fetchone.return_value = None
        mock_connect = MagicMock(
            return_value=MagicMock(
                __enter__=MagicMock(return_value=mock_conn), __exit__=MagicMock()
            )
        )

        with patch.object(manager.engine, "connect", mock_connect):
            result = manager.get_registrar_abuse_emails("test-registrar")
        assert result is None

    def test_get_hosting_abuse_emails_returns_none_for_empty(self, manager):
        """get_hosting_abuse_emails should return None for empty input."""
        result = manager.get_hosting_abuse_emails("")
        assert result is None

    def test_get_hosting_abuse_emails_returns_none_for_none(self, manager):
        """get_hosting_abuse_emails should return None for None input."""
        result = manager.get_hosting_abuse_emails(None)
        assert result is None

    def test_get_hosting_abuse_emails_returns_none_for_unknown(self, manager):
        """get_hosting_abuse_emails should return None for unknown provider."""
        result = manager.get_hosting_abuse_emails("unknown-provider-12345-test")
        assert result is None

    def test_get_hosting_abuse_emails_with_asn(self, manager):
        """get_hosting_abuse_emails should accept optional ASN parameter."""
        result = manager.get_hosting_abuse_emails("unknown-provider", asn="AS12345")
        assert result is None


class TestDatabaseManagerStorePhishing:
    """Tests for phishing site storage."""

    @pytest.fixture
    def manager(self):
        """Create a DatabaseManager instance."""
        return DatabaseManager()

    def test_store_detected_phishing_site_new_url(self, manager):
        """store_detected_phishing_site should return True for new URL."""
        import uuid
        import time

        # Use timestamp to ensure uniqueness between tests
        unique_url = f"http://test-phishing-new-{uuid.uuid4()}-{int(time.time()*1000)}.test/scam"

        try:
            result = manager.store_detected_phishing_site(
                url=unique_url, keywords=["login", "password"], source="test"
            )
            # New URL should return True
            assert result is True
        finally:
            # Cleanup
            with manager.engine.begin() as conn:
                conn.execute(
                    text("DELETE FROM phishing_sites WHERE url = :url"), {"url": unique_url}
                )

    def test_store_detected_phishing_site_handles_keywords(self, manager):
        """store_detected_phishing_site should accept keyword list."""
        import uuid
        import time

        unique_url = (
            f"http://test-phishing-keywords-{uuid.uuid4()}-{int(time.time()*1000)}.test/scam"
        )

        try:
            # Test with multiple keywords
            result = manager.store_detected_phishing_site(
                url=unique_url, keywords=["login", "password", "credit card"], source="unit_test"
            )
            # Should succeed
            assert result is True
        finally:
            # Cleanup
            with manager.engine.begin() as conn:
                conn.execute(
                    text("DELETE FROM phishing_sites WHERE url = :url"), {"url": unique_url}
                )
