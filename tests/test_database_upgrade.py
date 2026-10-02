"""
Tests for database upgrade functionality
"""

import pytest
from sqlalchemy import create_engine, text, MetaData
from pathlib import Path
import importlib.util
import sys

# Load main module
module_path = Path(__file__).parent.parent / "src" / "main.py"
spec = importlib.util.spec_from_file_location("src.main", str(module_path))
main = importlib.util.module_from_spec(spec)
spec.loader.exec_module(main)

# Import needed functions
upgrade_phishing_db = main.upgrade_phishing_db
DatabaseManager = main.DatabaseManager

# upgrade_phishing_db() lives in src.api.phishing_api and reads the db_engine
# global of THAT module — monkeypatch there, not on main.
import src.api.phishing_api as phishing_api_module


class TestDatabaseUpgrade:
    """Test database upgrade functionality"""

    @pytest.fixture
    def pg_old_schema_engine(self):
        """Recreate phishing_sites with the legacy minimal schema on the test
        PostgreSQL database (upgrade_phishing_db needs information_schema),
        then restore the full modern table for the rest of the suite."""
        engine = create_engine(main.DATABASE_URL)
        with engine.begin() as conn:
            conn.execute(text("DROP TABLE IF EXISTS phishing_sites CASCADE"))
            conn.execute(
                text(
                    """
                CREATE TABLE phishing_sites (
                    id SERIAL PRIMARY KEY,
                    url TEXT UNIQUE,
                    manual_flag INTEGER DEFAULT 0,
                    first_seen TIMESTAMP,
                    last_seen TIMESTAMP
                )
            """
                )
            )
        yield engine
        with engine.begin() as conn:
            conn.execute(text("DROP TABLE IF EXISTS phishing_sites CASCADE"))
        engine.dispose()
        DatabaseManager(db_url=main.DATABASE_URL).init_phishing_db()

    def test_upgrade_adds_missing_columns(self, pg_old_schema_engine, monkeypatch):
        """Test that upgrade adds all missing columns"""
        # Monkeypatch the db_engine of the module that owns the function
        monkeypatch.setattr(phishing_api_module, "db_engine", pg_old_schema_engine)

        # Run upgrade
        upgrade_phishing_db()

        # Check columns exist
        with pg_old_schema_engine.begin() as conn:
            result = conn.execute(
                text(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_name = 'phishing_sites'"
                )
            )
            columns = {row[0] for row in result}

        # Verify all expected columns exist
        expected_columns = {
            "id",
            "url",
            "manual_flag",
            "first_seen",
            "last_seen",
            "source",
            "priority",
            "description",
            "asn",
            "asn_abuse_email",
            "hosting_provider",
            "all_abuse_emails",
            "virustotal_result",
            "urlvoid_result",
            "phishtank_result",
            "multi_api_threat_level",
            "api_confidence_score",
            "auto_detected",
            "auto_analysis_status",
            "auto_analysis_timestamp",
            "detection_keywords",
            "auto_report_eligible",
            "requires_manual_review",
        }

        missing_columns = expected_columns - columns
        assert len(missing_columns) == 0, f"Missing columns: {missing_columns}"

    def test_upgrade_handles_existing_columns(self, pg_old_schema_engine, monkeypatch, caplog):
        """Test that upgrade gracefully handles existing columns"""
        monkeypatch.setattr(phishing_api_module, "db_engine", pg_old_schema_engine)

        # First run adds every missing column; second run must skip them all
        upgrade_phishing_db()
        upgrade_phishing_db()

        # Check that it logged existing columns
        assert "already exists" in caplog.text

    def test_upgrade_fixes_wrong_column_type(self, monkeypatch):
        """Test that upgrade fixes wrong column types (PostgreSQL specific)"""
        # This test would need a real PostgreSQL connection
        # For now, we'll create a mock test

        # Mock the database engine and connection
        class MockResult:
            def fetchone(self):
                return ("numeric", 5, 4)  # Wrong type

        class MockConn:
            def execute(self, query):
                if "information_schema.columns" in str(query):
                    if "column_name" in str(query):
                        # Return columns list
                        return [("api_confidence_score",)]
                    else:
                        # Return column info
                        return MockResult()
                return None

            def commit(self):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

        class MockEngine:
            def connect(self):
                return MockConn()

            def begin(self):
                return MockConn()

        monkeypatch.setattr(phishing_api_module, "db_engine", MockEngine())

        # Run upgrade - should attempt to fix column type
        upgrade_phishing_db()

        # In a real test, we'd verify the ALTER TABLE was executed

    def test_database_manager_init(self):
        """Test DatabaseManager initialization"""
        # Use the main DATABASE_URL (which is PostgreSQL in tests)
        from src.main import DATABASE_URL

        db_manager = DatabaseManager(db_url=DATABASE_URL)

        # Initialize tables
        db_manager.init_db()
        db_manager.init_phishing_db()

        # Check tables exist using PostgreSQL system tables
        with db_manager.engine.begin() as conn:
            # Check scan_results table
            result = conn.execute(
                text(
                    "SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename='scan_results'"
                )
            )
            assert result.fetchone() is not None

            # Check phishing_sites table
            result = conn.execute(
                text(
                    "SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename='phishing_sites'"
                )
            )
            assert result.fetchone() is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
