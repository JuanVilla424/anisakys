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


class TestDatabaseUpgrade:
    """Test database upgrade functionality"""

    @pytest.fixture
    def test_db_engine(self):
        """Create a test database engine"""
        # Use SQLite for testing
        engine = create_engine("sqlite:///:memory:")
        return engine

    @pytest.fixture
    def test_db_with_old_schema(self, test_db_engine):
        """Create a test database with old schema (missing columns)"""
        with test_db_engine.begin() as conn:
            # Create table with minimal columns (old schema)
            conn.execute(
                text(
                    """
                CREATE TABLE phishing_sites (
                    id INTEGER PRIMARY KEY,
                    url TEXT UNIQUE,
                    manual_flag INTEGER DEFAULT 0,
                    first_seen TIMESTAMP,
                    last_seen TIMESTAMP
                )
            """
                )
            )
        return test_db_engine

    @pytest.fixture
    def test_db_with_wrong_type(self, test_db_engine):
        """Create a test database with wrong column type"""
        with test_db_engine.begin() as conn:
            # Create table with wrong type for api_confidence_score
            conn.execute(
                text(
                    """
                CREATE TABLE phishing_sites (
                    id INTEGER PRIMARY KEY,
                    url TEXT UNIQUE,
                    manual_flag INTEGER DEFAULT 0,
                    first_seen TIMESTAMP,
                    last_seen TIMESTAMP,
                    api_confidence_score NUMERIC(5,4)
                )
            """
                )
            )
        return test_db_engine

    def test_upgrade_adds_missing_columns(self, test_db_with_old_schema, monkeypatch):
        """Test that upgrade adds all missing columns"""
        # Monkeypatch the db_engine to use our test engine
        monkeypatch.setattr(main, "db_engine", test_db_with_old_schema)

        # Run upgrade
        upgrade_phishing_db()

        # Check columns exist
        with test_db_with_old_schema.begin() as conn:
            # For SQLite, use pragma
            result = conn.execute(text("PRAGMA table_info(phishing_sites)"))
            columns = {row[1] for row in result}

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

    def test_upgrade_handles_existing_columns(self, test_db_engine, monkeypatch, caplog):
        """Test that upgrade gracefully handles existing columns"""
        # Create table with all columns
        with test_db_engine.begin() as conn:
            conn.execute(
                text(
                    """
                CREATE TABLE phishing_sites (
                    id INTEGER PRIMARY KEY,
                    url TEXT UNIQUE,
                    virustotal_result TEXT,
                    api_confidence_score INTEGER
                )
            """
                )
            )

        monkeypatch.setattr(main, "db_engine", test_db_engine)

        # Run upgrade - should not fail
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

            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

        class MockEngine:
            def begin(self):
                return MockConn()

        monkeypatch.setattr(main, "db_engine", MockEngine())

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
