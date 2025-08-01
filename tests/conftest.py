import sys
import os
import pytest
import uuid
from pathlib import Path
from urllib.parse import urlparse
import psycopg2
from sqlalchemy import create_engine, text
from contextlib import contextmanager

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


@pytest.fixture(scope="session")
def main_module():
    """Import and return the main module"""
    from src import main

    return main


@pytest.fixture(scope="session", autouse=True)
def create_test_database(main_module):
    """
    Creates the test database if it does not exist.
    """
    db_url = main_module.DATABASE_URL
    parsed = urlparse(db_url)
    test_db = parsed.path.lstrip("/")

    # Build a connection URL to the default database
    default_db = "postgres"
    default_db_url = db_url.replace(f"/{test_db}", f"/{default_db}")

    conn = psycopg2.connect(default_db_url)
    conn.autocommit = True
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM pg_database WHERE datname = %s", (test_db,))
    exists = cur.fetchone()
    if not exists:
        cur.execute(f"CREATE DATABASE {test_db}")
        print(f"Created test database '{test_db}'.")
    else:
        print(f"Test database '{test_db}' already exists.")
    cur.close()
    conn.close()

    yield db_url


@pytest.fixture
def db_engine(create_test_database):
    """Create database engine for tests"""
    engine = create_engine(create_test_database)
    yield engine
    engine.dispose()


@pytest.fixture
def db_session(db_engine):
    """Create a database session with automatic rollback"""
    connection = db_engine.connect()
    transaction = connection.begin()

    yield connection

    # Rollback transaction after test
    transaction.rollback()
    connection.close()


@pytest.fixture
def unique_test_id():
    """Generate unique ID for each test"""
    return f"test_{uuid.uuid4().hex[:12]}"


@pytest.fixture
def test_record_tracker():
    """Track test records for cleanup"""
    records = {"phishing_sites": [], "scan_results": [], "registrar_abuse": []}
    yield records


def cleanup_specific_records(engine, records):
    """Clean up only specific test records created"""
    with engine.begin() as conn:
        # Clean phishing_sites
        for url in records.get("phishing_sites", []):
            conn.execute(text("DELETE FROM phishing_sites WHERE url = :url"), {"url": url})

        # Clean scan_results
        for url in records.get("scan_results", []):
            conn.execute(text("DELETE FROM scan_results WHERE url = :url"), {"url": url})

        # Clean registrar_abuse
        for registrar in records.get("registrar_abuse", []):
            conn.execute(
                text("DELETE FROM registrar_abuse WHERE registrar = :registrar"),
                {"registrar": registrar},
            )


@pytest.fixture
def mock_smtp(monkeypatch):
    """Mock SMTP for email tests"""
    import smtplib
    from unittest.mock import MagicMock

    mock_smtp_class = MagicMock()
    mock_smtp_instance = MagicMock()
    mock_smtp_class.return_value = mock_smtp_instance

    monkeypatch.setattr(smtplib, "SMTP", mock_smtp_class)

    return mock_smtp_instance


@pytest.fixture
def test_urls(unique_test_id):
    """Generate test URLs with unique ID"""
    return {
        "phishing": f"https://phish-{unique_test_id}.com",
        "clean": f"https://clean-{unique_test_id}.com",
        "suspicious": f"https://sus-{unique_test_id}.net",
    }


@pytest.fixture(autouse=True)
def auto_cleanup(request, db_engine, test_record_tracker):
    """Automatically clean up test records after each test"""
    yield

    # Clean up only the specific records created by this test
    if hasattr(request.node, "test_records"):
        cleanup_specific_records(db_engine, request.node.test_records)
    else:
        cleanup_specific_records(db_engine, test_record_tracker)


@contextmanager
def temporary_test_data(engine, unique_id, data_type="phishing_site"):
    """Context manager for temporary test data - creates and cleans ONE record"""
    url = f"https://temp-{unique_id}-{uuid.uuid4().hex[:6]}.com"

    try:
        # Insert ONE test record
        with engine.begin() as conn:
            if data_type == "phishing_site":
                conn.execute(
                    text(
                        """
                        INSERT INTO phishing_sites (url, manual_flag, first_seen, description)
                        VALUES (:url, 1, CURRENT_TIMESTAMP, :desc)
                    """
                    ),
                    {"url": url, "desc": f"Test record {unique_id}"},
                )

        yield url

    finally:
        # Clean up ONLY this specific record
        with engine.begin() as conn:
            conn.execute(text("DELETE FROM phishing_sites WHERE url = :url"), {"url": url})


class TestDataManager:
    """Helper class to manage test data creation and cleanup"""

    def __init__(self, engine, unique_id):
        self.engine = engine
        self.unique_id = unique_id
        self.created_records = {"phishing_sites": [], "scan_results": [], "registrar_abuse": []}

    def create_phishing_site(self, suffix=""):
        """Create a single phishing site record"""
        url = f"https://test-{self.unique_id}{suffix}.com"

        with self.engine.begin() as conn:
            conn.execute(
                text(
                    """
                    INSERT INTO phishing_sites (url, manual_flag, first_seen)
                    VALUES (:url, 1, CURRENT_TIMESTAMP)
                """
                ),
                {"url": url},
            )

        self.created_records["phishing_sites"].append(url)
        return url

    def create_scan_result(self, suffix=""):
        """Create a single scan result record"""
        url = f"https://scan-{self.unique_id}{suffix}.com"

        with self.engine.begin() as conn:
            conn.execute(
                text(
                    """
                    INSERT INTO scan_results (url, first_seen, response_code)
                    VALUES (:url, CURRENT_TIMESTAMP, 200)
                """
                ),
                {"url": url},
            )

        self.created_records["scan_results"].append(url)
        return url

    def cleanup(self):
        """Clean up ONLY the records created by this test"""
        cleanup_specific_records(self.engine, self.created_records)


@pytest.fixture
def test_data_manager(db_engine, unique_test_id):
    """Provide test data manager for controlled record creation/cleanup"""
    manager = TestDataManager(db_engine, unique_test_id)
    yield manager
    # Cleanup automatically when test ends
    manager.cleanup()


# Test email configuration - using @passinbox.com to avoid real reports
TEST_USER_EMAIL = "r6ty5r296it6tl4eg5m.constant214@passinbox.com"
