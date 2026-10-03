import errno
import ipaddress
import socket
import sys
import os
import pytest
import uuid
from typing import Any, Optional, Union
from urllib.parse import urlparse
import psycopg2
from alembic import command
from sqlalchemy import create_engine, text
from contextlib import contextmanager

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Preload detection.analyzer first to resolve a src.intelligence <-> src.detection
# import cycle that otherwise breaks test collection. Safe at runtime (the app
# boots via src.main which imports these in a working order).
import src.detection.analyzer  # noqa: F401,E402

# ---------------------------------------------------------------------------
# Network guard: tests not marked `network` may only talk to this machine.
# ---------------------------------------------------------------------------
# Several code paths resolve hostnames or query WHOIS without being mocked;
# outside the `network` marker they must behave as if offline instead of
# silently depending on (and hammering) real services. PostgreSQL goes
# through libpq's own sockets and is not affected.

_REAL_CONNECT = socket.socket.connect
_REAL_CONNECT_EX = socket.socket.connect_ex
_REAL_SENDTO = socket.socket.sendto
_REAL_GETADDRINFO = socket.getaddrinfo


class NetworkAccessBlocked(OSError):
    """A test without the ``network`` marker tried to reach a remote host."""


def _host_is_local(host: Union[str, bytes, None]) -> bool:
    """Tell whether ``host`` designates this machine.

    Args:
        host: Host name or address as passed to the socket API.

    Returns:
        True for ``None`` (passive lookups), ``localhost`` and loopback IPs.
    """
    if host is None:
        return True
    name = host.decode() if isinstance(host, bytes) else str(host)
    if name in ("", "localhost"):
        return True
    try:
        return ipaddress.ip_address(name.split("%")[0]).is_loopback
    except ValueError:
        return False


def _blocked(target: Any) -> NetworkAccessBlocked:
    return NetworkAccessBlocked(
        errno.ENETUNREACH,
        f"test attempted network access to {target!r}; mark it @pytest.mark.network",
    )


def _guarded_connect(self: socket.socket, address: Any) -> None:
    if self.family in (socket.AF_INET, socket.AF_INET6) and not _host_is_local(address[0]):
        raise _blocked(address)
    return _REAL_CONNECT(self, address)


def _guarded_connect_ex(self: socket.socket, address: Any) -> int:
    if self.family in (socket.AF_INET, socket.AF_INET6) and not _host_is_local(address[0]):
        return errno.ENETUNREACH
    return _REAL_CONNECT_EX(self, address)


def _guarded_sendto(self: socket.socket, data: bytes, *args: Any) -> int:
    address = args[-1]
    if self.family in (socket.AF_INET, socket.AF_INET6) and not _host_is_local(address[0]):
        raise _blocked(address)
    return _REAL_SENDTO(self, data, *args)


def _guarded_getaddrinfo(host: Optional[Union[str, bytes]], *args: Any, **kwargs: Any) -> Any:
    if not _host_is_local(host):
        raise socket.gaierror(socket.EAI_NONAME, f"DNS lookup of {host!r} blocked in tests")
    return _REAL_GETADDRINFO(host, *args, **kwargs)


@pytest.fixture(autouse=True)
def _block_network_unless_marked(request, monkeypatch):
    """Keep every test that is not marked ``network`` off the internet."""
    if request.node.get_closest_marker("network") is None:
        monkeypatch.setattr(socket.socket, "connect", _guarded_connect)
        monkeypatch.setattr(socket.socket, "connect_ex", _guarded_connect_ex)
        monkeypatch.setattr(socket.socket, "sendto", _guarded_sendto)
        monkeypatch.setattr(socket, "getaddrinfo", _guarded_getaddrinfo)
    yield


@pytest.fixture(scope="session")
def main_module():
    """Import and return the main module"""
    from src import main

    return main


def maintenance_database_url(db_url: str) -> str:
    """Return the URL of the ``postgres`` maintenance database on the same server.

    Args:
        db_url: URL of any database on the server.

    Returns:
        The same URL pointing at the ``postgres`` database.
    """
    parsed = urlparse(db_url)
    return parsed._replace(path="/postgres").geturl()


def upgrade_database_to_head(db_url: str) -> None:
    """Build or update a database schema exactly like production: ``alembic upgrade head``.

    Args:
        db_url: URL of the database to migrate.
    """
    from src.database.schema import get_alembic_config

    command.upgrade(get_alembic_config(db_url), "head")


@pytest.fixture(scope="session", autouse=True)
def create_test_database(main_module):
    """Create the test database if needed and migrate it to the Alembic head.

    The schema comes only from the migrations (the application has no runtime
    DDL any more), so the suite exercises the same schema as production.
    """
    db_url = main_module.DATABASE_URL
    test_db = urlparse(db_url).path.lstrip("/")

    conn = psycopg2.connect(maintenance_database_url(db_url))
    conn.autocommit = True
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM pg_database WHERE datname = %s", (test_db,))
    if not cur.fetchone():
        cur.execute(f'CREATE DATABASE "{test_db}"')
    cur.close()
    conn.close()

    upgrade_database_to_head(db_url)

    yield db_url


@pytest.fixture
def scratch_database(create_test_database):
    """Factory for throw-away databases on the test server (migration tests).

    Each call creates an empty database named ``<test db>_mig_<random>`` and
    returns its URL; every database created this way is dropped at teardown.
    """
    test_db = urlparse(create_test_database).path.lstrip("/")
    created = []

    def _create() -> str:
        name = f"{test_db}_mig_{uuid.uuid4().hex[:8]}"
        conn = psycopg2.connect(maintenance_database_url(create_test_database))
        conn.autocommit = True
        try:
            with conn.cursor() as cur:
                cur.execute(f'CREATE DATABASE "{name}"')
        finally:
            conn.close()
        created.append(name)
        return urlparse(create_test_database)._replace(path=f"/{name}").geturl()

    yield _create

    conn = psycopg2.connect(maintenance_database_url(create_test_database))
    conn.autocommit = True
    try:
        with conn.cursor() as cur:
            for name in created:
                cur.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
    finally:
        conn.close()


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
                text("DELETE FROM registrar_abuse WHERE registrar_name = :registrar"),
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
                    text("""
                        INSERT INTO phishing_sites (url, manual_flag, first_seen, description)
                        VALUES (:url, 1, CURRENT_TIMESTAMP, :desc)
                    """),
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
                text("""
                    INSERT INTO phishing_sites (url, manual_flag, first_seen)
                    VALUES (:url, 1, CURRENT_TIMESTAMP)
                """),
                {"url": url},
            )

        self.created_records["phishing_sites"].append(url)
        return url

    def create_scan_result(self, suffix=""):
        """Create a single scan result record"""
        url = f"https://scan-{self.unique_id}{suffix}.com"

        with self.engine.begin() as conn:
            conn.execute(
                text("""
                    INSERT INTO scan_results (url, first_seen, response_code)
                    VALUES (:url, CURRENT_TIMESTAMP, 200)
                """),
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
