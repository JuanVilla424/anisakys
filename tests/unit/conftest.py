"""Conftest for unit tests - No database required.

Unit tests use mocks and don't need database fixtures.
"""
import pytest


# Override all database-related fixtures to prevent them from running
@pytest.fixture(scope="session", autouse=True)
def create_test_database():
    """Override to disable database creation for unit tests."""
    yield "mock://localhost/test"  # Return mock URL


@pytest.fixture
def main_module():
    """Override to provide dummy module."""
    class MockModule:
        DATABASE_URL = "mock://localhost/test"

    return MockModule()


@pytest.fixture
def db_engine():
    """Override to prevent DB engine creation."""
    return None


@pytest.fixture
def db_session():
    """Override to prevent DB session creation."""
    return None


@pytest.fixture
def test_record_tracker():
    """Override to prevent record tracking for cleanup."""
    return {"scan_results": [], "phishing_sites": [], "registrar_abuse": []}


@pytest.fixture
def unique_test_id():
    """Override to provide test ID without DB dependency."""
    import uuid
    return f"test_{uuid.uuid4().hex[:12]}"


@pytest.fixture(autouse=True)
def auto_cleanup():
    """Override to prevent cleanup attempts in unit tests."""
    yield  # Do nothing
