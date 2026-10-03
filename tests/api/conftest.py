"""Shared fixtures for API tests.

The ``migrated_db_url`` fixture builds the real application schema (``alembic
upgrade head``) inside a throw-away PostgreSQL schema of the test database, so
integration tests can run the API's raw SQL against PostgreSQL without touching
the tables other tests use in ``public``.
"""

import os
import uuid
from pathlib import Path
from typing import Iterator
from unittest.mock import MagicMock, patch

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text

ROOT = Path(__file__).resolve().parents[2]


def _with_search_path(db_url: str, schema: str) -> str:
    """Return ``db_url`` with a libpq option pinning ``search_path`` to ``schema``.

    Args:
        db_url: Base PostgreSQL URL of the test database.
        schema: Schema every connection made from the returned URL should use.

    Returns:
        The URL with an ``options=-csearch_path=<schema>`` query parameter.
    """
    separator = "&" if "?" in db_url else "?"
    return f"{db_url}{separator}options=-csearch_path={schema}"


@pytest.fixture(scope="module")
def migrated_db_url(create_test_database: str) -> Iterator[str]:
    """Create an isolated schema migrated to ``head`` and yield a URL bound to it.

    Args:
        create_test_database: Session fixture returning the test database URL.

    Yields:
        A database URL whose connections only see the isolated schema.
    """
    schema = f"ws_api_{uuid.uuid4().hex[:12]}"
    admin_engine = create_engine(create_test_database)
    with admin_engine.begin() as conn:
        conn.execute(text(f'CREATE SCHEMA "{schema}"'))

    schema_url = _with_search_path(create_test_database, schema)
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "alembic"))
    try:
        with patch.dict(os.environ, {"DATABASE_URL": schema_url}):
            command.upgrade(config, "head")
        # Columns the app still adds at startup (e.g. phishing_sites.detected_kit_type)
        # until that runtime DDL moves into Alembic; skipped once it is gone.
        from src.database.manager import DatabaseManager

        manager = DatabaseManager(db_url=schema_url)
        init_runtime_columns = getattr(manager, "init_phishing_db", None)
        if init_runtime_columns is not None:
            init_runtime_columns()
        manager.engine.dispose()
        yield schema_url
    finally:
        with admin_engine.begin() as conn:
            conn.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
        admin_engine.dispose()


@pytest.fixture
def pg_api(migrated_db_url: str):
    """A ``PhishingAPI`` whose database manager talks to the migrated schema.

    Outbound integrations (Grinder, multi-API validator) are mocked; requests
    authenticate with the master key ``test_key``.

    Args:
        migrated_db_url: URL of the isolated, migrated schema.

    Yields:
        Tuple of (Flask test client, DatabaseManager, auth headers).
    """
    from src.database.manager import DatabaseManager
    from src.reporting.email_detector import EnhancedAbuseEmailDetector

    with (
        patch("src.api.phishing_api.GrinderReportClient"),
        patch("src.api.phishing_api.MultiAPIValidator"),
    ):
        from src.api.phishing_api import PhishingAPI

        db_manager = DatabaseManager(db_url=migrated_db_url)
        api = PhishingAPI(
            db_manager, MagicMock(spec=EnhancedAbuseEmailDetector), api_key="test_key"
        )
        api.app.config["TESTING"] = True
        yield api.app.test_client(), db_manager, {"Authorization": "Bearer test_key"}
        db_manager.engine.dispose()
