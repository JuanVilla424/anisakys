"""Fixtures for the brand catalogue tests: a schema migrated to ``head``."""

from typing import Iterator

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

from src.brands import catalog
from tests.api.conftest import migrated_db_url  # noqa: F401  (re-exported fixture)


@pytest.fixture
def engine(migrated_db_url: str) -> Iterator[Engine]:  # noqa: F811
    """Engine bound to the isolated, migrated schema, with an empty catalogue.

    The schema is shared by the tests of a module (see tests/api/conftest.py), so the
    catalogue tables are emptied before each test.

    Args:
        migrated_db_url: URL of the schema.

    Yields:
        The engine.
    """
    eng = create_engine(migrated_db_url)
    with eng.begin() as conn:
        conn.execute(text("TRUNCATE brands, brand_domains, brand_assets RESTART IDENTITY CASCADE"))
    yield eng
    eng.dispose()


@pytest.fixture(autouse=True)
def _fresh_catalogue():
    """Every test starts without a cached detection catalogue."""
    catalog.invalidate()
    yield
    catalog.invalidate()
