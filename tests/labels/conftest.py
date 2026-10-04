"""Fixtures for the analyst-label tests: a schema migrated to ``head``."""

from typing import Iterator

import pytest
from sqlalchemy import create_engine
from sqlalchemy.engine import Engine

from tests.api.conftest import migrated_db_url  # noqa: F401  (re-exported fixture)


@pytest.fixture
def engine(migrated_db_url: str) -> Iterator[Engine]:  # noqa: F811
    """Engine bound to the isolated, migrated schema.

    Args:
        migrated_db_url: URL of the schema (see tests/api/conftest.py).

    Yields:
        The engine.
    """
    eng = create_engine(migrated_db_url)
    yield eng
    eng.dispose()
