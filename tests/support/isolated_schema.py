"""Run DB tests against a throw-away PostgreSQL schema built from migrations.

Each context gets its own schema in the test database, created by executing
the raw SQL of the Alembic migrations (``op.execute`` calls) and dropped
afterwards. Tests therefore do not depend on runtime DDL helpers or on rows
left behind by other tests.
"""

from __future__ import annotations

import importlib.util
import uuid
from contextlib import contextmanager
from pathlib import Path
from types import ModuleType
from typing import Iterable, Iterator, Tuple

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Connection, Engine, make_url
from sqlalchemy.pool import NullPool

VERSIONS_DIR = Path(__file__).resolve().parents[2] / "alembic" / "versions"


class _SqlOp:
    """Minimal stand-in for ``alembic.op`` that executes raw SQL."""

    def __init__(self, conn: Connection):
        """Bind to a connection.

        Args:
            conn: Connection inside an open transaction.
        """
        self._conn = conn

    def execute(self, sql: str) -> None:
        """Execute one SQL statement.

        Args:
            sql: Raw SQL text.
        """
        self._conn.execute(text(sql))


def load_migration(filename: str) -> ModuleType:
    """Import a migration module from ``alembic/versions`` by file name.

    Args:
        filename: File name without directory, e.g. ``"001_baseline_schema.py"``.

    Returns:
        The imported module.
    """
    path = VERSIONS_DIR / filename
    spec = importlib.util.spec_from_file_location(f"_migration_{path.stem}", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_upgrade(conn: Connection, filename: str) -> None:
    """Execute a migration's ``upgrade()`` against ``conn``.

    Args:
        conn: Connection inside an open transaction.
        filename: Migration file name.
    """
    module = load_migration(filename)
    module.op = _SqlOp(conn)
    module.upgrade()


@contextmanager
def isolated_schema(
    base_url: str, migrations: Iterable[str] = ("001_baseline_schema.py",)
) -> Iterator[Tuple[Engine, str]]:
    """Create a temporary schema, apply migrations and yield an engine bound to it.

    Args:
        base_url: SQLAlchemy URL of the test database.
        migrations: Migration file names to apply, in order.

    Yields:
        ``(engine, url)`` where both target the temporary schema through
        ``search_path``.
    """
    schema = f"wsc_{uuid.uuid4().hex[:12]}"
    admin = create_engine(base_url, poolclass=NullPool)
    with admin.begin() as conn:
        conn.execute(text(f'CREATE SCHEMA "{schema}"'))
    url = make_url(base_url).update_query_dict({"options": f"-csearch_path={schema}"})
    url_str = url.render_as_string(hide_password=False)
    engine = create_engine(url_str, poolclass=NullPool)
    try:
        with engine.begin() as conn:
            for filename in migrations:
                run_upgrade(conn, filename)
        yield engine, url_str
    finally:
        engine.dispose()
        with admin.begin() as conn:
            conn.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
        admin.dispose()
