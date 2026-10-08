"""Alembic environment for Anisakys.

The database URL is resolved, in order of precedence, from:

1. ``config.attributes["connection"]``: an open SQLAlchemy connection handed
   over by a programmatic caller;
2. the ``sqlalchemy.url`` main option, when a programmatic caller set it
   (``src.database.schema.get_alembic_config``, the test suite);
3. the ``DATABASE_URL`` environment variable;
4. ``DATABASE_URL`` in the active env file: ``$ANISAKYS_ENV_FILE`` when set,
   otherwise ``.env.test`` under pytest and ``.env`` everywhere else (the same
   rule ``src/config.py`` applies).

``target_metadata`` is ``None`` on purpose: the application has no ORM models
(all SQL is raw ``text()``), so autogenerate is not available and every
migration is written by hand with ``op.execute``.
"""

from __future__ import annotations

import os
import sys
from logging.config import fileConfig
from pathlib import Path
from typing import Optional

from alembic import context
from dotenv import dotenv_values
from sqlalchemy import engine_from_config, pool
from sqlalchemy.engine import Connection

PROJECT_ROOT = Path(__file__).resolve().parent.parent

config = context.config

# Only configure logging from alembic.ini when invoked from the CLI. A
# programmatic caller (pytest, the app) owns its logging configuration and
# fileConfig() would otherwise replace it.
if config.config_file_name is not None and config.cmd_opts is not None:
    fileConfig(config.config_file_name, disable_existing_loggers=False)

# No ORM models: migrations are raw SQL via op.execute(), autogenerate is off.
target_metadata = None


def _active_env_file() -> Path:
    """Return the env file the application itself would load.

    Returns:
        Path of ``$ANISAKYS_ENV_FILE``, ``.env.test`` under pytest, or ``.env``.
    """
    explicit = os.environ.get("ANISAKYS_ENV_FILE")
    if explicit:
        return Path(explicit)
    name = ".env.test" if "pytest" in sys.modules else ".env"
    return PROJECT_ROOT / name


def resolve_database_url() -> str:
    """Resolve the database URL Alembic must migrate.

    Returns:
        The SQLAlchemy URL.

    Raises:
        RuntimeError: If no source provides a URL.
    """
    configured: Optional[str] = config.get_main_option("sqlalchemy.url")
    if configured:
        return configured

    from_env = os.environ.get("DATABASE_URL")
    if from_env:
        return from_env

    env_file = _active_env_file()
    if env_file.exists():
        from_file = dotenv_values(env_file).get("DATABASE_URL")
        if from_file:
            return from_file

    raise RuntimeError(
        "DATABASE_URL is not set. Export it, add it to "
        f"{env_file} or set ANISAKYS_ENV_FILE to the env file to use."
    )


def run_migrations_offline() -> None:
    """Emit the migration SQL to stdout (``alembic upgrade head --sql``)."""
    context.configure(
        url=resolve_database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def _run_with_connection(connection: Connection) -> None:
    """Run the migrations on an already open connection.

    Args:
        connection: Connection to migrate.
    """
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run the migrations against a live database."""
    provided: Optional[Connection] = config.attributes.get("connection")
    if provided is not None:
        _run_with_connection(provided)
        return

    section = dict(config.get_section(config.config_ini_section, {}))
    section["sqlalchemy.url"] = resolve_database_url()
    connectable = engine_from_config(section, prefix="sqlalchemy.", poolclass=pool.NullPool)
    try:
        with connectable.connect() as connection:
            _run_with_connection(connection)
    finally:
        connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
