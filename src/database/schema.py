"""Schema version guard backed by Alembic.

The application never runs DDL. Alembic (``alembic/versions``) is the single
definition of the schema, and every process checks at startup that the
database it connects to is at the latest revision shipped with the code.

Typical use::

    from src.database.schema import ensure_schema_is_current

    ensure_schema_is_current(engine)  # raises if `alembic upgrade head` is due
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import FrozenSet, Optional, Set, Tuple

from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from alembic.util.exc import CommandError
from sqlalchemy.engine import Engine

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
ALEMBIC_INI = PROJECT_ROOT / "alembic.ini"
ALEMBIC_SCRIPT_LOCATION = PROJECT_ROOT / "alembic"

BEHIND_MESSAGE = "Database schema is behind; run `alembic upgrade head`"

_verified_lock = threading.Lock()
_verified: Set[Tuple[str, FrozenSet[str]]] = set()


def get_alembic_config(database_url: Optional[str] = None) -> Config:
    """Build an Alembic config that works regardless of the current directory.

    Args:
        database_url: URL to migrate. When omitted, ``alembic/env.py`` resolves
            it from ``DATABASE_URL`` or the active env file.

    Returns:
        A ready-to-use :class:`alembic.config.Config`.
    """
    cfg = Config(str(ALEMBIC_INI))
    cfg.set_main_option("script_location", str(ALEMBIC_SCRIPT_LOCATION))
    if database_url:
        # ConfigParser interpolation treats '%' specially (URL-encoded passwords).
        cfg.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
    return cfg


def get_head_revisions() -> FrozenSet[str]:
    """Return the head revision(s) of the migration scripts shipped with the code.

    Returns:
        The set of head revision ids (one unless the history has branched).
    """
    script = ScriptDirectory.from_config(get_alembic_config())
    return frozenset(script.get_heads())


def _is_known_revision(script: ScriptDirectory, revision: str) -> bool:
    """Tell whether a revision id exists in the shipped migration scripts.

    Args:
        script: The migration script directory.
        revision: Revision id read from the database.

    Returns:
        True if the scripts define the revision.
    """
    try:
        return script.get_revision(revision) is not None
    except CommandError:
        return False


def get_current_revisions(engine: Engine) -> FrozenSet[str]:
    """Return the revision(s) recorded in the database's ``alembic_version``.

    Args:
        engine: Engine connected to the database to inspect.

    Returns:
        The recorded revisions; empty when Alembic never ran on the database.
    """
    with engine.connect() as conn:
        return frozenset(MigrationContext.configure(conn).get_current_heads())


def ensure_schema_is_current(engine: Engine) -> None:
    """Fail fast unless the database is at the latest Alembic revision.

    The result is cached per database URL for the life of the process, so
    calling it from several constructors costs one query at most.

    Args:
        engine: Engine connected to the application database.

    Raises:
        RuntimeError: If the database is behind the code (``alembic upgrade
            head`` is due) or at a revision this code does not know (the code
            is older than the database).
    """
    heads = get_head_revisions()
    cache_key = (engine.url.render_as_string(hide_password=True), heads)
    with _verified_lock:
        if cache_key in _verified:
            return

    current = get_current_revisions(engine)
    if current == heads:
        with _verified_lock:
            _verified.add(cache_key)
        logger.debug("Database schema is current (revision %s)", ", ".join(sorted(heads)))
        return

    script = ScriptDirectory.from_config(get_alembic_config())
    unknown = sorted(rev for rev in current if not _is_known_revision(script, rev))
    if unknown:
        raise RuntimeError(
            f"Database schema is at revision {', '.join(unknown)}, which this code does "
            f"not know (latest known: {', '.join(sorted(heads))}); deploy the matching "
            "release instead of downgrading the database"
        )

    found = ", ".join(sorted(current)) or "none (alembic_version missing)"
    raise RuntimeError(f"{BEHIND_MESSAGE} (database: {found}; code: {', '.join(sorted(heads))})")


def reset_schema_check_cache() -> None:
    """Forget previous successful checks (for tests and long-lived tools)."""
    with _verified_lock:
        _verified.clear()
