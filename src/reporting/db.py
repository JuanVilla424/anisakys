"""Short, bounded database transactions for the reporting pipeline.

Every reporting write goes through :func:`short_transaction`: the transaction
gets its own ``statement_timeout`` and ``lock_timeout`` (``SET LOCAL``
semantics via ``set_config(..., true)``), so a stuck lock or a slow query
fails fast instead of pinning a worker, and nothing outlives the ``with``
block. Network I/O (WHOIS, DNS, SMTP, screenshots) must never run inside one.
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Callable, Iterator, Optional

from sqlalchemy import text
from sqlalchemy.engine import Connection, Engine

from src.config import settings

Clock = Callable[[], datetime]


def utc_now() -> datetime:
    """Return the current time as an aware UTC datetime.

    Returns:
        ``datetime.now(timezone.utc)``.
    """
    return datetime.now(timezone.utc)


@contextmanager
def short_transaction(
    engine: Engine,
    statement_timeout_ms: Optional[int] = None,
    lock_timeout_ms: Optional[int] = None,
) -> Iterator[Connection]:
    """Open a transaction with per-transaction statement and lock timeouts.

    Args:
        engine: SQLAlchemy engine to borrow a connection from.
        statement_timeout_ms: Statement timeout for this transaction only;
            defaults to ``REPORT_DB_STATEMENT_TIMEOUT_MS``.
        lock_timeout_ms: Lock wait timeout for this transaction only;
            defaults to ``REPORT_DB_LOCK_TIMEOUT_MS``.

    Yields:
        The connection, inside an open transaction that commits when the
        block exits normally and rolls back when it raises.

    Raises:
        sqlalchemy.exc.SQLAlchemyError: Propagated from the database.
    """
    statement_ms = statement_timeout_ms or settings.REPORT_DB_STATEMENT_TIMEOUT_MS
    lock_ms = lock_timeout_ms or settings.REPORT_DB_LOCK_TIMEOUT_MS
    with engine.begin() as conn:
        conn.execute(
            text(
                "SELECT set_config('statement_timeout', :statement_ms, true), "
                "set_config('lock_timeout', :lock_ms, true)"
            ),
            {"statement_ms": str(int(statement_ms)), "lock_ms": str(int(lock_ms))},
        )
        yield conn
