"""
SMTP send rate limiters for Anisakys.

Enforce a per-hour cap on outbound abuse-report e-mails so the relay is not
blacklisted for volume. Both limiters use a sliding window: only sends in the
last 3600 seconds count, so the window rolls continuously instead of resetting
on the hour.

* :class:`DatabaseSmtpRateLimiter` is the one the reporting pipeline uses. The
  window lives in the ``smtp_send_ledger`` table (migration 004) and
  ``acquire()`` serialises on a PostgreSQL advisory lock, so the cap is global
  across every process and thread that shares the database.
* :class:`SmtpRateLimiter` keeps the window in process memory. It is only
  correct for a single process (tools and tests) and is kept for them.

Both expose the same interface: ``acquire() -> bool`` and ``remaining``.
"""

from __future__ import annotations

import threading
import time
from collections import deque

from sqlalchemy import text
from sqlalchemy.engine import Connection, Engine

WINDOW_SECONDS = 3600
DEFAULT_BUCKET = "smtp"
# Ledger rows older than this many windows are pruned during acquire().
_LEDGER_RETENTION_WINDOWS = 24


class SmtpRateLimiter:
    """Thread-safe, in-process sliding-window rate limiter for SMTP sends."""

    def __init__(self, max_per_hour: int) -> None:
        """Create a limiter.

        Args:
            max_per_hour: Maximum number of sends in any rolling hour.
        """
        self._max = max_per_hour
        self._timestamps: deque = deque()
        self._lock = threading.Lock()

    def acquire(self) -> bool:
        """
        Attempt to acquire a send slot.

        Returns True if the send is allowed (slot consumed), False if the
        hourly limit has been reached.
        """
        now = time.time()
        with self._lock:
            self._purge(now)
            if len(self._timestamps) >= self._max:
                return False
            self._timestamps.append(now)
            return True

    @property
    def remaining(self) -> int:
        """Number of sends still allowed in the current sliding window."""
        now = time.time()
        with self._lock:
            self._purge(now)
            return max(0, self._max - len(self._timestamps))

    def _purge(self, now: float) -> None:
        """Remove timestamps older than 1 hour. Must be called with lock held."""
        cutoff = now - WINDOW_SECONDS
        while self._timestamps and self._timestamps[0] <= cutoff:
            self._timestamps.popleft()


class DatabaseSmtpRateLimiter:
    """Sliding-window SMTP rate limiter shared by every process on one database.

    Each granted slot is a row in ``smtp_send_ledger``. ``acquire()`` takes a
    transaction-scoped advisory lock keyed on the bucket, counts the rows of
    the window and inserts a new one only when under the cap, so two processes
    can never both take the last slot.
    """

    def __init__(
        self,
        engine: Engine,
        max_per_hour: int,
        bucket: str = DEFAULT_BUCKET,
        window_seconds: int = WINDOW_SECONDS,
    ) -> None:
        """Create a limiter bound to ``engine``.

        Args:
            engine: Engine of the database holding ``smtp_send_ledger``.
            max_per_hour: Maximum number of sends in any rolling window.
            bucket: Ledger partition; processes sharing a relay share a bucket.
            window_seconds: Window length (one hour unless overridden in tests).
        """
        self._engine = engine
        self._max = max_per_hour
        self._bucket = bucket
        self._window = window_seconds

    def acquire(self) -> bool:
        """Consume one send slot if the shared cap allows it.

        Returns:
            ``True`` when a slot was granted (and recorded), ``False`` when the
            cap is reached.

        Raises:
            sqlalchemy.exc.SQLAlchemyError: When the ledger cannot be read or
                written; callers must treat that as a failed send attempt.
        """
        from src.reporting.db import short_transaction

        with short_transaction(self._engine) as conn:
            conn.execute(
                text("SELECT pg_advisory_xact_lock(hashtext(:key))"),
                {"key": f"anisakys.smtp_rate.{self._bucket}"},
            )
            if self._count(conn) >= self._max:
                return False
            conn.execute(
                text("INSERT INTO smtp_send_ledger (bucket) VALUES (:bucket)"),
                {"bucket": self._bucket},
            )
            conn.execute(
                text(
                    "DELETE FROM smtp_send_ledger WHERE bucket = :bucket "
                    "AND acquired_at < now() - make_interval(secs => :retention)"
                ),
                {"bucket": self._bucket, "retention": self._window * _LEDGER_RETENTION_WINDOWS},
            )
            return True

    @property
    def remaining(self) -> int:
        """Number of sends still allowed in the current window, across processes.

        Returns:
            The remaining slot count (never negative).
        """
        from src.reporting.db import short_transaction

        with short_transaction(self._engine) as conn:
            return max(0, self._max - self._count(conn))

    def _count(self, conn: Connection) -> int:
        """Count this bucket's ledger rows inside the window.

        Args:
            conn: Open connection.

        Returns:
            Number of slots used in the rolling window.
        """
        used = conn.execute(
            text(
                "SELECT count(*) FROM smtp_send_ledger WHERE bucket = :bucket "
                "AND acquired_at > now() - make_interval(secs => :window)"
            ),
            {"bucket": self._bucket, "window": self._window},
        ).scalar()
        return int(used or 0)
