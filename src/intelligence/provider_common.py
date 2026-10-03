"""
Shared vocabulary and helpers for threat-intelligence provider clients.

Every provider result carries a ``status`` field with one of four values so
callers never confuse "the provider said nothing" with "the provider said the
URL is clean":

- ``listed``: the provider positively flags the URL/domain;
- ``not_listed``: the provider answered authoritatively and does not flag it
  (for list-only databases such as PhishTank this is the absence of a
  listing, which is not evidence that the URL is clean);
- ``error``: the lookup failed (HTTP error, timeout, unparseable body...);
- ``no_data``: the provider is disabled/unconfigured or has no usable verdict
  (e.g. a VirusTotal analysis that is pending, empty or stale).

Only ``listed`` and ``not_listed`` are answers; ``error`` and ``no_data`` must
never be counted as a clean vote.
"""

from __future__ import annotations

import threading
import time
from typing import Any, Callable, Mapping, Optional

from src.shutdown import wait_for_shutdown

LISTED = "listed"
NOT_LISTED = "not_listed"
ERROR = "error"
NO_DATA = "no_data"

PROVIDER_STATUSES = frozenset({LISTED, NOT_LISTED, ERROR, NO_DATA})


def has_data(result: Optional[Mapping[str, Any]]) -> bool:
    """Tell whether a provider result is usable evidence.

    Args:
        result: A provider result dict (may be ``None`` or empty).

    Returns:
        ``True`` only for ``listed`` and ``not_listed`` results.
    """
    return bool(result) and result.get("status") in (LISTED, NOT_LISTED)  # type: ignore[union-attr]


def is_listed(result: Optional[Mapping[str, Any]]) -> bool:
    """Tell whether a provider result positively flags the target.

    Args:
        result: A provider result dict (may be ``None`` or empty).

    Returns:
        ``True`` only when ``status`` is ``listed``.
    """
    return bool(result) and result.get("status") == LISTED  # type: ignore[union-attr]


class TokenBucket:
    """Thread-safe token bucket shared by every client of one rate-limited API.

    Tokens refill continuously at ``rate_per_minute / 60`` per second up to
    ``capacity``. Waiting for a token uses :func:`wait_for_shutdown`, so a stop
    request interrupts it.
    """

    def __init__(
        self,
        rate_per_minute: float,
        capacity: Optional[float] = None,
        clock: Callable[[], float] = time.monotonic,
    ):
        """Create a bucket that starts full.

        Args:
            rate_per_minute: Sustained number of permits per minute (> 0).
            capacity: Maximum burst; defaults to ``rate_per_minute``.
            clock: Monotonic time source (injectable for tests).

        Raises:
            ValueError: If ``rate_per_minute`` is not positive.
        """
        if rate_per_minute <= 0:
            raise ValueError("rate_per_minute must be positive")
        self.rate_per_second = rate_per_minute / 60.0
        self.capacity = float(capacity if capacity is not None else rate_per_minute)
        self._clock = clock
        self._tokens = self.capacity
        self._updated = clock()
        self._lock = threading.Lock()

    def _refill(self) -> None:
        """Add the tokens accrued since the last update. Caller holds the lock."""
        now = self._clock()
        elapsed = max(0.0, now - self._updated)
        self._tokens = min(self.capacity, self._tokens + elapsed * self.rate_per_second)
        self._updated = now

    def try_acquire(self) -> bool:
        """Take one token if available, without waiting.

        Returns:
            ``True`` if a token was taken.
        """
        with self._lock:
            self._refill()
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return True
            return False

    def acquire(self, max_wait: float) -> bool:
        """Take one token, waiting up to ``max_wait`` seconds for a refill.

        Args:
            max_wait: Maximum number of seconds to wait.

        Returns:
            ``True`` if a token was taken; ``False`` on timeout or shutdown.
        """
        deadline = self._clock() + max(0.0, max_wait)
        while True:
            with self._lock:
                self._refill()
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return True
                needed = (1.0 - self._tokens) / self.rate_per_second
            remaining = deadline - self._clock()
            if needed > remaining:
                return False
            if wait_for_shutdown(needed):
                return False
