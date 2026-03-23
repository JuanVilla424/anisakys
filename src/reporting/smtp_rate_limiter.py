"""
SMTP send rate limiter for Anisakys.

Enforces a global per-hour cap on outbound abuse report emails to prevent
the SMTP server from being blacklisted due to high sending volume.

Uses a sliding window algorithm: only emails sent in the last 3600 seconds
count toward the limit, so the window rolls continuously rather than
resetting at a fixed hour boundary.
"""

import threading
import time
from collections import deque


class SmtpRateLimiter:
    """Thread-safe sliding-window rate limiter for SMTP sends."""

    def __init__(self, max_per_hour: int) -> None:
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
        cutoff = now - 3600
        while self._timestamps and self._timestamps[0] <= cutoff:
            self._timestamps.popleft()
