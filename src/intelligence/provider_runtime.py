"""Shared provider runtime: one TTL cache and one token bucket per provider, per process.

Every ``MultiAPIValidator`` of a process (API, scheduler, scanner, evaluation) goes
through the same cache and rate limits, so two code paths scanning the same URL within the
TTL make one provider call, and a provider's free-tier quota (VirusTotal public: 4 requests
per minute) is respected by the whole process instead of per instance.

* Only answers are cached (``listed``/``not_listed`` and WHOIS data); errors, missing data
  and rate-limited results are retried on the next scan.
* A call that cannot get a token within ``wait_seconds`` returns a ``no_data`` result
  marked ``rate_limited`` instead of blocking the scan.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from typing import Any, Callable, Dict, Hashable, Optional, Tuple

from src.intelligence.provider_common import LISTED, NO_DATA, NOT_LISTED

# Seconds an answer stays valid, by stage.
DEFAULT_TTL_SECONDS: Dict[str, int] = {
    "virustotal_url": 6 * 3600,
    "virustotal_domain": 12 * 3600,
    "urlvoid": 12 * 3600,
    "phishtank": 3600,
    "google_safe_browsing": 1800,
    "whois": 24 * 3600,
}
# Requests per minute, by stage (free tiers; the settings below change them). WHOIS
# queries go to each suffix's own registry server, so one process-wide budget can be
# generous; a scan waits up to WHOIS_WAIT_SECONDS for it (see multi_api_validator).
DEFAULT_RATE_PER_MINUTE: Dict[str, float] = {
    "virustotal_url": 4,
    "virustotal_domain": 4,
    "urlvoid": 30,
    "phishtank": 30,
    "google_safe_browsing": 300,
    "whois": 120,
    # The LLM judge (src/detection/llm_judge.py): a coding-agent-like pace for gateways.
    "llm_judge": 20,
}
RATE_SETTINGS = {
    "virustotal_url": "VIRUSTOTAL_REQUESTS_PER_MINUTE",
    "virustotal_domain": "VIRUSTOTAL_REQUESTS_PER_MINUTE",
    "urlvoid": "URLVOID_REQUESTS_PER_MINUTE",
    "phishtank": "PHISHTANK_REQUESTS_PER_MINUTE",
    "google_safe_browsing": "GSB_REQUESTS_PER_MINUTE",
    "whois": "WHOIS_REQUESTS_PER_MINUTE",
    "llm_judge": "LLM_JUDGE_REQUESTS_PER_MINUTE",
}


class TTLCache:
    """Thread-safe LRU cache whose entries expire."""

    def __init__(self, maxsize: int = 10_000, clock: Callable[[], float] = time.monotonic) -> None:
        """Create a cache.

        Args:
            maxsize: Entries kept (least recently used dropped first).
            clock: Monotonic seconds (tests).
        """
        self._data: "OrderedDict[Hashable, Tuple[float, Any]]" = OrderedDict()
        self._lock = threading.Lock()
        self._maxsize = maxsize
        self._clock = clock

    def get(self, key: Hashable) -> Optional[Any]:
        """A live entry, or ``None``.

        Args:
            key: Cache key.

        Returns:
            The value, or ``None`` when missing or expired.
        """
        with self._lock:
            entry = self._data.get(key)
            if entry is None:
                return None
            expires, value = entry
            if self._clock() >= expires:
                del self._data[key]
                return None
            self._data.move_to_end(key)
            return value

    def set(self, key: Hashable, value: Any, ttl: float) -> None:
        """Store a value for ``ttl`` seconds.

        Args:
            key: Cache key.
            value: Value.
            ttl: Lifetime in seconds.
        """
        with self._lock:
            self._data[key] = (self._clock() + ttl, value)
            self._data.move_to_end(key)
            while len(self._data) > self._maxsize:
                self._data.popitem(last=False)

    def clear(self) -> None:
        """Drop every entry."""
        with self._lock:
            self._data.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._data)


class TokenBucket:
    """Thread-safe token bucket (``rate_per_minute`` tokens, refilled continuously)."""

    def __init__(
        self,
        rate_per_minute: float,
        burst: Optional[float] = None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        """Create a full bucket.

        Args:
            rate_per_minute: Sustained requests per minute (0 or less = unlimited).
            burst: Bucket size (default: one minute of tokens, at least 1).
            clock: Monotonic seconds (tests).
            sleep: Sleep function (tests).
        """
        self.rate = float(rate_per_minute) / 60.0
        self.capacity = float(burst if burst is not None else max(1.0, rate_per_minute))
        self._tokens = self.capacity
        self._updated = clock()
        self._clock = clock
        self._sleep = sleep
        self._lock = threading.Lock()

    def _refill(self) -> None:
        now = self._clock()
        self._tokens = min(self.capacity, self._tokens + (now - self._updated) * self.rate)
        self._updated = now

    def acquire(self, wait_seconds: float = 0.0) -> bool:
        """Take one token, waiting up to ``wait_seconds`` for it.

        Args:
            wait_seconds: Longest wait.

        Returns:
            ``True`` when a token was taken.
        """
        if self.rate <= 0:
            return True
        deadline = self._clock() + max(0.0, wait_seconds)
        while True:
            with self._lock:
                self._refill()
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return True
                missing = (1.0 - self._tokens) / self.rate
            if self._clock() + missing > deadline:
                return False
            self._sleep(min(missing, max(0.0, deadline - self._clock())))


_cache = TTLCache()
_buckets: Dict[str, TokenBucket] = {}
_buckets_lock = threading.Lock()


def _rate_for(stage: str) -> float:
    try:
        from src.config import settings

        configured = getattr(settings, RATE_SETTINGS.get(stage, ""), None)
    except Exception:  # pylint: disable=broad-except
        configured = None
    return float(configured) if configured is not None else DEFAULT_RATE_PER_MINUTE.get(stage, 0)


def bucket(stage: str) -> TokenBucket:
    """The process-wide token bucket of a stage.

    Args:
        stage: Stage name (``virustotal_url``...).

    Returns:
        The bucket (created on first use).
    """
    with _buckets_lock:
        if stage not in _buckets:
            _buckets[stage] = TokenBucket(_rate_for(stage))
        return _buckets[stage]


def _is_answer(result: Any) -> bool:
    if not isinstance(result, dict) or not result:
        return False
    status = result.get("status")
    if status is not None:
        return status in (LISTED, NOT_LISTED)
    return not result.get("error")


def cached_call(
    stage: str,
    key: Hashable,
    fn: Callable[..., Any],
    *args: Any,
    wait_seconds: float = 5.0,
    ttl: Optional[float] = None,
) -> Tuple[Any, bool]:
    """Call a provider through the shared cache and its rate limit.

    Args:
        stage: Stage name.
        key: Cache key (normalised URL or domain).
        fn: Provider call.
        *args: Its arguments.
        wait_seconds: Longest wait for a rate-limit token.
        ttl: Lifetime of an answer (default: :data:`DEFAULT_TTL_SECONDS`).

    Returns:
        ``(result, from_cache)``.
    """
    cached = _cache.get((stage, key))
    if cached is not None:
        return cached, True
    if not bucket(stage).acquire(wait_seconds):
        return {"status": NO_DATA, "error": "rate limited", "rate_limited": True}, False
    result = fn(*args)
    if _is_answer(result):
        _cache.set(
            (stage, key), result, ttl if ttl is not None else DEFAULT_TTL_SECONDS.get(stage, 600)
        )
    return result, False


def reset() -> None:
    """Empty the shared cache and forget the buckets (tests, configuration reload)."""
    _cache.clear()
    with _buckets_lock:
        _buckets.clear()
