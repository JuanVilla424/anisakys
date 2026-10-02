"""
Tests for src/reporting/smtp_rate_limiter.py
"""

import importlib.util
import threading
import time
from pathlib import Path
from unittest.mock import patch

import pytest

# Import directly by file path to avoid triggering src/reporting/__init__.py
# which has a pre-existing circular import via src.intelligence ↔ src.detection.
_spec = importlib.util.spec_from_file_location(
    "smtp_rate_limiter",
    Path(__file__).parent.parent / "src" / "reporting" / "smtp_rate_limiter.py",
)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
SmtpRateLimiter = _mod.SmtpRateLimiter


class TestSmtpRateLimiter:
    def test_allows_under_limit(self):
        limiter = SmtpRateLimiter(max_per_hour=10)
        for _ in range(5):
            assert limiter.acquire() is True

    def test_blocks_over_limit(self):
        limiter = SmtpRateLimiter(max_per_hour=3)
        assert limiter.acquire() is True
        assert limiter.acquire() is True
        assert limiter.acquire() is True
        assert limiter.acquire() is False

    def test_remaining_decrements(self):
        limiter = SmtpRateLimiter(max_per_hour=5)
        assert limiter.remaining == 5
        limiter.acquire()
        assert limiter.remaining == 4
        limiter.acquire()
        assert limiter.remaining == 3

    def test_remaining_zero_when_full(self):
        limiter = SmtpRateLimiter(max_per_hour=2)
        limiter.acquire()
        limiter.acquire()
        assert limiter.remaining == 0

    def test_sliding_window_expires(self):
        limiter = SmtpRateLimiter(max_per_hour=2)
        limiter.acquire()
        limiter.acquire()
        assert limiter.acquire() is False

        # Simulate 1 hour + 1 second passing
        future = time.time() + 3601
        with patch.object(_mod, "time") as mock_time:
            mock_time.time.return_value = future
            # Purge is triggered by acquire / remaining
            assert limiter.remaining == 2
            assert limiter.acquire() is True

    def test_thread_safety(self):
        max_per_hour = 50
        limiter = SmtpRateLimiter(max_per_hour=max_per_hour)
        results = []
        lock = threading.Lock()

        def worker():
            result = limiter.acquire()
            with lock:
                results.append(result)

        threads = [threading.Thread(target=worker) for _ in range(100)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        allowed = sum(1 for r in results if r is True)
        blocked = sum(1 for r in results if r is False)
        assert allowed == max_per_hour
        assert blocked == 100 - max_per_hour
