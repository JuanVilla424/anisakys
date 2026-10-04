"""Tests for src/intelligence/provider_common.py."""

from unittest.mock import patch

import pytest

from src.intelligence import provider_common as pc


class TestStatusHelpers:
    @pytest.mark.parametrize(
        "result, expected",
        [
            ({"status": "listed"}, True),
            ({"status": "not_listed"}, True),
            ({"status": "error"}, False),
            ({"status": "no_data"}, False),
            ({}, False),
            (None, False),
            ({"error": "boom"}, False),
        ],
    )
    def test_has_data(self, result, expected):
        assert pc.has_data(result) is expected

    def test_is_listed(self):
        assert pc.is_listed({"status": "listed"})
        assert not pc.is_listed({"status": "not_listed"})
        assert not pc.is_listed(None)


class FakeClock:
    """Deterministic monotonic clock."""

    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


class TestTokenBucket:
    def test_rejects_non_positive_rate(self):
        with pytest.raises(ValueError):
            pc.TokenBucket(0)

    def test_burst_then_empty(self):
        clock = FakeClock()
        bucket = pc.TokenBucket(4, clock=clock)
        assert all(bucket.try_acquire() for _ in range(4))
        assert bucket.try_acquire() is False

    def test_refills_over_time(self):
        clock = FakeClock()
        bucket = pc.TokenBucket(4, clock=clock)
        for _ in range(4):
            bucket.try_acquire()
        clock.now += 15  # 4/min -> one token every 15 s
        assert bucket.try_acquire() is True
        assert bucket.try_acquire() is False

    def test_acquire_waits_with_shutdown_aware_sleep(self):
        clock = FakeClock()
        bucket = pc.TokenBucket(4, clock=clock)
        for _ in range(4):
            bucket.try_acquire()

        def fake_wait(seconds):
            clock.now += seconds
            return False

        with patch.object(pc, "wait_for_shutdown", side_effect=fake_wait) as wait:
            assert bucket.acquire(max_wait=20) is True
        assert wait.called

    def test_acquire_gives_up_when_wait_exceeds_budget(self):
        clock = FakeClock()
        bucket = pc.TokenBucket(4, clock=clock)
        for _ in range(4):
            bucket.try_acquire()
        with patch.object(pc, "wait_for_shutdown") as wait:
            assert bucket.acquire(max_wait=5) is False
        wait.assert_not_called()

    def test_acquire_stops_on_shutdown(self):
        clock = FakeClock()
        bucket = pc.TokenBucket(4, clock=clock)
        for _ in range(4):
            bucket.try_acquire()
        with patch.object(pc, "wait_for_shutdown", return_value=True):
            assert bucket.acquire(max_wait=60) is False
