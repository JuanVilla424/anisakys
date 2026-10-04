"""DatabaseSmtpRateLimiter against the real test PostgreSQL.

The old limiter kept its window in process memory, so the API, scanner and
threads processes each had their own full hourly budget (3x the cap).
"""

from __future__ import annotations

import threading
import uuid

import pytest
from sqlalchemy import create_engine, text

from src import main  # noqa: F401 - seeds sys.modules to break the import cycle
from src.reporting.smtp_rate_limiter import DatabaseSmtpRateLimiter


@pytest.fixture
def bucket(db_engine):
    """A ledger bucket private to one test, removed afterwards."""
    name = f"test-{uuid.uuid4().hex[:12]}"
    yield name
    with db_engine.begin() as conn:
        conn.execute(text("DELETE FROM smtp_send_ledger WHERE bucket = :b"), {"b": name})


def test_cap_is_enforced(db_engine, bucket):
    limiter = DatabaseSmtpRateLimiter(db_engine, max_per_hour=3, bucket=bucket)

    granted = [limiter.acquire() for _ in range(4)]

    assert granted == [True, True, True, False]
    assert limiter.remaining == 0


def test_cap_is_shared_between_processes(create_test_database, bucket):
    """Two limiters with their own engines model two processes."""
    engine_a = create_engine(create_test_database)
    engine_b = create_engine(create_test_database)
    try:
        api_process = DatabaseSmtpRateLimiter(engine_a, max_per_hour=3, bucket=bucket)
        scheduler_process = DatabaseSmtpRateLimiter(engine_b, max_per_hour=3, bucket=bucket)

        assert api_process.acquire() and api_process.acquire()
        assert scheduler_process.acquire()
        assert not scheduler_process.acquire()
        assert not api_process.acquire()
    finally:
        engine_a.dispose()
        engine_b.dispose()


def test_concurrent_acquires_never_exceed_the_cap(create_test_database, bucket):
    engine = create_engine(create_test_database, pool_size=12, max_overflow=0)
    limiter = DatabaseSmtpRateLimiter(engine, max_per_hour=5, bucket=bucket)
    results: list[bool] = []
    lock = threading.Lock()
    start = threading.Barrier(12)

    def worker():
        start.wait()
        granted = limiter.acquire()
        with lock:
            results.append(granted)

    threads = [threading.Thread(target=worker) for _ in range(12)]
    try:
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
    finally:
        engine.dispose()

    assert results.count(True) == 5
    assert results.count(False) == 7


def test_slots_older_than_the_window_do_not_count(db_engine, bucket):
    with db_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO smtp_send_ledger (bucket, acquired_at) "
                "VALUES (:b, now() - interval '2 hours'), (:b, now() - interval '61 minutes')"
            ),
            {"b": bucket},
        )
    limiter = DatabaseSmtpRateLimiter(db_engine, max_per_hour=1, bucket=bucket)

    assert limiter.acquire() is True
    assert limiter.acquire() is False
