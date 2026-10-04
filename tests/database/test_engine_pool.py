"""Tests for the database engine pooling policy (create_db_engine)."""

from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.pool import NullPool, QueuePool

from src.database import manager


def test_default_policy_keeps_no_pooling(monkeypatch, create_test_database):
    monkeypatch.setattr(manager.settings, "DB_POOL_SIZE", 0)

    engine = manager.create_db_engine(create_test_database)
    try:
        assert isinstance(engine.pool, NullPool)
    finally:
        engine.dispose()


def test_positive_pool_size_enables_bounded_pre_pinged_pool(monkeypatch, create_test_database):
    monkeypatch.setattr(manager.settings, "DB_POOL_SIZE", 3)
    monkeypatch.setattr(manager.settings, "DB_MAX_OVERFLOW", 2)

    engine = manager.create_db_engine(create_test_database)
    try:
        assert isinstance(engine.pool, QueuePool)
        assert engine.pool.size() == 3
        assert engine.pool._max_overflow == 2
        assert engine.pool._pre_ping is True
        with engine.connect() as conn:
            assert conn.execute(text("SELECT 1")).scalar_one() == 1
        assert engine.pool.checkedin() == 1, "the connection is reused, not closed"
    finally:
        engine.dispose()


def test_forked_children_drop_inherited_pooled_connections(monkeypatch, create_test_database):
    monkeypatch.setattr(manager.settings, "DB_POOL_SIZE", 2)
    engine = manager.create_db_engine(create_test_database)
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        parent_pool = engine.pool
        assert isinstance(parent_pool, QueuePool) and parent_pool.checkedin() == 1

        manager._forget_inherited_connections()  # what os.register_at_fork runs in a child

        child_pool = engine.pool
        assert child_pool is not parent_pool
        assert isinstance(child_pool, QueuePool) and child_pool.checkedin() == 0
    finally:
        engine.dispose()
