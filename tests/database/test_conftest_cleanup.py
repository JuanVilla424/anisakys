"""Regression test for the shared test-record cleanup helper in conftest."""

from __future__ import annotations

import uuid

from sqlalchemy import text

from tests.conftest import cleanup_specific_records


def test_cleanup_removes_tracked_registrar_rows(db_engine):
    """Regression: cleanup queried a non-existent `registrar` column and crashed."""
    name = f"test-registrar-{uuid.uuid4().hex[:8]}"
    with db_engine.begin() as conn:
        conn.execute(
            text("INSERT INTO registrar_abuse (registrar_name, abuse_emails) VALUES (:n, 'a@b')"),
            {"n": name},
        )

    cleanup_specific_records(db_engine, {"registrar_abuse": [name]})

    with db_engine.connect() as conn:
        remaining = conn.execute(
            text("SELECT COUNT(*) FROM registrar_abuse WHERE registrar_name = :n"), {"n": name}
        ).scalar_one()
    assert remaining == 0
