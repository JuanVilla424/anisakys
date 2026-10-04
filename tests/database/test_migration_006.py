"""Tests for alembic/versions/006_analyst_labels.py (run as raw SQL)."""

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from src.database.manager import DATABASE_URL
from tests.support.isolated_schema import isolated_schema, load_migration, run_upgrade

MIGRATION = "006_analyst_labels.py"
SCHEMA = ("001_baseline_schema.py", MIGRATION)


def _site_columns(conn):
    rows = conn.execute(
        text(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_schema = current_schema() AND table_name = 'phishing_sites'"
        )
    ).fetchall()
    return {r[0] for r in rows}


def _has_labels_table(conn):
    return (
        conn.execute(
            text(
                "SELECT 1 FROM information_schema.tables WHERE table_schema = current_schema()"
                " AND table_name = 'labels'"
            )
        ).first()
        is not None
    )


def _site(conn, url="https://m.example/"):
    return conn.execute(
        text("INSERT INTO phishing_sites (url) VALUES (:u) RETURNING id"), {"u": url}
    ).scalar_one()


def test_revision_chain():
    module = load_migration(MIGRATION)
    assert module.revision == "006"
    assert module.down_revision == "005"


def test_upgrade_is_idempotent_and_adds_label_columns():
    with isolated_schema(DATABASE_URL, SCHEMA) as (engine, _):
        with engine.begin() as conn:
            run_upgrade(conn, MIGRATION)  # second run must be a no-op
            assert {
                "label_verdict",
                "labeled_at",
                "approval_requested_at",
                "approval_requested_by",
            } <= _site_columns(conn)
            assert _has_labels_table(conn)
            site_id = _site(conn)
            conn.execute(
                text(
                    "INSERT INTO labels (site_id, url, registrable_domain, verdict, action) "
                    "VALUES (:s, 'https://m.example/', 'm.example', 'phishing', 'confirm')"
                ),
                {"s": site_id},
            )
            row = conn.execute(text("SELECT detector_snapshot, created_at FROM labels")).one()
            assert row[0] == {}
            assert row[1] is not None


@pytest.mark.parametrize(
    "verdict,action",
    [("maybe", "confirm"), ("phishing", "approve")],
)
def test_label_checks_reject_unknown_values(verdict, action):
    with isolated_schema(DATABASE_URL, SCHEMA) as (engine, _):
        with pytest.raises(IntegrityError):
            with engine.begin() as conn:
                conn.execute(
                    text(
                        "INSERT INTO labels (url, registrable_domain, verdict, action) "
                        "VALUES ('https://x.example/', 'x.example', :v, :a)"
                    ),
                    {"v": verdict, "a": action},
                )


def test_site_verdict_check_rejects_unknown_values():
    with isolated_schema(DATABASE_URL, SCHEMA) as (engine, _):
        with pytest.raises(IntegrityError):
            with engine.begin() as conn:
                conn.execute(
                    text("INSERT INTO phishing_sites (url, label_verdict) VALUES ('u', 'x')")
                )


def test_labels_survive_site_deletion():
    with isolated_schema(DATABASE_URL, SCHEMA) as (engine, _):
        with engine.begin() as conn:
            site_id = _site(conn)
            conn.execute(
                text(
                    "INSERT INTO labels (site_id, url, registrable_domain, verdict, action) "
                    "VALUES (:s, 'https://m.example/', 'm.example', 'benign', 'dismiss')"
                ),
                {"s": site_id},
            )
            conn.execute(text("DELETE FROM phishing_sites"))
            assert conn.execute(text("SELECT site_id FROM labels")).scalar() is None


def test_downgrade_removes_everything():
    module = load_migration(MIGRATION)
    with isolated_schema(DATABASE_URL, SCHEMA) as (engine, _):
        with engine.begin() as conn:
            for statement in module.DOWNGRADE_STATEMENTS:
                conn.execute(text(statement))
            columns = _site_columns(conn)
            assert not {"label_verdict", "labeled_at", "approval_requested_at"} & columns
            assert not _has_labels_table(conn)
