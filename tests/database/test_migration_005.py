"""Tests for alembic/versions/005_takedown_status.py (run as raw SQL)."""

from sqlalchemy import text

from src.database.manager import DATABASE_URL
from tests.support.isolated_schema import isolated_schema, load_migration, run_upgrade

MIGRATION = "005_takedown_status.py"


def _columns(conn):
    rows = conn.execute(
        text(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_schema = current_schema() AND table_name = 'phishing_sites'"
        )
    ).fetchall()
    return {r[0] for r in rows}


def _has_events_table(conn):
    return (
        conn.execute(
            text(
                "SELECT 1 FROM information_schema.tables WHERE table_schema = current_schema()"
                " AND table_name = 'site_status_events'"
            )
        ).first()
        is not None
    )


def test_revision_chain():
    module = load_migration(MIGRATION)
    assert module.revision == "005"
    assert module.down_revision == "004"


def test_upgrade_adds_columns_and_events_table_idempotently():
    with isolated_schema(DATABASE_URL, ("001_baseline_schema.py", MIGRATION)) as (engine, _):
        with engine.begin() as conn:
            run_upgrade(conn, MIGRATION)  # second run must be a no-op
            cols = _columns(conn)
            assert {
                "consecutive_failures",
                "consecutive_parked",
                "last_probe_class",
                "last_probe_at",
                "ip_checked_at",
            } <= cols
            assert _has_events_table(conn)
            conn.execute(text("INSERT INTO phishing_sites (url) VALUES ('https://m.example/')"))
            row = conn.execute(
                text("SELECT consecutive_failures, consecutive_parked FROM phishing_sites")
            ).one()
            assert tuple(row) == (0, 0)


def test_events_cascade_on_site_delete():
    with isolated_schema(DATABASE_URL, ("001_baseline_schema.py", MIGRATION)) as (engine, _):
        with engine.begin() as conn:
            site_id = conn.execute(
                text("INSERT INTO phishing_sites (url) VALUES ('https://c.example/') RETURNING id")
            ).scalar_one()
            conn.execute(
                text(
                    "INSERT INTO site_status_events (site_id, site_url, old_status, new_status)"
                    " VALUES (:i, 'https://c.example/', 'up', 'down')"
                ),
                {"i": site_id},
            )
            conn.execute(text("DELETE FROM phishing_sites"))
            assert conn.execute(text("SELECT COUNT(*) FROM site_status_events")).scalar() == 0


def test_downgrade_removes_everything():
    module = load_migration(MIGRATION)
    with isolated_schema(DATABASE_URL, ("001_baseline_schema.py", MIGRATION)) as (engine, _):
        with engine.begin() as conn:
            for statement in module.DOWNGRADE_STATEMENTS:
                conn.execute(text(statement))
            assert "consecutive_failures" not in _columns(conn)
            assert not _has_events_table(conn)
