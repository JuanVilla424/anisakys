"""Tests for src/reporting/report_tracker.py."""

from __future__ import annotations

from unittest.mock import MagicMock

from src import main  # noqa: F401 - seeds sys.modules to break the import cycle
from src.reporting.report_tracker import ReportTracker, create_report_record

_DDL_KEYWORDS = ("DROP ", "CREATE ", "ALTER ", "TRUNCATE ", "RENAME ")


def _recording_engine(fail: bool) -> tuple[MagicMock, list[str]]:
    """Engine double that records every SQL statement and can fail them all."""
    statements: list[str] = []
    conn = MagicMock()

    def execute(statement, *args, **kwargs):
        statements.append(str(statement).upper())
        if fail:
            raise RuntimeError("relation abuse_reports does not exist")
        return MagicMock(rowcount=1)

    conn.execute.side_effect = execute
    engine = MagicMock()
    engine.begin.return_value.__enter__.return_value = conn
    engine.connect.return_value.__enter__.return_value = conn
    return engine, statements


class TestNoRuntimeDDL:
    """ReportTracker used to repair its table at runtime: on any error it ran
    ``DROP TABLE IF EXISTS abuse_reports CASCADE`` and recreated a six-column
    table, destroying the report history."""

    def test_constructor_issues_no_sql(self):
        engine, statements = _recording_engine(fail=True)

        ReportTracker(engine)

        assert statements == []

    def test_failing_database_never_triggers_ddl(self):
        engine, statements = _recording_engine(fail=True)
        tracker = ReportTracker(engine)
        report = create_report_record("https://phish.example", ["abuse@reg.example"], "s")

        assert tracker.track_report(report) is False
        tracker.update_report_status(report.report_id, MagicMock(value="resolved"))
        tracker.get_overdue_reports()
        tracker.mark_report_for_followup(report.report_id)

        assert statements, "the tracker should have tried to talk to the database"
        assert not [s for s in statements if s.lstrip().startswith(_DDL_KEYWORDS)]


class TestAppendOnlyTracking:
    """track_report() looked up the latest row of the site and overwrote it, so
    a new report replaced the previous one (and its SLA/follow-up history)."""

    def test_new_report_for_same_site_adds_a_row(self, db_engine):
        from tests.reporting.pipeline_support import cleanup_sites, insert_site, make_site_url

        url = make_site_url("append")
        insert_site(db_engine, url)
        tracker = ReportTracker(db_engine)
        first = create_report_record(url, ["abuse@reg.example"], "first")
        second = create_report_record(url, ["abuse@reg.example"], "second")
        try:
            assert tracker.track_report(first) and tracker.track_report(second)
            rows = tracker.get_reports_by_site(url)
        finally:
            cleanup_sites(db_engine)

        assert {row["report_id"] for row in rows} == {first.report_id, second.report_id}
        assert {row["subject"] for row in rows} == {"first", "second"}


class TestFollowupDeadline:
    """mark_report_for_followup() never moved sla_deadline, so every overdue
    check would follow the same report up again."""

    def test_marking_a_follow_up_advances_the_deadline(self, db_engine):
        from datetime import datetime, timedelta, timezone

        from tests.reporting.pipeline_support import cleanup_sites, insert_site, make_site_url

        url = make_site_url("deadline")
        insert_site(db_engine, url)
        tracker = ReportTracker(db_engine)
        sent_at = datetime(2026, 10, 5, 10, 0, tzinfo=timezone.utc)
        report = create_report_record(url, ["abuse@reg.example"], "s")
        report.report_date = sent_at
        report.sla_deadline = sent_at + timedelta(days=2)
        now = sent_at + timedelta(days=3)
        try:
            tracker.track_report(report)
            assert [r["report_id"] for r in tracker.get_overdue_reports(now=now)] == [
                report.report_id
            ]

            assert tracker.mark_report_for_followup(report.report_id, now=now, interval_hours=48)

            assert tracker.get_overdue_reports(now=now) == []
            later = now + timedelta(hours=49)
            assert [r["report_id"] for r in tracker.get_overdue_reports(now=later)] == [
                report.report_id
            ]
        finally:
            cleanup_sites(db_engine)

    def test_only_the_newest_report_of_a_site_is_followed_up(self, db_engine):
        from datetime import datetime, timedelta, timezone

        from tests.reporting.pipeline_support import cleanup_sites, insert_site, make_site_url

        url = make_site_url("newest")
        insert_site(db_engine, url)
        tracker = ReportTracker(db_engine)
        sent_at = datetime(2026, 10, 5, 10, 0, tzinfo=timezone.utc)
        older = create_report_record(url, ["abuse@reg.example"], "old")
        newer = create_report_record(url, ["abuse@reg.example"], "new")
        for record in (older, newer):
            record.report_date = sent_at
            record.sla_deadline = sent_at + timedelta(days=2)
        try:
            tracker.track_report(older)
            tracker.track_report(newer)
            overdue = tracker.get_overdue_reports(now=sent_at + timedelta(days=3))
        finally:
            cleanup_sites(db_engine)

        assert [r["report_id"] for r in overdue] == [newer.report_id]
