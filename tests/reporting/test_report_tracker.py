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
