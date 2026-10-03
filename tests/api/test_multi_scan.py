"""Tests for POST /api/v1/multi-scan persistence and report-status read-back."""

from contextlib import contextmanager
from typing import Any, Iterator, Optional, cast
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy.exc import ResourceClosedError

from src.reporting.email_detector import EnhancedAbuseEmailDetector

AUTH = {"Authorization": "Bearer test_key"}


class _ClosingConnection:
    """Connection double that, like SQLAlchemy, refuses to execute once closed."""

    def __init__(self) -> None:
        self.closed = False
        self.statements: list[str] = []

    def execute(self, statement: Any, params: Optional[dict] = None) -> MagicMock:
        """Record the statement and return canned rows.

        Args:
            statement: The SQL statement being executed.
            params: Bound parameters (ignored).

        Returns:
            A result double with ``fetchone`` configured per statement.

        Raises:
            ResourceClosedError: If called after the transaction block exited.
        """
        if self.closed:
            raise ResourceClosedError("This Connection is closed")
        sql = str(statement)
        self.statements.append(sql)
        result = MagicMock()
        if "SELECT last_report_sent" in sql:
            result.fetchone.return_value = ("2026-01-01 00:00:00", 1, "abuse@registrar.example")
        else:
            result.fetchone.return_value = None
        return result


class _Engine:
    """Engine double whose ``begin()`` closes the connection on exit."""

    def __init__(self) -> None:
        self.conn = _ClosingConnection()

    @contextmanager
    def begin(self) -> Iterator[_ClosingConnection]:
        """Yield the connection and close it when the block exits.

        Yields:
            The shared connection double.
        """
        try:
            yield self.conn
        finally:
            self.conn.closed = True


@pytest.fixture
def scan_api():
    """PhishingAPI wired to the closing-connection engine double."""
    with (
        patch("src.api.phishing_api.GrinderReportClient"),
        patch("src.api.phishing_api.MultiAPIValidator"),
    ):
        from src.api.phishing_api import PhishingAPI

        db_manager = MagicMock()
        db_manager.engine = _Engine()
        detector = MagicMock(spec=EnhancedAbuseEmailDetector)
        detector.get_enhanced_abuse_email.return_value = ["abuse@registrar.example"]
        api = PhishingAPI(db_manager, detector, api_key="test_key")
        api.app.config["TESTING"] = True
        validator = cast(MagicMock, api.multi_api_validator)  # the class is patched
        validator.comprehensive_scan.return_value = {
            "domain": "phish.example",
            "aggregated_threat_level": "high",
            "confidence_score": 90,
        }
        yield api


def test_multi_scan_returns_report_status_from_the_same_transaction(scan_api):
    with patch("src.api.phishing_api.assess_url_target", return_value="unresolved"):
        resp = scan_api.app.test_client().post(
            "/api/v1/multi-scan",
            json={"url": "https://phish.example/login", "include_screenshot": False},
            headers=AUTH,
        )

    assert resp.status_code == 200
    body = resp.get_json()
    assert body["abuse_report_sent"] is True
    assert body["last_report_sent"] == "2026-01-01 00:00:00"
    statements = scan_api.db_manager.engine.conn.statements
    assert any("INSERT INTO phishing_sites" in sql for sql in statements)
    assert any("SELECT last_report_sent" in sql for sql in statements)
