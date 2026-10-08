"""
POST /api/v1/report persists synchronously and leaves the slow abuse-contact
lookup (WHOIS) and the immediate abuse report to a background thread, so a slow
lookup can no longer turn a report that was saved into a 503.
"""

import threading
import time
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from src.database.manager import DatabaseManager
from src.reporting.email_detector import EnhancedAbuseEmailDetector

AUTH = {"Authorization": "Bearer test_api_key"}
URL = "https://phish.example/login"


class CapturedThread:
    """Stands in for threading.Thread: records the background task instead of starting it."""

    started = []

    def __init__(self, target=None, args=(), kwargs=None, daemon=None, name=None):
        self.target = target
        self.args = args
        self.kwargs = kwargs or {}
        self.daemon = daemon
        self.name = name

    def start(self):
        CapturedThread.started.append(self)

    def run_now(self):
        self.target(*self.args, **self.kwargs)


@pytest.fixture
def api():
    """PhishingAPI with mocked DB, detector and report manager (same pattern as test_phishing_api)."""
    CapturedThread.started = []
    with (
        patch("src.api.phishing_api.GrinderReportClient") as mock_grinder,
        patch("src.api.phishing_api.MultiAPIValidator"),
        patch("src.api.phishing_api.GRINDER_INTEGRATION_ENABLED", False),
        # Keep the SSRF guard offline: no DNS lookups for the test URL.
        patch("src.api.phishing_api.assess_url_target", return_value="public"),
        # Keep the process-wide shutdown registry clean; tests inspect the mock.
        patch("src.api.phishing_api.register_thread") as register,
    ):
        mock_grinder.return_value.test_connection.return_value = {"status": "success"}
        from src.api.phishing_api import PhishingAPI

        db = MagicMock(spec=DatabaseManager)
        db.engine = MagicMock()
        detector = MagicMock(spec=EnhancedAbuseEmailDetector)
        instance = PhishingAPI(db, detector, api_key="test_api_key", report_manager=MagicMock())
        instance.app.config["TESTING"] = True
        instance.register_thread_mock = register  # type: ignore[attr-defined]
        yield instance


def db_conn(api):
    return api.db_manager.engine.begin.return_value.__enter__.return_value


def capture_background_threads():
    """Swap only phishing_api's view of the threading module, not the real one."""
    return patch("src.api.phishing_api.threading", SimpleNamespace(Thread=CapturedThread))


def post_report(api, body=None):
    return api.app.test_client().post("/api/v1/report", json=body or {"url": URL}, headers=AUTH)


def test_new_report_is_saved_without_waiting_for_whois(api):
    db_conn(api).execute.return_value.fetchone.return_value = None

    with capture_background_threads():
        response = post_report(api)

    assert response.status_code == 200
    body = response.get_json()
    assert body["status"] == "created"
    assert body["processing"] == "queued"
    api.abuse_detector.get_enhanced_whois_info.assert_not_called()
    assert len(CapturedThread.started) == 1
    # Registered with src.shutdown so a graceful shutdown joins it.
    api.register_thread_mock.assert_called_once_with(CapturedThread.started[0])


def test_background_task_resolves_contacts_and_sends_report(api):
    conn = db_conn(api)
    conn.execute.return_value.fetchone.return_value = None
    api.abuse_detector.get_enhanced_abuse_email.return_value = ["abuse@registrar.example"]
    api.report_manager.send_abuse_report.return_value = True

    with capture_background_threads():
        post_report(api)
    CapturedThread.started[0].run_now()

    api.abuse_detector.get_enhanced_whois_info.assert_called_once_with("phish.example")
    api.report_manager.send_abuse_report.assert_called_once()
    assert api.report_manager.send_abuse_report.call_args.args[0] == ["abuse@registrar.example"]
    statements = [str(call.args[0]) for call in conn.execute.call_args_list]
    assert any("all_abuse_emails = COALESCE" in sql for sql in statements)
    # send_abuse_report marks the site itself, inside its outbox transaction.
    assert not any("abuse_report_sent = 1" in sql for sql in statements)


def test_skipped_report_is_not_an_error_and_writes_nothing(api, caplog):
    """False means claimed elsewhere or inside the resend cool-down."""
    conn = db_conn(api)
    conn.execute.return_value.fetchone.return_value = ("abuse@x.example", "abuse@x.example", False)
    api.report_manager.send_abuse_report.return_value = False

    with capture_background_threads():
        post_report(api)
    calls_before = conn.execute.call_count
    with caplog.at_level("INFO"):
        CapturedThread.started[0].run_now()

    assert api.report_manager.send_abuse_report.call_count == 1
    assert conn.execute.call_count == calls_before
    assert "not sent now" in caplog.text
    assert not [r for r in caplog.records if r.levelname == "ERROR"]


def test_without_report_manager_the_scheduler_role_does_the_work(api):
    """The gunicorn API role has no report manager: no WHOIS thread is started."""
    api.report_manager = None
    db_conn(api).execute.return_value.fetchone.return_value = None

    with capture_background_threads():
        response = post_report(api)

    assert response.status_code == 200
    assert response.get_json()["processing"] == "scheduled"
    assert CapturedThread.started == []
    api.register_thread_mock.assert_not_called()
    api.abuse_detector.get_enhanced_whois_info.assert_not_called()


def test_already_reported_site_without_report_manager_is_done(api):
    api.report_manager = None
    db_conn(api).execute.return_value.fetchone.return_value = ("a@x.example", "a@x.example", True)

    with capture_background_threads():
        response = post_report(api)

    assert response.get_json()["processing"] == "done"
    assert CapturedThread.started == []


def test_slow_whois_does_not_delay_the_response(api):
    db_conn(api).execute.return_value.fetchone.return_value = None
    release = threading.Event()
    api.abuse_detector.get_enhanced_whois_info.side_effect = lambda _domain: release.wait(5)

    started = time.monotonic()
    response = post_report(api)
    elapsed = time.monotonic() - started
    release.set()

    assert response.status_code == 200
    assert elapsed < 2


def test_database_error_returns_500(api):
    api.db_manager.engine.begin.side_effect = RuntimeError("db down")

    response = post_report(api)

    assert response.status_code == 500
    assert response.get_json()["status"] == "error"
