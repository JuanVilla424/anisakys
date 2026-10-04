"""POST /api/v1/report: report_send scope, analyst approval and SSRF guard."""

import hashlib
import uuid
from contextlib import contextmanager
from typing import Iterator
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import text

from src.reporting.email_detector import EnhancedAbuseEmailDetector

KEY = "ank_report-approval-tests"
HEADERS = {"Authorization": f"Bearer {KEY}"}


@contextmanager
def key_with(scopes: str) -> Iterator[None]:
    """Authenticate requests as a database key holding ``scopes``."""
    row = {
        "scopes": scopes,
        "allowed_ips": None,
        "key_hash": hashlib.sha256(KEY.encode()).hexdigest(),
    }
    with (
        patch("src.auth._lookup_db_key", return_value=row),
        patch("src.auth._update_last_used"),
    ):
        yield


@contextmanager
def target(verdict: str) -> Iterator[MagicMock]:
    """Stub the SSRF guard (no DNS in tests)."""
    with patch("src.api.phishing_api.assess_url_target", return_value=verdict) as guard:
        yield guard


@pytest.fixture
def api():
    """API with mocked DB, report manager and background threads."""
    with (
        patch("src.api.phishing_api.GrinderReportClient"),
        patch("src.api.phishing_api.MultiAPIValidator"),
        patch("src.api.phishing_api.GRINDER_INTEGRATION_ENABLED", False),
        # Tests replace threading with mocks: keep those out of the process-wide
        # shutdown registry, which later tests join.
        patch("src.api.phishing_api.register_thread"),
    ):
        from src.api.phishing_api import PhishingAPI

        instance = PhishingAPI(
            MagicMock(),
            MagicMock(spec=EnhancedAbuseEmailDetector),
            api_key="master",
            report_manager=MagicMock(),
        )
        instance.app.config["TESTING"] = True
        conn = instance.db_manager.engine.begin.return_value.__enter__.return_value
        conn.execute.return_value.fetchone.return_value = None
        yield instance


def _post(api, body=None, headers=HEADERS):
    return api.app.test_client().post(
        "/api/v1/report", json=body or {"url": "https://phish.example/login"}, headers=headers
    )


def _statements(api):
    conn = api.db_manager.engine.begin.return_value.__enter__.return_value
    return [str(c.args[0]) for c in conn.execute.call_args_list]


class TestReportScopeOnly:
    def test_submission_is_recorded_for_approval_not_sent(self, api):
        with key_with("report"), target("public"), patch("src.api.phishing_api.threading") as th:
            resp = _post(api)

        assert resp.status_code == 202
        body = resp.get_json()
        assert body["status"] == "pending_approval"
        assert body["approval_required"] is True
        th.Thread.assert_not_called()
        api.report_manager.send_abuse_report.assert_not_called()
        insert = next(sql for sql in _statements(api) if "INSERT INTO phishing_sites" in sql)
        assert "'awaiting_approval'" in insert
        assert "VALUES (:url, 0," in insert  # manual_flag = 0

    def test_existing_site_is_not_flagged_for_reporting(self, api):
        conn = api.db_manager.engine.begin.return_value.__enter__.return_value
        conn.execute.return_value.fetchone.return_value = (7,)
        with key_with("report"), target("public"):
            resp = _post(api)

        assert resp.status_code == 202
        update = next(sql for sql in _statements(api) if "UPDATE phishing_sites" in sql)
        assert "manual_flag = 1" not in update.replace("WHEN manual_flag = 1", "")
        assert "source" not in update

    def test_gsb_report_needs_report_send(self, api):
        with key_with("report"):
            resp = api.app.test_client().post(
                "/api/v1/gsb/report", json={"url": "https://phish.example/"}, headers=HEADERS
            )

        assert resp.status_code == 403


class TestReportSendScope:
    @pytest.mark.parametrize("scopes", ["report_send", "report,report_send"])
    def test_report_send_keeps_the_immediate_reporting_flow(self, api, scopes):
        with key_with(scopes), target("public"), patch("src.api.phishing_api.threading") as th:
            resp = _post(api)

        assert resp.status_code == 200
        assert resp.get_json()["status"] == "created"
        th.Thread.assert_called_once()
        insert = next(sql for sql in _statements(api) if "INSERT INTO phishing_sites" in sql)
        assert "VALUES (:url, 1," in insert  # manual_flag = 1

    def test_master_key_keeps_the_immediate_reporting_flow(self, api):
        with target("public"), patch("src.api.phishing_api.threading"):
            resp = _post(api, headers={"Authorization": "Bearer master"})

        assert resp.status_code == 200

    def test_report_send_implies_report(self):
        from src.auth import _scope_allowed

        assert _scope_allowed("report_send", "report") is True
        assert _scope_allowed("report", "report_send") is False


class TestSsrfGuard:
    @pytest.mark.parametrize("scopes", ["report", "report_send"])
    def test_non_public_targets_are_refused_before_anything_is_stored(self, api, scopes):
        with key_with(scopes), target("blocked"):
            resp = _post(api, {"url": "http://internal.example/"})

        assert resp.status_code == 403
        api.db_manager.engine.begin.assert_not_called()

    def test_guard_runs_on_the_submitted_url(self, api):
        with key_with("report"), target("public") as guard:
            _post(api, {"url": "https://phish.example/a"})

        guard.assert_called_once_with("https://phish.example/a")

    @pytest.mark.parametrize(
        "body",
        [
            {"url": "https://phish.example/", "priority": "urgent"},
            {"url": "https://phish.example/", "source": ""},
            {"url": "https://phish.example/", "source": 5},
            {"url": "https://phish.example/", "description": ["x"]},
            {"url": ["https://phish.example/"]},
        ],
    )
    def test_malformed_fields_are_400(self, api, body):
        with key_with("report"), target("public"):
            assert _post(api, body).status_code == 400


class TestPendingRowsStayOutOfAutomaticPaths:
    """Run the reporting loop's and the auto-analyzer's selection SQL on PostgreSQL."""

    REPORTING_LOOP = """
        SELECT url FROM phishing_sites
        WHERE (manual_flag = 1 OR auto_report_eligible = 1)
          AND site_status = 'up' AND abuse_report_sent = 0
    """
    AUTO_ANALYSIS = """
        SELECT url FROM phishing_sites
        WHERE ((auto_analysis_status = 'pending' AND auto_detected = 1)
            OR (manual_flag = 1 AND auto_analysis_status IS NULL)
            OR (source = 'external_api' AND auto_analysis_status IS NULL))
          AND site_status != 'down'
    """

    def test_pending_submission_is_neither_reported_nor_auto_analysed(self, pg_api):
        client, db_manager, _ = pg_api
        url = f"https://pending-{uuid.uuid4().hex[:8]}.example/"

        with key_with("report"), target("public"):
            resp = client.post("/api/v1/report", json={"url": url}, headers=HEADERS)

        assert resp.status_code == 202, resp.get_json()
        with db_manager.engine.connect() as conn:
            reported = {r[0] for r in conn.execute(text(self.REPORTING_LOOP))}
            analysed = {r[0] for r in conn.execute(text(self.AUTO_ANALYSIS))}
            row = conn.execute(
                text(
                    "SELECT manual_flag, auto_report_eligible, requires_manual_review, source "
                    "FROM phishing_sites WHERE url = :u"
                ),
                {"u": url},
            ).one()
        assert url not in reported
        assert url not in analysed
        assert tuple(row) == (0, 0, 1, "external_api")
