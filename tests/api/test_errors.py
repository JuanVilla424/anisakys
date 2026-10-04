"""Error responses must not leak exception text and must carry a request ID."""

import json
from unittest.mock import MagicMock, patch

import pytest

from src.api.errors import REQUEST_ID_HEADER, scrub_provider_errors
from src.reporting.email_detector import EnhancedAbuseEmailDetector

AUTH = {"Authorization": "Bearer test_key"}
SECRET = "postgresql://admin:hunter2@db.internal:5432/anisakys"


@pytest.fixture
def api():
    """PhishingAPI with mocked DB and integrations; master-key auth."""
    with (
        patch("src.api.phishing_api.GrinderReportClient"),
        patch("src.api.phishing_api.MultiAPIValidator"),
        patch("src.api.phishing_api.GRINDER_INTEGRATION_ENABLED", False),
    ):
        from src.api.phishing_api import PhishingAPI

        instance = PhishingAPI(
            MagicMock(), MagicMock(spec=EnhancedAbuseEmailDetector), api_key="test_key"
        )
        instance.app.config["TESTING"] = True
        yield instance


def _assert_generic_500(resp):
    assert resp.status_code == 500
    body = json.loads(resp.data)
    assert SECRET not in resp.get_data(as_text=True)
    assert "hunter2" not in resp.get_data(as_text=True)
    assert body["request_id"] == resp.headers[REQUEST_ID_HEADER]
    return body


class TestNoExceptionTextInResponses:
    def test_database_failure_in_a_list_route(self, api):
        api.db_manager.engine.begin.side_effect = RuntimeError(SECRET)

        resp = api.app.test_client().get("/api/v1/sites", headers=AUTH)

        assert _assert_generic_500(resp)["error"] == "Internal server error"

    def test_google_alerts_failure(self, api):
        with (
            patch("src.api.phishing_api.settings") as settings,
            patch(
                "src.intelligence.alert_center_client.get_alert_center_client",
                side_effect=RuntimeError(SECRET),
            ),
        ):
            settings.GOOGLE_SERVICE_ACCOUNT_FILE = "/secrets/sa.json"
            settings.GOOGLE_ADMIN_EMAIL = "admin@example.com"
            settings.GOOGLE_WORKSPACE_DOMAIN = "example.com"
            resp = api.app.test_client().get("/api/v1/alerts/google", headers=AUTH)

        _assert_generic_500(resp)

    def test_scan_domain_failure(self, api):
        with patch("src.intelligence.domain_scanner.full_scan", side_effect=OSError(SECRET)):
            resp = api.app.test_client().post(
                "/api/v1/scan/domain", json={"domain": "phish.example"}, headers=AUTH
            )

        _assert_generic_500(resp)

    def test_report_persistence_failure(self, api):
        api.db_manager.engine.begin.side_effect = RuntimeError(SECRET)

        with patch("src.api.phishing_api.assess_url_target", return_value="unresolved"):
            resp = api.app.test_client().post(
                "/api/v1/report", json={"url": "https://phish.example/"}, headers=AUTH
            )

        body = _assert_generic_500(resp)
        assert body["status"] == "error"
        assert body["message"] == "Failed to process report"

    def test_gsb_check_error_text_is_replaced(self, api):
        gsb = MagicMock()
        gsb.is_available.return_value = True
        gsb.check_url.return_value = {
            "checked": False,
            "error": f"Request failed: https://safebrowsing.example/?key={SECRET}",
        }
        with patch(
            "src.intelligence.google_safe_browsing.GoogleSafeBrowsingIntegration",
            return_value=gsb,
        ):
            resp = api.app.test_client().post(
                "/api/v1/gsb/check", json={"url": "https://phish.example/"}, headers=AUTH
            )

        assert resp.status_code == 200
        assert SECRET not in resp.get_data(as_text=True)
        assert json.loads(resp.data)["error"] == "Safe Browsing lookup failed"

    def test_multi_scan_provider_errors_are_scrubbed(self, api):
        api.multi_api_validator.comprehensive_scan.return_value = {
            "domain": "phish.example",
            "urlvoid": {"error": f"HTTPSConnectionPool: /api1000/{SECRET}/host", "details": SECRET},
            "virustotal": {"malicious": 3},
        }
        api.abuse_detector.get_enhanced_abuse_email.return_value = []
        conn = api.db_manager.engine.begin.return_value.__enter__.return_value
        conn.execute.return_value.fetchone.return_value = None
        with patch("src.api.phishing_api.assess_url_target", return_value="unresolved"):
            resp = api.app.test_client().post(
                "/api/v1/multi-scan",
                json={"url": "https://phish.example/", "include_screenshot": False},
                headers=AUTH,
            )

        assert resp.status_code == 200
        body = json.loads(resp.data)
        assert SECRET not in resp.get_data(as_text=True)
        assert body["urlvoid"] == {"error": "Lookup failed"}
        assert body["virustotal"] == {"malicious": 3}


class TestRequestIds:
    def test_every_response_carries_a_request_id(self, api):
        resp = api.app.test_client().get("/api/v1/nonexistent")

        assert resp.status_code == 404
        assert len(resp.headers[REQUEST_ID_HEADER]) >= 8

    def test_safe_client_request_id_is_echoed(self, api):
        resp = api.app.test_client().get(
            "/api/v1/nonexistent", headers={REQUEST_ID_HEADER: "trace-1234abcd"}
        )

        assert resp.headers[REQUEST_ID_HEADER] == "trace-1234abcd"

    def test_unsafe_client_request_id_is_replaced(self, api):
        resp = api.app.test_client().get(
            "/api/v1/nonexistent", headers={REQUEST_ID_HEADER: "<script>alert(1)</script>"}
        )

        assert "<" not in resp.headers[REQUEST_ID_HEADER]


def test_scrub_provider_errors_keeps_healthy_results_untouched():
    result = {"a": {"error": "boom", "details": "x", "status": "circuit_open"}, "b": {"ok": 1}}

    scrubbed = scrub_provider_errors(result, generic="failed")

    assert scrubbed == {"a": {"error": "failed", "status": "circuit_open"}, "b": {"ok": 1}}
    assert result["a"]["error"] == "boom"  # input not mutated
