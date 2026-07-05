"""
Tests for API-key-aware rate limiting in src/api/phishing_api.py.

Two layers, matching this repo's existing house styles:
  - Isolated unit tests of rate_limit_key() (mirrors tests/test_auth.py's
    _make_app / test_request_context pattern) — no DB, no real limiter.
  - One integration test that exercises the real Limiter end-to-end via a
    real PhishingAPI instance (mirrors tests/api/test_phishing_api.py's
    graph_setup fixture) to confirm requests actually get 429'd.
"""

import hashlib
from unittest.mock import MagicMock, patch

import pytest
from flask import Flask

from src.api.phishing_api import rate_limit_key


def _hash(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def _make_app(master_key: str = "master-key-123") -> Flask:
    app = Flask(__name__)
    app.api_key = master_key
    app.config["TESTING"] = True
    return app


class TestRateLimitKeyUnit:
    """rate_limit_key() must parse the Authorization header itself — it runs
    before require_api_key on every request, per the limiter/auth decorator
    ordering in setup_routes()."""

    def test_master_key_gets_shared_operator_bucket(self):
        app = _make_app("master-secret")
        with app.test_request_context("/", headers={"Authorization": "Bearer master-secret"}):
            key = rate_limit_key()
        assert key == "apikey:master"

    def test_non_master_bearer_gets_bucketed_by_its_own_hash(self):
        app = _make_app("master-secret")
        with app.test_request_context("/", headers={"Authorization": "Bearer some-other-token"}):
            key = rate_limit_key()
        assert key == f"apikey:{_hash('some-other-token')}"

    def test_two_different_tokens_get_different_buckets(self):
        app = _make_app("master-secret")
        with app.test_request_context("/", headers={"Authorization": "Bearer token-a"}):
            key_a = rate_limit_key()
        with app.test_request_context("/", headers={"Authorization": "Bearer token-b"}):
            key_b = rate_limit_key()
        assert key_a != key_b

    def test_same_token_always_gets_same_bucket(self):
        app = _make_app("master-secret")
        with app.test_request_context("/", headers={"Authorization": "Bearer repeat-me"}):
            key_1 = rate_limit_key()
        with app.test_request_context("/", headers={"Authorization": "Bearer repeat-me"}):
            key_2 = rate_limit_key()
        assert key_1 == key_2

    def test_no_authorization_header_falls_back_to_ip(self):
        app = _make_app("master-secret")
        with (
            app.test_request_context("/", environ_base={"REMOTE_ADDR": "203.0.113.7"}),
            patch("src.api.phishing_api.get_remote_address", return_value="203.0.113.7") as mock_ip,
        ):
            key = rate_limit_key()
        assert key == "203.0.113.7"
        mock_ip.assert_called_once()

    def test_malformed_header_without_bearer_prefix_falls_back_to_ip(self):
        app = _make_app("master-secret")
        with (
            app.test_request_context("/", headers={"Authorization": "Basic abc123"}),
            patch("src.api.phishing_api.get_remote_address", return_value="198.51.100.1"),
        ):
            key = rate_limit_key()
        assert key == "198.51.100.1"

    def test_no_master_key_configured_still_hashes_bearer_token(self):
        app = Flask(__name__)
        app.config["TESTING"] = True  # app.api_key intentionally left unset
        with app.test_request_context("/", headers={"Authorization": "Bearer anything"}):
            key = rate_limit_key()
        assert key == f"apikey:{_hash('anything')}"


class TestMultiScanRateLimit429:
    """One integration test proving the limiter actually rejects the 4th
    request — using a literal-IP target so the SSRF guard 403s instantly
    with zero DNS and zero scan work, keeping this test fast."""

    @pytest.fixture
    def api_client(self):
        with (
            patch("src.api.phishing_api.GrinderReportClient"),
            patch("src.api.phishing_api.MultiAPIValidator"),
        ):
            from src.api.phishing_api import PhishingAPI
            from src.database.manager import DatabaseManager
            from src.reporting.email_detector import EnhancedAbuseEmailDetector

            mock_db = MagicMock(spec=DatabaseManager)
            mock_detector = MagicMock(spec=EnhancedAbuseEmailDetector)
            api = PhishingAPI(mock_db, mock_detector, api_key="test_key")
            api.app.config["TESTING"] = True
            return api.app.test_client()

    def test_fourth_request_in_a_minute_gets_429(self, api_client):
        headers = {"Authorization": "Bearer test_key"}
        body = {"url": "http://127.0.0.1/"}

        responses = [
            api_client.post("/api/v1/multi-scan", json=body, headers=headers) for _ in range(4)
        ]

        # First 3: rejected by the SSRF guard inside the view (blocked target).
        for resp in responses[:3]:
            assert resp.status_code == 403
        # 4th: the limiter itself rejects it before the view ever runs.
        assert responses[3].status_code == 429
