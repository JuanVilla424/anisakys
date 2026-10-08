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


class TestRateLimitStorage:
    """RATELIMIT_STORAGE_URL selects where counters live (shared across workers)."""

    REDIS_URL = "redis://127.0.0.1:56379/0"

    @staticmethod
    def _api(storage_url):
        with (
            patch("src.api.phishing_api.GrinderReportClient"),
            patch("src.api.phishing_api.MultiAPIValidator"),
            patch("src.api.phishing_api.settings.RATELIMIT_STORAGE_URL", storage_url),
        ):
            from src.api.phishing_api import PhishingAPI
            from src.database.manager import DatabaseManager
            from src.reporting.email_detector import EnhancedAbuseEmailDetector

            api = PhishingAPI(
                MagicMock(spec=DatabaseManager),
                MagicMock(spec=EnhancedAbuseEmailDetector),
                api_key="test_key",
            )
            api.app.config["TESTING"] = True
            return api

    @staticmethod
    def _redis_available() -> bool:
        import redis

        try:
            return bool(redis.Redis.from_url(TestRateLimitStorage.REDIS_URL).ping())
        except redis.RedisError:
            return False

    def test_unset_storage_uses_memory_and_warns(self, caplog):
        from src.api.phishing_api import rate_limit_storage_uri

        with (
            patch("src.api.phishing_api.settings.RATELIMIT_STORAGE_URL", None),
            caplog.at_level("WARNING"),
        ):
            assert rate_limit_storage_uri() == "memory://"
        assert "per process" in caplog.text

    def test_configured_uri_is_used_without_logging_credentials(self, caplog):
        from src.api.phishing_api import rate_limit_storage_uri

        uri = "redis://:s3cret@redis.internal:6379/0"
        with (
            patch("src.api.phishing_api.settings.RATELIMIT_STORAGE_URL", uri),
            caplog.at_level("INFO"),
        ):
            assert rate_limit_storage_uri() == uri
        assert "s3cret" not in caplog.text

    def test_redis_storage_shares_counters_between_workers(self):
        """Two app instances (two gunicorn workers) must share one bucket."""
        import uuid

        if not self._redis_available():
            pytest.skip("local Redis not reachable")
        worker_a, worker_b = self._api(self.REDIS_URL), self._api(self.REDIS_URL)
        # A random (invalid) token gets its own bucket; the limiter counts it
        # before require_api_key answers 401, so no DB lookup is needed.
        headers = {"Authorization": f"Bearer {uuid.uuid4().hex}"}
        body = {"url": "http://127.0.0.1/"}

        statuses = []
        for client in [worker_a.app.test_client(), worker_b.app.test_client()] * 3:
            with patch("src.auth._lookup_db_key", return_value=None):
                statuses.append(client.post("/api/v1/report", json=body, headers=headers))

        assert [r.status_code for r in statuses] == [401] * 5 + [429]

    def test_memory_storage_counts_per_worker(self):
        import uuid

        worker_a, worker_b = self._api(None), self._api(None)
        headers = {"Authorization": f"Bearer {uuid.uuid4().hex}"}

        statuses = []
        for client in [worker_a.app.test_client(), worker_b.app.test_client()] * 3:
            with patch("src.auth._lookup_db_key", return_value=None):
                statuses.append(
                    client.post("/api/v1/report", json={"url": "x"}, headers=headers).status_code
                )

        assert statuses == [401] * 6


def _mocked_api():
    """A PhishingAPI on a mocked database whose queries return empty results."""
    with (
        patch("src.api.phishing_api.GrinderReportClient"),
        patch("src.api.phishing_api.MultiAPIValidator"),
    ):
        from src.api.phishing_api import PhishingAPI
        from src.reporting.email_detector import EnhancedAbuseEmailDetector

        db = MagicMock()
        conn = db.engine.begin.return_value.__enter__.return_value
        conn.execute.return_value.scalar.return_value = 0
        conn.execute.return_value.fetchall.return_value = []
        api = PhishingAPI(db, MagicMock(spec=EnhancedAbuseEmailDetector), api_key="test_key")
        api.app.config["TESTING"] = True
        return api


HEADERS = {"Authorization": "Bearer test_key"}


class TestRateLimitResponses:
    """429s are JSON with the seconds to wait; every limited response has headers."""

    def test_429_is_json_with_retry_after_matching_the_header(self):
        client = _mocked_api().app.test_client()
        body = {"url": "http://127.0.0.1/"}

        responses = [
            client.post("/api/v1/multi-scan", json=body, headers=HEADERS) for _ in range(4)
        ]

        limited = responses[3]
        assert limited.status_code == 429
        assert limited.is_json
        data = limited.get_json()
        assert set(data) == {"error", "retry_after"}
        assert "Rate limit exceeded" in data["error"]
        # flask-limiter rounds the window reset up to the next whole second.
        assert isinstance(data["retry_after"], int) and 1 <= data["retry_after"] <= 61
        assert limited.headers["Retry-After"] == str(data["retry_after"])

    def test_successful_responses_carry_rate_limit_headers(self):
        client = _mocked_api().app.test_client()

        resp = client.get("/api/v1/stats", headers=HEADERS)

        assert resp.status_code == 200
        assert resp.headers["X-RateLimit-Limit"] == "120"
        assert resp.headers["X-RateLimit-Remaining"] == "119"
        assert "X-RateLimit-Reset" in resp.headers
        assert "Retry-After" in resp.headers


class TestConsolePollingLimits:
    """Read endpoints the analyst console polls must not starve a normal session."""

    def test_stats_allows_120_requests_per_minute(self):
        client = _mocked_api().app.test_client()

        statuses = [client.get("/api/v1/stats", headers=HEADERS).status_code for _ in range(121)]

        assert statuses[:120] == [200] * 120
        assert statuses[120] == 429

    def test_thread_results_are_bucketed_per_thread(self):
        client = _mocked_api().app.test_client()

        first = [
            client.get("/api/v1/threads/1/results", headers=HEADERS).status_code for _ in range(31)
        ]
        other = client.get("/api/v1/threads/2/results", headers=HEADERS)

        assert first[:30] == [200] * 30
        assert first[30] == 429
        # Polling one busy thread does not lock the other threads out.
        assert other.status_code == 200

    def test_thread_results_are_capped_per_key_across_threads(self):
        client = _mocked_api().app.test_client()

        statuses = [
            client.get(f"/api/v1/threads/{i % 6}/results", headers=HEADERS).status_code
            for i in range(121)
        ]

        assert statuses[:120] == [200] * 120
        assert statuses[120] == 429

    def test_thread_results_buckets_are_per_api_key(self):
        api = _mocked_api()
        client = api.app.test_client()
        for _ in range(30):
            client.get("/api/v1/threads/1/results", headers=HEADERS)

        row = {"scopes": "read", "allowed_ips": None, "key_hash": "h"}
        with (
            patch("src.auth._lookup_db_key", return_value=row),
            patch("src.auth._update_last_used"),
        ):
            resp = client.get("/api/v1/threads/1/results", headers={"Authorization": "Bearer k2"})

        assert resp.status_code == 200

    def test_report_submission_stays_strict(self):
        client = _mocked_api().app.test_client()

        statuses = [
            client.post("/api/v1/report", json={}, headers=HEADERS).status_code for _ in range(6)
        ]

        assert statuses[5] == 429
        assert 429 not in statuses[:5]
