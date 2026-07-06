"""
Tests for src/api/phishing_api.py - PhishingAPI
"""

import json
from unittest.mock import patch, MagicMock
from functools import wraps

import pytest

from src.database.manager import DatabaseManager
from src.reporting.email_detector import EnhancedAbuseEmailDetector


class TestPhishingAPIInit:
    """Tests for PhishingAPI initialization."""

    @pytest.fixture
    def mock_db_manager(self):
        """Create mock database manager."""
        return MagicMock(spec=DatabaseManager)

    @pytest.fixture
    def mock_abuse_detector(self):
        """Create mock abuse detector."""
        return MagicMock(spec=EnhancedAbuseEmailDetector)

    @patch("src.api.phishing_api.GrinderReportClient")
    @patch("src.api.phishing_api.MultiAPIValidator")
    def test_api_creates_flask_app(
        self, mock_validator, mock_grinder, mock_db_manager, mock_abuse_detector
    ):
        """PhishingAPI should create Flask app."""
        from src.api.phishing_api import PhishingAPI

        api = PhishingAPI(mock_db_manager, mock_abuse_detector, api_key="test_key")
        assert api.app is not None

    @patch("src.api.phishing_api.GrinderReportClient")
    @patch("src.api.phishing_api.MultiAPIValidator")
    def test_api_stores_api_key(
        self, mock_validator, mock_grinder, mock_db_manager, mock_abuse_detector
    ):
        """PhishingAPI should store API key."""
        from src.api.phishing_api import PhishingAPI

        api = PhishingAPI(mock_db_manager, mock_abuse_detector, api_key="test_key_123")
        assert api.api_key == "test_key_123"

    @patch("src.api.phishing_api.GrinderReportClient")
    @patch("src.api.phishing_api.MultiAPIValidator")
    def test_api_without_key(
        self, mock_validator, mock_grinder, mock_db_manager, mock_abuse_detector
    ):
        """PhishingAPI should work without API key."""
        from src.api.phishing_api import PhishingAPI

        api = PhishingAPI(mock_db_manager, mock_abuse_detector, api_key=None)
        assert api.api_key is None


class TestPhishingAPIEndpoints:
    """Tests for PhishingAPI endpoints."""

    @pytest.fixture
    def api_client(self):
        """Create test client for API with mocked dependencies."""
        with (
            patch("src.api.phishing_api.GrinderReportClient") as mock_grinder,
            patch("src.api.phishing_api.MultiAPIValidator") as mock_validator,
        ):
            mock_grinder.return_value.test_connection.return_value = {"status": "success"}
            from src.api.phishing_api import PhishingAPI

            mock_db = MagicMock(spec=DatabaseManager)
            mock_detector = MagicMock(spec=EnhancedAbuseEmailDetector)
            api = PhishingAPI(mock_db, mock_detector, api_key="test_api_key")
            api.app.config["TESTING"] = True
            return api.app.test_client()

    def test_health_endpoint_returns_200(self, api_client):
        """Health endpoint should return 200."""
        response = api_client.get("/api/v1/health")
        assert response.status_code == 200

    def test_health_endpoint_returns_json(self, api_client):
        """Health endpoint should return JSON."""
        response = api_client.get("/api/v1/health")
        data = json.loads(response.data)
        assert "status" in data
        assert data["status"] == "healthy"

    def test_health_endpoint_includes_timestamp(self, api_client):
        """Health endpoint should include timestamp."""
        response = api_client.get("/api/v1/health")
        data = json.loads(response.data)
        assert "timestamp" in data

    def test_health_endpoint_includes_grinder_status(self, api_client):
        """Health endpoint should include grinder integration status."""
        response = api_client.get("/api/v1/health")
        data = json.loads(response.data)
        assert "grinder_integration" in data

    def test_health_endpoint_includes_version(self, api_client):
        """Health endpoint should include a non-empty app version string."""
        response = api_client.get("/api/v1/health")
        data = json.loads(response.data)
        assert "version" in data
        assert isinstance(data["version"], str)
        assert data["version"] != ""

    def test_health_endpoint_includes_auth_status(self, api_client):
        """Health endpoint should include authentication status."""
        response = api_client.get("/api/v1/health")
        data = json.loads(response.data)
        assert "api_authentication" in data
        assert data["api_authentication"] is True

    def test_nonexistent_endpoint_returns_404(self, api_client):
        """Non-existent endpoint should return 404."""
        response = api_client.get("/api/v1/nonexistent")
        assert response.status_code == 404


class TestPhishingAPIAuthentication:
    """Tests for API authentication behavior."""

    @pytest.fixture
    def api_with_mocked_auth(self):
        """Create API with properly mocked auth decorator."""

        def mock_require_api_key(f=None, *, scope=None):
            """Mock require_api_key supporting bare and factory (scope=...) usage."""
            from flask import current_app, request, jsonify

            def decorator(func):
                @wraps(func)
                def decorated_function(*args, **kwargs):
                    auth_header = request.headers.get("Authorization", "")

                    if not auth_header.startswith("Bearer "):
                        return jsonify({"error": "Authorization required"}), 401

                    provided_key = auth_header[7:]
                    expected_key = current_app.api_key

                    if not expected_key:
                        return jsonify({"error": "API not configured"}), 500

                    if provided_key != expected_key:
                        return jsonify({"error": "Invalid API key"}), 401

                    return func(*args, **kwargs)

                return decorated_function

            return decorator(f) if f is not None else decorator

        with (
            patch("src.api.phishing_api.require_api_key", mock_require_api_key),
            patch("src.api.phishing_api.GrinderReportClient") as mock_grinder,
            patch("src.api.phishing_api.MultiAPIValidator"),
        ):
            from src.api.phishing_api import PhishingAPI

            mock_grinder.return_value.test_connection.return_value = {"status": "success"}
            mock_db = MagicMock(spec=DatabaseManager)
            mock_detector = MagicMock(spec=EnhancedAbuseEmailDetector)
            api = PhishingAPI(mock_db, mock_detector, api_key="secret_key_123")
            api.app.config["TESTING"] = True
            return api.app.test_client()

    def test_stats_requires_bearer_prefix(self, api_with_mocked_auth):
        """Stats endpoint should reject requests without Bearer prefix."""
        response = api_with_mocked_auth.get(
            "/api/v1/stats", headers={"Authorization": "secret_key_123"}
        )
        assert response.status_code == 401

    def test_stats_requires_valid_key(self, api_with_mocked_auth):
        """Stats endpoint should reject invalid API keys (not return 200)."""
        response = api_with_mocked_auth.get(
            "/api/v1/stats", headers={"Authorization": "Bearer wrong_key"}
        )
        # Should return 401 (invalid key) or 500 (auth config issue), but never 200
        assert response.status_code in [401, 500]
        assert response.status_code != 200

    def test_stats_accepts_valid_auth(self, api_with_mocked_auth):
        """Stats endpoint should accept valid Bearer token."""
        response = api_with_mocked_auth.get(
            "/api/v1/stats", headers={"Authorization": "Bearer secret_key_123"}
        )
        # May return 200 or 500 (db error) but not 401
        assert response.status_code != 401

    def test_report_requires_auth(self, api_with_mocked_auth):
        """Report endpoint should require authentication."""
        response = api_with_mocked_auth.post("/api/v1/report", json={"url": "http://test.com"})
        assert response.status_code == 401

    def test_multi_scan_requires_auth(self, api_with_mocked_auth):
        """Multi-scan endpoint should require authentication."""
        response = api_with_mocked_auth.post("/api/v1/multi-scan", json={"url": "http://test.com"})
        assert response.status_code == 401


class TestGraphEndpoint:
    """Tests for GET /api/v1/graph — builds nodes/edges from real sites."""

    SAMPLE_ROWS = [
        # domain, resolved_ip, registrar, threat, avg_conf, cloudflare, first, last, hits
        (
            "brand-alpha.example",
            "203.0.113.10",
            "Acme Registrar",
            "critical",
            92.0,
            False,
            "2026-01-01",
            "2026-01-05",
            3,
        ),
        (
            "brand-alpha.example",
            "203.0.113.10",
            "Acme Registrar",
            "high",
            80.0,
            False,
            "2026-01-02",
            "2026-01-06",
            1,
        ),
        (
            "acme-bank.example",
            "190.2.3.4",
            "Acme Registrar",
            "medium",
            70.0,
            True,
            "2026-01-03",
            "2026-01-07",
            2,
        ),
        ("solo.example", None, None, None, None, False, "2026-01-04", "2026-01-08", 1),
    ]

    @pytest.fixture
    def graph_setup(self):
        """API with a mocked DB engine; master-key auth (no DB auth needed)."""
        with (
            patch("src.api.phishing_api.GrinderReportClient"),
            patch("src.api.phishing_api.MultiAPIValidator"),
        ):
            from src.api.phishing_api import PhishingAPI

            mock_db = MagicMock()
            mock_db.engine.begin.return_value.__enter__.return_value
            api = PhishingAPI(
                mock_db, MagicMock(spec=EnhancedAbuseEmailDetector), api_key="test_key"
            )
            api.app.config["TESTING"] = True
            client = api.app.test_client()
            return client, mock_db, {"Authorization": "Bearer test_key"}

    @staticmethod
    def _rows(mock_db, rows):
        conn = mock_db.engine.begin.return_value.__enter__.return_value
        conn.execute.return_value.fetchall.return_value = rows

    def test_graph_builds_nodes_and_edges(self, graph_setup):
        client, mock_db, headers = graph_setup
        self._rows(mock_db, self.SAMPLE_ROWS)

        resp = client.get("/api/v1/graph", headers=headers)
        assert resp.status_code == 200
        data = json.loads(resp.data)

        assert data["meta"]["domains"] == 3
        assert data["meta"]["ips"] == 2
        assert data["meta"]["registrars"] == 1
        assert len(data["nodes"]) == 6
        assert len(data["edges"]) == 4

        ids = {n["id"] for n in data["nodes"]}
        assert "domain:brand-alpha.example" in ids
        assert "ip:203.0.113.10" in ids
        assert "registrar:Acme Registrar" in ids

    def test_graph_picks_severest_threat(self, graph_setup):
        client, mock_db, headers = graph_setup
        self._rows(mock_db, self.SAMPLE_ROWS)

        data = json.loads(client.get("/api/v1/graph", headers=headers).data)
        node = next(n for n in data["nodes"] if n["id"] == "domain:brand-alpha.example")
        assert node["severity"] == "critical"

    def test_graph_dedupes_edges(self, graph_setup):
        client, mock_db, headers = graph_setup
        self._rows(mock_db, self.SAMPLE_ROWS)

        data = json.loads(client.get("/api/v1/graph", headers=headers).data)
        same = [
            e
            for e in data["edges"]
            if e["source"] == "domain:brand-alpha.example" and e["target"] == "ip:203.0.113.10"
        ]
        assert len(same) == 1

    def test_graph_focus_one_hop(self, graph_setup):
        client, mock_db, headers = graph_setup
        self._rows(mock_db, self.SAMPLE_ROWS)

        data = json.loads(client.get("/api/v1/graph?focus=ip:203.0.113.10", headers=headers).data)
        ids = {n["id"] for n in data["nodes"]}
        assert ids == {"ip:203.0.113.10", "domain:brand-alpha.example"}
        assert len(data["edges"]) == 1

    def test_graph_empty_when_no_sites(self, graph_setup):
        client, mock_db, headers = graph_setup
        self._rows(mock_db, [])

        data = json.loads(client.get("/api/v1/graph", headers=headers).data)
        assert data["nodes"] == []
        assert data["edges"] == []
        assert data["meta"]["domains"] == 0

    def test_graph_requires_auth(self, graph_setup):
        client, mock_db, _ = graph_setup
        self._rows(mock_db, [])
        assert client.get("/api/v1/graph").status_code == 401


class TestCTMonitorThreadRoute:
    """Tests for POST /api/v1/threads/ct-monitor and the ct_monitor branch
    of POST /api/v1/threads/<id>/search."""

    @pytest.fixture
    def api_setup(self):
        with (
            patch("src.api.phishing_api.GrinderReportClient"),
            patch("src.api.phishing_api.MultiAPIValidator"),
        ):
            from src.api.phishing_api import PhishingAPI

            mock_db = MagicMock()
            api = PhishingAPI(
                mock_db, MagicMock(spec=EnhancedAbuseEmailDetector), api_key="test_key"
            )
            api.app.config["TESTING"] = True
            client = api.app.test_client()
            return client, mock_db, {"Authorization": "Bearer test_key"}

    def test_create_inserts_new_row_when_none_exists(self, api_setup):
        client, mock_db, headers = api_setup
        conn = mock_db.engine.begin.return_value.__enter__.return_value
        conn.execute.return_value.fetchone.side_effect = [None, (5,)]

        resp = client.post("/api/v1/threads/ct-monitor", headers=headers)

        assert resp.status_code == 201
        assert json.loads(resp.data) == {"id": 5, "status": "active"}

    def test_create_returns_existing_row_idempotently(self, api_setup):
        client, mock_db, headers = api_setup
        conn = mock_db.engine.begin.return_value.__enter__.return_value
        conn.execute.return_value.fetchone.return_value = (7,)

        resp = client.post("/api/v1/threads/ct-monitor", headers=headers)

        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data["id"] == 7
        assert data["existing"] is True

    def test_create_requires_auth(self, api_setup):
        client, _, _ = api_setup
        assert client.post("/api/v1/threads/ct-monitor").status_code == 401

    def test_search_trigger_rejects_ct_monitor_with_400(self, api_setup):
        client, mock_db, headers = api_setup
        conn = mock_db.engine.begin.return_value.__enter__.return_value
        conn.execute.return_value.fetchone.return_value = ("ct_monitor", None, None)

        resp = client.post("/api/v1/threads/1/search", headers=headers)

        assert resp.status_code == 400
        assert "no on-demand search trigger" in json.loads(resp.data)["error"]


class TestThreadUpdateRoutes404:
    """PATCH /threads/<id>, /threads/<id>/results/<rid>, and .../discard must
    404 on a nonexistent id instead of silently reporting success (rowcount
    == 0) -- confirmed as a real, narrowly-scoped gap during the BOLA/IDOR
    audit: update_report and block_sender/unblock_sender already get this
    right elsewhere in this same file; these 3 routes didn't."""

    @pytest.fixture
    def api_setup(self):
        with (
            patch("src.api.phishing_api.GrinderReportClient"),
            patch("src.api.phishing_api.MultiAPIValidator"),
        ):
            from src.api.phishing_api import PhishingAPI

            mock_db = MagicMock()
            api = PhishingAPI(
                mock_db, MagicMock(spec=EnhancedAbuseEmailDetector), api_key="test_key"
            )
            api.app.config["TESTING"] = True
            client = api.app.test_client()
            return client, mock_db, {"Authorization": "Bearer test_key"}

    def test_update_thread_404_when_no_row_matched(self, api_setup):
        client, mock_db, headers = api_setup
        conn = mock_db.engine.begin.return_value.__enter__.return_value
        conn.execute.return_value.rowcount = 0

        resp = client.patch("/api/v1/threads/999", json={"label": "x"}, headers=headers)

        assert resp.status_code == 404
        assert json.loads(resp.data)["error"] == "Thread not found"

    def test_update_thread_200_when_row_matched(self, api_setup):
        client, mock_db, headers = api_setup
        conn = mock_db.engine.begin.return_value.__enter__.return_value
        conn.execute.return_value.rowcount = 1

        resp = client.patch("/api/v1/threads/1", json={"label": "x"}, headers=headers)

        assert resp.status_code == 200
        assert json.loads(resp.data)["status"] == "updated"

    def test_update_thread_result_404_when_no_row_matched(self, api_setup):
        client, mock_db, headers = api_setup
        conn = mock_db.engine.begin.return_value.__enter__.return_value
        conn.execute.return_value.rowcount = 0

        resp = client.patch(
            "/api/v1/threads/1/results/999", json={"status": "clean"}, headers=headers
        )

        assert resp.status_code == 404
        assert json.loads(resp.data)["error"] == "Thread result not found"

    def test_update_thread_result_200_when_row_matched(self, api_setup):
        client, mock_db, headers = api_setup
        conn = mock_db.engine.begin.return_value.__enter__.return_value
        conn.execute.return_value.rowcount = 1

        resp = client.patch(
            "/api/v1/threads/1/results/1", json={"status": "clean"}, headers=headers
        )

        assert resp.status_code == 200
        assert json.loads(resp.data)["status"] == "updated"

    def test_discard_thread_result_404_when_no_row_matched(self, api_setup):
        client, mock_db, headers = api_setup
        conn = mock_db.engine.begin.return_value.__enter__.return_value
        conn.execute.return_value.rowcount = 0

        resp = client.patch("/api/v1/threads/1/results/999/discard", headers=headers)

        assert resp.status_code == 404
        assert json.loads(resp.data)["error"] == "Thread result not found"

    def test_discard_thread_result_200_when_row_matched(self, api_setup):
        client, mock_db, headers = api_setup
        conn = mock_db.engine.begin.return_value.__enter__.return_value
        conn.execute.return_value.rowcount = 1

        resp = client.patch("/api/v1/threads/1/results/1/discard", headers=headers)

        assert resp.status_code == 200
        assert json.loads(resp.data)["discarded"] == 1
