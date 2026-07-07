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


class TestIntegrationsEndpoint:
    """Tests for GET /api/v1/integrations -- real circuit-breaker latency surfacing."""

    @pytest.fixture
    def integrations_setup(self):
        """API with a mocked validator whose sub-integrations we control directly."""
        with (
            patch("src.api.phishing_api.GrinderReportClient") as mock_grinder,
            patch("src.api.phishing_api.MultiAPIValidator"),
        ):
            mock_grinder.return_value.test_connection.return_value = {"status": "success"}
            from src.api.phishing_api import PhishingAPI

            mock_db = MagicMock(spec=DatabaseManager)
            mock_detector = MagicMock(spec=EnhancedAbuseEmailDetector)
            api = PhishingAPI(mock_db, mock_detector, api_key="test_key")
            api.app.config["TESTING"] = True
            client = api.app.test_client()

            # Every other integration stays a bare MagicMock, which would make
            # _cb_info()'s "real circuit breaker" branch choke on non-numeric
            # stats, and its raw `.api_key`/`.enabled` MagicMock attributes
            # aren't JSON-serializable as the new `configured` field. Give them
            # no circuit breaker plus real bool attributes so they take the
            # clean-default branch, leaving only virustotal under direct test
            # control -- with a real (fresh) CircuitBreaker of its own so
            # _cb_info() can read real stats off it by default.
            from src.circuit_breaker import CircuitBreaker

            mv = api.multi_api_validator
            mv.virustotal.api_key = "unused-in-these-tests"
            mv.virustotal.circuit_breaker = CircuitBreaker("VirusTotal")
            for name in ("urlvoid", "phishtank", "google_safe_browsing"):
                integration = getattr(mv, name)
                integration.circuit_breaker = None
                integration.api_key = None
                integration.enabled = False
            api.grinder_client.circuit_breaker = None
            api.grinder_client.enabled = False

            return client, api, {"Authorization": "Bearer test_key"}

    def test_last_call_ms_is_null_when_integration_never_called(self, integrations_setup):
        """A fresh circuit breaker with no calls yet should report null latency."""
        from src.circuit_breaker import CircuitBreaker

        client, api, headers = integrations_setup
        api.multi_api_validator.virustotal.circuit_breaker = CircuitBreaker("VirusTotal")

        resp = client.get("/api/v1/integrations", headers=headers)
        assert resp.status_code == 200
        data = json.loads(resp.data)
        vt = next(i for i in data if i["name"] == "virustotal")
        assert vt["last_call_ms"] is None

    def test_last_call_ms_reflects_real_circuit_breaker_latency(self, integrations_setup):
        """Once the circuit breaker has made a call, the API should surface its real duration."""
        from src.circuit_breaker import CircuitBreaker

        client, api, headers = integrations_setup
        cb = CircuitBreaker("VirusTotal")
        cb.call(lambda: "ok")  # exercises the real timing path
        api.multi_api_validator.virustotal.circuit_breaker = cb

        resp = client.get("/api/v1/integrations", headers=headers)
        data = json.loads(resp.data)
        vt = next(i for i in data if i["name"] == "virustotal")
        assert vt["last_call_ms"] == cb.stats.last_call_ms
        assert vt["last_call_ms"] is not None

    def test_phishtank_is_always_configured(self, integrations_setup):
        """PhishTank's checkurl endpoint works unauthenticated, so it's never
        blocked on a missing key -- unlike the other integrations."""
        client, api, headers = integrations_setup

        resp = client.get("/api/v1/integrations", headers=headers)
        data = json.loads(resp.data)
        pt = next(i for i in data if i["name"] == "phishtank")
        assert pt["configured"] is True

    def test_virustotal_reports_unconfigured_without_api_key(self, integrations_setup):
        """An integration that requires a real key should say so explicitly,
        instead of looking indistinguishable from 'not called yet'."""
        client, api, headers = integrations_setup
        api.multi_api_validator.virustotal.api_key = None

        resp = client.get("/api/v1/integrations", headers=headers)
        data = json.loads(resp.data)
        vt = next(i for i in data if i["name"] == "virustotal")
        assert vt["configured"] is False

    def test_virustotal_reports_configured_with_api_key(self, integrations_setup):
        """Once a real key is present, it should report itself as configured."""
        client, api, headers = integrations_setup
        api.multi_api_validator.virustotal.api_key = "real-key-value"

        resp = client.get("/api/v1/integrations", headers=headers)
        data = json.loads(resp.data)
        vt = next(i for i in data if i["name"] == "virustotal")
        assert vt["configured"] is True


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
        # domain, resolved_ip, registrar, threat, avg_conf, cloudflare, first, last, hits, detected_kit_type
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
            "evilginx",
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
            "evilginx",
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
            None,
        ),
        ("solo.example", None, None, None, None, False, "2026-01-04", "2026-01-08", 1, None),
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
        assert data["meta"]["kits"] == 1
        assert len(data["nodes"]) == 7
        assert len(data["edges"]) == 5

        ids = {n["id"] for n in data["nodes"]}
        assert "domain:brand-alpha.example" in ids
        assert "ip:203.0.113.10" in ids
        assert "registrar:Acme Registrar" in ids
        assert "kit:evilginx" in ids

    def test_graph_kit_node_and_edge(self, graph_setup):
        client, mock_db, headers = graph_setup
        self._rows(mock_db, self.SAMPLE_ROWS)

        data = json.loads(client.get("/api/v1/graph", headers=headers).data)
        kit_node = next(n for n in data["nodes"] if n["id"] == "kit:evilginx")
        assert kit_node["type"] == "kit"
        assert kit_node["severity"] == "critical"

        kit_edges = [e for e in data["edges"] if e["target"] == "kit:evilginx"]
        assert len(kit_edges) == 1
        assert kit_edges[0]["source"] == "domain:brand-alpha.example"
        assert kit_edges[0]["relation"] == "detected_as"

    def test_graph_focus_kit_one_hop(self, graph_setup):
        client, mock_db, headers = graph_setup
        self._rows(mock_db, self.SAMPLE_ROWS)

        data = json.loads(client.get("/api/v1/graph?focus=kit:evilginx", headers=headers).data)
        ids = {n["id"] for n in data["nodes"]}
        assert ids == {"kit:evilginx", "domain:brand-alpha.example"}

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


class TestIntelligenceSharingRoutes:
    """The 4 STIX/TAXII/MISP routes -- no production TAXII/MISP server
    exists yet (confirmed with the user), so taxii/misp are always
    mocked here; stix_export.py uses the real stix2 library (validation
    correctness is what it's for)."""

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
            return client, {"Authorization": "Bearer test_key"}

    def test_stix_validate_requires_bundle(self, api_setup):
        client, headers = api_setup
        resp = client.post("/api/v1/intelligence/stix/validate", json={}, headers=headers)
        assert resp.status_code == 400

    def test_stix_validate_valid_bundle(self, api_setup):
        client, headers = api_setup
        bundle = {
            "type": "bundle",
            "id": "bundle--e9e0b1a4-6a1e-4d1a-9e5b-2c8b2c2b2c2b",
            "objects": [
                {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": "indicator--c1b3b3b3-1111-4222-8333-444444444444",
                    "created": "2026-01-01T00:00:00.000Z",
                    "modified": "2026-01-01T00:00:00.000Z",
                    "pattern": "[domain-name:value = 'evil.example.com']",
                    "pattern_type": "stix",
                    "labels": ["malicious-activity"],
                    "valid_from": "2026-01-01T00:00:00.000Z",
                }
            ],
        }
        resp = client.post(
            "/api/v1/intelligence/stix/validate", json={"bundle": bundle}, headers=headers
        )
        assert resp.status_code == 200
        assert json.loads(resp.data)["valid"] is True

    def test_taxii_push_returns_503_when_unconfigured(self, api_setup):
        client, headers = api_setup
        with patch("src.api.phishing_api.settings") as mock_settings:
            mock_settings.TAXII_BASE_URL = None
            resp = client.post(
                "/api/v1/intelligence/taxii/push", json={"bundle": {}}, headers=headers
            )
        assert resp.status_code == 503

    def test_taxii_pull_returns_503_when_unconfigured(self, api_setup):
        client, headers = api_setup
        with patch("src.api.phishing_api.settings") as mock_settings:
            mock_settings.TAXII_BASE_URL = None
            resp = client.get("/api/v1/intelligence/taxii/pull", headers=headers)
        assert resp.status_code == 503

    def test_taxii_pull_requires_api_root_and_collection_id(self, api_setup):
        client, headers = api_setup
        with patch("src.api.phishing_api.settings") as mock_settings:
            mock_settings.TAXII_BASE_URL = "https://taxii.example.com"
            mock_settings.TAXII_DEFAULT_API_ROOT = None
            mock_settings.TAXII_DEFAULT_COLLECTION_ID = None
            resp = client.get("/api/v1/intelligence/taxii/pull", headers=headers)
        assert resp.status_code == 400

    def test_taxii_pull_calls_client_with_configured_defaults(self, api_setup):
        client, headers = api_setup
        with (
            patch("src.api.phishing_api.settings") as mock_settings,
            patch("src.intelligence.taxii_client.TAXIIClient") as mock_client_cls,
        ):
            mock_settings.TAXII_BASE_URL = "https://taxii.example.com"
            mock_settings.TAXII_DEFAULT_API_ROOT = "api1"
            mock_settings.TAXII_DEFAULT_COLLECTION_ID = "col-1"
            mock_client_cls.return_value.pull_objects.return_value = [{"type": "indicator"}]

            resp = client.get("/api/v1/intelligence/taxii/pull", headers=headers)

        assert resp.status_code == 200
        assert json.loads(resp.data)["objects"] == [{"type": "indicator"}]

    def test_misp_push_returns_503_when_unconfigured(self, api_setup):
        client, headers = api_setup
        with patch("src.api.phishing_api.settings") as mock_settings:
            mock_settings.MISP_URL = None
            resp = client.post(
                "/api/v1/intelligence/misp/push",
                json={"indicators": [], "event_info": "x"},
                headers=headers,
            )
        assert resp.status_code == 503

    def test_misp_push_requires_indicators_and_event_info(self, api_setup):
        client, headers = api_setup
        with patch("src.api.phishing_api.settings") as mock_settings:
            mock_settings.MISP_URL = "https://misp.example.com"
            resp = client.post("/api/v1/intelligence/misp/push", json={}, headers=headers)
        assert resp.status_code == 400

    def test_misp_push_success(self, api_setup):
        client, headers = api_setup
        with (
            patch("src.api.phishing_api.settings") as mock_settings,
            patch("src.intelligence.misp_client.MISPClient") as mock_client_cls,
        ):
            mock_settings.MISP_URL = "https://misp.example.com"
            mock_client_cls.return_value.push_indicators.return_value = {"Event": {"id": "1"}}

            resp = client.post(
                "/api/v1/intelligence/misp/push",
                json={"indicators": [{"type": "domain", "value": "x.com"}], "event_info": "x"},
                headers=headers,
            )

        assert resp.status_code == 200
        assert json.loads(resp.data) == {"Event": {"id": "1"}}

    def test_misp_push_returns_502_when_push_fails(self, api_setup):
        client, headers = api_setup
        with (
            patch("src.api.phishing_api.settings") as mock_settings,
            patch("src.intelligence.misp_client.MISPClient") as mock_client_cls,
        ):
            mock_settings.MISP_URL = "https://misp.example.com"
            mock_client_cls.return_value.push_indicators.return_value = None

            resp = client.post(
                "/api/v1/intelligence/misp/push",
                json={"indicators": [{"type": "domain", "value": "x.com"}], "event_info": "x"},
                headers=headers,
            )

        assert resp.status_code == 502

    def test_requires_auth(self, api_setup):
        client, _ = api_setup
        assert client.post("/api/v1/intelligence/stix/validate").status_code == 401
        assert client.post("/api/v1/intelligence/taxii/push").status_code == 401
        assert client.get("/api/v1/intelligence/taxii/pull").status_code == 401
        assert client.post("/api/v1/intelligence/misp/push").status_code == 401
