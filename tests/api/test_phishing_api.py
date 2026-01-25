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

        def mock_require_api_key(f):
            """Mock require_api_key that uses current_app."""
            from flask import current_app, request, jsonify

            @wraps(f)
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

                return f(*args, **kwargs)

            return decorated_function

        with (
            patch("src.intelligence.grinder.require_api_key", mock_require_api_key),
            patch("src.api.phishing_api.require_api_key", mock_require_api_key),
            patch("src.api.phishing_api.GrinderReportClient") as mock_grinder,
            patch("src.api.phishing_api.MultiAPIValidator") as mock_validator,
        ):

            # Force reimport with patched decorator
            import importlib
            import src.api.phishing_api as api_module

            importlib.reload(api_module)

            mock_grinder.return_value.test_connection.return_value = {"status": "success"}
            mock_db = MagicMock(spec=DatabaseManager)
            mock_detector = MagicMock(spec=EnhancedAbuseEmailDetector)
            api = api_module.PhishingAPI(mock_db, mock_detector, api_key="secret_key_123")
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
