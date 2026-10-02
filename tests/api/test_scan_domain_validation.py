"""
POST /api/v1/scan/domain must reject anything but a plain hostname before
full_scan() shells out to dig/whois.
"""

from unittest.mock import patch, MagicMock

import pytest

from src.database.manager import DatabaseManager
from src.reporting.email_detector import EnhancedAbuseEmailDetector

AUTH = {"Authorization": "Bearer test_api_key"}


@pytest.fixture
def api_client():
    """Test client for the API with mocked dependencies (same pattern as test_phishing_api)."""
    with (
        patch("src.api.phishing_api.GrinderReportClient") as mock_grinder,
        patch("src.api.phishing_api.MultiAPIValidator"),
    ):
        mock_grinder.return_value.test_connection.return_value = {"status": "success"}
        from src.api.phishing_api import PhishingAPI

        mock_db = MagicMock(spec=DatabaseManager)
        mock_detector = MagicMock(spec=EnhancedAbuseEmailDetector)
        api = PhishingAPI(mock_db, mock_detector, api_key="test_api_key")
        api.app.config["TESTING"] = True
        return api.app.test_client()


@pytest.mark.parametrize(
    "body", [{"domain": "-f/etc/passwd"}, {"domain": "a b.com"}, {"domain": "evil.com;id"}]
)
def test_invalid_domain_is_rejected_before_scanning(api_client, body):
    with patch("src.intelligence.domain_scanner.full_scan") as full_scan:
        response = api_client.post("/api/v1/scan/domain", json=body, headers=AUTH)

    assert response.status_code == 400
    full_scan.assert_not_called()


def test_invalid_victim_domain_is_rejected(api_client):
    with patch("src.intelligence.domain_scanner.full_scan") as full_scan:
        response = api_client.post(
            "/api/v1/scan/domain",
            json={"domain": "example.com", "victim_domain": "-h evil.example"},
            headers=AUTH,
        )

    assert response.status_code == 400
    full_scan.assert_not_called()


def test_www_prefix_is_removed_not_leading_characters(api_client):
    with patch("src.intelligence.domain_scanner.full_scan", return_value={}) as full_scan:
        response = api_client.post(
            "/api/v1/scan/domain",
            json={"domain": "www.web.com", "victim_domain": "example.com"},
            headers=AUTH,
        )

    assert response.status_code == 200
    full_scan.assert_called_once_with("web.com", victim_domain="example.com")
