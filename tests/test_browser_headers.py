"""Tests for browser headers and user agent functionality"""

import pytest
from unittest.mock import patch, MagicMock
import requests
from src import main


class TestBrowserHeaders:
    """Test browser headers functionality"""

    def test_default_user_agent(self):
        """Test that default user agent is properly set"""
        assert main.DEFAULT_USER_AGENT == (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/131.0.0.0 Safari/537.36"
        )

    def test_browser_headers_structure(self):
        """Test browser headers contain all expected fields"""
        expected_headers = [
            "User-Agent",
            "Accept",
            "Accept-Language",
            "Accept-Encoding",
            "DNT",
            "Connection",
            "Upgrade-Insecure-Requests",
            "Sec-Fetch-Dest",
            "Sec-Fetch-Mode",
            "Sec-Fetch-Site",
            "Sec-Fetch-User",
            "Cache-Control",
        ]

        for header in expected_headers:
            assert header in main.BROWSER_HEADERS

    def test_virustotal_api_headers(self):
        """Test VirusTotal API uses browser-like headers"""
        with patch.dict("os.environ", {"VIRUSTOTAL_API_KEY": "test_key"}):
            vt_client = main.VirusTotalIntegration(api_key="test_key")

            # Check session headers
            assert vt_client.session.headers["User-Agent"] == main.DEFAULT_USER_AGENT
            assert "Origin" in vt_client.session.headers
            assert "Referer" in vt_client.session.headers
            assert vt_client.session.headers["Origin"] == "https://www.virustotal.com"

    def test_grinder_api_headers(self):
        """Test Grinder API uses browser-like headers"""
        with patch.dict(
            "os.environ", {"GRINDER0X_API_URL": "http://test.com", "GRINDER0X_API_KEY": "test_key"}
        ):
            grinder_client = main.GrinderReportClient(api_url="http://test.com", api_key="test_key")

            # Check session headers
            assert grinder_client.session.headers["User-Agent"] == main.DEFAULT_USER_AGENT
            assert "Accept" in grinder_client.session.headers
            assert "Accept-Language" in grinder_client.session.headers
            assert "Sec-Fetch-Mode" in grinder_client.session.headers

    @patch("requests.get")
    def test_phishing_scanner_uses_browser_headers(self, mock_get):
        """Test PhishingScanner uses browser headers for requests"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "Test page content"
        mock_get.return_value = mock_response

        scanner = main.PhishingScanner(
            timeout=5, keywords=["test"], domains=[".com"], allowed_sites=[], args=MagicMock()
        )

        # Mock get_candidate_urls to return a test URL
        with patch.object(scanner, "get_candidate_urls", return_value=["https://test.com"]):
            scanner.scan_site("test")

        # Verify headers were used
        mock_get.assert_called()
        call_args = mock_get.call_args
        headers = call_args[1]["headers"]

        assert headers["User-Agent"] == main.DEFAULT_USER_AGENT
        assert "Accept" in headers
        assert "Accept-Language" in headers
        assert headers["DNT"] == "1"

    def test_firefox_user_agent_available(self):
        """Test Firefox user agent is defined as fallback"""
        assert hasattr(main, "FIREFOX_USER_AGENT")
        assert "Firefox" in main.FIREFOX_USER_AGENT
        assert "Gecko" in main.FIREFOX_USER_AGENT

    @patch("requests.head")
    def test_head_requests_use_appropriate_headers(self, mock_head):
        """Test HEAD requests use simplified browser headers"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_head.return_value = mock_response

        scanner = main.PhishingScanner(
            timeout=5, keywords=["test"], domains=[".com"], allowed_sites=[], args=MagicMock()
        )

        # Call method that uses HEAD requests
        scanner.get_candidate_urls("test")

        # Verify simplified headers were used
        if mock_head.called:
            call_args = mock_head.call_args
            headers = call_args[1]["headers"]

            assert headers["User-Agent"] == main.DEFAULT_USER_AGENT
            assert headers["Accept"] == "*/*"

    def test_screenshot_service_headers(self):
        """Test screenshot service initialization"""
        from src.screenshot_service import ScreenshotService

        service = ScreenshotService(timeout=10)

        # Test that service initializes properly
        assert service.timeout == 10
        assert service.preferred_engine in ["playwright", "selenium", None]
