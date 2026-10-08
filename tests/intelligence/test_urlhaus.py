"""
Unit tests for src/intelligence/urlhaus.py -- URLhausIntegration.
"""

import unittest
from unittest.mock import MagicMock, patch

from src.intelligence.urlhaus import URLhausIntegration


class TestURLhausIntegration(unittest.TestCase):
    def setUp(self):
        self.integration = URLhausIntegration(api_key="test-auth-key")

    @patch("src.intelligence.urlhaus.requests.Session.get")
    def test_fetch_recent_returns_urls_array_on_ok_status(self, mock_get):
        mock_get.return_value = MagicMock(
            status_code=200,
            json=lambda: {
                "query_status": "ok",
                "urls": [
                    {"id": "1", "url": "https://evil.example.com/", "url_status": "online"},
                    {"id": "2", "url": "https://evil2.example.com/", "url_status": "offline"},
                ],
            },
        )
        result = self.integration.fetch_recent()
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["url"], "https://evil.example.com/")

    @patch("src.intelligence.urlhaus.requests.Session.get")
    def test_fetch_recent_sends_auth_key_header(self, mock_get):
        mock_get.return_value = MagicMock(
            status_code=200, json=lambda: {"query_status": "ok", "urls": []}
        )
        self.integration.fetch_recent()
        _, kwargs = mock_get.call_args
        self.assertEqual(kwargs["headers"], {"Auth-Key": "test-auth-key"})

    @patch("src.intelligence.urlhaus.requests.Session.get")
    def test_fetch_recent_returns_empty_list_when_query_status_not_ok(self, mock_get):
        mock_get.return_value = MagicMock(
            status_code=200, json=lambda: {"query_status": "no_results"}
        )
        result = self.integration.fetch_recent()
        self.assertEqual(result, [])

    @patch("src.intelligence.urlhaus.requests.Session.get")
    def test_fetch_recent_returns_empty_list_on_non_200(self, mock_get):
        mock_get.return_value = MagicMock(status_code=503)
        result = self.integration.fetch_recent()
        self.assertEqual(result, [])

    def test_fetch_recent_skips_request_when_no_api_key(self):
        integration = URLhausIntegration(api_key=None)
        with patch("src.intelligence.urlhaus.requests.Session.get") as mock_get:
            result = integration.fetch_recent()
        mock_get.assert_not_called()
        self.assertEqual(result, [])

    @patch(
        "src.intelligence.urlhaus.requests.Session.get",
        side_effect=ConnectionError("down"),
    )
    def test_fetch_recent_returns_empty_list_on_exception(self, mock_get):
        result = self.integration.fetch_recent()
        self.assertEqual(result, [])


if __name__ == "__main__":
    unittest.main()
