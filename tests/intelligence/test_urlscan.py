"""
Unit tests for src/intelligence/urlscan.py -- URLscanIntegration + build_brand_query.
"""

import unittest
from unittest.mock import MagicMock, patch

from src.intelligence.urlscan import URLscanIntegration, build_brand_query


class TestBuildBrandQuery(unittest.TestCase):
    def test_builds_domain_and_title_query(self):
        query = build_brand_query("nequi")
        self.assertEqual(query, 'page.domain:*nequi* OR page.title:"nequi"')


class TestURLscanIntegration(unittest.TestCase):
    def setUp(self):
        self.integration = URLscanIntegration(api_key="test-api-key")

    @patch("src.intelligence.urlscan.requests.Session.get")
    def test_search_returns_results_list(self, mock_get):
        mock_get.return_value = MagicMock(
            status_code=200,
            json=lambda: {
                "results": [
                    {"page": {"domain": "nequi-verify.example.com", "url": "https://x/"}},
                ]
            },
        )
        result = self.integration.search(build_brand_query("nequi"))
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["page"]["domain"], "nequi-verify.example.com")

    @patch("src.intelligence.urlscan.requests.Session.get")
    def test_search_sends_api_key_header(self, mock_get):
        mock_get.return_value = MagicMock(status_code=200, json=lambda: {"results": []})
        self.integration.search("page.domain:*foo*")
        _, kwargs = mock_get.call_args
        self.assertEqual(kwargs["headers"], {"API-Key": "test-api-key"})

    @patch("src.intelligence.urlscan.requests.Session.get")
    def test_search_returns_empty_list_on_non_200(self, mock_get):
        mock_get.return_value = MagicMock(status_code=429)
        result = self.integration.search("page.domain:*foo*")
        self.assertEqual(result, [])

    def test_search_skips_request_when_no_api_key(self):
        integration = URLscanIntegration(api_key=None)
        with patch("src.intelligence.urlscan.requests.Session.get") as mock_get:
            result = integration.search("page.domain:*foo*")
        mock_get.assert_not_called()
        self.assertEqual(result, [])

    @patch(
        "src.intelligence.urlscan.requests.Session.get",
        side_effect=ConnectionError("down"),
    )
    def test_search_returns_empty_list_on_exception(self, mock_get):
        result = self.integration.search("page.domain:*foo*")
        self.assertEqual(result, [])


if __name__ == "__main__":
    unittest.main()
