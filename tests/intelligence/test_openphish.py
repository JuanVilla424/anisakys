"""
Unit tests for src/intelligence/openphish.py -- OpenPhishIntegration.
"""

import unittest
from unittest.mock import MagicMock, patch

from src.intelligence.openphish import OpenPhishIntegration


class TestOpenPhishIntegration(unittest.TestCase):
    def setUp(self):
        self.integration = OpenPhishIntegration()

    @patch("src.intelligence.openphish.requests.Session.get")
    def test_fetch_feed_parses_newline_separated_urls(self, mock_get):
        mock_get.return_value = MagicMock(
            status_code=200,
            text="https://evil1.example.com/login\nhttps://evil2.example.com/verify\n\n",
        )
        result = self.integration.fetch_feed()
        self.assertEqual(
            result,
            {"https://evil1.example.com/login", "https://evil2.example.com/verify"},
        )

    @patch("src.intelligence.openphish.requests.Session.get")
    def test_fetch_feed_returns_empty_set_on_non_200(self, mock_get):
        mock_get.return_value = MagicMock(status_code=503, text="")
        result = self.integration.fetch_feed()
        self.assertEqual(result, set())

    @patch("src.intelligence.openphish.requests.Session.get", side_effect=ConnectionError("down"))
    def test_fetch_feed_returns_empty_set_on_exception(self, mock_get):
        result = self.integration.fetch_feed()
        self.assertEqual(result, set())

    def test_uses_the_real_community_feed_url(self):
        self.assertEqual(
            self.integration.feed_url,
            "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt",
        )


if __name__ == "__main__":
    unittest.main()
