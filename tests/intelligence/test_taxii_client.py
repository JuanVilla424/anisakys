"""
Unit tests for src/intelligence/taxii_client.py -- TAXIIClient.

No production TAXII server exists to test against live (confirmed with the
user); every test here mocks requests.Session.request against the real
TAXII 2.1 REST shape confirmed from the OASIS spec this session.
"""

import unittest
from unittest.mock import MagicMock, patch

from src.intelligence.taxii_client import TAXIIClient


class TestTAXIIClient(unittest.TestCase):
    def setUp(self):
        self.client = TAXIIClient(
            base_url="https://taxii.example.com", username="user", password="pass"
        )

    @patch("src.intelligence.taxii_client.requests.Session.request")
    def test_discover_hits_correct_path(self, mock_request):
        mock_request.return_value = MagicMock(
            status_code=200, json=lambda: {"title": "Example TAXII", "api_roots": ["/api1/"]}
        )
        result = self.client.discover()
        args, kwargs = mock_request.call_args
        self.assertEqual(args[0], "GET")
        self.assertEqual(args[1], "https://taxii.example.com/taxii2/")
        self.assertEqual(result["title"], "Example TAXII")

    @patch("src.intelligence.taxii_client.requests.Session.request")
    def test_sends_correct_media_type_headers(self, mock_request):
        mock_request.return_value = MagicMock(status_code=200, json=lambda: {})
        self.client.discover()
        _, kwargs = mock_request.call_args
        self.assertEqual(kwargs["headers"]["Accept"], "application/taxii+json;version=2.1")
        self.assertEqual(kwargs["headers"]["Content-Type"], "application/taxii+json;version=2.1")

    @patch("src.intelligence.taxii_client.requests.Session.request")
    def test_sends_basic_auth_when_credentials_configured(self, mock_request):
        mock_request.return_value = MagicMock(status_code=200, json=lambda: {})
        self.client.discover()
        _, kwargs = mock_request.call_args
        self.assertEqual(kwargs["auth"].username, "user")
        self.assertEqual(kwargs["auth"].password, "pass")

    def test_no_auth_when_no_credentials_configured(self):
        client = TAXIIClient(base_url="https://taxii.example.com")
        self.assertIsNone(client.auth)

    @patch("src.intelligence.taxii_client.requests.Session.request")
    def test_get_collections_returns_collections_list(self, mock_request):
        mock_request.return_value = MagicMock(
            status_code=200, json=lambda: {"collections": [{"id": "col-1", "title": "Feed"}]}
        )
        result = self.client.get_collections("api1")
        args, _ = mock_request.call_args
        self.assertEqual(args[1], "https://taxii.example.com/api1/collections/")
        self.assertEqual(result, [{"id": "col-1", "title": "Feed"}])

    @patch("src.intelligence.taxii_client.requests.Session.request")
    def test_pull_objects_returns_objects_list(self, mock_request):
        mock_request.return_value = MagicMock(
            status_code=200, json=lambda: {"objects": [{"type": "indicator", "id": "indicator--1"}]}
        )
        result = self.client.pull_objects("api1", "col-1")
        args, _ = mock_request.call_args
        self.assertEqual(args[1], "https://taxii.example.com/api1/collections/col-1/objects/")
        self.assertEqual(result, [{"type": "indicator", "id": "indicator--1"}])

    @patch("src.intelligence.taxii_client.requests.Session.request")
    def test_push_objects_posts_correct_envelope(self, mock_request):
        mock_request.return_value = MagicMock(status_code=202, json=lambda: {"status": "pending"})
        stix_objects = [{"type": "indicator", "id": "indicator--1"}]
        result = self.client.push_objects("api1", "col-1", stix_objects)
        args, kwargs = mock_request.call_args
        self.assertEqual(args[0], "POST")
        self.assertEqual(kwargs["json"], {"objects": stix_objects})
        self.assertEqual(result, {"status": "pending"})

    def test_missing_base_url_skips_request_entirely(self):
        client = TAXIIClient(base_url=None)
        with patch("src.intelligence.taxii_client.requests.Session.request") as mock_request:
            result = client.discover()
        mock_request.assert_not_called()
        self.assertEqual(result, {})

    @patch("src.intelligence.taxii_client.requests.Session.request")
    def test_non_2xx_status_returns_empty(self, mock_request):
        mock_request.return_value = MagicMock(status_code=500)
        result = self.client.get_collections("api1")
        self.assertEqual(result, [])

    @patch(
        "src.intelligence.taxii_client.requests.Session.request",
        side_effect=ConnectionError("down"),
    )
    def test_connection_error_returns_empty(self, mock_request):
        result = self.client.pull_objects("api1", "col-1")
        self.assertEqual(result, [])


if __name__ == "__main__":
    unittest.main()
