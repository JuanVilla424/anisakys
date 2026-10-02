"""
Unit tests for src/intelligence/misp_client.py -- MISPClient.

No production MISP instance exists to test against live (confirmed with the
user); pymisp.PyMISP/MISPEvent are mocked (patched on the pymisp module
itself, since misp_client.py imports them lazily inside methods to avoid
PyMISP's constructor making a real HTTP call at import/construction time).
"""

import unittest
from unittest.mock import MagicMock, patch

from src.intelligence.misp_client import MISPClient


class TestMISPClient(unittest.TestCase):
    def setUp(self):
        self.client = MISPClient(url="https://misp.example.com", api_key="test-key")

    @patch("pymisp.PyMISP")
    @patch("pymisp.MISPEvent")
    def test_push_indicators_builds_event_and_adds_attributes(
        self, mock_event_cls, mock_pymisp_cls
    ):
        mock_event = MagicMock()
        mock_event_cls.return_value = mock_event
        mock_pymisp_instance = MagicMock()
        mock_pymisp_instance.add_event.return_value = {"Event": {"id": "1"}}
        mock_pymisp_cls.return_value = mock_pymisp_instance

        result = self.client.push_indicators(
            [
                {"type": "domain", "value": "evil.example.com"},
                {"type": "ip", "value": "203.0.113.5"},
                {"type": "url", "value": "https://evil.example.com/login"},
            ],
            event_info="Phishing campaign X",
        )

        self.assertEqual(mock_event.info, "Phishing campaign X")
        mock_event.add_attribute.assert_any_call("domain", "evil.example.com")
        mock_event.add_attribute.assert_any_call("ip-dst", "203.0.113.5")
        mock_event.add_attribute.assert_any_call("url", "https://evil.example.com/login")
        mock_pymisp_instance.add_event.assert_called_once_with(mock_event, pythonify=True)
        self.assertEqual(result, {"Event": {"id": "1"}})

    @patch("pymisp.PyMISP")
    @patch("pymisp.MISPEvent")
    def test_unknown_indicator_type_is_skipped(self, mock_event_cls, mock_pymisp_cls):
        mock_event = MagicMock()
        mock_event_cls.return_value = mock_event
        mock_pymisp_cls.return_value = MagicMock()

        self.client.push_indicators([{"type": "carrier-pigeon", "value": "x"}], event_info="x")

        mock_event.add_attribute.assert_not_called()

    def test_returns_none_when_unconfigured(self):
        client = MISPClient(url=None, api_key=None)
        result = client.push_indicators([{"type": "domain", "value": "x.com"}], event_info="x")
        self.assertIsNone(result)

    @patch("pymisp.PyMISP", side_effect=ConnectionError("down"))
    def test_returns_none_when_client_init_fails(self, mock_pymisp_cls):
        result = self.client.push_indicators([{"type": "domain", "value": "x.com"}], event_info="x")
        self.assertIsNone(result)

    @patch("pymisp.PyMISP")
    @patch("pymisp.MISPEvent")
    def test_returns_none_when_add_event_raises(self, mock_event_cls, mock_pymisp_cls):
        mock_event_cls.return_value = MagicMock()
        mock_pymisp_instance = MagicMock()
        mock_pymisp_instance.add_event.side_effect = Exception("server error")
        mock_pymisp_cls.return_value = mock_pymisp_instance

        result = self.client.push_indicators([{"type": "domain", "value": "x.com"}], event_info="x")

        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
