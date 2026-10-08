"""Tests for src/intelligence/urlvoid.py.

The client is unverified against the vendor's documented API, so it must be
disabled by default and every disabled/unconfigured/unknown outcome must be
``no_data`` (never clean).
"""

import logging
from unittest.mock import MagicMock

import pytest
import requests

from src.intelligence import urlvoid as uv_module
from src.intelligence.urlvoid import URLVoidIntegration

DOMAIN = "phish.example"


def _resp(status=200, body=None):
    resp = MagicMock()
    resp.status_code = status
    resp.json.return_value = body
    return resp


@pytest.fixture
def enabled_client():
    client = URLVoidIntegration(api_key="uv-test-key", enabled=True)
    client.session = MagicMock()
    return client


class TestDisabledByDefault:
    def test_setting_defaults_to_false(self):
        from src.config import Settings

        assert Settings.model_fields["URLVOID_ENABLED"].default is False

    def test_disabled_client_makes_no_request_and_returns_no_data(self):
        client = URLVoidIntegration(api_key="uv-test-key", enabled=False)
        client.session = MagicMock()
        result = client.analyze_domain(DOMAIN)
        assert result["status"] == "no_data"
        assert result["threat_level"] == "unknown"
        assert "error" not in result
        client.session.get.assert_not_called()

    def test_unconfigured_client_returns_no_data(self):
        client = URLVoidIntegration(api_key=None, enabled=True)
        client.api_key = None
        assert client.analyze_domain(DOMAIN)["status"] == "no_data"

    def test_startup_warning_when_key_set_but_disabled(self, monkeypatch, caplog):
        monkeypatch.setattr(uv_module, "_startup_warning_logged", False)
        with caplog.at_level(logging.WARNING):
            URLVoidIntegration(api_key="uv-test-key", enabled=False)
            URLVoidIntegration(api_key="uv-test-key", enabled=False)
        assert caplog.text.count("URLVoid is disabled") == 1

    def test_startup_warning_when_enabled(self, monkeypatch, caplog):
        monkeypatch.setattr(uv_module, "_startup_warning_logged", False)
        with caplog.at_level(logging.WARNING):
            URLVoidIntegration(api_key="uv-test-key", enabled=True)
        assert "unverified" in caplog.text


class TestEnabledClient:
    def test_request_has_timeout(self, enabled_client):
        enabled_client.session.get.return_value = _resp(200, {"data": {"report": {}}})
        enabled_client.analyze_domain(DOMAIN)
        assert enabled_client.session.get.call_args.kwargs["timeout"] > 0

    def test_empty_report_is_no_data_not_clean(self, enabled_client):
        enabled_client.session.get.return_value = _resp(200, {"data": {"report": {}}})
        result = enabled_client.analyze_domain(DOMAIN)
        assert result["status"] == "no_data"
        assert result["threat_level"] == "unknown"
        assert result["safety_score"] is None

    def test_empty_blacklist_without_score_is_not_clean(self, enabled_client):
        body = {"data": {"report": {"blacklists": []}}}
        enabled_client.session.get.return_value = _resp(200, body)
        assert enabled_client.analyze_domain(DOMAIN)["threat_level"] == "unknown"

    def test_high_score_is_not_listed(self, enabled_client):
        body = {"data": {"report": {"safety_score": 95, "blacklists": []}}}
        enabled_client.session.get.return_value = _resp(200, body)
        result = enabled_client.analyze_domain(DOMAIN)
        assert result["status"] == "not_listed"
        assert result["threat_level"] == "clean"

    def test_blacklisted_is_listed(self, enabled_client):
        body = {"data": {"report": {"safety_score": 20, "blacklists": ["a", "b", "c"]}}}
        enabled_client.session.get.return_value = _resp(200, body)
        result = enabled_client.analyze_domain(DOMAIN)
        assert result["status"] == "listed"
        assert result["threat_level"] == "high"

    def test_http_error_is_error(self, enabled_client):
        enabled_client.session.get.return_value = _resp(403)
        assert enabled_client.analyze_domain(DOMAIN)["status"] == "error"

    def test_key_is_redacted_from_errors(self, enabled_client, caplog):
        enabled_client.circuit_breaker.config.max_retries = 1
        err = requests.ConnectionError(
            "Max retries exceeded with url: /v1/host/phish.example?key=uv-test-key&host=x"
        )
        enabled_client.session.get.side_effect = err
        with caplog.at_level(logging.DEBUG):
            result = enabled_client.analyze_domain(DOMAIN)
        assert result["status"] == "error"
        assert "uv-test-key" not in result["error"]
        assert "uv-test-key" not in caplog.text
