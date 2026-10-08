"""Tests for src/intelligence/phishtank.py.

Covers: request timeout, the ``valid`` flag (verified-not-phish is not
phishing), ``phish_detail_page``, "not in database"/no results never being
clean, and the disabled submission path.
"""

import logging
from unittest.mock import MagicMock

import pytest
import requests

from src.intelligence import phishtank as pt_module
from src.intelligence.phishtank import PhishTankIntegration

URL = "http://phish.example/login"


def _resp(status=200, body=None, json_error=False):
    resp = MagicMock()
    resp.status_code = status
    if json_error:
        resp.json.side_effect = ValueError("bad")
    else:
        resp.json.return_value = body
    return resp


def _results(**fields):
    base = {
        "url": URL,
        "in_database": True,
        "phish_id": "123",
        "phish_detail_page": "https://phishtank.org/phish_detail.php?phish_id=123",
        "verified": True,
        "verified_at": "2026-09-01T00:00:00+00:00",
        "valid": True,
    }
    base.update(fields)
    return {"meta": {}, "results": base}


@pytest.fixture
def pt():
    client = PhishTankIntegration(api_key="pt-test-key")
    client.session = MagicMock()
    return client


class TestLookup:
    def test_request_has_timeout_and_no_key_in_url(self, pt):
        pt.session.post.return_value = _resp(200, _results())
        pt.check_phishing_status(URL)
        args, kwargs = pt.session.post.call_args
        assert kwargs["timeout"] > 0
        assert "pt-test-key" not in args[0]

    def test_verified_valid_phish_is_listed(self, pt):
        pt.session.post.return_value = _resp(200, _results())
        result = pt.check_phishing_status(URL)
        assert result["status"] == "listed"
        assert result["is_phishing"] is True
        assert result["verified"] is True
        assert result["threat_level"] == "high"

    def test_verified_not_phish_is_not_phishing(self, pt):
        pt.session.post.return_value = _resp(200, _results(valid=False))
        result = pt.check_phishing_status(URL)
        assert result["is_phishing"] is False
        assert result["status"] == "not_listed"
        assert result["verified_not_phish"] is True
        assert result["threat_level"] != "critical"

    def test_string_booleans_are_parsed(self, pt):
        body = _results(in_database="true", verified="true", valid="false")
        pt.session.post.return_value = _resp(200, body)
        assert pt.check_phishing_status(URL)["is_phishing"] is False

    def test_unverified_invalid_submission_is_not_evidence(self, pt):
        # example.com repro: in_database with verified=False, valid=False (a
        # dead or rejected submission) must not count as phishing evidence.
        pt.session.post.return_value = _resp(200, _results(verified=False, valid=False))
        result = pt.check_phishing_status(URL)
        assert result["status"] == "not_listed"
        assert result["is_phishing"] is False
        assert result["verified"] is False
        assert result["stale_submission"] is True
        assert result["threat_level"] == "unknown"

    def test_unverified_live_report_is_listed_medium(self, pt):
        # Reported and still valid: the community vote is pending, and the
        # entry counts as medium evidence.
        pt.session.post.return_value = _resp(200, _results(verified=False, valid=True))
        result = pt.check_phishing_status(URL)
        assert result["status"] == "listed"
        assert result["is_phishing"] is True
        assert result["verified"] is False
        assert result["threat_level"] == "medium"

    def test_detail_page_field_is_read(self, pt):
        pt.session.post.return_value = _resp(200, _results())
        result = pt.check_phishing_status(URL)
        assert result["details_url"] == "https://phishtank.org/phish_detail.php?phish_id=123"

    def test_not_in_database_is_not_listed_not_clean(self, pt):
        pt.session.post.return_value = _resp(200, {"results": {"url": URL, "in_database": False}})
        result = pt.check_phishing_status(URL)
        assert result["status"] == "not_listed"
        assert result["is_phishing"] is False
        assert result["threat_level"] != "clean"

    def test_missing_results_is_no_data(self, pt):
        pt.session.post.return_value = _resp(200, {"meta": {}})
        result = pt.check_phishing_status(URL)
        assert result["status"] == "no_data"
        assert result["threat_level"] != "clean"

    def test_http_error_is_error(self, pt):
        pt.session.post.return_value = _resp(509)
        result = pt.check_phishing_status(URL)
        assert result["status"] == "error"
        assert "error" in result

    def test_unparseable_body_is_error(self, pt):
        pt.session.post.return_value = _resp(200, json_error=True)
        assert pt.check_phishing_status(URL)["status"] == "error"

    def test_timeout_is_error_and_retried_as_lookup(self, pt):
        pt.circuit_breaker.config.retry_backoff_base = 0.001
        pt.session.post.side_effect = requests.Timeout("slow")
        result = pt.check_phishing_status(URL)
        assert result["status"] == "error"
        assert pt.session.post.call_count == pt.circuit_breaker.config.max_retries


class TestSubmission:
    def test_submission_is_disabled_and_makes_no_request(self, pt, monkeypatch, caplog):
        monkeypatch.setattr(pt_module, "_submission_warning_logged", False)
        with caplog.at_level(logging.WARNING):
            first = pt.submit_phishing_url(URL)
            second = pt.submit_phishing_url(URL)
        assert first["success"] is False
        assert first["status"] == "not_supported"
        assert second["status"] == "not_supported"
        pt.session.post.assert_not_called()
        assert caplog.text.count("PhishTank submission is not supported") == 1
