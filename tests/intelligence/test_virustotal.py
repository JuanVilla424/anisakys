"""Tests for src/intelligence/virustotal.py.

Covers: explicit timeouts on every call, domain/file lookups through the
circuit breaker, pending/0-engine/stale analyses reported as no data (never
clean), and the shared token bucket.
"""

from typing import Optional
import time
from unittest.mock import MagicMock, patch

import pytest
import requests

from src.circuit_breaker import CircuitState
from src.intelligence import virustotal as vt_module
from src.intelligence.provider_common import TokenBucket
from src.intelligence.virustotal import VirusTotalIntegration

URL = "https://phish.example/login"
FRESH = int(time.time()) - 3600
STALE = int(time.time()) - 8 * 86400


def _resp(status=200, body=None):
    resp = MagicMock()
    resp.status_code = status
    resp.json.return_value = body or {}
    return resp


def _report(stats, date: Optional[int] = FRESH):
    return {"data": {"attributes": {"last_analysis_stats": stats, "last_analysis_date": date}}}


CLEAN_STATS = {"malicious": 0, "suspicious": 0, "harmless": 70, "undetected": 20}
BAD_STATS = {"malicious": 12, "suspicious": 1, "harmless": 60, "undetected": 17}


@pytest.fixture
def vt():
    client = VirusTotalIntegration(api_key="vt-test-key", rate_limiter=TokenBucket(10_000))
    client.session = MagicMock()
    return client


class TestTimeouts:
    def test_url_lookup_has_timeout(self, vt):
        vt.session.get.return_value = _resp(200, _report(CLEAN_STATS))
        vt.scan_url(URL)
        assert vt.session.get.call_args.kwargs["timeout"] > 0

    def test_submission_has_timeout(self, vt):
        vt.session.get.return_value = _resp(404)
        vt.session.post.return_value = _resp(200)
        vt.scan_url(URL)
        assert vt.session.post.call_args.kwargs["timeout"] > 0

    def test_domain_report_has_timeout(self, vt):
        vt.session.get.return_value = _resp(200, _report(CLEAN_STATS))
        vt.get_domain_report("phish.example")
        assert vt.session.get.call_args.kwargs["timeout"] > 0

    def test_file_lookup_has_timeout(self, vt):
        vt.session.get.return_value = _resp(404)
        vt.lookup_file_hash("a" * 64)
        assert vt.session.get.call_args.kwargs["timeout"] > 0


class TestCircuitBreakerCoverage:
    def test_domain_and_file_lookups_use_breaker(self, vt):
        vt.session.get.return_value = _resp(200, _report(CLEAN_STATS))
        with patch.object(vt.circuit_breaker, "call", wraps=vt.circuit_breaker.call) as call:
            vt.get_domain_report("phish.example")
            vt.lookup_file_hash("b" * 64)
        assert call.call_count == 2

    def test_open_breaker_returns_error_for_domain(self, vt):
        vt.circuit_breaker._state = CircuitState.OPEN
        vt.circuit_breaker._last_failure_time = time.time()
        result = vt.get_domain_report("phish.example")
        assert result["status"] == "error"
        vt.session.get.assert_not_called()

    def test_submission_is_not_retried(self, vt):
        vt.session.get.return_value = _resp(404)
        err = requests.ConnectionError("reset")
        vt.session.post.side_effect = err
        result = vt.scan_url(URL)
        assert vt.session.post.call_count == 1
        assert result["status"] == "error"


class TestNoDataIsNotClean:
    def test_submitted_url_is_no_data(self, vt):
        vt.session.get.return_value = _resp(404)
        vt.session.post.return_value = _resp(200)
        result = vt.scan_url(URL)
        assert result["status"] == "no_data"
        assert result["submitted"] is True
        assert result["threat_level"] == "unknown"

    def test_zero_engines_is_no_data(self, vt):
        vt.session.get.return_value = _resp(200, _report({}))
        result = vt.scan_url(URL)
        assert result["status"] == "no_data"
        assert result["threat_level"] == "unknown"

    def test_fresh_clean_is_not_listed(self, vt):
        vt.session.get.return_value = _resp(200, _report(CLEAN_STATS))
        result = vt.scan_url(URL)
        assert result["status"] == "not_listed"
        assert result["threat_level"] == "clean"
        assert result["stale"] is False

    def test_stale_clean_is_no_data(self, vt):
        vt.session.get.return_value = _resp(200, _report(CLEAN_STATS, STALE))
        result = vt.scan_url(URL)
        assert result["status"] == "no_data"
        assert result["stale"] is True
        assert result["threat_level"] != "clean"

    def test_missing_date_is_stale(self, vt):
        vt.session.get.return_value = _resp(200, _report(CLEAN_STATS, None))
        result = vt.scan_url(URL)
        assert result["stale"] is True
        assert result["status"] == "no_data"

    def test_stale_detections_stay_listed(self, vt):
        vt.session.get.return_value = _resp(200, _report(BAD_STATS, STALE))
        result = vt.scan_url(URL)
        assert result["status"] == "listed"
        assert result["stale"] is True
        assert result["threat_level"] == "high"

    def test_unconfigured_is_no_data(self):
        result = VirusTotalIntegration(api_key=None).scan_url(URL)
        assert result["status"] == "no_data"

    def test_http_error_is_error(self, vt):
        vt.session.get.return_value = _resp(500)
        result = vt.scan_url(URL)
        assert result["status"] == "error"
        assert result["threat_level"] == "unknown"

    def test_unknown_file_is_no_data(self, vt):
        vt.session.get.return_value = _resp(404)
        result = vt.lookup_file_hash("c" * 64)
        assert result == {"found": False, "status": "no_data", "threat_level": "unknown"}

    def test_stale_clean_domain_is_no_data(self, vt):
        vt.session.get.return_value = _resp(200, _report(CLEAN_STATS, STALE))
        assert vt.get_domain_report("phish.example")["status"] == "no_data"


class TestRateLimit:
    def test_empty_bucket_returns_rate_limited_error_without_request(self, vt):
        bucket = MagicMock()
        bucket.acquire.return_value = False
        vt._rate_limiter = bucket
        result = vt.scan_url(URL)
        assert result["status"] == "error"
        assert result["reason"] == "rate_limited"
        vt.session.get.assert_not_called()
        # Local throttling is not an upstream failure.
        assert vt.circuit_breaker.stats.failed_requests == 0

    def test_every_request_draws_a_token(self, vt):
        bucket = MagicMock()
        bucket.acquire.return_value = True
        vt._rate_limiter = bucket
        vt.session.get.return_value = _resp(404)
        vt.session.post.return_value = _resp(200)
        vt.scan_url(URL)
        assert bucket.acquire.call_count == 2

    def test_shared_bucket_defaults_to_public_quota(self, monkeypatch):
        monkeypatch.setattr(vt_module, "_rate_limiter", None)
        bucket = vt_module.get_rate_limiter()
        assert bucket is vt_module.get_rate_limiter()
        assert bucket.capacity == 4
        assert bucket.rate_per_second == pytest.approx(4 / 60)
