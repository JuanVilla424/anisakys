"""Tests for src/intelligence/google_safe_browsing.py.

Covers the "clean on error" fixes: ``checked`` only on HTTP 200 with a
parseable body, per-platform matches de-duplicated by threat type, the key
sent in ``X-Goog-Api-Key`` (never in the URL or logs), batching at 500 URLs
and the cacheDuration cache.
"""

import importlib
import logging
from unittest.mock import MagicMock, patch

import pytest
import requests

from src.intelligence.google_safe_browsing import GoogleSafeBrowsingIntegration

# The package re-exports a singleton named ``google_safe_browsing`` that
# shadows the submodule attribute, so fetch the module object explicitly.
gsb_module = importlib.import_module("src.intelligence.google_safe_browsing")

API_KEY = "AIzaTEST-not-a-real-key"
URL = "https://phish.example/login"


def _resp(status=200, body=None, json_error=False):
    """Build a mock HTTP response.

    Args:
        status: HTTP status code.
        body: JSON body returned by ``json()``.
        json_error: Make ``json()`` raise ``ValueError``.

    Returns:
        The mock response.
    """
    resp = MagicMock()
    resp.status_code = status
    resp.text = "" if body is None else str(body)
    if json_error:
        resp.json.side_effect = ValueError("not json")
    else:
        resp.json.return_value = {} if body is None else body
    return resp


def _match(url, threat_type, platform, cache="300s"):
    return {
        "threatType": threat_type,
        "platformType": platform,
        "threat": {"url": url},
        "cacheDuration": cache,
        "threatEntryType": "URL",
    }


@pytest.fixture
def gsb():
    return GoogleSafeBrowsingIntegration(api_key=API_KEY)


class TestCheckedOnlyOn200:
    @pytest.mark.parametrize("status", [400, 403, 429, 500, 503])
    def test_http_error_is_not_checked_and_not_safe(self, gsb, status):
        with patch.object(gsb_module.requests, "post", return_value=_resp(status)):
            result = gsb.check_url(URL)
        assert result["checked"] is False
        assert result["status"] == "error"
        assert result["safe"] is None
        assert result["error"]

    def test_unparseable_body_is_not_checked(self, gsb):
        with patch.object(gsb_module.requests, "post", return_value=_resp(json_error=True)):
            result = gsb.check_url(URL)
        assert result["checked"] is False
        assert result["status"] == "error"
        assert result["safe"] is None

    def test_non_object_body_is_not_checked(self, gsb):
        with patch.object(gsb_module.requests, "post", return_value=_resp(body=["x"])):
            result = gsb.check_url(URL)
        assert result["checked"] is False

    def test_timeout_is_error(self, gsb):
        with patch.object(gsb_module.requests, "post", side_effect=requests.exceptions.Timeout()):
            result = gsb.check_url(URL)
        assert result["checked"] is False
        assert result["error"] == "Request timeout"

    def test_empty_200_body_is_not_listed(self, gsb):
        with patch.object(gsb_module.requests, "post", return_value=_resp(200, {})):
            result = gsb.check_url(URL)
        assert result["checked"] is True
        assert result["status"] == "not_listed"
        assert result["safe"] is True

    def test_unconfigured_is_no_data(self):
        result = GoogleSafeBrowsingIntegration(api_key="").check_url(URL)
        assert result["checked"] is False
        assert result["status"] == "no_data"
        assert result["safe"] is None


class TestDedupe:
    def test_platform_duplicates_count_once_per_threat_type(self, gsb):
        body = {
            "matches": [
                _match(URL, "SOCIAL_ENGINEERING", p)
                for p in ("ANY_PLATFORM", "WINDOWS", "LINUX", "OSX", "ANDROID", "IOS")
            ]
            + [_match(URL, "MALWARE", "WINDOWS")]
        }
        with patch.object(gsb_module.requests, "post", return_value=_resp(200, body)):
            result = gsb.check_url(URL)
        assert result["status"] == "listed"
        assert result["safe"] is False
        assert result["threat_count"] == 2
        assert result["threat_types"] == ["SOCIAL_ENGINEERING", "MALWARE"]
        se = result["threats_found"][0]
        assert len(se["platform_types"]) == 6


class TestKeyHandling:
    def test_key_sent_in_header_not_url(self, gsb):
        with patch.object(gsb_module.requests, "post", return_value=_resp(200, {})) as post:
            gsb.check_url(URL)
        args, kwargs = post.call_args
        assert API_KEY not in args[0]
        assert "key=" not in args[0]
        assert kwargs["headers"]["X-Goog-Api-Key"] == API_KEY
        assert kwargs["timeout"] > 0

    def test_exception_text_with_key_is_redacted(self, gsb, caplog):
        err = requests.exceptions.ConnectionError(
            f"Max retries exceeded with url: /v4/threatMatches:find?key={API_KEY}"
        )
        with patch.object(gsb_module.requests, "post", side_effect=err):
            with caplog.at_level(logging.DEBUG):
                result = gsb.check_url(URL)
        assert API_KEY not in caplog.text
        assert API_KEY not in result["error"]


class TestBatching:
    def test_lookup_urls_batches_by_500(self, gsb):
        urls = [f"https://p{i}.example/" for i in range(1201)]

        def fake_post(url, json, headers, timeout):
            entries = json["threatInfo"]["threatEntries"]
            assert len(entries) <= 500
            first = entries[0]["url"]
            return _resp(200, {"matches": [_match(first, "SOCIAL_ENGINEERING", "ANY_PLATFORM")]})

        with patch.object(gsb_module.requests, "post", side_effect=fake_post) as post:
            results = gsb.lookup_urls(urls)
        assert post.call_count == 3
        assert len(results) == 1201
        assert results[urls[0]]["status"] == "listed"
        assert results[urls[500]]["status"] == "listed"
        assert results[urls[1]]["status"] == "not_listed"

    def test_chunk_error_marks_only_that_chunk(self, gsb):
        urls = [f"https://p{i}.example/" for i in range(600)]
        responses = iter([_resp(200, {}), _resp(503)])
        with patch.object(gsb_module.requests, "post", side_effect=lambda *a, **k: next(responses)):
            results = gsb.lookup_urls(urls)
        assert results[urls[0]]["status"] == "not_listed"
        assert results[urls[599]]["status"] == "error"
        assert results[urls[599]]["checked"] is False


class TestCacheDuration:
    def test_positive_result_cached_within_duration(self, gsb):
        body = {"matches": [_match(URL, "SOCIAL_ENGINEERING", "ANY_PLATFORM", "300s")]}
        with patch.object(gsb_module.requests, "post", return_value=_resp(200, body)) as post:
            first = gsb.check_url(URL)
            second = gsb.check_url(URL)
        assert post.call_count == 1
        assert first["status"] == second["status"] == "listed"
        assert second["cached"] is True

    def test_cache_expires(self, gsb):
        body = {"matches": [_match(URL, "SOCIAL_ENGINEERING", "ANY_PLATFORM", "300s")]}
        clock = [1000.0]
        with (
            patch.object(gsb_module.time, "monotonic", side_effect=lambda: clock[0]),
            patch.object(gsb_module.requests, "post", return_value=_resp(200, body)) as post,
        ):
            gsb.check_url(URL)
            clock[0] += 301
            gsb.check_url(URL)
        assert post.call_count == 2

    def test_negative_results_are_not_cached(self, gsb):
        with patch.object(gsb_module.requests, "post", return_value=_resp(200, {})) as post:
            gsb.check_url(URL)
            gsb.check_url(URL)
        assert post.call_count == 2
