"""Tests for src/detection/liveness.py (probe classification, offline).

One test per class: up, nxdomain, connection_error, http_error, waf_challenge,
parked and ssrf_blocked, plus multi-profile combination and the connectivity
canary. HTTP is mocked at the SSRF-safe fetch helper; DNS at getaddrinfo.
"""

import socket
from unittest.mock import patch

import pytest
import requests
from requests.structures import CaseInsensitiveDict

from src.detection import liveness
from src.detection.liveness import (
    DEFAULT_PROFILES,
    DESKTOP_CHROME,
    MOBILE_SAFARI,
    ProbeClass,
    ProbeResult,
    classify_response,
    combine,
    network_is_healthy,
    probe_site,
    probe_with_profile,
    resolve_host,
)
from src.dns.network_utils import SSRFRedirectError

URL = "https://phish.example/login"


def make_response(status, body="", headers=None):
    """Build a real, already-consumed ``requests.Response``."""
    resp = requests.Response()
    resp.status_code = status
    resp._content = body.encode() if isinstance(body, str) else body
    resp._content_consumed = True
    resp.headers = CaseInsensitiveDict(headers or {})
    resp.encoding = "utf-8"
    resp.url = URL
    return resp


def public_dns(host):
    return None, ("203.0.113.10",)


CF_CHALLENGE = (
    "<!DOCTYPE html><html><head><title>Just a moment...</title></head>"
    '<body><script src="/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page/v1"></script>'
    "</body></html>"
)
GODADDY_PARKED = (
    '<html><head><script>window.location.href="/lander"</script></head>'
    '<body><img src="https://img1.wsimg.com/parking-lander/static/logo.svg"></body></html>'
)
SUSPENDED_LURE = (
    "<html><body><h1>Your account has been suspended</h1>"
    '<form><input name="email"><input type="password" name="pw"></form></body></html>'
)


class TestClassifyResponse:
    def test_plain_200_is_up(self):
        assert classify_response(200, {}, "<html>hello</html>", "p").classification == "up"

    def test_suspended_word_is_not_down(self):
        result = classify_response(200, {}, SUSPENDED_LURE, "p")
        assert result.classification == ProbeClass.UP
        assert result.is_alive

    @pytest.mark.parametrize("status", [403, 503])
    def test_cloudflare_challenge_page(self, status):
        headers = {"Server": "cloudflare"}
        result = classify_response(status, headers, CF_CHALLENGE, "p")
        assert result.classification == ProbeClass.WAF_CHALLENGE
        assert result.is_alive and not result.is_failure

    def test_cf_mitigated_header_is_challenge_on_any_status(self):
        result = classify_response(200, {"cf-mitigated": "challenge"}, "", "p")
        assert result.classification == ProbeClass.WAF_CHALLENGE

    def test_akamai_block_is_challenge(self):
        body = "<HTML><HEAD><TITLE>Access Denied</TITLE></HEAD>Reference #18.abc</HTML>"
        result = classify_response(403, {"Server": "AkamaiGHost"}, body, "p")
        assert result.classification == ProbeClass.WAF_CHALLENGE

    def test_rate_limit_with_captcha_is_challenge(self):
        body = '<div class="g-recaptcha" data-sitekey="x"></div>'
        result = classify_response(429, {"Server": "nginx"}, body, "p")
        assert result.classification == ProbeClass.WAF_CHALLENGE

    def test_aws_waf_header_is_challenge(self):
        result = classify_response(405, {"x-amzn-waf-action": "captcha"}, "", "p")
        assert result.classification == ProbeClass.WAF_CHALLENGE

    def test_plain_403_is_inconclusive_http_error(self):
        result = classify_response(403, {"Server": "nginx"}, "Forbidden", "p")
        assert result.classification == ProbeClass.HTTP_ERROR
        assert not result.is_failure and not result.is_alive

    @pytest.mark.parametrize("status", [404, 410])
    def test_404_410_are_failures(self, status):
        result = classify_response(status, {}, "Not Found", "p")
        assert result.classification == ProbeClass.HTTP_ERROR
        assert result.is_failure

    @pytest.mark.parametrize("status", [401, 451, 500, 502, 503])
    def test_other_errors_are_inconclusive(self, status):
        result = classify_response(status, {"Server": "Apache"}, "error", "p")
        assert result.classification == ProbeClass.HTTP_ERROR
        assert not result.is_failure

    def test_cloudflare_origin_down_is_connection_error(self):
        result = classify_response(522, {"Server": "cloudflare"}, "Connection timed out", "p")
        assert result.classification == ProbeClass.CONNECTION_ERROR
        assert result.is_failure

    def test_parking_page_is_parked(self):
        result = classify_response(200, {}, GODADDY_PARKED, "p")
        assert result.classification == ProbeClass.PARKED
        assert not result.is_alive and not result.is_failure

    @pytest.mark.parametrize(
        "marker",
        ["sedoparking.com", "parkingcrew.net", "parkingpage.namecheap.com", "bodis.com/"],
    )
    def test_known_parking_services(self, marker):
        body = f'<script src="https://{marker}/js"></script>'
        assert classify_response(200, {}, body, "p").classification == ProbeClass.PARKED

    def test_parking_marker_with_password_form_is_up(self):
        body = GODADDY_PARKED + '<input type="password">'
        assert classify_response(200, {}, body, "p").classification == ProbeClass.UP

    def test_generic_for_sale_text_is_not_parked(self):
        body = "<h1>This domain is for sale!</h1><p>Login to continue</p>"
        assert classify_response(200, {}, body, "p").classification == ProbeClass.UP


class TestResolveHost:
    def test_nxdomain(self):
        err = socket.gaierror(socket.EAI_NONAME, "Name or service not known")
        with patch.object(liveness.socket, "getaddrinfo", side_effect=err):
            failure, ips = resolve_host("gone.example")
        assert failure.classification == ProbeClass.NXDOMAIN
        assert failure.is_failure
        assert ips == ()

    def test_temporary_dns_failure_is_connection_error(self):
        err = socket.gaierror(socket.EAI_AGAIN, "Temporary failure in name resolution")
        with patch.object(liveness.socket, "getaddrinfo", side_effect=err):
            failure, _ = resolve_host("flaky.example")
        assert failure.classification == ProbeClass.CONNECTION_ERROR

    def test_private_address_is_ssrf_blocked(self):
        infos = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 0))]
        with patch.object(liveness.socket, "getaddrinfo", return_value=infos):
            failure, ips = resolve_host("internal.example")
        assert failure.classification == ProbeClass.SSRF_BLOCKED
        assert not failure.is_failure
        assert ips == ("10.0.0.5",)

    def test_public_address_resolves(self):
        infos = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.215.14", 0))]
        with patch.object(liveness.socket, "getaddrinfo", return_value=infos):
            failure, ips = resolve_host("phish.example")
        assert failure is None
        assert ips == ("93.184.215.14",)

    def test_loopback_literal_is_blocked_without_dns(self):
        with patch.object(liveness.socket, "getaddrinfo") as gai:
            failure, _ = resolve_host("127.0.0.1")
        assert failure.classification == ProbeClass.SSRF_BLOCKED
        gai.assert_not_called()


class TestProbeWithProfile:
    def test_ssrf_redirect_is_blocked(self):
        err = SSRFRedirectError("http://169.254.169.254/", "blocked")
        with patch.object(liveness, "safe_get_with_redirects", side_effect=err):
            result = probe_with_profile(URL, DESKTOP_CHROME, 5)
        assert result.classification == ProbeClass.SSRF_BLOCKED
        assert not result.is_failure

    @pytest.mark.parametrize(
        "exc, detail",
        [
            (requests.ConnectTimeout("t"), "timeout"),
            (requests.ReadTimeout("t"), "timeout"),
            (requests.ConnectionError("refused"), "connection_failed"),
        ],
    )
    def test_network_errors_are_connection_errors(self, exc, detail):
        with patch.object(liveness, "safe_get_with_redirects", side_effect=exc):
            result = probe_with_profile(URL, DESKTOP_CHROME, 5)
        assert result.classification == ProbeClass.CONNECTION_ERROR
        assert result.detail == detail

    def test_tls_error_retried_without_verification(self):
        calls = []

        def fake_get(url, **kwargs):
            calls.append(kwargs.get("verify", True))
            if kwargs.get("verify", True):
                raise requests.exceptions.SSLError("certificate has expired")
            return make_response(200, "<html>phish</html>")

        with patch.object(liveness, "safe_get_with_redirects", side_effect=fake_get):
            result = probe_with_profile(URL, DESKTOP_CHROME, 5)
        assert calls == [True, False]
        assert result.classification == ProbeClass.UP

    def test_too_many_redirects_is_inconclusive(self):
        err = requests.TooManyRedirects("loop")
        with patch.object(liveness, "safe_get_with_redirects", side_effect=err):
            result = probe_with_profile(URL, DESKTOP_CHROME, 5)
        assert result.classification == ProbeClass.HTTP_ERROR
        assert not result.is_failure

    def test_profile_headers_and_timeout_are_sent(self):
        with patch.object(
            liveness, "safe_get_with_redirects", return_value=make_response(200, "ok")
        ) as get:
            probe_with_profile(URL, MOBILE_SAFARI, 7)
        kwargs = get.call_args.kwargs
        assert "iPhone" in kwargs["headers"]["User-Agent"]
        assert kwargs["timeout"] == 7
        assert kwargs["stream"] is True


class TestProbeSite:
    def test_uses_at_least_two_profiles(self):
        assert len(DEFAULT_PROFILES) >= 2
        assert len({p.headers["User-Agent"] for p in DEFAULT_PROFILES}) == len(DEFAULT_PROFILES)

    def test_cloaking_towards_desktop_still_up(self):
        responses = iter([make_response(404, "nope"), make_response(200, "<html>phish</html>")])
        with patch.object(
            liveness, "safe_get_with_redirects", side_effect=lambda *a, **k: next(responses)
        ) as get:
            probe = probe_site(URL, 5, resolver=public_dns)
        assert get.call_count == 2
        assert probe.result.classification == ProbeClass.UP
        assert probe.result.profile == "mobile_safari"

    def test_both_profiles_404_is_failure(self):
        with patch.object(
            liveness, "safe_get_with_redirects", side_effect=lambda *a, **k: make_response(404)
        ):
            probe = probe_site(URL, 5, resolver=public_dns)
        assert probe.result.is_failure
        assert len(probe.observations) == 2

    def test_alive_first_profile_skips_second(self):
        with patch.object(
            liveness, "safe_get_with_redirects", return_value=make_response(200, "ok")
        ) as get:
            probe = probe_site(URL, 5, resolver=public_dns)
        assert get.call_count == 1
        assert probe.result.is_alive
        assert probe.resolved_ips == ("203.0.113.10",)

    def test_nxdomain_short_circuits_http(self):
        failure = ProbeResult(ProbeClass.NXDOMAIN, "dns", None, "nxdomain")
        with patch.object(liveness, "safe_get_with_redirects") as get:
            probe = probe_site(URL, 5, resolver=lambda host: (failure, ()))
        get.assert_not_called()
        assert probe.result.classification == ProbeClass.NXDOMAIN

    def test_404_plus_challenge_is_alive(self):
        responses = iter(
            [make_response(404), make_response(403, CF_CHALLENGE, {"Server": "cloudflare"})]
        )
        with patch.object(
            liveness, "safe_get_with_redirects", side_effect=lambda *a, **k: next(responses)
        ):
            probe = probe_site(URL, 5, resolver=public_dns)
        assert probe.result.classification == ProbeClass.WAF_CHALLENGE

    def test_url_without_host_is_inconclusive(self):
        probe = probe_site("http://", 5, resolver=public_dns)
        assert probe.result.classification == ProbeClass.HTTP_ERROR
        assert not probe.result.is_failure


class TestCombine:
    def test_failure_only_if_all_fail(self):
        a = ProbeResult(ProbeClass.CONNECTION_ERROR, "a")
        b = ProbeResult(ProbeClass.HTTP_ERROR, "b", 500)
        assert combine([a, b]).classification == ProbeClass.HTTP_ERROR

    def test_parked_beats_failures(self):
        a = ProbeResult(ProbeClass.HTTP_ERROR, "a", 404)
        b = ProbeResult(ProbeClass.PARKED, "b", 200)
        assert combine([a, b]).classification == ProbeClass.PARKED

    def test_empty_raises(self):
        with pytest.raises(ValueError):
            combine([])


class TestCanary:
    def test_empty_list_is_healthy(self):
        assert network_is_healthy([], 1) is True

    def test_all_canaries_down_is_unhealthy(self):
        with patch.object(liveness.requests, "get", side_effect=requests.ConnectionError()):
            assert network_is_healthy(["https://a.example", "https://b.example"], 1) is False

    def test_one_canary_up_is_healthy(self):
        responses = [requests.ConnectionError(), make_response(204)]

        def fake_get(*a, **k):
            item = responses.pop(0)
            if isinstance(item, Exception):
                raise item
            return item

        with patch.object(liveness.requests, "get", side_effect=fake_get):
            assert network_is_healthy(["https://a.example", "https://b.example"], 1) is True
