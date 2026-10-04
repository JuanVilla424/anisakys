"""
Unit tests for PhishingUtils.determine_site_status (single-probe wrapper).

A single probe may show that a site is alive, but it must never confirm a
takedown: SSRF-blocked targets, network errors, error pages, bot challenges,
parking pages and pages containing the word "suspended" all keep the known
status. Only the takedown monitor (N consecutive failing cycles) marks sites
down.
"""

from typing import Optional
import socket
import unittest
from unittest.mock import patch

import requests
from requests.structures import CaseInsensitiveDict

from src.detection import liveness
from src.detection.liveness import ProbeClass, ProbeResult, SiteProbe
from src.detection.utils import PhishingUtils
from src.dns.network_utils import SSRFRedirectError

URL = "https://phish.example/login"
PUBLIC_INFOS = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.215.14", 0))]


def _probe(cls, code=None):
    result = ProbeResult(cls, "desktop_chrome", code)
    return SiteProbe(result, (result,), ("93.184.215.14",))


def _response(status, body):
    resp = requests.Response()
    resp.status_code = status
    resp._content = body.encode()
    resp._content_consumed = True
    resp.headers = CaseInsensitiveDict()
    resp.encoding = "utf-8"
    return resp


def _call(
    current_status: Optional[str] = "up",
    current_takedown: Optional[str] = None,
    resolved_ip: Optional[str] = "203.0.113.5",
):
    return PhishingUtils.determine_site_status(
        url=URL,
        resolved_ip=resolved_ip,
        current_status=current_status,
        current_takedown=current_takedown,
        timestamp="2026-01-01 00:00:00",
        timeout=10,
    )


class TestDetermineSiteStatus(unittest.TestCase):
    def test_ssrf_redirect_does_not_mark_down(self):
        with (
            patch.object(liveness.socket, "getaddrinfo", return_value=PUBLIC_INFOS),
            patch.object(
                liveness,
                "safe_get_with_redirects",
                side_effect=SSRFRedirectError("http://169.254.169.254/", "blocked"),
            ),
        ):
            status, takedown = _call()
        self.assertEqual(status, "up")
        self.assertIsNone(takedown)

    def test_already_down_site_keeps_its_takedown_date(self):
        with patch("src.detection.utils.probe_site", return_value=_probe(ProbeClass.NXDOMAIN)):
            status, takedown = _call("down", "2025-12-25 00:00:00")
        self.assertEqual(status, "down")
        self.assertEqual(takedown, "2025-12-25 00:00:00")

    def test_normal_200_response_marks_site_up(self):
        with (
            patch.object(liveness.socket, "getaddrinfo", return_value=PUBLIC_INFOS),
            patch.object(
                liveness, "safe_get_with_redirects", return_value=_response(200, "Welcome")
            ),
        ):
            status, takedown = _call()
        self.assertEqual(status, "up")
        self.assertIsNone(takedown)

    def test_suspended_lure_is_still_up(self):
        body = "This account has been suspended. Enter your password to restore access."
        with (
            patch.object(liveness.socket, "getaddrinfo", return_value=PUBLIC_INFOS),
            patch.object(liveness, "safe_get_with_redirects", return_value=_response(200, body)),
        ):
            status, takedown = _call()
        self.assertEqual(status, "up")
        self.assertIsNone(takedown)

    def test_network_error_does_not_mark_down(self):
        with (
            patch.object(liveness.socket, "getaddrinfo", return_value=PUBLIC_INFOS),
            patch.object(
                liveness, "safe_get_with_redirects", side_effect=requests.ConnectionError("boom")
            ),
        ):
            status, takedown = _call()
        self.assertEqual(status, "up")
        self.assertIsNone(takedown)

    def test_missing_resolved_ip_is_ignored(self):
        """Callers pass resolved_ip=None whenever RDAP failed; that is no evidence."""
        with patch("src.detection.utils.probe_site", return_value=_probe(ProbeClass.UP, 200)):
            status, _ = _call(resolved_ip=None)
        self.assertEqual(status, "up")

    def test_dead_down_site_back_up_is_resurrected(self):
        with patch("src.detection.utils.probe_site", return_value=_probe(ProbeClass.UP, 200)):
            status, takedown = _call("down", "2025-12-25 00:00:00")
        self.assertEqual(status, "up")
        self.assertIsNone(takedown)

    def test_waf_challenge_keeps_site_up(self):
        probe = _probe(ProbeClass.WAF_CHALLENGE, 403)
        with patch("src.detection.utils.probe_site", return_value=probe):
            status, _ = _call("up")
        self.assertEqual(status, "up")

    def test_unknown_caller_status_falls_back_to_stored_status(self):
        with (
            patch("src.detection.utils.probe_site", return_value=_probe(ProbeClass.PARKED, 200)),
            patch.object(PhishingUtils, "_stored_site_status", return_value=("parked", None)),
        ):
            status, takedown = _call(current_status=None)
        self.assertEqual(status, "parked")
        self.assertIsNone(takedown)

    def test_unknown_site_defaults_to_up(self):
        with (
            patch("src.detection.utils.probe_site", return_value=_probe(ProbeClass.NXDOMAIN)),
            patch.object(PhishingUtils, "_stored_site_status", return_value=(None, None)),
        ):
            status, _ = _call(current_status=None)
        self.assertEqual(status, "up")


if __name__ == "__main__":
    unittest.main()
