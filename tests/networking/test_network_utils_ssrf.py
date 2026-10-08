"""
Unit tests for the SSRF guard in src.dns.network_utils.

assess_url_target must:
- reject non-http(s) schemes and hostless URLs as "invalid",
- classify literal-IP hosts without any DNS,
- resolve DNS hostnames and block any that reach a non-public address
  (private, loopback, link-local incl. cloud metadata, multicast, reserved),
- return "unresolved" when a host cannot be resolved (external threat-intel
  APIs may still be queried, but nothing internal was reached).
"""

import unittest
from unittest.mock import patch, MagicMock

import requests

from src.dns.network_utils import (
    assess_url_target,
    _ip_is_public,
    safe_get_with_redirects,
    SSRFRedirectError,
)


def _addrinfo(ip: str):
    """Minimal getaddrinfo return shape: (family, type, proto, canon, sockaddr)."""
    return [(2, 1, 6, "", (ip, 0))]


class TestIpIsPublic(unittest.TestCase):
    def test_public_ipv4(self):
        self.assertTrue(_ip_is_public("8.8.8.8"))

    def test_private_ranges_blocked(self):
        for ip in ("10.0.0.1", "192.168.1.1", "172.16.0.1"):
            self.assertFalse(_ip_is_public(ip), ip)

    def test_loopback_blocked(self):
        self.assertFalse(_ip_is_public("127.0.0.1"))
        self.assertFalse(_ip_is_public("::1"))

    def test_cloud_metadata_blocked(self):
        # 169.254.169.254 is link-local — the classic metadata SSRF target.
        self.assertFalse(_ip_is_public("169.254.169.254"))

    def test_ipv6_mapped_private_blocked(self):
        self.assertFalse(_ip_is_public("::ffff:10.0.0.1"))

    def test_garbage_blocked(self):
        self.assertFalse(_ip_is_public("not-an-ip"))


class TestAssessUrlTarget(unittest.TestCase):
    def test_rejects_non_http_scheme(self):
        self.assertEqual(assess_url_target("file:///etc/passwd"), "invalid")
        self.assertEqual(assess_url_target("gopher://x/1"), "invalid")

    def test_rejects_hostless(self):
        self.assertEqual(assess_url_target("http:///nohost"), "invalid")

    def test_literal_public_ip_no_dns(self):
        with patch("src.dns.network_utils.socket.getaddrinfo") as gai:
            self.assertEqual(assess_url_target("http://8.8.8.8/x"), "public")
            gai.assert_not_called()

    def test_literal_private_ip_blocked_no_dns(self):
        with patch("src.dns.network_utils.socket.getaddrinfo") as gai:
            self.assertEqual(assess_url_target("http://127.0.0.1:6379/"), "blocked")
            self.assertEqual(
                assess_url_target("http://169.254.169.254/latest/meta-data/"), "blocked"
            )
            gai.assert_not_called()

    def test_hostname_resolving_public(self):
        with patch(
            "src.dns.network_utils.socket.getaddrinfo", return_value=_addrinfo("93.184.216.34")
        ):
            self.assertEqual(assess_url_target("https://example.com/login"), "public")

    def test_hostname_resolving_private_blocked(self):
        with patch("src.dns.network_utils.socket.getaddrinfo", return_value=_addrinfo("10.1.2.3")):
            self.assertEqual(assess_url_target("https://internal.evil.test/"), "blocked")

    def test_hostname_mixed_resolution_blocked(self):
        # Any non-public answer poisons the whole verdict (DNS-rebinding safety).
        infos = _addrinfo("93.184.216.34") + _addrinfo("127.0.0.1")
        with patch("src.dns.network_utils.socket.getaddrinfo", return_value=infos):
            self.assertEqual(assess_url_target("https://rebind.test/"), "blocked")

    def test_unresolvable_host(self):
        import socket as _socket

        with patch("src.dns.network_utils.socket.getaddrinfo", side_effect=_socket.gaierror):
            self.assertEqual(assess_url_target("https://taken-down-phish.test/"), "unresolved")


def _redirect(status_code: int, location: str):
    resp = MagicMock()
    resp.status_code = status_code
    resp.headers = {"Location": location}
    return resp


def _final(status_code: int = 200):
    resp = MagicMock()
    resp.status_code = status_code
    resp.headers = {}
    return resp


class TestSafeGetWithRedirects(unittest.TestCase):
    def test_blocked_initial_hop_raises_without_any_request(self):
        with (
            patch("src.dns.network_utils.assess_url_target", return_value="blocked"),
            patch("src.dns.network_utils.requests.get") as mock_get,
        ):
            with self.assertRaises(SSRFRedirectError) as ctx:
                safe_get_with_redirects("http://10.0.0.1/")
            self.assertEqual(ctx.exception.verdict, "blocked")
            mock_get.assert_not_called()

    def test_mid_chain_block_stops_before_fetching_blocked_hop(self):
        with (
            patch(
                "src.dns.network_utils.assess_url_target",
                side_effect=["public", "blocked"],
            ),
            patch(
                "src.dns.network_utils.requests.get",
                return_value=_redirect(302, "http://10.0.0.1/internal"),
            ) as mock_get,
        ):
            with self.assertRaises(SSRFRedirectError) as ctx:
                safe_get_with_redirects("https://public-looking.example/")
            self.assertEqual(ctx.exception.blocked_url, "http://10.0.0.1/internal")
            mock_get.assert_called_once()

    def test_follows_public_redirect_chain_to_final_response(self):
        responses = [_redirect(302, "https://public-looking.example/step2"), _final(200)]
        with (
            patch("src.dns.network_utils.assess_url_target", return_value="public"),
            patch("src.dns.network_utils.requests.get", side_effect=responses) as mock_get,
        ):
            result = safe_get_with_redirects("https://public-looking.example/step1")
            self.assertIs(result, responses[1])
            self.assertEqual(mock_get.call_count, 2)

    def test_redirect_without_location_returns_as_is(self):
        broken = _redirect(302, "")
        broken.headers = {}
        with (
            patch("src.dns.network_utils.assess_url_target", return_value="public"),
            patch("src.dns.network_utils.requests.get", return_value=broken),
        ):
            result = safe_get_with_redirects("https://public-looking.example/")
            self.assertIs(result, broken)

    def test_exceeding_max_hops_raises_too_many_redirects(self):
        always_redirect = _redirect(302, "https://public-looking.example/loop")
        with (
            patch("src.dns.network_utils.assess_url_target", return_value="public"),
            patch("src.dns.network_utils.requests.get", return_value=always_redirect) as mock_get,
        ):
            with self.assertRaises(requests.TooManyRedirects):
                safe_get_with_redirects("https://public-looking.example/loop", max_hops=3)
            self.assertEqual(mock_get.call_count, 3)

    def test_uses_provided_session_instead_of_module_requests(self):
        session = MagicMock()
        session.get.return_value = _final(200)
        with patch("src.dns.network_utils.assess_url_target", return_value="public"):
            result = safe_get_with_redirects("https://public-looking.example/", session=session)
        self.assertIs(result, session.get.return_value)
        session.get.assert_called_once()


if __name__ == "__main__":
    unittest.main()
