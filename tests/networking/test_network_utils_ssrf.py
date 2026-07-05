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
from unittest.mock import patch

from src.dns.network_utils import assess_url_target, _ip_is_public


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


if __name__ == "__main__":
    unittest.main()
