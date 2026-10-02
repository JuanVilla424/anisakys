"""
Unit tests for the SSRF guard in PhishingUtils.determine_site_status.

determine_site_status must:
- mark a site "down" when its liveness check hits a non-public redirect
  target (SSRFRedirectError), without leaking that exception,
- keep its existing "up"/"down" behavior for ordinary responses,
- keep its existing "down" fallback for ordinary network errors.
"""

import unittest
from unittest.mock import patch, MagicMock

from src.detection.utils import PhishingUtils
from src.dns.network_utils import SSRFRedirectError


class TestDetermineSiteStatusSSRF(unittest.TestCase):
    def test_ssrf_redirect_marks_site_down(self):
        with patch(
            "src.detection.utils.safe_get_with_redirects",
            side_effect=SSRFRedirectError("http://169.254.169.254/", "blocked"),
        ):
            status, takedown = PhishingUtils.determine_site_status(
                url="https://phish.example/login",
                resolved_ip="203.0.113.5",
                current_status="up",
                current_takedown=None,
                timestamp="2026-01-01 00:00:00",
                timeout=10,
            )
        self.assertEqual(status, "down")
        self.assertEqual(takedown, "2026-01-01 00:00:00")

    def test_ssrf_redirect_preserves_existing_takedown_when_already_down(self):
        with patch(
            "src.detection.utils.safe_get_with_redirects",
            side_effect=SSRFRedirectError("http://10.0.0.5/", "blocked"),
        ):
            status, takedown = PhishingUtils.determine_site_status(
                url="https://phish.example/login",
                resolved_ip="203.0.113.5",
                current_status="down",
                current_takedown="2025-12-25 00:00:00",
                timestamp="2026-01-01 00:00:00",
                timeout=10,
            )
        self.assertEqual(status, "down")
        self.assertEqual(takedown, "2025-12-25 00:00:00")

    def test_normal_200_response_marks_site_up(self):
        resp = MagicMock(status_code=200, text="Welcome to the site")
        with patch("src.detection.utils.safe_get_with_redirects", return_value=resp):
            status, takedown = PhishingUtils.determine_site_status(
                url="https://phish.example/login",
                resolved_ip="203.0.113.5",
                current_status="up",
                current_takedown=None,
                timestamp="2026-01-01 00:00:00",
                timeout=10,
            )
        self.assertEqual(status, "up")
        self.assertIsNone(takedown)

    def test_suspended_body_marks_site_down(self):
        resp = MagicMock(status_code=200, text="This account has been suspended")
        with patch("src.detection.utils.safe_get_with_redirects", return_value=resp):
            status, takedown = PhishingUtils.determine_site_status(
                url="https://phish.example/login",
                resolved_ip="203.0.113.5",
                current_status="up",
                current_takedown=None,
                timestamp="2026-01-01 00:00:00",
                timeout=10,
            )
        self.assertEqual(status, "down")
        self.assertEqual(takedown, "2026-01-01 00:00:00")

    def test_ordinary_network_error_still_marks_down(self):
        with patch(
            "src.detection.utils.safe_get_with_redirects", side_effect=ConnectionError("boom")
        ):
            status, takedown = PhishingUtils.determine_site_status(
                url="https://phish.example/login",
                resolved_ip="203.0.113.5",
                current_status="up",
                current_takedown=None,
                timestamp="2026-01-01 00:00:00",
                timeout=10,
            )
        self.assertEqual(status, "down")
        self.assertEqual(takedown, "2026-01-01 00:00:00")

    def test_no_resolved_ip_marks_down_without_any_request(self):
        with patch("src.detection.utils.safe_get_with_redirects") as mock_get:
            status, takedown = PhishingUtils.determine_site_status(
                url="https://phish.example/login",
                resolved_ip=None,
                current_status="up",
                current_takedown=None,
                timestamp="2026-01-01 00:00:00",
                timeout=10,
            )
        self.assertEqual(status, "down")
        mock_get.assert_not_called()


if __name__ == "__main__":
    unittest.main()
