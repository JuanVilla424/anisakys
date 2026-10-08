"""
Unit tests for the SSRF guard in GoogleAdsPhishingDetector.

_follow_redirects and _analyze_landing_page both fetch attacker-supplied
("final_url" from a Google Ad click) URLs server-side. Both must refuse a
non-public target before issuing any request to it.
"""

import unittest
from unittest.mock import patch, MagicMock

from src.detection.google_ads_detector import GoogleAdsPhishingDetector
from src.dns.network_utils import SSRFRedirectError


def _redirect(status_code: int, location: str):
    resp = MagicMock()
    resp.status_code = status_code
    resp.headers = {"Location": location}
    return resp


def _final(status_code: int = 200, text: str = "<html></html>"):
    resp = MagicMock()
    resp.status_code = status_code
    resp.headers = {}
    resp.text = text
    return resp


class TestGoogleAdsDetectorSSRF(unittest.TestCase):
    def setUp(self):
        self.detector = GoogleAdsPhishingDetector()

    def test_follow_redirects_refuses_blocked_initial_url_without_any_request(self):
        with (
            patch(
                "src.detection.google_ads_detector.assess_url_target",
                return_value="blocked",
            ),
            patch("src.detection.google_ads_detector.requests.Session.get") as mock_get,
        ):
            result = self.detector._follow_redirects("http://169.254.169.254/")

        self.assertEqual(result["chain"], [])
        self.assertEqual(result["final_url"], "http://169.254.169.254/")
        mock_get.assert_not_called()

    def test_follow_redirects_stops_before_fetching_blocked_hop(self):
        with (
            patch(
                "src.detection.google_ads_detector.assess_url_target",
                side_effect=["public", "blocked"],
            ),
            patch(
                "src.detection.google_ads_detector.requests.Session.get",
                return_value=_redirect(302, "http://10.0.0.5/internal"),
            ) as mock_get,
        ):
            result = self.detector._follow_redirects("https://ad-click.example/go")

        self.assertEqual(mock_get.call_count, 1)
        self.assertEqual(result["final_url"], "https://ad-click.example/go")
        self.assertEqual(len(result["chain"]), 1)

    def test_follow_redirects_happy_path_records_chain(self):
        responses = [
            _redirect(302, "https://ad-click.example/step2"),
            _final(200),
        ]
        with (
            patch(
                "src.detection.google_ads_detector.assess_url_target",
                return_value="public",
            ),
            patch(
                "src.detection.google_ads_detector.requests.Session.get",
                side_effect=responses,
            ) as mock_get,
        ):
            result = self.detector._follow_redirects("https://ad-click.example/step1")

        self.assertEqual(mock_get.call_count, 2)
        self.assertEqual(result["final_url"], "https://ad-click.example/step2")
        self.assertEqual(len(result["chain"]), 2)

    def test_analyze_landing_page_returns_none_when_blocked(self):
        with patch(
            "src.detection.google_ads_detector.safe_get_with_redirects",
            side_effect=SSRFRedirectError("http://127.0.0.1/", "blocked"),
        ):
            result = self.detector._analyze_landing_page("https://ad-click.example/final")

        self.assertIsNone(result)

    def test_analyze_landing_page_analyzes_when_public(self):
        page = _final(200, text="<html><body><form><input type='password'></form></body></html>")
        with patch("src.detection.google_ads_detector.safe_get_with_redirects", return_value=page):
            result = self.detector._analyze_landing_page("https://ad-click.example/final")

        self.assertIsNotNone(result)
        self.assertEqual(result["password_fields"], 1)
        self.assertIn("PASSWORD_FIELD_PRESENT", result["indicators"])


if __name__ == "__main__":
    unittest.main()
