"""
Unit tests for src/detection/kit_fingerprint.py -- score_kit_indicators.
"""

import unittest
from unittest.mock import MagicMock

from src.detection.kit_fingerprint import score_kit_indicators


def _response(headers=None, text="", url="https://evil.example.com/login"):
    resp = MagicMock()
    resp.headers = headers or {}
    resp.text = text
    resp.url = url
    return resp


class TestScoreKitIndicators(unittest.TestCase):
    def test_x_evilginx_header_is_high_confidence_evilginx(self):
        resp = _response(headers={"X-Evilginx": "phishlet-v3"})
        result = score_kit_indicators("https://evil.example.com/", resp)
        self.assertEqual(result["kit_type"], "evilginx")
        self.assertIn("x_evilginx_header", result["indicators"])
        self.assertGreaterEqual(result["confidence"], 90)

    def test_header_check_is_case_insensitive(self):
        resp = _response(headers={"x-EVILGINX": "1"})
        result = score_kit_indicators("https://evil.example.com/", resp)
        self.assertEqual(result["kit_type"], "evilginx")

    def test_missing_hsts_csp_without_brand_hint_scores_nothing(self):
        resp = _response(headers={})
        result = score_kit_indicators(
            "https://some-random-site.example.com/", resp, brand_hint=None
        )
        self.assertIsNone(result["kit_type"])
        self.assertEqual(result["confidence"], 0)
        self.assertEqual(result["indicators"], [])

    def test_missing_hsts_csp_with_brand_hint_scores_but_not_evilginx(self):
        resp = _response(headers={})
        result = score_kit_indicators(
            "https://nequi-verificacion.example.com/", resp, brand_hint="nequi"
        )
        self.assertIn("missing_hsts", result["indicators"])
        self.assertIn("missing_csp", result["indicators"])
        self.assertNotEqual(result["kit_type"], "evilginx")

    def test_brand_domain_leak_detected(self):
        resp = _response(
            headers={
                "Strict-Transport-Security": "max-age=1",
                "Content-Security-Policy": "default-src 'self'",
            },
            text="<html>...fetch('https://nequi.com/api/session')...</html>",
        )
        result = score_kit_indicators(
            "https://nequi-verificacion.example.com/", resp, brand_hint="nequi"
        )
        self.assertTrue(any(i.startswith("brand_domain_leak:") for i in result["indicators"]))
        self.assertEqual(result["kit_type"], "generic_aitm")

    def test_brand_domain_leak_not_flagged_when_it_is_the_candidates_own_domain(self):
        resp = _response(
            headers={"Strict-Transport-Security": "max-age=1", "Content-Security-Policy": "x"},
            text="<html>nequi.com content</html>",
        )
        result = score_kit_indicators("https://nequi.com/", resp, brand_hint="nequi")
        self.assertFalse(any(i.startswith("brand_domain_leak:") for i in result["indicators"]))

    def test_combined_signals_below_threshold_stay_ungeneric(self):
        resp = _response(headers={"Strict-Transport-Security": "max-age=1"})
        result = score_kit_indicators(
            "https://nequi-verificacion.example.com/", resp, brand_hint="nequi"
        )
        self.assertIsNone(result["kit_type"])

    def test_confidence_capped_at_100(self):
        resp = _response(headers={"X-Evilginx": "1"}, text="nequi.com")
        result = score_kit_indicators(
            "https://nequi-verificacion.example.com/", resp, brand_hint="nequi"
        )
        self.assertLessEqual(result["confidence"], 100)

    def test_unknown_brand_hint_has_no_real_domains_to_leak_check(self):
        resp = _response(headers={})
        result = score_kit_indicators("https://x.example.com/", resp, brand_hint="not-a-real-brand")
        self.assertFalse(any(i.startswith("brand_domain_leak:") for i in result["indicators"]))


if __name__ == "__main__":
    unittest.main()
