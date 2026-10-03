"""Evidence handling in src/intelligence/multi_api_validator.py.

Errors and missing data must never count as clean votes, Google Safe Browsing
SOCIAL_ENGINEERING must yield at least "high", the verdict is forced to
unknown only when no external source answered, and domain extraction must
use the real host name.
"""

from unittest.mock import patch

import pytest

from src.intelligence.multi_api_validator import (
    MultiAPIValidator,
    extract_domain,
    gsb_status,
    provider_status,
)

GSB_PHISHING = {
    "checked": True,
    "status": "listed",
    "safe": False,
    "threats_found": [{"threat_type": "SOCIAL_ENGINEERING"}],
    "threat_count": 1,
}
GSB_ERROR = {"checked": False, "status": "error", "safe": None, "error": "API error: 503"}
GSB_LEGACY_ERROR = {"checked": True, "safe": True, "error": "API error: 503"}
GSB_CLEAN = {"checked": True, "status": "not_listed", "safe": True, "threats_found": []}
VT_CLEAN = {"status": "not_listed", "threat_level": "clean", "total_engines": 90, "stale": False}
VT_STALE = {"status": "no_data", "threat_level": "unknown", "total_engines": 90, "stale": True}
VT_ERROR = {"status": "error", "error": "API error: 500", "threat_level": "unknown"}
UV_DISABLED = {"status": "no_data", "enabled": False, "threat_level": "unknown"}
UV_ERROR = {"status": "error", "error": "API error: 403", "threat_level": "unknown"}
PT_NOT_LISTED = {"status": "not_listed", "is_phishing": False, "threat_level": "unknown"}
PT_ERROR = {"status": "error", "error": "API error: 509", "threat_level": "unknown"}
OLD_DOMAIN_DAYS = 3650
NO_URL_RISK = {"risk_score": 0}

agg = MultiAPIValidator._aggregate_threat_level
conf = MultiAPIValidator._calculate_confidence_score


class TestStatusHelpers:
    def test_gsb_error_shapes_are_errors(self):
        assert gsb_status(GSB_ERROR) == "error"
        assert gsb_status(GSB_LEGACY_ERROR) == "error"
        assert gsb_status({"status": "not_listed", "checked": False}) == "error"
        assert gsb_status(None) == "no_data"

    def test_gsb_answers(self):
        assert gsb_status(GSB_PHISHING) == "listed"
        assert gsb_status(GSB_CLEAN) == "not_listed"

    @pytest.mark.parametrize(
        "result, expected",
        [
            ({"error": "x"}, "error"),
            ({"status": "submitted"}, "no_data"),
            ({"threat_level": "clean"}, "not_listed"),
            ({"threat_level": "high"}, "listed"),
            ({"is_phishing": False}, "not_listed"),
            ({"is_phishing": True}, "listed"),
            ({}, "no_data"),
        ],
    )
    def test_legacy_provider_shapes(self, result, expected):
        assert provider_status(result) == expected


class TestAggregate:
    def test_gsb_phishing_old_domain_vt_clean_is_not_low(self):
        level = agg(
            VT_CLEAN, UV_DISABLED, PT_NOT_LISTED, OLD_DOMAIN_DAYS, NO_URL_RISK, GSB_PHISHING
        )
        assert level not in ("low", "clean")
        assert level in ("high", "critical")

    def test_gsb_social_engineering_floor_is_high(self):
        level = agg(VT_ERROR, UV_ERROR, PT_ERROR, OLD_DOMAIN_DAYS, NO_URL_RISK, GSB_PHISHING)
        assert level == "high"

    @pytest.mark.parametrize("gsb", [GSB_ERROR, GSB_LEGACY_ERROR])
    def test_errored_gsb_is_not_a_vote(self, gsb):
        with_error = agg(VT_CLEAN, UV_DISABLED, PT_NOT_LISTED, 10, NO_URL_RISK, gsb)
        without = agg(VT_CLEAN, UV_DISABLED, PT_NOT_LISTED, 10, NO_URL_RISK, None)
        assert with_error == without

    def test_stale_vt_is_not_a_clean_vote(self):
        # New domain (score 4) alone -> high; a stale VT must not dilute it.
        level = agg(VT_STALE, UV_DISABLED, PT_NOT_LISTED, 3, NO_URL_RISK, None)
        assert level == "high"
        diluted = agg(VT_CLEAN, UV_DISABLED, PT_NOT_LISTED, 3, NO_URL_RISK, None)
        assert diluted != "high"  # sanity: a fresh clean answer does vote

    def test_errored_vt_with_legacy_clean_threat_level_is_not_a_vote(self):
        vt = {"error": "boom", "threat_level": "clean"}
        assert agg(vt, UV_DISABLED, PT_NOT_LISTED, 3, NO_URL_RISK, None) == "high"

    def test_verified_not_phish_is_not_critical(self):
        pt = {"status": "not_listed", "is_phishing": False, "verified": True, "valid": False}
        assert agg(VT_ERROR, UV_ERROR, pt, OLD_DOMAIN_DAYS, NO_URL_RISK, None) != "critical"


class TestConfidence:
    @pytest.mark.parametrize("gsb", [GSB_ERROR, GSB_LEGACY_ERROR])
    def test_errored_gsb_adds_no_confidence(self, gsb):
        assert conf(VT_CLEAN, UV_DISABLED, PT_ERROR, 10, NO_URL_RISK, gsb) == conf(
            VT_CLEAN, UV_DISABLED, PT_ERROR, 10, NO_URL_RISK, None
        )

    def test_pt_absence_adds_no_confidence(self):
        assert conf(VT_CLEAN, UV_DISABLED, PT_NOT_LISTED, 10, NO_URL_RISK, None) == conf(
            VT_CLEAN, UV_DISABLED, PT_ERROR, 10, NO_URL_RISK, None
        )

    def test_vt_no_data_adds_no_factor(self):
        submitted = {"status": "no_data", "submitted": True, "total_engines": 0}
        assert conf(submitted, UV_DISABLED, PT_ERROR, 10, NO_URL_RISK, None) == conf(
            VT_ERROR, UV_DISABLED, PT_ERROR, 10, NO_URL_RISK, None
        )

    def test_disabled_urlvoid_adds_no_factor(self):
        assert conf(VT_CLEAN, UV_DISABLED, PT_ERROR, 10, NO_URL_RISK, None) == conf(
            VT_CLEAN, UV_ERROR, PT_ERROR, 10, NO_URL_RISK, None
        )


class TestExtractDomain:
    @pytest.mark.parametrize(
        "url, expected",
        [
            ("http://paypal.com@evil.com/login", "evil.com"),
            ("https://user:pw@evil.com:8443/a?b=c#d", "evil.com"),
            ("https://Login.Example.COM./x", "login.example.com"),
            ("evil.com/path", "evil.com"),
            ("http://[2001:db8::1]:8080/", "2001:db8::1"),
            ("https://evil.com?next=http://paypal.com", "evil.com"),
        ],
    )
    def test_host_name_only(self, url, expected):
        assert extract_domain(url) == expected


@pytest.fixture
def validator():
    v = MultiAPIValidator()
    patches = [
        patch.object(v.url_analyzer, "analyze", return_value={"risk_score": 0}),
        patch(
            "src.intelligence.multi_api_validator.safe_get_with_redirects",
            side_effect=ConnectionError("offline"),
        ),
        patch(
            "src.reporting.email_detector.EnhancedAbuseEmailDetector.get_enhanced_whois_info",
            return_value={"registrar": "Example Registrar", "creation_date": "2010-01-01"},
        ),
        patch.object(v.virustotal, "get_domain_report", return_value=VT_ERROR),
    ]
    for p in patches:
        p.start()
    yield v
    for p in patches:
        p.stop()


class TestComprehensiveScan:
    def test_all_providers_errored_but_gsb_phishing_is_not_unknown(self, validator):
        with (
            patch.object(validator.virustotal, "scan_url", return_value=VT_ERROR),
            patch.object(validator.urlvoid, "analyze_domain", return_value=UV_ERROR),
            patch.object(validator.phishtank, "check_phishing_status", return_value=PT_ERROR),
            patch.object(validator.google_safe_browsing, "check_url", return_value=GSB_PHISHING),
        ):
            result = validator.comprehensive_scan("https://phish.example/login")
        assert result["aggregated_threat_level"] == "high"
        assert result["confidence_score"] > 0

    def test_nothing_answered_is_unknown(self, validator):
        with (
            patch.object(validator.virustotal, "scan_url", return_value=VT_ERROR),
            patch.object(validator.urlvoid, "analyze_domain", return_value=UV_DISABLED),
            patch.object(validator.phishtank, "check_phishing_status", return_value=PT_ERROR),
            patch.object(validator.google_safe_browsing, "check_url", return_value=GSB_ERROR),
        ):
            result = validator.comprehensive_scan("https://phish.example/login")
        assert result["aggregated_threat_level"] == "unknown"
        assert result["confidence_score"] == 0

    def test_kit_detection_alone_prevents_unknown(self, validator):
        with (
            patch.object(validator.virustotal, "scan_url", return_value=VT_ERROR),
            patch.object(validator.urlvoid, "analyze_domain", return_value=UV_ERROR),
            patch.object(validator.phishtank, "check_phishing_status", return_value=PT_ERROR),
            patch.object(validator.google_safe_browsing, "check_url", return_value=GSB_ERROR),
            patch("src.intelligence.multi_api_validator.safe_get_with_redirects"),
            patch(
                "src.intelligence.multi_api_validator.score_kit_indicators",
                return_value={"kit_type": "evilginx", "confidence": 90, "indicators": ["x"]},
            ),
        ):
            result = validator.comprehensive_scan("https://phish.example/login")
        assert result["aggregated_threat_level"] == "critical"

    def test_userinfo_trick_queries_the_real_host(self, validator):
        with (
            patch.object(validator.virustotal, "scan_url", return_value=VT_ERROR),
            patch.object(validator.urlvoid, "analyze_domain", return_value=UV_DISABLED) as uv,
            patch.object(validator.phishtank, "check_phishing_status", return_value=PT_ERROR),
            patch.object(validator.google_safe_browsing, "check_url", return_value=GSB_ERROR),
        ):
            result = validator.comprehensive_scan("http://paypal.com@evil.example:8080/x?y=1")
        assert result["domain"] == "evil.example"
        uv.assert_called_once_with("evil.example")
        validator.virustotal.get_domain_report.assert_called_once_with("evil.example")

    def test_errored_gsb_recommendations_do_not_claim_threats(self, validator):
        with (
            patch.object(validator.virustotal, "scan_url", return_value=VT_CLEAN),
            patch.object(validator.urlvoid, "analyze_domain", return_value=UV_DISABLED),
            patch.object(validator.phishtank, "check_phishing_status", return_value=PT_NOT_LISTED),
            patch.object(
                validator.google_safe_browsing, "check_url", return_value=GSB_LEGACY_ERROR
            ),
        ):
            result = validator.comprehensive_scan("https://phish.example/login")
        assert not any("GOOGLE SAFE BROWSING" in r for r in result["recommendations"])
