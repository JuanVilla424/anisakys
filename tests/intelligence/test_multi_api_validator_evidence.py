"""Evidence handling in src/intelligence/multi_api_validator.py.

Errors and missing data must never count as clean votes, Google Safe Browsing
SOCIAL_ENGINEERING must yield at least "high", the verdict is forced to
unknown only when no external source answered, and domain extraction must
use the real host name.
"""

from unittest.mock import patch

import pytest

from src.capture.service import PageCapture
from src.detection.llm_judge import Judgement

from src.intelligence.multi_api_validator import (
    MultiAPIValidator,
    extract_domain,
    gsb_status,
    kit_brand_hint,
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


OFFLINE_CAPTURE = PageCapture(url="https://phish.example/login", status="error", error="offline")
PAGE_CAPTURE = PageCapture(
    url="https://phish.example/login",
    status="ok",
    final_url="https://phish.example/login",
    http_status=200,
    headers={"x-evilginx": "1"},
    html="<html><title>Sign in</title><form><input type='password'></form></html>",
)


@pytest.fixture
def validator():
    v = MultiAPIValidator()
    patches = [
        patch.object(v.url_analyzer, "analyze", return_value={"risk_score": 0}),
        patch("src.intelligence.multi_api_validator.fetch_page", return_value=OFFLINE_CAPTURE),
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
            patch("src.intelligence.multi_api_validator.fetch_page", return_value=PAGE_CAPTURE),
        ):
            result = validator.comprehensive_scan("https://phish.example/login")
        assert result["detected_kit_type"] == "evilginx"
        assert result["aggregated_threat_level"] == "critical"
        assert result["capture"]["status"] == "ok"
        assert result["page_features"]["password_fields"] == 1

    def test_userinfo_trick_queries_the_actual_host(self, validator):
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


class TestStageInstrumentation:
    """Per-stage latency and answers, read by the evaluation harness (src/eval)."""

    def test_every_stage_is_timed_and_its_answer_recorded(self, validator):
        with (
            patch.object(validator.virustotal, "scan_url", return_value=VT_CLEAN),
            patch.object(validator.urlvoid, "analyze_domain", return_value=UV_DISABLED),
            patch.object(validator.phishtank, "check_phishing_status", return_value=PT_ERROR),
            patch.object(validator.google_safe_browsing, "check_url", return_value=GSB_PHISHING),
        ):
            result = validator.comprehensive_scan("https://phish.example/login")

        assert set(result["stage_timings_ms"]) == {
            "url_analysis",
            "virustotal_url",
            "virustotal_domain",
            "urlvoid",
            "phishtank",
            "whois",
            "google_safe_browsing",
            "capture",
            "kit_fingerprint",
            "content_features",
        }
        assert all(ms >= 0 for ms in result["stage_timings_ms"].values())
        assert result["stage_status"] == {
            "virustotal_url": "not_listed",
            "virustotal_domain": "error",
            "urlvoid": "no_data",
            "phishtank": "error",
            "google_safe_browsing": "listed",
            "whois": "not_listed",
            "capture": "error",
            "kit_fingerprint": "no_data",
        }

    def test_answers_are_shared_through_the_cache(self, validator):
        validator.virustotal.api_key = "configured"  # only configured providers are cached
        with (
            patch.object(validator.virustotal, "scan_url", return_value=VT_CLEAN) as vt,
            patch.object(validator.urlvoid, "analyze_domain", return_value=UV_DISABLED),
            patch.object(validator.phishtank, "check_phishing_status", return_value=PT_ERROR) as pt,
            patch.object(validator.google_safe_browsing, "check_url", return_value=GSB_PHISHING),
        ):
            validator.comprehensive_scan("https://phish.example/login")
            second = validator.comprehensive_scan("https://phish.example/login")

        assert vt.call_count == 1  # the answer was cached for the second scan
        assert pt.call_count == 2  # errors are never cached
        assert second["stage_status"]["virustotal_url"] == "not_listed"


COMBO = {"combo_squatting": {"detected": True, "target_brand": "google"}}
SWAP = {"tld_swap": {"detected": True, "target_brand": "google", "suffix": "com.pe"}}
TYPO = {"typosquatting": {"detected": True, "target_brand": "paypal"}}


class TestUnconfiguredProviders:
    def test_they_answer_at_once_without_spending_the_budget(self, validator):
        validator.virustotal.api_key = None
        validator.urlvoid.enabled = False
        validator.google_safe_browsing.enabled = False
        with (
            patch.object(validator.virustotal, "scan_url", return_value=VT_ERROR) as vt,
            patch.object(validator.urlvoid, "analyze_domain", return_value=UV_DISABLED) as uv,
            patch.object(validator.phishtank, "check_phishing_status", return_value=PT_ERROR),
            patch.object(validator.google_safe_browsing, "check_url", return_value=GSB_ERROR),
            patch(
                "src.intelligence.multi_api_validator.cached_call",
                side_effect=lambda stage, key, fn, *args, **kw: (fn(*args), False),
            ) as budgeted,
        ):
            validator.comprehensive_scan("https://phish.example/login")

        assert vt.called and uv.called
        assert sorted(call.args[0] for call in budgeted.call_args_list) == ["phishtank", "whois"]


class TestWhoisUnderLoad:
    def test_a_rate_limited_lookup_is_no_data_not_an_answer(self, validator):
        limited = {"status": "no_data", "error": "rate limited", "rate_limited": True}
        with (
            patch.object(validator.virustotal, "scan_url", return_value=VT_ERROR),
            patch.object(validator.urlvoid, "analyze_domain", return_value=UV_DISABLED),
            patch.object(validator.phishtank, "check_phishing_status", return_value=PT_ERROR),
            patch.object(validator.google_safe_browsing, "check_url", return_value=GSB_ERROR),
            patch.object(validator, "_whois_lookup", return_value={}),
            patch(
                "src.intelligence.multi_api_validator.cached_call",
                side_effect=lambda stage, key, fn, *args, **kw: (
                    (limited, False) if stage == "whois" else (fn(*args), False)
                ),
            ),
        ):
            result = validator.comprehensive_scan("https://phish.example/login")

        assert result["whois"] == {} and result["stage_status"]["whois"] == "no_data"
        assert result["domain_age_days"] is None


class TestEstablishedDomains:
    """A brand in the name of an old domain is usually the brand's own property."""

    @pytest.mark.parametrize(
        "analysis, age, expected",
        [
            (TYPO, 5000, "paypal"),  # a lookalike always counts
            (COMBO, 10, "google"),
            (COMBO, None, "google"),
            (COMBO, 4000, None),  # thinkwithgoogle.com
            (SWAP, 10, "google"),
            (SWAP, None, None),  # unknown age: no proof it is not the brand's own
            (SWAP, 9000, None),  # google.com.pe
            ({}, 10, None),
        ],
    )
    def test_kit_brand_hint(self, analysis, age, expected):
        assert kit_brand_hint(analysis, age) == expected

    def test_the_rules_do_not_count_an_established_brand_domain(self):
        url_risk = {"risk_score": 20}
        young_swap = agg(VT_ERROR, UV_DISABLED, PT_ERROR, 20, {**url_risk, **SWAP}, GSB_ERROR)
        old_swap = agg(VT_ERROR, UV_DISABLED, PT_ERROR, 9000, {**url_risk, **SWAP}, GSB_ERROR)
        old_combo = agg(VT_ERROR, UV_DISABLED, PT_ERROR, 9000, {**url_risk, **COMBO}, GSB_ERROR)

        rank = ["unknown", "clean", "low", "medium", "high", "critical"]
        assert rank.index(young_swap) > rank.index(old_swap)
        assert rank.index(old_combo) == rank.index(old_swap)


# A page with a login form and nothing a provider or the kit fingerprint would flag.
PLAIN_LOGIN = PageCapture(
    url="https://phish.example/login",
    status="ok",
    final_url="https://phish.example/signin",
    http_status=200,
    html="<html><title>Sign in</title><script>var x=1</script><p>Enter your password</p></html>",
)


class StubJudge:
    """Answers every page with the same judgement and records what it was shown."""

    def __init__(self, judgement: Judgement) -> None:
        self.judgement = judgement
        self.calls: list = []

    def judge(self, url, final_url=None, title=None, page_text=None, screenshot=None):
        self.calls.append((url, final_url, title, page_text))
        return self.judgement


class TestJudgeStep:
    """The optional LLM judge: evidence attached to the scan, never the verdict itself."""

    def _scan(self, validator, judge, capture):
        validator.judge = judge
        with (
            patch.object(validator.virustotal, "scan_url", return_value=VT_ERROR),
            patch.object(validator.urlvoid, "analyze_domain", return_value=UV_DISABLED),
            patch.object(validator.phishtank, "check_phishing_status", return_value=PT_ERROR),
            patch.object(validator.google_safe_browsing, "check_url", return_value=GSB_ERROR),
            patch("src.intelligence.multi_api_validator.fetch_page", return_value=capture),
        ):
            return validator.comprehensive_scan("https://phish.example/login")

    def test_the_judgement_is_attached_without_changing_the_verdict(self, validator):
        judge = StubJudge(
            Judgement(status="ok", verdict={"is_phishing": True, "confidence": 0.97}, cost_usd=0.01)
        )

        result = self._scan(validator, judge, PLAIN_LOGIN)

        assert judge.calls == [
            (
                "https://phish.example/login",
                "https://phish.example/signin",
                "Sign in",
                "Sign in Enter your password",
            )
        ]
        assert result["llm_judge"]["verdict"]["is_phishing"] is True
        assert result["stage_status"]["llm_judge"] == "listed"
        assert "llm_judge" in result["stage_timings_ms"]
        assert result["aggregated_threat_level"] == "unknown"  # nothing external answered

    def test_a_benign_judgement_and_a_failed_one(self, validator):
        benign = StubJudge(
            Judgement(status="ok", verdict={"is_phishing": False, "confidence": 0.8})
        )
        failed = StubJudge(Judgement(status="error", error="HTTP 500"))
        undecided = StubJudge(
            Judgement(status="ok", verdict={"is_phishing": None, "confidence": 0})
        )

        assert self._scan(validator, benign, PLAIN_LOGIN)["stage_status"]["llm_judge"] == (
            "not_listed"
        )
        assert self._scan(validator, failed, PLAIN_LOGIN)["stage_status"]["llm_judge"] == "error"
        assert self._scan(validator, undecided, PLAIN_LOGIN)["stage_status"]["llm_judge"] == (
            "no_data"
        )

    def test_no_capture_no_question(self, validator):
        judge = StubJudge(Judgement(status="ok", verdict={"is_phishing": True, "confidence": 1}))

        result = self._scan(validator, judge, OFFLINE_CAPTURE)

        assert judge.calls == []
        assert result["llm_judge"]["status"] == "no_capture"
        assert result["stage_status"]["llm_judge"] == "no_data"
