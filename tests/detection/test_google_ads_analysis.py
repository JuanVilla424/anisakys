"""Google Ads detector: URL analysis, landing pages, result parsing and reports (no network)."""

import json
import os
import socket
from datetime import datetime, timedelta
from types import SimpleNamespace
from typing import Any, Dict
from unittest.mock import patch

import pytest
from bs4 import BeautifulSoup

from src.detection import google_ads_detector as module
from src.detection.google_ads_detector import GoogleAdsPhishingDetector


@pytest.fixture
def detector(monkeypatch) -> GoogleAdsPhishingDetector:
    monkeypatch.setattr(module.settings, "KEYWORDS", "fcm, Runt ")
    monkeypatch.setattr(module.settings, "DOMAINS", ".com,.co")
    monkeypatch.setattr(module.settings, "ALLOWED_SITES", "www.fcm.org.co, www.runt.gov.co")
    return GoogleAdsPhishingDetector()


def _quiet(detector: GoogleAdsPhishingDetector, **overrides: Any) -> Dict[str, Any]:
    """Patch every network step of analyze_ad_url with neutral answers."""
    defaults: Dict[str, Any] = {
        "_follow_redirects": lambda url: {
            "chain": [{"url": url, "status_code": 200}],
            "final_url": url,
        },
        "_check_domain_info": lambda url: None,
        "_check_ssl_certificate": lambda url: {"valid": True},
        "_analyze_landing_page": lambda url: None,
    }
    defaults.update(overrides)
    return defaults


def _analyze(detector, url, display=None, **overrides):
    steps = _quiet(detector, **overrides)
    with (
        patch.object(detector, "_follow_redirects", side_effect=steps["_follow_redirects"]),
        patch.object(detector, "_check_domain_info", side_effect=steps["_check_domain_info"]),
        patch.object(
            detector, "_check_ssl_certificate", side_effect=steps["_check_ssl_certificate"]
        ),
        patch.object(detector, "_analyze_landing_page", side_effect=steps["_analyze_landing_page"]),
    ):
        return detector.analyze_ad_url(url, display)


class TestConfiguration:
    def test_settings_are_normalised(self, detector):
        assert detector.keywords == ["fcm", "runt"]
        assert detector.domains == [".com", ".co"]
        assert detector.allowed_sites == ["www.fcm.org.co", "www.runt.gov.co"]
        assert "fcm" in detector.suspicious_patterns["phishing_keywords"]


class TestAnalyzeAdUrl:
    def test_allowed_sites_are_safe_without_any_check(self, detector):
        with patch.object(detector, "_follow_redirects") as follow:
            result = detector.analyze_ad_url("https://www.fcm.org.co/pagos")

        assert result["risk_level"] == "SAFE" and result["indicators"] == ["ALLOWED_SITE"]
        follow.assert_not_called()

    def test_a_clean_ad_is_minimal(self, detector):
        result = _analyze(detector, "https://shop-demo.com/", "shop-demo.com")

        assert result["risk_level"] == "MINIMAL" and result["risk_score"] == 0
        assert result["display_url"] == "shop-demo.com"
        assert result["final_destination"] == "https://shop-demo.com/"

    def test_every_indicator_adds_up_to_high(self, detector):
        chain = [{"url": f"https://bit.ly/{n}", "status_code": 302} for n in range(4)]
        final = "https://fcm-pagos.tk/verify-account"
        result = _analyze(
            detector,
            "https://bit.ly/x",
            _follow_redirects=lambda url: {"chain": chain, "final_url": final},
            _check_domain_info=lambda url: {"days_old": 3, "domain": "fcm-pagos.tk"},
            _check_ssl_certificate=lambda url: {"valid": False},
            _analyze_landing_page=lambda url: {
                "risk_score": 15,
                "indicators": ["PASSWORD_FIELD_PRESENT"],
            },
        )

        assert result["risk_level"] == "HIGH"
        indicators = " | ".join(result["indicators"])
        for expected in (
            "URL_SHORTENER_DETECTED",
            "EXCESSIVE_REDIRECTS",
            "SUSPICIOUS_KEYWORDS: fcm",
            "SUSPICIOUS_TLD",
            "PHISHING_KEYWORDS",
            "NEWLY_REGISTERED_DOMAIN",
            "INVALID_SSL_CERTIFICATE",
            "PASSWORD_FIELD_PRESENT",
        ):
            assert expected in indicators
        assert result["keywords_found"] == ["fcm"]
        assert result["domain_info"]["days_old"] == 3

    @pytest.mark.parametrize(
        "landing_score, expected",
        [(45, "MEDIUM"), (22, "LOW"), (5, "MINIMAL")],
    )
    def test_risk_levels(self, detector, landing_score, expected):
        result = _analyze(
            detector,
            "https://shop-demo.com/",
            _analyze_landing_page=lambda url: {"risk_score": landing_score, "indicators": []},
        )

        assert result["risk_level"] == expected

    def test_an_old_domain_is_not_new(self, detector):
        result = _analyze(
            detector,
            "https://shop-demo.com/",
            _check_domain_info=lambda url: {"days_old": 4000},
        )

        assert "NEWLY_REGISTERED_DOMAIN" not in result["indicators"]


class TestUrlChecks:
    def test_homoglyphs_and_close_names(self, detector):
        assert detector._check_homoglyphs("https://g00gle-login.com/") == "Mimicking google"
        assert detector._check_homoglyphs("https://paypa1.com/") == "Similar to paypal"
        assert detector._check_homoglyphs("https://paypal.com/") is None
        assert detector._check_homoglyphs("https://weather-demo.com/") is None

    def test_levenshtein(self, detector):
        assert detector._levenshtein_distance("kitten", "sitting") == 3
        assert detector._levenshtein_distance("", "abc") == 3
        assert detector._levenshtein_distance("same", "same") == 0

    def test_tlds_shorteners_and_keywords(self, detector):
        assert detector._check_suspicious_tld("https://pagos.tk/")
        assert not detector._check_suspicious_tld("https://pagos.com/")
        assert detector._check_url_shortener("https://bit.ly/abc")
        assert not detector._check_url_shortener("https://example-demo.com/")
        assert detector._check_phishing_keywords("https://x.com/security-alert/prize") == [
            "security-alert",
            "prize",
        ]
        assert detector._check_configured_keywords("https://RUNT-pagos.com") == ["runt"]


class TestDomainAndCertificate:
    def test_domain_age_from_whois(self, detector):
        created = datetime.now() - timedelta(days=10)
        answer = SimpleNamespace(creation_date=[created, created], registrar="Example Registrar")
        with patch.object(module.whois, "whois", return_value=answer):
            info = detector._check_domain_info("https://new-demo.com/x")

        assert info is not None
        assert info["domain"] == "new-demo.com" and info["days_old"] == 10
        assert info["registrar"] == "Example Registrar"

    def test_whois_without_a_date_or_failing(self, detector):
        with patch.object(module.whois, "whois", return_value=SimpleNamespace(creation_date=None)):
            assert detector._check_domain_info("https://x-demo.com/") is None
        with patch.object(module.whois, "whois", side_effect=Exception("whois down")):
            assert detector._check_domain_info("https://x-demo.com/") is None

    def test_an_unreachable_host_has_no_valid_certificate(self, detector):
        with patch.object(socket, "create_connection", side_effect=OSError("refused")):
            result = detector._check_ssl_certificate("https://x-demo.com/")

        assert result == {"valid": False, "issuer": None, "expires": None}


LANDING = """<html><body>
<form action="/pay"><input type="password" name="clave"></form>
<p>Paga tu multa FCM hoy: tu cuenta será suspendida</p>
<script src="https://cdn.evil-demo.tk/kit.js"></script>
<img src="https://static.shop-demo.com/logo.png">
</body></html>"""


class TestLandingPage:
    def test_signals_on_the_page(self, detector):
        response = SimpleNamespace(text=LANDING)
        with patch.object(module, "safe_get_with_redirects", return_value=response):
            analysis = detector._analyze_landing_page("https://fcm-demo.com/")

        assert analysis is not None
        assert analysis["forms_found"] == 1 and analysis["password_fields"] == 1
        assert analysis["keywords_in_page"] == ["fcm"]
        assert analysis["external_resources"] == ["https://cdn.evil-demo.tk/kit.js"]
        indicators = " | ".join(analysis["indicators"])
        assert "PASSWORD_FIELD_PRESENT" in indicators and "URGENCY_LANGUAGE" in indicators
        assert "SUSPICIOUS_EXTERNAL_RESOURCES" in indicators
        assert analysis["risk_score"] == 15 + 20 + 10 + 5

    def test_a_failing_fetch_is_no_analysis(self, detector):
        with patch.object(module, "safe_get_with_redirects", side_effect=RuntimeError("boom")):
            assert detector._analyze_landing_page("https://x-demo.com/") is None


SERP = """<html><body>
<div id="tads">
  <div><span>Patrocinado</span>
    <a href="https://www.google.com/aclk?sa=l&adurl=https://fcm-pagos-demo.com/inicio">Paga tu multa</a>
    <cite>fcm-pagos-demo.com</cite><div class="VwiC3b">Descuento del 50%</div>
  </div>
  <div><a href="https://runt-consulta-demo.co/">Consulta RUNT</a><cite>runt-consulta-demo.co</cite></div>
</div>
<div class="mnr-c"><a href="/url?q=https://side-demo.com/">Side ad</a><cite>side-demo.com</cite></div>
<div data-text-ad="1"><a href="https://text-ad-demo.com/">Text ad</a></div>
<a href="/url?q=https://fcm-pagos-demo.com/inicio">Duplicate</a>
</body></html>"""


class TestSearchResults:
    def test_ads_are_extracted_once_with_their_real_url(self, detector):
        ads = detector._extract_google_ads(BeautifulSoup(SERP, "html.parser"))

        urls = [ad["url"] for ad in ads]
        assert urls[0] == "https://fcm-pagos-demo.com/inicio"
        assert set(urls) == {
            "https://fcm-pagos-demo.com/inicio",
            "https://runt-consulta-demo.co/",
            "https://side-demo.com/",
            "https://text-ad-demo.com/",
        }
        first = ads[0]
        assert first["title"] == "Paga tu multa" and first["display_url"] == "fcm-pagos-demo.com"
        assert first["description"] == "Descuento del 50%" and first["is_ad"]

    def test_fallback_reads_sponsored_blocks(self, detector):
        page = '<div>Sponsored <a href="https://fallback-demo.com/">Offer</a></div>'

        ads = detector._extract_google_ads(BeautifulSoup(page, "html.parser"))

        assert [ad["url"] for ad in ads] == ["https://fallback-demo.com/"]

    def test_one_ad_element(self, detector):
        element = BeautifulSoup(
            '<div><h3>Paga</h3><a href="/aclk?adurl=https://a-demo.com/">x</a>'
            '<cite>a-demo.com</cite><div class="MUxGbd">texto</div></div>',
            "html.parser",
        )

        assert detector._parse_ad_element(element) == {
            "title": "Paga",
            "url": "https://a-demo.com/",
            "display_url": "a-demo.com",
            "description": "texto",
        }
        assert (
            detector._parse_ad_element(BeautifulSoup("<div><h3>t</h3></div>", "html.parser"))
            is None
        )

    @pytest.mark.parametrize(
        "google_url, expected",
        [
            ("https://www.google.com/aclk?adurl=https://a-demo.com/", "https://a-demo.com/"),
            ("/url?q=https://b-demo.com/&sa=U", "https://b-demo.com/"),
            ("https://c-demo.com/plain", "https://c-demo.com/plain"),
        ],
    )
    def test_actual_url(self, detector, google_url, expected):
        assert detector._extract_actual_url(google_url) == expected

    def test_search_combinations(self, detector):
        terms = detector._generate_search_combinations()

        assert len(terms) == len(set(terms))
        assert {"fcm", "runt", "fcm pagar", "runt pagar consulta"} <= set(terms)
        assert all(term == term.strip() and term for term in terms)


class TestCampaignsAndReports:
    def test_campaign_scan_skips_ads_without_url(self, detector):
        campaign = [
            {"id": 1, "final_url": "https://a-demo.com/", "headline": "A", "display_url": "a"},
            {"id": 2, "headline": "no url"},
        ]
        with patch.object(
            detector, "analyze_ad_url", side_effect=lambda url, display: {"url": url}
        ):
            results = detector.scan_google_ads_campaign(campaign)

        assert results == [{"url": "https://a-demo.com/", "ad_id": 1, "ad_text": "A"}]

    def test_report_counts_levels_indicators_and_keywords(self, detector, tmp_path):
        results = [
            {
                "risk_level": "HIGH",
                "indicators": ["SUSPICIOUS_TLD", "SUSPICIOUS_KEYWORDS: fcm"],
                "keywords_found": ["fcm"],
            },
            {"risk_level": "MEDIUM", "indicators": ["SUSPICIOUS_TLD"], "keywords_found": ["fcm"]},
            {"risk_level": "LOW", "indicators": []},
            {"risk_level": "SAFE", "indicators": ["ALLOWED_SITE"]},
            {"risk_level": "MINIMAL"},
        ]
        out = tmp_path / "report.json"

        report = detector.generate_report(results, str(out))

        stats = report["statistics"]
        assert (stats["high_risk_count"], stats["medium_risk_count"]) == (1, 1)
        assert (stats["low_risk_count"], stats["safe_count"]) == (1, 1)
        assert stats["common_indicators"] == {
            "SUSPICIOUS_TLD": 2,
            "SUSPICIOUS_KEYWORDS": 1,
            "ALLOWED_SITE": 1,
        }
        assert stats["keywords_detected"] == {"fcm": 2}
        assert json.loads(out.read_text())["total_ads_scanned"] == 5

    def test_alert_report_is_written(self, detector, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        ads = [
            {"risk_level": "HIGH", "url": "https://a-demo.com/", "ad_info": {"title": "A"}},
            {"risk_level": "MEDIUM", "url": "https://b-demo.com/", "ad_info": {"title": "B"}},
        ]

        detector._generate_alert_report(ads)

        (written,) = os.listdir(tmp_path / "alerts")
        report = json.loads((tmp_path / "alerts" / written).read_text())
        assert (report["high_risk_count"], report["medium_risk_count"]) == (1, 1)

    def test_quick_scan_analyses_what_the_search_returns(self, detector):
        found = [{"url": "https://a-demo.com/", "display_url": "a"}, {"title": "no url"}]
        levels = iter(["HIGH", "MINIMAL"] * 20)
        with (
            patch.object(detector, "_generate_search_combinations", return_value=["fcm", "runt"]),
            patch.object(detector, "search_google_ads", return_value=found) as search,
            patch.object(
                detector,
                "analyze_ad_url",
                side_effect=lambda url, display: {"url": url, "risk_level": next(levels)},
            ),
            patch.object(module.time, "sleep"),
        ):
            summary = detector.quick_scan()

        assert search.call_count == 2
        assert summary["total_ads"] == 2 and summary["suspicious_count"] == 1
        assert summary["ads_analyzed"][0]["ad_info"] == found[0]
