"""
Tests for multi-API validation functionality
"""

import pytest
from unittest.mock import patch, MagicMock
import json
from src import main

# Import needed classes
Engine = main.Engine
MultiAPIValidator = main.MultiAPIValidator
VirusTotalIntegration = main.VirusTotalIntegration


class TestMultiAPIValidation:
    """Test multi-API validation functionality"""

    @pytest.fixture
    def mock_settings(self, monkeypatch):
        """Mock settings for API keys"""
        monkeypatch.setattr(main.settings, "VIRUSTOTAL_API_KEY", "test_vt_key")
        monkeypatch.setattr(main.settings, "URLVOID_API_KEY", "test_uv_key")
        monkeypatch.setattr(main.settings, "PHISHTANK_API_KEY", "test_pt_key")

    @pytest.fixture
    def api_scanner(self, mock_settings):
        """Create MultiAPIValidator instance"""
        return MultiAPIValidator()

    def test_comprehensive_scan_success(self, api_scanner):
        """Test successful comprehensive scan"""
        # Mock the VirusTotal integration
        with patch.object(api_scanner.virustotal, "scan_url") as mock_vt:
            with patch.object(api_scanner.urlvoid, "analyze_domain") as mock_uv:
                with patch.object(api_scanner.phishtank, "check_phishing_status") as mock_pt:

                    # Setup mock returns
                    mock_vt.return_value = {
                        "malicious": 5,
                        "suspicious": 2,
                        "reputation": -10,
                        "total_engines": 85,
                        "threat_level": "high",
                    }

                    mock_uv.return_value = {
                        "detections": 3,
                        "engines_count": 30,
                        "threat_level": "medium",
                    }

                    mock_pt.return_value = {
                        "is_phishing": True,
                        "verified": True,
                        "threat_level": "critical",
                    }

                    result = api_scanner.comprehensive_scan("https://phishing-test.com")

                    assert result["url"] == "https://phishing-test.com"
                    assert result["aggregated_threat_level"] == "critical"
                    assert result["confidence_score"] > 0
                    assert "virustotal" in result
                    assert "urlvoid" in result
                    assert "phishtank" in result

    def test_comprehensive_scan_with_errors(self, api_scanner):
        """Test comprehensive scan with API errors"""
        # Mock all API calls to return errors
        with patch.object(api_scanner.virustotal, "scan_url") as mock_vt:
            with patch.object(api_scanner.urlvoid, "analyze_domain") as mock_uv:
                with patch.object(api_scanner.phishtank, "check_phishing_status") as mock_pt:

                    # Setup mock returns with errors
                    mock_vt.return_value = {"error": "API key invalid"}
                    mock_uv.return_value = {"error": "Rate limit exceeded"}
                    mock_pt.return_value = {"error": "Service unavailable"}

                    result = api_scanner.comprehensive_scan("https://test.com")

                    assert result["url"] == "https://test.com"
                    assert result["aggregated_threat_level"] == "unknown"
                    assert result["confidence_score"] == 0
                    assert "virustotal" in result
                    assert "urlvoid" in result
                    assert "phishtank" in result

    def test_individual_api_integrations(self, api_scanner):
        """Test that individual API integrations are properly initialized"""
        assert hasattr(api_scanner, "virustotal")
        assert hasattr(api_scanner, "urlvoid")
        assert hasattr(api_scanner, "phishtank")

        # Test that they have the expected methods
        assert hasattr(api_scanner.virustotal, "scan_url")
        assert hasattr(api_scanner.urlvoid, "analyze_domain")
        assert hasattr(api_scanner.phishtank, "check_phishing_status")


class TestPhishingScannerIntegration:
    """Test PhishingScanner integration with multi-API"""

    @pytest.fixture
    def scanner_args(self):
        """Create scanner arguments"""
        import argparse

        return argparse.Namespace(
            timeout=5,
            log_level="INFO",
            test_report=False,
            threads_only=False,
            regen_queries=False,
            report=None,
            process_reports=False,
            multi_api_scan=True,
            url=None,
        )

    def test_scanner_with_multi_api_enabled(self, scanner_args, monkeypatch):
        """Test scanner initialization with multi-API enabled"""
        monkeypatch.setattr(main.settings, "AUTO_MULTI_API_SCAN", True)
        monkeypatch.setattr(main.settings, "VIRUSTOTAL_API_KEY", "test_key")

        scanner = main.PhishingScanner(
            timeout=5, keywords=["test"], domains=[".com"], allowed_sites=[], args=scanner_args
        )

        assert hasattr(scanner, "multi_api_validator")
        assert scanner.multi_api_validator is not None


class TestKitFingerprintStep:
    """Step 5.5 -- must degrade cleanly on any failure and never crash the
    scan (matching every other step's resilience convention), extract its
    brand hint from Step 0's already-computed result, and escalate the
    aggregated verdict when a kit is detected."""

    @pytest.fixture
    def mock_settings(self, monkeypatch):
        monkeypatch.setattr(main.settings, "VIRUSTOTAL_API_KEY", "test_vt_key")
        monkeypatch.setattr(main.settings, "URLVOID_API_KEY", "test_uv_key")
        monkeypatch.setattr(main.settings, "PHISHTANK_API_KEY", "test_pt_key")

    @pytest.fixture
    def api_scanner(self, mock_settings):
        return MultiAPIValidator()

    def test_kit_fetch_uses_brand_hint_from_step_0(self, api_scanner):
        with patch.object(
            api_scanner.virustotal,
            "scan_url",
            return_value={"threat_level": "clean", "total_engines": 60},
        ):
            with patch.object(
                api_scanner.urlvoid,
                "analyze_domain",
                return_value={"threat_level": "clean", "safety_score": 90},
            ):
                with patch.object(
                    api_scanner.phishtank,
                    "check_phishing_status",
                    return_value={"is_phishing": False},
                ):
                    with patch.object(
                        api_scanner.url_analyzer,
                        "analyze",
                        return_value={
                            "risk_score": 80,
                            "risk_factors": [],
                            "typosquatting": {"detected": True, "target_brand": "nequi"},
                            "combo_squatting": {},
                            "homoglyphs": {},
                            "suspicious_tld": {},
                            "excessive_subdomains": {},
                        },
                    ):
                        with patch("src.intelligence.multi_api_validator.safe_get_with_redirects"):
                            with patch(
                                "src.intelligence.multi_api_validator.score_kit_indicators",
                                return_value={"kit_type": None, "confidence": 0, "indicators": []},
                            ) as mock_score:
                                api_scanner.comprehensive_scan(
                                    "https://nequi-verificacion.example.com/"
                                )

        _, kwargs = mock_score.call_args
        assert kwargs.get("brand_hint") == "nequi"

    def test_fetch_failure_degrades_without_raising(self, api_scanner):
        with patch.object(
            api_scanner.virustotal,
            "scan_url",
            return_value={"threat_level": "clean", "total_engines": 60},
        ):
            with patch.object(
                api_scanner.urlvoid,
                "analyze_domain",
                return_value={"threat_level": "clean", "safety_score": 90},
            ):
                with patch.object(
                    api_scanner.phishtank,
                    "check_phishing_status",
                    return_value={"is_phishing": False},
                ):
                    with patch(
                        "src.intelligence.multi_api_validator.safe_get_with_redirects",
                        side_effect=Exception("network down"),
                    ):
                        result = api_scanner.comprehensive_scan("https://test-site.com")

        assert result["detected_kit_type"] is None
        assert result["kit_fingerprint"] == {}

    def test_detected_kit_escalates_threat_level_and_confidence(self, api_scanner):
        with patch.object(
            api_scanner.virustotal,
            "scan_url",
            return_value={"threat_level": "clean", "total_engines": 60},
        ):
            with patch.object(
                api_scanner.urlvoid,
                "analyze_domain",
                return_value={"threat_level": "clean", "safety_score": 90},
            ):
                with patch.object(
                    api_scanner.phishtank,
                    "check_phishing_status",
                    return_value={"is_phishing": False},
                ):
                    with patch("src.intelligence.multi_api_validator.safe_get_with_redirects"):
                        with patch(
                            "src.intelligence.multi_api_validator.score_kit_indicators",
                            return_value={
                                "kit_type": "evilginx",
                                "confidence": 95,
                                "indicators": ["x_evilginx_header"],
                            },
                        ):
                            result = api_scanner.comprehensive_scan(
                                "https://nequi-verificacion.example.com/"
                            )

        assert result["aggregated_threat_level"] == "critical"
        assert result["detected_kit_type"] == "evilginx"
        assert result["kit_confidence"] == 95
        assert any("AiTM proxy detected" in r for r in result["recommendations"])

    def test_no_kit_detected_does_not_force_critical(self, api_scanner):
        with patch.object(
            api_scanner.virustotal,
            "scan_url",
            return_value={"threat_level": "clean", "total_engines": 60},
        ):
            with patch.object(
                api_scanner.urlvoid,
                "analyze_domain",
                return_value={"threat_level": "clean", "safety_score": 90},
            ):
                with patch.object(
                    api_scanner.phishtank,
                    "check_phishing_status",
                    return_value={"is_phishing": False},
                ):
                    with patch("src.intelligence.multi_api_validator.safe_get_with_redirects"):
                        with patch(
                            "src.intelligence.multi_api_validator.score_kit_indicators",
                            return_value={"kit_type": None, "confidence": 0, "indicators": []},
                        ):
                            result = api_scanner.comprehensive_scan("https://test-site.com")

        assert result["detected_kit_type"] is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
