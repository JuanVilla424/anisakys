"""
Tests for multi-API validation functionality
"""

import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path
import importlib.util
import json

# Load main module
module_path = Path(__file__).parent.parent / "src" / "main.py"
spec = importlib.util.spec_from_file_location("src.main", str(module_path))
main = importlib.util.module_from_spec(spec)
spec.loader.exec_module(main)

# Import needed classes
# Note: MultiAPIScanner doesn't exist as a separate class in main.py
# The multi-API functionality is integrated into the Engine class
Engine = main.Engine
PhishingScanner = main.PhishingScanner


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
        """Create MultiAPIScanner instance"""
        return MultiAPIScanner()

    def test_virustotal_scan_success(self, api_scanner):
        """Test successful VirusTotal scan"""
        # Mock the requests
        with patch("requests.get") as mock_get:
            # Mock successful response
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 5,
                            "suspicious": 2,
                            "harmless": 60,
                            "undetected": 30,
                        },
                        "reputation": -10,
                        "last_analysis_results": {
                            "Avast": {"category": "malicious", "result": "phishing"},
                            "BitDefender": {"category": "malicious", "result": "phishing"},
                        },
                    }
                }
            }
            mock_get.return_value = mock_response

            result = api_scanner.virustotal_scan("https://phishing-test.com")

            assert result["success"] is True
            assert result["malicious"] == 5
            assert result["suspicious"] == 2
            assert result["reputation"] == -10
            assert "Avast" in result["engines"]

    def test_virustotal_scan_api_error(self, api_scanner):
        """Test VirusTotal scan with API error"""
        with patch("requests.get") as mock_get:
            mock_get.side_effect = Exception("API Error")

            result = api_scanner.virustotal_scan("https://test.com")

            assert result["success"] is False
            assert "error" in result

    def test_urlvoid_scan_success(self, api_scanner):
        """Test successful URLVoid scan"""
        with patch("requests.get") as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.text = """
            <response>
                <details>
                    <engines>
                        <engine>Engine1</engine>
                        <engine>Engine2</engine>
                    </engines>
                    <detections>2</detections>
                    <country>US</country>
                    <ip>1.2.3.4</ip>
                </details>
            </response>
            """
            mock_get.return_value = mock_response

            result = api_scanner.urlvoid_scan("test.com")

            assert result["success"] is True
            assert result["engines_count"] == 2
            assert result["detections"] == 2
            assert result["country"] == "US"

    def test_phishtank_check_success(self, api_scanner):
        """Test successful PhishTank check"""
        with patch("requests.post") as mock_post:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "results": {
                    "url": "https://phishing-test.com",
                    "in_database": True,
                    "phish_id": 123456,
                    "verified": True,
                    "verified_at": "2023-01-01T00:00:00+00:00",
                }
            }
            mock_post.return_value = mock_response

            result = api_scanner.phishtank_check("https://phishing-test.com")

            assert result["success"] is True
            assert result["in_database"] is True
            assert result["phish_id"] == 123456

    def test_multi_api_scan_integration(self, api_scanner):
        """Test complete multi-API scan integration"""
        test_url = "https://suspicious-site.com"

        # Mock all API calls
        with (
            patch.object(api_scanner, "virustotal_scan") as mock_vt,
            patch.object(api_scanner, "urlvoid_scan") as mock_uv,
            patch.object(api_scanner, "phishtank_check") as mock_pt,
        ):

            # Setup mock returns
            mock_vt.return_value = {
                "success": True,
                "malicious": 10,
                "suspicious": 5,
                "reputation": -50,
            }

            mock_uv.return_value = {"success": True, "detections": 3, "engines_count": 30}

            mock_pt.return_value = {"success": True, "in_database": True, "verified": True}

            # Perform scan
            results = api_scanner.multi_api_scan(test_url)

            # Verify results
            assert results["url"] == test_url
            assert results["threat_level"] == "critical"  # Based on high malicious count
            assert results["confidence_score"] >= 90  # High confidence due to multiple detections
            assert "virustotal" in results
            assert "urlvoid" in results
            assert "phishtank" in results

    def test_threat_level_calculation(self, api_scanner):
        """Test threat level calculation logic"""
        # Test critical threat
        results = {
            "virustotal": {"success": True, "malicious": 15},
            "urlvoid": {"success": True, "detections": 5},
            "phishtank": {"success": True, "in_database": True, "verified": True},
        }
        threat_level, confidence = api_scanner.calculate_threat_level(results)
        assert threat_level == "critical"
        assert confidence >= 95

        # Test high threat
        results = {
            "virustotal": {"success": True, "malicious": 8},
            "urlvoid": {"success": True, "detections": 2},
            "phishtank": {"success": False},
        }
        threat_level, confidence = api_scanner.calculate_threat_level(results)
        assert threat_level == "high"

        # Test medium threat
        results = {
            "virustotal": {"success": True, "malicious": 3},
            "urlvoid": {"success": True, "detections": 1},
            "phishtank": {"success": True, "in_database": False},
        }
        threat_level, confidence = api_scanner.calculate_threat_level(results)
        assert threat_level == "medium"

        # Test clean
        results = {
            "virustotal": {"success": True, "malicious": 0},
            "urlvoid": {"success": True, "detections": 0},
            "phishtank": {"success": True, "in_database": False},
        }
        threat_level, confidence = api_scanner.calculate_threat_level(results)
        assert threat_level == "clean"

    def test_api_timeout_handling(self, api_scanner):
        """Test API timeout handling"""
        with patch("requests.get") as mock_get:
            mock_get.side_effect = TimeoutError("Request timeout")

            result = api_scanner.virustotal_scan("https://test.com", timeout=1)

            assert result["success"] is False
            assert "timeout" in result["error"].lower()

    def test_api_rate_limiting(self, api_scanner):
        """Test API rate limiting response"""
        with patch("requests.get") as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 429  # Too Many Requests
            mock_response.text = "Rate limit exceeded"
            mock_get.return_value = mock_response

            result = api_scanner.virustotal_scan("https://test.com")

            assert result["success"] is False
            assert "429" in result["error"] or "rate" in result["error"].lower()


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

        scanner = PhishingScanner(
            timeout=5, keywords=["test"], domains=[".com"], allowed_sites=[], args=scanner_args
        )

        assert scanner.multi_api_enabled is True
        assert scanner.multi_api_scanner is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
