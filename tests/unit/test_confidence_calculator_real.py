"""Unit tests for ConfidenceCalculator Sprint 1 implementation.

Tests actual implementation:
- Weights: VT=40%, UV=30%, PT=30%
- Threat Levels: safe (0-20), suspicious (21-60), malicious (61-100)
"""

import pytest
from src.services.confidence_calculator import ConfidenceCalculator, ThreatLevel


class TestConfidenceCalculatorBasics:
    """Test basic confidence calculation."""

    @pytest.fixture
    def calculator(self):
        return ConfidenceCalculator()

    def test_all_apis_available_clean(self, calculator):
        """All APIs returning clean results."""
        api_results = {
            "virustotal": {"positives": 0, "total": 70},
            "urlvoid": {"blacklists": 0, "engines": 30},
            "phishtank": {"is_phishing": False, "verified": False}
        }

        result = calculator.calculate(api_results)

        assert result["confidence_score"] == 0.0
        assert result["threat_level"] == ThreatLevel.SAFE
        assert result["total_apis_used"] == 3
        assert all(result["api_availability"].values())

    def test_all_apis_available_malicious(self, calculator):
        """All APIs detecting threats."""
        api_results = {
            "virustotal": {"positives": 70, "total": 70},  # 100% * 0.40 = 40
            "urlvoid": {"blacklists": 30, "engines": 30},   # 100% * 0.30 = 30
            "phishtank": {"is_phishing": True, "verified": True}  # 100% * 0.30 = 30
        }

        result = calculator.calculate(api_results)

        assert result["confidence_score"] == 100.0
        assert result["threat_level"] == ThreatLevel.MALICIOUS
        assert result["total_apis_used"] == 3

    def test_mixed_results(self, calculator):
        """Mixed threat detection results."""
        api_results = {
            "virustotal": {"positives": 35, "total": 70},  # 50% * 0.40 = 20
            "urlvoid": {"blacklists": 10, "engines": 30},  # 33.3% * 0.30 = 10
            "phishtank": {"is_phishing": False, "verified": False}  # 0% * 0.30 = 0
        }

        result = calculator.calculate(api_results)

        assert 29.0 <= result["confidence_score"] <= 31.0  # ~30
        assert result["threat_level"] == ThreatLevel.SUSPICIOUS
        assert result["total_apis_used"] == 3


class TestDegradedMode:
    """Test confidence calculation with partial API failures."""

    @pytest.fixture
    def calculator(self):
        return ConfidenceCalculator()

    def test_only_virustotal_available(self, calculator):
        """Only VirusTotal responding."""
        api_results = {
            "virustotal": {"positives": 50, "total": 70},  # 71.4%
            "urlvoid": None,
            "phishtank": None
        }

        result = calculator.calculate(api_results)

        # VT weight normalized to 100%: 71.4% * 1.0 = 71.4%
        assert 70.0 <= result["confidence_score"] <= 72.0
        assert result["threat_level"] == ThreatLevel.MALICIOUS
        assert result["total_apis_used"] == 1
        assert result["api_availability"]["virustotal"] is True
        assert result["api_availability"]["urlvoid"] is False

    def test_two_apis_available(self, calculator):
        """Two APIs responding."""
        api_results = {
            "virustotal": {"positives": 35, "total": 70},  # 50%
            "urlvoid": {"blacklists": 15, "engines": 30},  # 50%
            "phishtank": None
        }

        result = calculator.calculate(api_results)

        # Weights: VT=0.4/(0.4+0.3)=57.1%, UV=0.3/(0.4+0.3)=42.9%
        # Score: 50*0.571 + 50*0.429 = 50%
        assert 49.0 <= result["confidence_score"] <= 51.0
        assert result["threat_level"] == ThreatLevel.SUSPICIOUS
        assert result["total_apis_used"] == 2

    def test_all_apis_unavailable(self, calculator):
        """No APIs responding."""
        api_results = {
            "virustotal": None,
            "urlvoid": None,
            "phishtank": None
        }

        result = calculator.calculate(api_results)

        assert result["confidence_score"] == 0.0
        assert result["threat_level"] == ThreatLevel.UNKNOWN
        assert result["total_apis_used"] == 0
        assert "error" in result


class TestThreatLevelClassification:
    """Test threat level determination."""

    @pytest.fixture
    def calculator(self):
        return ConfidenceCalculator()

    @pytest.mark.parametrize("score,expected_level", [
        (0.0, ThreatLevel.SAFE),
        (10.0, ThreatLevel.SAFE),
        (20.0, ThreatLevel.SAFE),
        (20.1, ThreatLevel.SUSPICIOUS),
        (30.0, ThreatLevel.SUSPICIOUS),
        (50.0, ThreatLevel.SUSPICIOUS),
        (60.0, ThreatLevel.SUSPICIOUS),
        (60.1, ThreatLevel.MALICIOUS),
        (75.0, ThreatLevel.MALICIOUS),
        (100.0, ThreatLevel.MALICIOUS),
    ])
    def test_threat_levels(self, calculator, score, expected_level):
        """Test threat level boundaries."""
        level = calculator._determine_threat_level(score)
        assert level == expected_level


class TestComponentScoring:
    """Test individual API scoring methods."""

    @pytest.fixture
    def calculator(self):
        return ConfidenceCalculator()

    def test_score_virustotal_clean(self, calculator):
        """VirusTotal with no detections."""
        result = {"positives": 0, "total": 70}
        score = calculator._score_virustotal(result)
        assert score == 0.0

    def test_score_virustotal_full_detection(self, calculator):
        """VirusTotal with all detections."""
        result = {"positives": 70, "total": 70}
        score = calculator._score_virustotal(result)
        assert score == 100.0

    def test_score_virustotal_partial(self, calculator):
        """VirusTotal with partial detections."""
        result = {"positives": 35, "total": 70}
        score = calculator._score_virustotal(result)
        assert score == 50.0

    def test_score_urlvoid_clean(self, calculator):
        """URLVoid with no blacklists."""
        result = {"blacklists": 0, "engines": 30}
        score = calculator._score_urlvoid(result)
        assert score == 0.0

    def test_score_urlvoid_all_blacklisted(self, calculator):
        """URLVoid with all blacklists."""
        result = {"blacklists": 30, "engines": 30}
        score = calculator._score_urlvoid(result)
        assert score == 100.0

    def test_score_phishtank_not_phishing(self, calculator):
        """PhishTank - not phishing."""
        result = {"is_phishing": False, "verified": False}
        score = calculator._score_phishtank(result)
        assert score == 0.0

    def test_score_phishtank_verified(self, calculator):
        """PhishTank - verified phishing."""
        result = {"is_phishing": True, "verified": True}
        score = calculator._score_phishtank(result)
        assert score == 100.0

    def test_score_phishtank_unverified(self, calculator):
        """PhishTank - unverified phishing."""
        result = {"is_phishing": True, "verified": False}
        score = calculator._score_phishtank(result)
        assert score == 70.0


class TestRecommendations:
    """Test security recommendations."""

    @pytest.fixture
    def calculator(self):
        return ConfidenceCalculator()

    def test_recommendation_safe(self, calculator):
        """Recommendation for safe threat level."""
        rec = calculator.get_recommendation(10.0, ThreatLevel.SAFE)
        assert "safe" in rec.lower()

    def test_recommendation_suspicious(self, calculator):
        """Recommendation for suspicious threat level."""
        rec = calculator.get_recommendation(45.0, ThreatLevel.SUSPICIOUS)
        assert "suspicious" in rec.lower() or "caution" in rec.lower()

    def test_recommendation_malicious(self, calculator):
        """Recommendation for malicious threat level."""
        rec = calculator.get_recommendation(80.0, ThreatLevel.MALICIOUS)
        assert "malicious" in rec.lower() or "not" in rec.lower()

    def test_recommendation_unknown(self, calculator):
        """Recommendation for unknown threat level."""
        rec = calculator.get_recommendation(0.0, ThreatLevel.UNKNOWN)
        assert "insufficient" in rec.lower() or "manual" in rec.lower()
