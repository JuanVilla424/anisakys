"""Quick Sprint 1 validation tests - standalone without DB."""

from src.services.confidence_calculator import ConfidenceCalculator, ThreatLevel


def test_confidence_calculator_all_clean():
    """Test confidence calculator with all clean results."""
    calc = ConfidenceCalculator()

    api_results = {
        "virustotal": {"positives": 0, "total": 70},
        "urlvoid": {"blacklists": 0, "engines": 30},
        "phishtank": {"is_phishing": False, "verified": False}
    }

    result = calc.calculate(api_results)

    assert result["confidence_score"] == 0.0
    assert result["threat_level"] == ThreatLevel.SAFE
    assert result["total_apis_used"] == 3
    print("✅ Test confidence_calculator_all_clean PASSED")


def test_confidence_calculator_all_malicious():
    """Test confidence calculator with all malicious."""
    calc = ConfidenceCalculator()

    api_results = {
        "virustotal": {"positives": 70, "total": 70},
        "urlvoid": {"blacklists": 30, "engines": 30},
        "phishtank": {"is_phishing": True, "verified": True}
    }

    result = calc.calculate(api_results)

    assert result["confidence_score"] == 100.0
    assert result["threat_level"] == ThreatLevel.MALICIOUS
    print("✅ Test confidence_calculator_all_malicious PASSED")


def test_confidence_calculator_mixed():
    """Test with mixed results."""
    calc = ConfidenceCalculator()

    api_results = {
        "virustotal": {"positives": 35, "total": 70},  # 50%
        "urlvoid": {"blacklists": 10, "engines": 30},  # 33%
        "phishtank": {"is_phishing": False, "verified": False}  # 0%
    }

    result = calc.calculate(api_results)

    # Expected: (50*0.4) + (33.3*0.3) + (0*0.3) = 20 + 10 + 0 = 30%
    assert 29.0 <= result["confidence_score"] <= 31.0
    assert result["threat_level"] == ThreatLevel.SUSPICIOUS
    print("✅ Test confidence_calculator_mixed PASSED")


def test_degraded_mode_one_api():
    """Test with only one API available."""
    calc = ConfidenceCalculator()

    api_results = {
        "virustotal": {"positives": 50, "total": 70},
        "urlvoid": None,
        "phishtank": None
    }

    result = calc.calculate(api_results)

    # VT weight normalized to 100%: ~71.4%
    assert 70.0 <= result["confidence_score"] <= 72.0
    assert result["threat_level"] == ThreatLevel.MALICIOUS
    assert result["total_apis_used"] == 1
    print("✅ Test degraded_mode_one_api PASSED")


def test_threat_levels():
    """Test threat level classification."""
    calc = ConfidenceCalculator()

    assert calc._determine_threat_level(0.0) == ThreatLevel.SAFE
    assert calc._determine_threat_level(20.0) == ThreatLevel.SAFE
    assert calc._determine_threat_level(20.1) == ThreatLevel.SUSPICIOUS
    assert calc._determine_threat_level(50.0) == ThreatLevel.SUSPICIOUS
    assert calc._determine_threat_level(60.0) == ThreatLevel.SUSPICIOUS
    assert calc._determine_threat_level(60.1) == ThreatLevel.MALICIOUS
    assert calc._determine_threat_level(100.0) == ThreatLevel.MALICIOUS
    print("✅ Test threat_levels PASSED")


if __name__ == "__main__":
    print("\n🚀 Sprint 1 Quick Validation Tests\n")

    test_confidence_calculator_all_clean()
    test_confidence_calculator_all_malicious()
    test_confidence_calculator_mixed()
    test_degraded_mode_one_api()
    test_threat_levels()

    print("\n✨ All Sprint 1 core tests PASSED!")
    print("📊 Confidence Calculator: VALIDATED")
    print("🎯 Threat Level Classification: VALIDATED")
    print("⚡ Degraded Mode: VALIDATED")
