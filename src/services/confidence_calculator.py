"""Confidence score calculator for multi-API scan results."""

from typing import Dict, Optional, List
from enum import Enum


class ThreatLevel(str, Enum):
    """Threat level classification."""
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"


class ConfidenceCalculator:
    """Calculate confidence scores from multi-API scan results.

    Implements weighted scoring algorithm considering:
    - VirusTotal detections (40% weight)
    - URLVoid blacklist reputation (30% weight)
    - PhishTank verified phishing (30% weight)

    Example:
        ```python
        calc = ConfidenceCalculator()
        results = {
            "virustotal": {"positives": 45, "total": 70},
            "urlvoid": {"blacklists": 5, "engines": 30},
            "phishtank": {"is_phishing": True, "verified": True}
        }
        score = calc.calculate(results)
        print(f"Confidence: {score['confidence_score']}%")
        print(f"Threat: {score['threat_level']}")
        ```
    """

    # Scoring weights (must sum to 1.0)
    WEIGHTS = {
        "virustotal": 0.40,
        "urlvoid": 0.30,
        "phishtank": 0.30,
    }

    # Threat level thresholds
    THRESHOLDS = {
        "safe": 20,        # 0-20: Safe
        "suspicious": 60,  # 21-60: Suspicious
        # 61-100: Malicious
    }

    def __init__(self):
        """Initialize confidence calculator."""
        pass

    def calculate(self, api_results: Dict[str, Optional[dict]]) -> dict:
        """Calculate confidence score from API results.

        Args:
            api_results: Dictionary with API results:
                {
                    "virustotal": {...} or None,
                    "urlvoid": {...} or None,
                    "phishtank": {...} or None
                }

        Returns:
            Dict with confidence analysis:
            {
                "confidence_score": 75.5,  # 0-100
                "threat_level": "malicious",
                "component_scores": {
                    "virustotal": 64.3,
                    "urlvoid": 83.3,
                    "phishtank": 100.0
                },
                "api_availability": {
                    "virustotal": True,
                    "urlvoid": True,
                    "phishtank": False
                },
                "total_apis_used": 2
            }

        Example:
            ```python
            results = {
                "virustotal": {"positives": 10, "total": 70},
                "urlvoid": None,  # API unavailable
                "phishtank": {"is_phishing": False}
            }
            analysis = calc.calculate(results)
            ```
        """
        component_scores = {}
        api_availability = {}
        weights_used = {}

        # Calculate individual component scores
        for api_name, result in api_results.items():
            if result is None:
                # API unavailable
                api_availability[api_name] = False
                component_scores[api_name] = 0.0
                weights_used[api_name] = 0.0
            else:
                api_availability[api_name] = True
                weights_used[api_name] = self.WEIGHTS[api_name]

                # Calculate component score
                if api_name == "virustotal":
                    component_scores[api_name] = self._score_virustotal(result)
                elif api_name == "urlvoid":
                    component_scores[api_name] = self._score_urlvoid(result)
                elif api_name == "phishtank":
                    component_scores[api_name] = self._score_phishtank(result)
                else:
                    component_scores[api_name] = 0.0

        # Normalize weights (re-distribute if some APIs are unavailable)
        total_weight = sum(weights_used.values())
        if total_weight == 0:
            # All APIs unavailable
            return {
                "confidence_score": 0.0,
                "threat_level": ThreatLevel.UNKNOWN,
                "component_scores": component_scores,
                "api_availability": api_availability,
                "total_apis_used": 0,
                "error": "No APIs available"
            }

        normalized_weights = {
            k: v / total_weight for k, v in weights_used.items()
        }

        # Calculate weighted confidence score
        confidence_score = sum(
            component_scores[api] * normalized_weights[api]
            for api in api_results.keys()
            if api_availability[api]
        )

        # Determine threat level
        threat_level = self._determine_threat_level(confidence_score)

        # Count available APIs
        total_apis_used = sum(1 for available in api_availability.values() if available)

        return {
            "confidence_score": round(confidence_score, 2),
            "threat_level": threat_level,
            "component_scores": {k: round(v, 2) for k, v in component_scores.items()},
            "api_availability": api_availability,
            "total_apis_used": total_apis_used
        }

    def _score_virustotal(self, result: dict) -> float:
        """Score VirusTotal results (0-100).

        Args:
            result: VirusTotal API result

        Returns:
            Score where 0 = clean, 100 = maximum threat
        """
        positives = result.get("positives", 0)
        total = result.get("total", 1)

        if total == 0:
            return 0.0

        # Percentage of engines detecting threat
        detection_rate = (positives / total) * 100

        return min(detection_rate, 100.0)

    def _score_urlvoid(self, result: dict) -> float:
        """Score URLVoid results (0-100).

        Args:
            result: URLVoid API result

        Returns:
            Score where 0 = clean, 100 = maximum threat
        """
        blacklists = result.get("blacklists", 0)
        engines = result.get("engines", 1)

        if engines == 0:
            return 0.0

        # Percentage of blacklists flagging
        blacklist_rate = (blacklists / engines) * 100

        return min(blacklist_rate, 100.0)

    def _score_phishtank(self, result: dict) -> float:
        """Score PhishTank results (0-100).

        Args:
            result: PhishTank API result

        Returns:
            Score where 0 = clean, 100 = confirmed phishing
        """
        is_phishing = result.get("is_phishing", False)
        verified = result.get("verified", False)

        if not is_phishing:
            return 0.0

        # Verified phishing = 100, unverified = 70
        return 100.0 if verified else 70.0

    def _determine_threat_level(self, confidence_score: float) -> ThreatLevel:
        """Determine threat level from confidence score.

        Args:
            confidence_score: Calculated confidence (0-100)

        Returns:
            ThreatLevel enum value
        """
        if confidence_score <= self.THRESHOLDS["safe"]:
            return ThreatLevel.SAFE
        elif confidence_score <= self.THRESHOLDS["suspicious"]:
            return ThreatLevel.SUSPICIOUS
        else:
            return ThreatLevel.MALICIOUS

    def get_recommendation(self, confidence_score: float, threat_level: ThreatLevel) -> str:
        """Get security recommendation based on analysis.

        Args:
            confidence_score: Confidence score
            threat_level: Determined threat level

        Returns:
            Human-readable recommendation string
        """
        if threat_level == ThreatLevel.SAFE:
            return "URL appears safe based on current threat intelligence."
        elif threat_level == ThreatLevel.SUSPICIOUS:
            return "URL shows suspicious indicators. Proceed with caution and verify source."
        elif threat_level == ThreatLevel.MALICIOUS:
            return "URL flagged as malicious. Do NOT visit or interact with this site."
        else:
            return "Insufficient data to determine threat level. Manual review recommended."
