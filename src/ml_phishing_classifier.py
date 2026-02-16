"""
Machine Learning Phishing Classifier
Advanced ML-based phishing scoring and classification:
- Feature extraction from URLs, content, visual, and OSINT data
- Ensemble scoring from multiple signals
- Real-time threat classification
- Confidence scoring with explainability
"""
import logging
from typing import Dict, Any, List
import re
from urllib.parse import urlparse
import numpy as np

logger = logging.getLogger(__name__)


class MLPhishingClassifier:
    """Machine learning powered phishing classifier."""

    def __init__(self):
        # Feature weights (tuned for phishing detection)
        self.weights = {
            'url_features': 0.20,
            'content_features': 0.25,
            'visual_features': 0.20,
            'threat_intel': 0.20,
            'osint_features': 0.15
        }

    def extract_url_features(self, url: str) -> Dict[str, Any]:
        """
        Extract ML features from URL.

        Args:
            url: URL to analyze

        Returns:
            URL feature scores
        """
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            path = parsed.path.lower()

            score = 0
            features = {}

            # Feature 1: URL length
            url_length = len(url)
            if url_length > 75:
                score += 15
                features['long_url'] = True
            elif url_length > 50:
                score += 10

            # Feature 2: Subdomain count
            subdomain_count = domain.count('.') - 1
            if subdomain_count >= 3:
                score += 20
                features['excessive_subdomains'] = True
            elif subdomain_count >= 2:
                score += 10

            # Feature 3: IP address in URL
            if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
                score += 30
                features['ip_address_url'] = True

            # Feature 4: Suspicious TLDs
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz',
                              '.top', '.work', '.click', '.link']
            if any(domain.endswith(tld) for tld in suspicious_tlds):
                score += 25
                features['suspicious_tld'] = True

            # Feature 5: HTTPS
            if parsed.scheme != 'https':
                score += 15
                features['no_https'] = True

            # Feature 6: @ symbol (user confusion)
            if '@' in url:
                score += 30
                features['at_symbol'] = True

            # Feature 7: Hyphens in domain
            hyphen_count = domain.count('-')
            if hyphen_count >= 3:
                score += 15
                features['excessive_hyphens'] = True

            # Feature 8: Suspicious keywords in path
            suspicious_words = ['login', 'account', 'verify', 'secure', 'update',
                               'confirm', 'banking', 'paypal', 'ebay']
            path_suspicious = sum(1 for word in suspicious_words if word in path)
            if path_suspicious >= 2:
                score += 20
                features['suspicious_path_keywords'] = path_suspicious

            # Feature 9: Port number (unusual)
            if parsed.port and parsed.port not in [80, 443]:
                score += 10
                features['unusual_port'] = parsed.port

            features['url_score'] = min(score, 100)
            return features

        except Exception as e:
            logger.error(f"❌ URL feature extraction error: {e}")
            return {'url_score': 0, 'error': str(e)}

    def calculate_threat_intel_score(
        self,
        feed_detections: List[Dict[str, Any]]
    ) -> int:
        """
        Calculate score from threat intelligence feed detections.

        Args:
            feed_detections: List of detections from various feeds

        Returns:
            Threat intel score (0-100)
        """
        if not feed_detections:
            return 0

        # If detected in any feed, very high confidence
        max_confidence = max(d.get('confidence', 0) for d in feed_detections)
        detection_count = len(feed_detections)

        # Multiple feed detections = higher confidence
        score = max_confidence + (detection_count - 1) * 5

        return min(score, 100)

    def calculate_ensemble_score(
        self,
        url_features: Dict[str, Any],
        content_score: int = 0,
        visual_score: int = 0,
        threat_intel_score: int = 0,
        osint_score: int = 0
    ) -> Dict[str, Any]:
        """
        Calculate ensemble phishing score from all features.

        Args:
            url_features: URL feature dict
            content_score: Content NLP score (0-100)
            visual_score: Visual similarity score (0-100)
            threat_intel_score: Threat feed score (0-100)
            osint_score: OSINT risk score (0-100)

        Returns:
            Final ensemble score with breakdown
        """
        url_score = url_features.get('url_score', 0)

        # Weighted ensemble
        ensemble = (
            url_score * self.weights['url_features'] +
            content_score * self.weights['content_features'] +
            visual_score * self.weights['visual_features'] +
            threat_intel_score * self.weights['threat_intel'] +
            osint_score * self.weights['osint_features']
        )

        final_score = int(ensemble)

        # Determine threat level
        if final_score >= 85:
            threat_level = 'critical'
        elif final_score >= 70:
            threat_level = 'high'
        elif final_score >= 50:
            threat_level = 'medium'
        elif final_score >= 30:
            threat_level = 'low'
        else:
            threat_level = 'minimal'

        # Build explanation
        contributors = []
        if url_score >= 50:
            contributors.append(f"Suspicious URL patterns ({url_score}%)")
        if content_score >= 50:
            contributors.append(f"Malicious content detected ({content_score}%)")
        if visual_score >= 70:
            contributors.append(f"Visual impersonation ({visual_score}%)")
        if threat_intel_score >= 90:
            contributors.append(f"Detected in threat feeds ({threat_intel_score}%)")
        if osint_score >= 50:
            contributors.append(f"Suspicious infrastructure ({osint_score}%)")

        return {
            'final_score': final_score,
            'threat_level': threat_level,
            'breakdown': {
                'url_score': url_score,
                'content_score': content_score,
                'visual_score': visual_score,
                'threat_intel_score': threat_intel_score,
                'osint_score': osint_score
            },
            'weights_applied': self.weights,
            'top_contributors': contributors,
            'confidence': self._calculate_confidence(
                url_score, content_score, visual_score,
                threat_intel_score, osint_score
            )
        }

    def _calculate_confidence(
        self,
        url_score: int,
        content_score: int,
        visual_score: int,
        threat_intel_score: int,
        osint_score: int
    ) -> str:
        """Calculate confidence level in the classification."""
        # Count how many signals are strong
        strong_signals = sum([
            url_score >= 60,
            content_score >= 60,
            visual_score >= 70,
            threat_intel_score >= 90,
            osint_score >= 50
        ])

        if strong_signals >= 4:
            return 'very_high'
        elif strong_signals >= 3:
            return 'high'
        elif strong_signals >= 2:
            return 'medium'
        elif strong_signals >= 1:
            return 'low'
        else:
            return 'very_low'


def test_ml_classifier():
    """Test ML phishing classifier."""
    classifier = MLPhishingClassifier()

    print("\n🤖 Testing ML Phishing Classifier...")

    # Test with phishing URL
    phishing_url = "http://paypal-security-verify.tk/login.php?user=test@confirm"
    url_features = classifier.extract_url_features(phishing_url)

    print(f"   URL Score: {url_features['url_score']}/100")
    print(f"   Features: {list(url_features.keys())[:5]}")

    # Test ensemble
    ensemble = classifier.calculate_ensemble_score(
        url_features=url_features,
        content_score=75,
        visual_score=85,
        threat_intel_score=95,
        osint_score=40
    )

    print(f"   Final Score: {ensemble['final_score']}/100")
    print(f"   Threat Level: {ensemble['threat_level']}")
    print(f"   Confidence: {ensemble['confidence']}")

    print("✅ ML classifier test complete")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    test_ml_classifier()
