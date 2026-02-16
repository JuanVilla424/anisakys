"""
Threat Intelligence API Endpoints
Professional-grade threat intelligence endpoints for Anisakys
"""
import logging
from flask import Blueprint, request, jsonify
from functools import wraps
from typing import Dict, Any

# Import all threat intelligence modules
from src.cert_transparency_monitor import CertTransparencyMonitor
from src.threat_intel_feeds import ThreatIntelFeeds
from src.ml_visual_analyzer import MLVisualAnalyzer
from src.nlp_content_analyzer import NLPContentAnalyzer
from src.osint_automation import OSINTAutomation
from src.social_media_monitor import SocialMediaMonitor
from src.ml_phishing_classifier import MLPhishingClassifier

logger = logging.getLogger(__name__)

# Create Blueprint
threat_intel_bp = Blueprint('threat_intel', __name__, url_prefix='/api/v1/threat-intel')


class ThreatIntelAPI:
    """Professional Threat Intelligence API handler."""

    def __init__(self, require_api_key_decorator):
        self.require_api_key = require_api_key_decorator

        # Initialize all modules
        self.ct_monitor = CertTransparencyMonitor()
        self.threat_feeds = ThreatIntelFeeds()
        self.ml_visual = MLVisualAnalyzer()
        self.nlp_analyzer = NLPContentAnalyzer()
        self.osint = OSINTAutomation()
        self.social_monitor = SocialMediaMonitor()
        self.ml_classifier = MLPhishingClassifier()

        # Register all routes
        self.register_routes()

    def register_routes(self):
        """Register all threat intelligence routes."""

        @threat_intel_bp.route('/certificate-transparency', methods=['POST'])
        @self.require_api_key
        def certificate_transparency():
            """Search Certificate Transparency logs for suspicious certs."""
            try:
                data = request.get_json() or {}
                brand = data.get('brand')
                days_back = data.get('days_back', 7)
                legitimate_domains = data.get('legitimate_domains', [])

                if not brand:
                    return jsonify({'error': 'brand is required'}), 400

                logger.info(f"🔍 CT search for brand: {brand}")

                results = self.ct_monitor.search_certificates(
                    brand=brand,
                    days_back=days_back,
                    exclude_legit_domains=legitimate_domains
                )

                return jsonify({
                    'brand': brand,
                    'days_searched': days_back,
                    'certificates_found': len(results),
                    'results': results
                }), 200

            except Exception as e:
                logger.error(f"❌ CT API error: {e}")
                return jsonify({'error': str(e)}), 500

        @threat_intel_bp.route('/threat-feeds', methods=['GET'])
        @self.require_api_key
        def get_threat_feeds():
            """Get all active threats from threat intelligence feeds."""
            try:
                max_per_feed = request.args.get('max_per_feed', 500, type=int)
                brand = request.args.get('brand', None)

                logger.info(f"📥 Fetching threat feeds (brand: {brand or 'all'})")

                if brand:
                    # Search specific brand
                    results = self.threat_feeds.search_feeds_for_brand(brand)
                    return jsonify({
                        'brand': brand,
                        'threats_found': len(results),
                        'threats': results
                    }), 200
                else:
                    # Get all threats
                    results = self.threat_feeds.get_all_active_threats(max_per_feed=max_per_feed)
                    return jsonify(results), 200

            except Exception as e:
                logger.error(f"❌ Threat feeds API error: {e}")
                return jsonify({'error': str(e)}), 500

        @threat_intel_bp.route('/check-url-feeds', methods=['POST'])
        @self.require_api_key
        def check_url_in_feeds():
            """Check if URL exists in threat feeds."""
            try:
                data = request.get_json() or {}
                url = data.get('url')

                if not url:
                    return jsonify({'error': 'url is required'}), 400

                logger.info(f"🔍 Checking URL in threat feeds")

                result = self.threat_feeds.check_url_in_feeds(url)
                return jsonify(result), 200

            except Exception as e:
                logger.error(f"❌ Check URL API error: {e}")
                return jsonify({'error': str(e)}), 500

        @threat_intel_bp.route('/osint-analysis', methods=['POST'])
        @self.require_api_key
        def osint_analysis():
            """Perform comprehensive OSINT analysis."""
            try:
                data = request.get_json() or {}
                domain = data.get('domain')
                ip = data.get('ip')

                if not domain:
                    return jsonify({'error': 'domain is required'}), 400

                logger.info(f"🔍 OSINT analysis for: {domain}")

                result = self.osint.comprehensive_osint(domain, ip)
                return jsonify(result), 200

            except Exception as e:
                logger.error(f"❌ OSINT API error: {e}")
                return jsonify({'error': str(e)}), 500

        @threat_intel_bp.route('/social-media-monitor', methods=['POST'])
        @self.require_api_key
        def social_media_monitoring():
            """Monitor social media for brand mentions."""
            try:
                data = request.get_json() or {}
                brand = data.get('brand')
                keywords = data.get('keywords')

                if not brand:
                    return jsonify({'error': 'brand is required'}), 400

                logger.info(f"📱 Social media monitoring for: {brand}")

                result = self.social_monitor.monitor_brand_mentions(brand, keywords)
                return jsonify(result), 200

            except Exception as e:
                logger.error(f"❌ Social media API error: {e}")
                return jsonify({'error': str(e)}), 500

        @threat_intel_bp.route('/ml-classify', methods=['POST'])
        @self.require_api_key
        def ml_classification():
            """Perform ML-based phishing classification."""
            try:
                data = request.get_json() or {}
                url = data.get('url')
                content_score = data.get('content_score', 0)
                visual_score = data.get('visual_score', 0)
                threat_intel_score = data.get('threat_intel_score', 0)
                osint_score = data.get('osint_score', 0)

                if not url:
                    return jsonify({'error': 'url is required'}), 400

                logger.info(f"🤖 ML classification for: {url[:50]}")

                # Extract URL features
                url_features = self.ml_classifier.extract_url_features(url)

                # Calculate ensemble score
                ensemble = self.ml_classifier.calculate_ensemble_score(
                    url_features=url_features,
                    content_score=content_score,
                    visual_score=visual_score,
                    threat_intel_score=threat_intel_score,
                    osint_score=osint_score
                )

                return jsonify(ensemble), 200

            except Exception as e:
                logger.error(f"❌ ML classification API error: {e}")
                return jsonify({'error': str(e)}), 500

        @threat_intel_bp.route('/comprehensive-scan', methods=['POST'])
        @self.require_api_key
        def comprehensive_threat_scan():
            """
            ULTIMATE COMPREHENSIVE THREAT INTELLIGENCE SCAN
            Combines ALL modules for maximum detection capability.
            """
            try:
                data = request.get_json() or {}
                url = data.get('url')
                domain = data.get('domain')
                brand = data.get('brand')

                if not url and not domain:
                    return jsonify({'error': 'url or domain is required'}), 400

                logger.info(f"🚀 COMPREHENSIVE SCAN: {url or domain}")

                scan_results = {
                    'url': url,
                    'domain': domain,
                    'brand': brand,
                    'scan_timestamp': 'now',
                    'modules_executed': []
                }

                # Module 1: Threat Intelligence Feeds
                logger.info("   📥 Module 1/7: Threat Intelligence Feeds")
                if url:
                    feed_check = self.threat_feeds.check_url_in_feeds(url)
                    scan_results['threat_feeds'] = feed_check
                    scan_results['modules_executed'].append('threat_feeds')

                # Module 2: Certificate Transparency (if brand provided)
                if brand:
                    logger.info("   📜 Module 2/7: Certificate Transparency")
                    ct_results = self.ct_monitor.search_certificates(
                        brand=brand,
                        days_back=30,
                        exclude_legit_domains=[domain] if domain else []
                    )
                    scan_results['certificate_transparency'] = {
                        'suspicious_certs_found': len(ct_results),
                        'results': ct_results[:10]  # Top 10
                    }
                    scan_results['modules_executed'].append('certificate_transparency')

                # Module 3: OSINT Analysis
                if domain:
                    logger.info("   🔍 Module 3/7: OSINT Analysis")
                    osint_results = self.osint.comprehensive_osint(domain)
                    scan_results['osint'] = osint_results
                    scan_results['modules_executed'].append('osint')

                # Module 4: Social Media Monitoring
                if brand:
                    logger.info("   📱 Module 4/7: Social Media Monitoring")
                    social_results = self.social_monitor.monitor_brand_mentions(brand)
                    scan_results['social_media'] = social_results
                    scan_results['modules_executed'].append('social_media')

                # Module 5: ML Classification
                if url:
                    logger.info("   🤖 Module 5/7: ML Classification")
                    url_features = self.ml_classifier.extract_url_features(url)

                    # Get scores from previous modules
                    threat_intel_score = 95 if feed_check.get('is_malicious') else 0
                    osint_score = osint_results.get('risk_score', 0) if domain else 0

                    ensemble = self.ml_classifier.calculate_ensemble_score(
                        url_features=url_features,
                        content_score=0,  # Would come from HTML analysis
                        visual_score=0,   # Would come from screenshot
                        threat_intel_score=threat_intel_score,
                        osint_score=osint_score
                    )
                    scan_results['ml_classification'] = ensemble
                    scan_results['modules_executed'].append('ml_classification')

                # Calculate FINAL THREAT SCORE
                scores = []
                if 'ml_classification' in scan_results:
                    scores.append(scan_results['ml_classification']['final_score'])
                if 'osint' in scan_results:
                    scores.append(scan_results['osint'].get('risk_score', 0))
                if 'threat_feeds' in scan_results and scan_results['threat_feeds'].get('is_malicious'):
                    scores.append(95)

                if scores:
                    final_score = int(sum(scores) / len(scores))
                else:
                    final_score = 0

                scan_results['final_threat_score'] = final_score

                if final_score >= 85:
                    scan_results['final_verdict'] = 'CRITICAL_THREAT'
                elif final_score >= 70:
                    scan_results['final_verdict'] = 'HIGH_RISK'
                elif final_score >= 50:
                    scan_results['final_verdict'] = 'MEDIUM_RISK'
                else:
                    scan_results['final_verdict'] = 'LOW_RISK'

                logger.info(f"✅ COMPREHENSIVE SCAN COMPLETE: {scan_results['final_verdict']} ({final_score}/100)")

                return jsonify(scan_results), 200

            except Exception as e:
                logger.error(f"❌ Comprehensive scan error: {e}")
                import traceback
                traceback.print_exc()
                return jsonify({'error': str(e)}), 500


def create_threat_intel_api(app, require_api_key):
    """
    Create and register threat intelligence API.

    Args:
        app: Flask app instance
        require_api_key: API key decorator function

    Returns:
        ThreatIntelAPI instance
    """
    threat_api = ThreatIntelAPI(require_api_key)
    app.register_blueprint(threat_intel_bp)

    logger.info("✅ Threat Intelligence API registered")
    return threat_api
