"""
Multi-API Validator for Anisakys Phishing Detection Engine.

Aggregates results from multiple threat intelligence APIs
(VirusTotal, URLVoid, PhishTank) for comprehensive threat assessment.
"""

import datetime
import logging
import re
from typing import Any, Dict, List, Optional

from src.config import settings
from src.logger import logger
from src.observability.structured_logger import log_with_context

# Import integrations
from src.intelligence.virustotal import VirusTotalIntegration, VIRUSTOTAL_API_KEY
from src.intelligence.urlvoid import URLVoidIntegration, URLVOID_API_KEY
from src.intelligence.phishtank import PhishTankIntegration, PHISHTANK_API_KEY
from src.intelligence.google_safe_browsing import GoogleSafeBrowsingIntegration
from src.detection.url_analyzer import URLAnalyzer

# Auto-Analysis Configuration
AUTO_MULTI_API_SCAN = getattr(settings, "AUTO_MULTI_API_SCAN", False)
AUTO_REPORT_THRESHOLD_CONFIDENCE = getattr(settings, "AUTO_REPORT_THRESHOLD_CONFIDENCE", 80)
MANUAL_REVIEW_THRESHOLD_CONFIDENCE = getattr(settings, "MANUAL_REVIEW_THRESHOLD_CONFIDENCE", 50)

# Auto-analysis is only truly enabled if we have API keys AND the setting is enabled
AUTO_ANALYSIS_ENABLED = AUTO_MULTI_API_SCAN and (
    VIRUSTOTAL_API_KEY or URLVOID_API_KEY or PHISHTANK_API_KEY
)


class MultiAPIValidator:
    """
    Multi-API validation pipeline for comprehensive phishing detection.

    Orchestrates VirusTotal, URLVoid, and PhishTank APIs for enhanced
    threat detection with configurable validation thresholds.
    """

    def __init__(self):
        """Initialize multi-API validator with all integrated services."""
        self.virustotal = VirusTotalIntegration()
        self.urlvoid = URLVoidIntegration()
        self.phishtank = PhishTankIntegration()
        self.google_safe_browsing = GoogleSafeBrowsingIntegration()
        self.url_analyzer = URLAnalyzer()

    def comprehensive_scan(self, url: str) -> Dict[str, Any]:
        """
        Perform comprehensive multi-API validation scan.

        Args:
            url (str): URL to validate

        Returns:
            Dict[str, Any]: Comprehensive validation report with aggregated results
        """
        logger.info(f"🔍 Starting comprehensive multi-API scan for {url}")

        # Extract domain for domain-specific checks
        domain = re.sub(r"^https?://", "", url).strip().split("/")[0]

        results = {
            "url": url,
            "domain": domain,
            "scan_timestamp": datetime.datetime.now().isoformat(),
            "virustotal": {},
            "urlvoid": {},
            "phishtank": {},
            "google_safe_browsing": {},
            "url_analysis": {},
            "aggregated_threat_level": "unknown",
            "confidence_score": 0,
            "recommendations": [],
        }

        # Step 0: URL Lexical Analysis (fast, no API calls)
        logger.info(f"📊 Step 0: URL lexical analysis for {url}")
        url_analysis = self.url_analyzer.analyze(url)
        results["url_analysis"] = url_analysis
        if url_analysis.get("risk_score", 0) > 0:
            logger.warning(f"⚠️ URL analysis risk score: {url_analysis['risk_score']}")
            for factor in url_analysis.get("risk_factors", []):
                logger.warning(f"   - {factor}")

        # Step 1: VirusTotal URL scan
        logger.info(f"📊 Step 1: VirusTotal URL analysis for {url}")
        vt_result = self.virustotal.scan_url(url)
        results["virustotal"] = vt_result

        # Step 1.5: VirusTotal domain report for registrar info
        vt_domain = self.virustotal.get_domain_report(domain)
        if not vt_domain.get("error"):
            results["virustotal"]["registrar"] = vt_domain.get("registrar")
            results["virustotal"]["creation_date"] = vt_domain.get("creation_date")

        # Step 2: URLVoid domain analysis
        logger.info(f"📊 Step 2: URLVoid domain analysis for {domain}")
        uv_result = self.urlvoid.analyze_domain(domain)
        results["urlvoid"] = uv_result

        # Merge registrar info from VT into urlvoid for consistent storage
        if not uv_result.get("error"):
            uv_result["registrar_name"] = (
                vt_domain.get("registrar") if not vt_domain.get("error") else None
            )

        # Step 3: PhishTank community check
        logger.info(f"📊 Step 3: PhishTank community database check for {url}")
        pt_result = self.phishtank.check_phishing_status(url)
        results["phishtank"] = pt_result

        # Step 4: WHOIS lookup for domain registration info
        logger.info(f"📊 Step 4: WHOIS lookup for {domain}")
        whois_info = {}
        try:
            # Lazy import to avoid circular dependency
            from src.reporting.email_detector import EnhancedAbuseEmailDetector

            whois_data = EnhancedAbuseEmailDetector.get_enhanced_whois_info(domain)
            if whois_data:
                # Extract registrar
                registrar = None
                if hasattr(whois_data, "registrar"):
                    registrar = whois_data.registrar
                    if isinstance(registrar, list):
                        registrar = registrar[0] if registrar else None
                elif isinstance(whois_data, dict):
                    registrar = whois_data.get("registrar")

                # Extract creation date
                creation_date = None
                domain_age_days = None
                if hasattr(whois_data, "creation_date"):
                    creation_date = whois_data.creation_date
                    if isinstance(creation_date, list):
                        creation_date = creation_date[0] if creation_date else None
                elif isinstance(whois_data, dict):
                    creation_date = whois_data.get("creation_date")

                # Calculate domain age
                if creation_date:
                    try:
                        parsed_date = None
                        if isinstance(creation_date, datetime.datetime):
                            parsed_date = creation_date
                        elif isinstance(creation_date, str):
                            # Try multiple date formats
                            date_formats = [
                                "%Y-%m-%dT%H:%M:%SZ",
                                "%Y-%m-%dT%H:%M:%S%z",
                                "%Y-%m-%d %H:%M:%S",
                                "%Y-%m-%d",
                                "%d-%b-%Y",
                                "%Y/%m/%d",
                                "%d/%m/%Y",
                            ]
                            date_str = creation_date.replace("Z", "").split(".")[0].strip()
                            for fmt in date_formats:
                                try:
                                    parsed_date = datetime.datetime.strptime(date_str, fmt)
                                    break
                                except ValueError:
                                    continue
                            # Fallback to fromisoformat
                            if not parsed_date:
                                try:
                                    parsed_date = datetime.datetime.fromisoformat(
                                        creation_date.replace("Z", "+00:00")
                                    )
                                except ValueError:
                                    pass

                        if parsed_date:
                            # Make both naive for comparison
                            if parsed_date.tzinfo is not None:
                                parsed_date = parsed_date.replace(tzinfo=None)
                            domain_age_days = (datetime.datetime.now() - parsed_date).days
                    except Exception as date_err:
                        logger.debug(f"Date calculation error: {date_err}")

                # Extract registrant org
                registrant_org = None
                if hasattr(whois_data, "org"):
                    registrant_org = whois_data.org
                elif hasattr(whois_data, "registrant_org"):
                    registrant_org = whois_data.registrant_org
                elif isinstance(whois_data, dict):
                    registrant_org = whois_data.get("org") or whois_data.get("registrant_org")

                whois_info = {
                    "registrar": registrar,
                    "creation_date": str(creation_date) if creation_date else None,
                    "domain_age_days": domain_age_days,
                    "registrant_org": registrant_org,
                }
                logger.info(f"📋 WHOIS for {domain}: registrar={registrar}, age={domain_age_days}d")
        except Exception as e:
            logger.warning(f"⚠️ WHOIS lookup failed for {domain}: {e}")

        results["whois"] = whois_info
        domain_age = whois_info.get("domain_age_days")

        # Step 5: Google Safe Browsing check
        logger.info(f"📊 Step 5: Google Safe Browsing check for {url}")
        gsb_result = self.google_safe_browsing.check_url(url)
        results["google_safe_browsing"] = gsb_result
        if not gsb_result.get("safe", True):
            logger.warning(
                f"🚨 Google Safe Browsing threats found: {gsb_result.get('threat_count', 0)}"
            )

        # Step 6: Aggregate results and calculate threat level
        results["aggregated_threat_level"] = self._aggregate_threat_level(
            vt_result, uv_result, pt_result, domain_age, url_analysis, gsb_result
        )
        results["confidence_score"] = self._calculate_confidence_score(
            vt_result, uv_result, pt_result, domain_age, url_analysis, gsb_result
        )
        results["recommendations"] = self._generate_recommendations(
            vt_result, uv_result, pt_result, domain_age, url_analysis, gsb_result
        )

        # Add registration info to top-level results for frontend (from WHOIS)
        results["registration_date"] = whois_info.get("creation_date")
        results["registrar_name"] = whois_info.get("registrar")
        results["domain_age_days"] = whois_info.get("domain_age_days")
        results["registrant_org"] = whois_info.get("registrant_org")

        # Lookup registrar abuse form URL (for providers that require web forms)
        from src.data.registrar_form_db import lookup_registrar_form

        form_info = lookup_registrar_form(results.get("registrar_name"))
        results["registrar_abuse_form_url"] = form_info["form_url"] if form_info else None
        results["registrar_abuse_method"] = form_info["method"] if form_info else "email"

        log_with_context(
            logger,
            logging.INFO,
            "Multi-API scan completed",
            url=url,
            domain=domain,
            threat_level=results["aggregated_threat_level"],
            confidence_score=results["confidence_score"],
            virustotal_threat=vt_result.get("threat_level", "unknown"),
            urlvoid_safety_score=uv_result.get("safety_score", 0),
            phishtank_verified=pt_result.get("verified", False),
            event_type="multi_api_scan_complete",
        )

        return results

    @staticmethod
    def _aggregate_threat_level(
        vt_result: Dict[str, Any],
        uv_result: Dict[str, Any],
        pt_result: Dict[str, Any],
        domain_age_days: Optional[int] = None,
        url_analysis: Optional[Dict[str, Any]] = None,
        gsb_result: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Aggregate threat levels from multiple APIs into single assessment.

        Args:
            vt_result (Dict[str, Any]): VirusTotal scan result
            uv_result (Dict[str, Any]): URLVoid analysis result
            pt_result (Dict[str, Any]): PhishTank check result
            domain_age_days (Optional[int]): Domain age in days
            url_analysis (Optional[Dict]): URL lexical analysis result
            gsb_result (Optional[Dict]): Google Safe Browsing result

        Returns:
            str: Aggregated threat level (critical, high, medium, low, clean)
        """
        threat_scores = []

        # PhishTank has the highest priority (verified community reports)
        if pt_result.get("is_phishing") and pt_result.get("verified"):
            return "critical"
        elif pt_result.get("is_phishing"):
            threat_scores.append(4)  # High threat from PhishTank

        # Google Safe Browsing threats (very high priority)
        if gsb_result and not gsb_result.get("safe", True):
            threats = gsb_result.get("threats_found", [])
            for threat in threats:
                if threat.get("threat_type") == "MALWARE":
                    return "critical"
                elif threat.get("threat_type") == "SOCIAL_ENGINEERING":
                    threat_scores.append(5)  # Phishing confirmed by Google

        # URL Analysis (typosquatting, homoglyphs, etc.)
        min_threat_level = None
        if url_analysis:
            url_risk = url_analysis.get("risk_score", 0)
            # Homoglyphs are extremely suspicious - CRITICAL
            if url_analysis.get("homoglyphs", {}).get("detected"):
                return "critical"
            # Typosquatting is a direct impersonation attempt - HIGH minimum
            if url_analysis.get("typosquatting", {}).get("detected"):
                return "high"
            # Combo-squatting (brand + keywords) is also highly suspicious
            if url_analysis.get("combo_squatting", {}).get("detected"):
                threat_scores.append(5)
            # Suspicious TLD forces minimum "medium"
            if url_analysis.get("suspicious_tld", {}).get("detected"):
                min_threat_level = "medium"
                threat_scores.append(3)
            # High URL risk score
            if url_risk >= 70:
                threat_scores.append(5)
            elif url_risk >= 50:
                threat_scores.append(4)
            elif url_risk >= 30:
                threat_scores.append(3)
            elif url_risk >= 15:
                threat_scores.append(2)

        # Domain age is a strong indicator for phishing
        if domain_age_days is not None:
            if domain_age_days < 7:
                threat_scores.append(4)  # Very new domain = high risk
            elif domain_age_days < 30:
                threat_scores.append(3)  # New domain = medium risk
            elif domain_age_days < 90:
                threat_scores.append(2)  # Relatively new = low risk
            else:
                threat_scores.append(1)  # Established domain = clean

        # VirusTotal threat level mapping
        vt_threat = vt_result.get("threat_level", "unknown")
        if vt_threat == "high":
            threat_scores.append(4)
        elif vt_threat == "medium":
            threat_scores.append(3)
        elif vt_threat == "low":
            threat_scores.append(2)
        elif vt_threat == "clean":
            threat_scores.append(1)

        # URLVoid threat level mapping
        uv_threat = uv_result.get("threat_level", "unknown")
        if uv_threat == "high":
            threat_scores.append(4)
        elif uv_threat == "medium":
            threat_scores.append(3)
        elif uv_threat == "low":
            threat_scores.append(2)
        elif uv_threat == "clean":
            threat_scores.append(1)

        if not threat_scores:
            return min_threat_level or "unknown"

        avg_score = sum(threat_scores) / len(threat_scores)

        if avg_score >= 4.5:
            result = "critical"
        elif avg_score >= 3.5:
            result = "high"
        elif avg_score >= 2.5:
            result = "medium"
        elif avg_score >= 1.5:
            result = "low"
        else:
            result = "clean"

        # Enforce minimum threat level from suspicious indicators
        if min_threat_level:
            threat_order = ["clean", "low", "medium", "high", "critical"]
            if threat_order.index(result) < threat_order.index(min_threat_level):
                return min_threat_level

        return result

    @staticmethod
    def _calculate_confidence_score(
        vt_result: Dict[str, Any],
        uv_result: Dict[str, Any],
        pt_result: Dict[str, Any],
        domain_age_days: Optional[int] = None,
        url_analysis: Optional[Dict[str, Any]] = None,
        gsb_result: Optional[Dict[str, Any]] = None,
    ) -> int:
        """
        Calculate confidence score based on API response quality and agreement.

        Returns:
            int: Confidence score (0-100)
        """
        confidence = 0
        factors = 0

        # URL Analysis confidence (local analysis, always available)
        if url_analysis:
            factors += 1
            url_risk = url_analysis.get("risk_score", 0)
            if url_risk >= 70:
                confidence += 95  # Very high confidence for obvious threats
            elif url_risk >= 50:
                confidence += 85
            elif url_risk >= 30:
                confidence += 75
            else:
                confidence += 60

        # Google Safe Browsing confidence
        if gsb_result and gsb_result.get("checked"):
            factors += 1
            if not gsb_result.get("safe", True):
                confidence += 98  # Very high confidence from Google
            else:
                confidence += 70  # Base confidence for clean result

        # Domain age provides reliable signal
        if domain_age_days is not None:
            factors += 1
            if domain_age_days < 7:
                confidence += 85  # Very confident about new domain risk
            elif domain_age_days < 30:
                confidence += 75  # Confident about new domain
            elif domain_age_days < 90:
                confidence += 65  # Moderate confidence
            else:
                confidence += 70  # Established domain

        # PhishTank confidence
        if not pt_result.get("error"):
            factors += 1
            if pt_result.get("verified"):
                confidence += 95  # High confidence for verified reports
            elif pt_result.get("is_phishing"):
                confidence += 75  # Medium confidence for unverified reports
            else:
                confidence += 60  # Base confidence for a clean result

        # VirusTotal confidence
        if not vt_result.get("error"):
            factors += 1
            total_engines = vt_result.get("total_engines", 0)
            if total_engines >= 50:
                confidence += 90  # High confidence with many engines
            elif total_engines >= 20:
                confidence += 75  # Medium confidence
            elif total_engines > 0:
                confidence += 60  # Low confidence

        # URLVoid confidence
        if not uv_result.get("error"):
            factors += 1
            safety_score = uv_result.get("safety_score", 50)
            confidence += min(90, safety_score + 20)  # Scale safety score

        return int(confidence / factors) if factors > 0 else 0

    @staticmethod
    def _generate_recommendations(
        vt_result: Dict[str, Any],
        uv_result: Dict[str, Any],
        pt_result: Dict[str, Any],
        domain_age_days: Optional[int] = None,
        url_analysis: Optional[Dict[str, Any]] = None,
        gsb_result: Optional[Dict[str, Any]] = None,
    ) -> List[str]:
        """
        Generate actionable recommendations based on scan results.

        Returns:
            List[str]: List of recommendations
        """
        recommendations = []

        # URL Analysis recommendations (highest priority - local detection)
        if url_analysis:
            # Homoglyphs (IDN attack)
            if url_analysis.get("homoglyphs", {}).get("detected"):
                homoglyphs = url_analysis["homoglyphs"]
                recommendations.append(
                    "🚨 CRITICAL: Homoglyph/IDN attack detected - URL uses deceptive Unicode characters"
                )
                if homoglyphs.get("target_brand"):
                    recommendations.append(f"🎯 Impersonating brand: {homoglyphs['target_brand']}")

            # Typosquatting
            if url_analysis.get("typosquatting", {}).get("detected"):
                typo = url_analysis["typosquatting"]
                recommendations.append(f"🚨 TYPOSQUATTING: Domain mimics '{typo['target_brand']}'")
                techniques = ", ".join(typo.get("techniques", []))
                if techniques:
                    recommendations.append(f"   Techniques: {techniques}")

            # Combo-squatting
            if url_analysis.get("combo_squatting", {}).get("detected"):
                combo = url_analysis["combo_squatting"]
                recommendations.append(
                    f"⚠️ COMBO-SQUATTING: Domain contains '{combo['target_brand']}' with extra text"
                )

            # Suspicious keywords
            if url_analysis.get("suspicious_keywords", {}).get("detected"):
                keywords = url_analysis["suspicious_keywords"]["keywords_found"][:5]
                recommendations.append(f"⚠️ Suspicious keywords in URL: {', '.join(keywords)}")

            # Suspicious TLD
            if url_analysis.get("suspicious_tld", {}).get("detected"):
                tld = url_analysis["suspicious_tld"]["tld"]
                recommendations.append(f"⚠️ Suspicious TLD: {tld} (commonly used in phishing)")

            # Excessive subdomains with brand
            if url_analysis.get("excessive_subdomains", {}).get("brand_in_subdomain"):
                brand = url_analysis["excessive_subdomains"]["brand_in_subdomain"]
                recommendations.append(
                    f"🚨 Brand '{brand}' hidden in subdomain - common phishing technique"
                )

        # Google Safe Browsing recommendations
        if gsb_result and not gsb_result.get("safe", True):
            threats = gsb_result.get("threats_found", [])
            for threat in threats:
                threat_type = threat.get("threat_type", "UNKNOWN")
                if threat_type == "SOCIAL_ENGINEERING":
                    recommendations.append("🚨 GOOGLE SAFE BROWSING: Confirmed phishing site")
                elif threat_type == "MALWARE":
                    recommendations.append("🚨 GOOGLE SAFE BROWSING: Malware distribution detected")
                else:
                    recommendations.append(f"🚨 GOOGLE SAFE BROWSING: {threat_type} detected")

        # Domain age recommendations
        if domain_age_days is not None:
            if domain_age_days < 7:
                recommendations.append(
                    f"🚨 SUSPICIOUS: Domain registered only {domain_age_days} days ago"
                )
                recommendations.append("⚠️ Very new domains are commonly used for phishing attacks")
            elif domain_age_days < 30:
                recommendations.append(f"⚠️ CAUTION: New domain ({domain_age_days} days old)")

        # PhishTank recommendations
        if pt_result.get("is_phishing"):
            if pt_result.get("verified"):
                recommendations.append(
                    "🚨 CRITICAL: URL verified as phishing by PhishTank community"
                )
                recommendations.append(
                    "🔒 IMMEDIATE ACTION: Block URL and report to hosting provider"
                )
            else:
                recommendations.append("⚠️ WARNING: URL reported as phishing (unverified)")

        # VirusTotal recommendations
        if not vt_result.get("error"):
            malicious = vt_result.get("malicious", 0)
            total = vt_result.get("total_engines", 0)

            if malicious > 0:
                recommendations.append(
                    f"🛡️ VirusTotal: {malicious}/{total} engines flagged as malicious"
                )
                if malicious >= 5:
                    recommendations.append(
                        "🚨 HIGH RISK: Multiple security engines detected threats"
                    )

        # URLVoid recommendations
        if not uv_result.get("error"):
            safety_score = uv_result.get("safety_score", 100)
            blacklists = uv_result.get("blacklists", [])

            if safety_score <= 50:
                recommendations.append(f"⚠️ URLVoid: Low safety score ({safety_score}/100)")

            if blacklists:
                recommendations.append(
                    f"🚫 Found on {len(blacklists)} blacklist(s): {', '.join(blacklists[:3])}"
                )

        # General recommendations
        if not recommendations:
            recommendations.append("✅ No immediate threats detected by available scanners")
            recommendations.append("🔍 Continue monitoring for changes")

        return recommendations
