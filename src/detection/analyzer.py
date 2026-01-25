"""
Auto Phishing Analyzer for Anisakys Phishing Detection Engine.

Provides automated phishing analysis using multi-API validation.
"""

from __future__ import annotations

import re
import time
import threading
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from sqlalchemy import text

from src.config import settings
from src.intelligence import MultiAPIValidator, AUTO_ANALYSIS_ENABLED
from src.logger import logger

# Get config value
AUTO_ANALYSIS_DELAY_SECONDS = getattr(settings, "AUTO_ANALYSIS_DELAY_SECONDS", 30) or 30

if TYPE_CHECKING:
    from src.database import DatabaseManager
    from src.reporting import EnhancedAbuseEmailDetector


class AutoPhishingAnalyzer:
    """
    Automated phishing analysis engine with multi-API integration and intelligent auto-reporting.

    This class handles the automatic analysis of detected phishing sites using multiple APIs
    and makes intelligent decisions about auto-reporting based on threat levels and confidence scores.
    """

    def __init__(self, db_manager: "DatabaseManager", abuse_detector: "EnhancedAbuseEmailDetector"):
        """
        Initialize the auto-analyzer.

        Args:
            db_manager (DatabaseManager): Database manager instance
            abuse_detector (EnhancedAbuseEmailDetector): Abuse email detector instance
        """
        self.db_manager = db_manager
        self.abuse_detector = abuse_detector
        self.multi_api_validator = MultiAPIValidator()
        self.running = False

    def start_analysis_worker(self):
        """Start the background analysis worker thread."""
        if not self.running:
            self.running = True
            analysis_thread = threading.Thread(target=self._analysis_worker_loop, daemon=True)
            analysis_thread.start()
            logger.info("🤖 Auto-analysis worker started")

    def stop_analysis_worker(self):
        """Stop the background analysis worker."""
        self.running = False
        logger.info("🛑 Auto-analysis worker stopped")

    def _analysis_worker_loop(self):
        """Main loop for the analysis worker."""
        logger.info("🔄 Auto-analysis worker loop started")

        while self.running:
            try:
                # Get pending sites for analysis
                pending_sites = self.db_manager.get_pending_analysis_sites(limit=5)

                if pending_sites:
                    logger.info(f"🔍 Processing {len(pending_sites)} sites for auto-analysis")

                    for site_info in pending_sites:
                        if not self.running:
                            break

                        try:
                            self.analyze_detected_site(
                                site_info["url"],
                                site_info["keywords"].split(", ") if site_info["keywords"] else [],
                            )

                            # Small delay between analyses to avoid overwhelming APIs
                            time.sleep(AUTO_ANALYSIS_DELAY_SECONDS)

                        except Exception as e:
                            logger.error(f"❌ Error analyzing site {site_info['url']}: {e}")
                            continue
                else:
                    # No, pending sites, wait longer
                    time.sleep(60)

            except Exception as e:
                logger.error(f"❌ Error in auto-analysis worker loop: {e}")
                time.sleep(30)

    def analyze_detected_site(self, url: str, detection_keywords: List[str]) -> Dict[str, Any]:
        """
        Perform comprehensive analysis on a detected phishing site.

        Args:
            url (str): URL to analyze
            detection_keywords (List[str]): Keywords that triggered detection

        Returns:
            Dict[str, Any]: Analysis results and auto-report decision
        """
        logger.info(f"🔍 Starting comprehensive analysis for: {url}")

        try:
            # Get site information to determine source and flags
            site_info = None
            try:
                with self.db_manager.engine.begin() as conn:
                    result = conn.execute(
                        text(
                            "SELECT source, manual_flag, auto_detected FROM phishing_sites WHERE url = :url"
                        ),
                        {"url": url},
                    ).fetchone()
                    if result:
                        site_info = {
                            "source": result[0],
                            "manual_flag": result[1],
                            "auto_detected": result[2],
                        }
            except Exception as e:
                logger.warning(f"Could not get site info for {url}: {e}")
                site_info = {"source": "unknown", "manual_flag": 0, "auto_detected": 1}

            # Perform multi-API scan
            if AUTO_ANALYSIS_ENABLED:
                multi_api_results = self.multi_api_validator.comprehensive_scan(url)
            else:
                logger.warning("⚠️  Auto multi-API scan disabled or no API keys configured")
                multi_api_results = {
                    "aggregated_threat_level": "unknown",
                    "confidence_score": 0,
                    "virustotal": {"error": "API key not configured"},
                    "urlvoid": {"error": "API key not configured"},
                    "phishtank": {"error": "API key not configured"},
                }

            # Make auto-report decision based on source
            auto_report_decision = self._make_auto_report_decision(
                multi_api_results, detection_keywords, site_info
            )

            # Update database with results
            self.db_manager.update_analysis_results(url, multi_api_results, auto_report_decision)

            # Log decision
            threat_level = multi_api_results.get("aggregated_threat_level", "unknown")
            confidence = multi_api_results.get("confidence_score", 0)

            if auto_report_decision.get("auto_report", False):
                logger.info(
                    f"🚨 AUTO-REPORT ELIGIBLE: {url} - "
                    f"Threat: {threat_level}, Confidence: {confidence}%, "
                    f"Keywords: {', '.join(detection_keywords)}"
                )
            elif auto_report_decision.get("manual_review", False):
                logger.info(
                    f"👀 MANUAL REVIEW REQUIRED: {url} - "
                    f"Threat: {threat_level}, Confidence: {confidence}%, "
                    f"Keywords: {', '.join(detection_keywords)}"
                )
            else:
                logger.info(
                    f"✅ ANALYSIS COMPLETE: {url} - "
                    f"Threat: {threat_level}, Confidence: {confidence}% - No action required"
                )

            return {
                "url": url,
                "multi_api_results": multi_api_results,
                "auto_report_decision": auto_report_decision,
                "analysis_timestamp": datetime.datetime.now().isoformat(),
            }

        except Exception as e:
            logger.error(f"❌ Failed to analyze detected site {url}: {e}")
            return {"error": str(e), "url": url}

    @staticmethod
    def _make_auto_report_decision(
        multi_api_results: Dict[str, Any],
        detection_keywords: List[str],
        site_info: Dict[str, Any] = None,
    ) -> Dict[str, Any]:
        """
        Make intelligent auto-report decision based on analysis results and site source.

        IMPORTANT: Auto-detected sites should NEVER trigger automatic reports.
        Only manual flagged sites and API-imported sites should be eligible for auto-reporting.

        Args:
            multi_api_results (Dict[str, Any]): Multi-API scan results
            detection_keywords (List[str]): Keywords that triggered detection
            site_info (Dict[str, Any], optional): Site source and flag information

        Returns:
            Dict[str, Any]: Auto-report decision with reasoning
        """
        threat_level = multi_api_results.get("aggregated_threat_level", "unknown")
        confidence_score = multi_api_results.get("confidence_score", 0)

        decision = {
            "auto_report": False,
            "manual_review": False,
            "priority": "medium",
            "reasoning": [],
        }

        # CRITICAL: Block auto-reporting for automatically detected sites
        if site_info and site_info.get("auto_detected") == 1 and not site_info.get("manual_flag"):
            decision["auto_report"] = False
            decision["manual_review"] = True  # Always require manual review for auto-detections
            decision["reasoning"].append(
                "Auto-detected sites require manual review - no automatic reporting"
            )
            return decision

        # Only allow auto-reporting for manual flags or API imports
        if not site_info or not (
            site_info.get("manual_flag") == 1 or site_info.get("source") == "external_api"
        ):
            decision["manual_review"] = True
            decision["reasoning"].append("Only manual or API sites eligible for auto-reporting")
            return decision

        # Critical threat level from PhishTank verified
        pt_result = multi_api_results.get("phishtank", {})
        if pt_result.get("is_phishing") and pt_result.get("verified"):
            decision["auto_report"] = True
            decision["priority"] = "high"
            decision["reasoning"].append("PhishTank verified phishing site")

        # High threat level with high confidence
        elif (
            threat_level in ["critical", "high"]
            and confidence_score >= AUTO_REPORT_THRESHOLD_CONFIDENCE
        ):
            decision["auto_report"] = True
            decision["priority"] = "high" if threat_level == "critical" else "medium"
            decision["reasoning"].append(
                f"High threat level ({threat_level}) with {confidence_score}% confidence"
            )

        # VirusTotal multiple detections
        vt_result = multi_api_results.get("virustotal", {})
        if not vt_result.get("error"):
            malicious_count = vt_result.get("malicious", 0)
            total_engines = vt_result.get("total_engines", 0)

            if malicious_count >= 5 and confidence_score >= AUTO_REPORT_THRESHOLD_CONFIDENCE:
                decision["auto_report"] = True
                decision["priority"] = "high"
                decision["reasoning"].append(
                    f"VirusTotal: {malicious_count}/{total_engines} engines detected threats"
                )
            elif malicious_count >= 2 and confidence_score >= MANUAL_REVIEW_THRESHOLD_CONFIDENCE:
                decision["manual_review"] = True
                decision["reasoning"].append(
                    f"VirusTotal: {malicious_count}/{total_engines} engines detected threats (manual review)"
                )

        # URLVoid blacklist detections
        uv_result = multi_api_results.get("urlvoid", {})
        if not uv_result.get("error"):
            blacklists = uv_result.get("blacklists", [])
            safety_score = uv_result.get("safety_score", 100)

            if len(blacklists) >= 3 and confidence_score >= AUTO_REPORT_THRESHOLD_CONFIDENCE:
                decision["auto_report"] = True
                decision["priority"] = "high"
                decision["reasoning"].append(f"URLVoid: Found on {len(blacklists)} blacklists")
            elif (
                len(blacklists) >= 1 or safety_score <= 30
            ) and confidence_score >= MANUAL_REVIEW_THRESHOLD_CONFIDENCE:
                decision["manual_review"] = True
                decision["reasoning"].append(
                    f"URLVoid: Safety score {safety_score}/100, {len(blacklists)} blacklists"
                )

        # High-value keywords detected
        high_value_keywords = [
            "login",
            "password",
            "account",
            "verify",
            "suspend",
            "billing",
            "payment",
        ]
        matching_hvk = [
            kw
            for kw in detection_keywords
            if kw.lower() in [hvk.lower() for hvk in high_value_keywords]
        ]

        if len(matching_hvk) >= 2 and confidence_score >= MANUAL_REVIEW_THRESHOLD_CONFIDENCE:
            if not decision["auto_report"]:
                decision["manual_review"] = True
            decision["reasoning"].append(f"High-value keywords detected: {', '.join(matching_hvk)}")

        # Medium threat with reasonable confidence needs manual review
        if (
            threat_level in ["medium", "high"]
            and confidence_score >= MANUAL_REVIEW_THRESHOLD_CONFIDENCE
            and not decision["auto_report"]
        ):
            decision["manual_review"] = True
            decision["reasoning"].append(
                f"Medium/High threat level with {confidence_score}% confidence"
            )

        # Default reasoning if none set
        if not decision["reasoning"]:
            decision["reasoning"].append(
                f"Low threat level ({threat_level}) or insufficient confidence ({confidence_score}%)"
            )

        return decision

    def process_auto_reports(self, report_manager) -> int:
        """
        Process sites eligible for automatic reporting.

        Args:
            report_manager: AbuseReportManager instance

        Returns:
            int: Number of sites processed for auto-reporting
        """
        try:
            eligible_sites = self.db_manager.get_auto_report_eligible_sites(limit=5)

            if not eligible_sites:
                return 0

            logger.info(f"📋 Processing {len(eligible_sites)} sites for auto-reporting")
            processed_count = 0

            for site_info in eligible_sites:
                try:
                    url = site_info["url"]
                    threat_level = site_info["threat_level"]
                    confidence = site_info["confidence_score"]
                    keywords = site_info["keywords"]

                    logger.info(
                        f"🚨 Auto-reporting: {url} - "
                        f"Threat: {threat_level}, Confidence: {confidence}%, "
                        f"Keywords: {keywords}"
                    )

                    # Get WHOIS and abuse emails
                    whois_info = basic_whois_lookup(url)
                    whois_str = str(whois_info)
                    domain = re.sub(r"^https?://", "", url).strip().split("/")[0]
                    registrar = self.abuse_detector.extract_registrar(whois_info)
                    abuse_list = self.abuse_detector.get_enhanced_abuse_email(
                        domain, whois_info, registrar
                    )

                    if not abuse_list:
                        logger.warning(
                            f"⚠️  No valid abuse emails found for {url}, marking for manual review"
                        )
                        # Mark for manual review instead
                        with self.db_manager.engine.begin() as conn:
                            conn.execute(
                                text(
                                    """
                                    UPDATE phishing_sites
                                    SET auto_report_eligible = 0, requires_manual_review = 1
                                    WHERE url = :url
                                """
                                ),
                                {"url": url},
                            )
                        continue

                    # Get enhanced multi-API results for a report
                    with self.db_manager.engine.begin() as conn:
                        api_results = conn.execute(
                            text(
                                """
                                SELECT virustotal_result, urlvoid_result, phishtank_result,
                                       multi_api_threat_level, api_confidence_score
                                FROM phishing_sites WHERE url = :url
                            """
                            ),
                            {"url": url},
                        ).fetchone()

                    if api_results:
                        enhanced_results = {
                            "aggregated_threat_level": api_results[3],
                            "confidence_score": api_results[4],
                            "virustotal": json.loads(api_results[0]) if api_results[0] else {},
                            "urlvoid": json.loads(api_results[1]) if api_results[1] else {},
                            "phishtank": json.loads(api_results[2]) if api_results[2] else {},
                            "recommendations": [
                                f"🤖 AUTO-DETECTED: Site flagged by automated system",
                                f"🎯 DETECTION KEYWORDS: {keywords}",
                                f"📊 THREAT ASSESSMENT: {threat_level.upper()} ({confidence}% confidence)",
                            ],
                        }
                    else:
                        enhanced_results = None

                    # Send an abuse report with enhanced data
                    attachment_paths = AttachmentConfig.get_all_attachments()
                    success = report_manager.send_abuse_report(
                        abuse_list,
                        url,
                        whois_str,
                        attachment_paths=attachment_paths,
                        multi_api_results=enhanced_results,
                    )

                    if success:
                        # Update database to mark as reported
                        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        with self.db_manager.engine.begin() as conn:
                            conn.execute(
                                text(
                                    """
                                    UPDATE phishing_sites
                                    SET abuse_report_sent = 1,
                                        last_report_sent = :timestamp,
                                        abuse_email = CASE
                                            WHEN manual_emails = 1 THEN abuse_email
                                            ELSE :abuse_email
                                        END,
                                        reported = 1
                                    WHERE url = :url
                                """
                                ),
                                {"timestamp": timestamp, "abuse_email": abuse_list[0], "url": url},
                            )

                        logger.info(f"✅ AUTO-REPORT SENT: {url} to {abuse_list[0]}")
                        processed_count += 1
                    else:
                        logger.error(f"❌ AUTO-REPORT FAILED: {url}")

                except Exception as e:
                    logger.error(f"❌ Error processing auto-report: {e}")
                    continue

            if processed_count > 0:
                logger.info(
                    f"📊 AUTO-REPORT SUMMARY: {processed_count}/{len(eligible_sites)} sites reported successfully"
                )

            return processed_count

        except Exception as e:
            logger.error(f"❌ Error in process_auto_reports: {e}")
            return 0


# EPIC-006: Functions moved to src/dns/network_utils.py
# - get_ip_info()
# - is_cloudflare_ip()
