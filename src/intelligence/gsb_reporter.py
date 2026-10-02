"""
Google Safe Browsing URL Reporter

Submits detected phishing URLs to Google Safe Browsing for inclusion in their blocklist.
Uses a dual-strategy approach:
1. Primary: Undocumented crx-report API (free, no auth required)
2. Fallback: Web Risk Submission API (paid, requires Google Cloud API key)

Author: BMAD Dev Team
Date: 2026-01-25
"""

import logging
import requests
import json
import base64
from typing import Dict, Any, Optional, List
from datetime import datetime

from src.config import settings
from src.observability.structured_logger import log_with_context

logger = logging.getLogger(__name__)

# Configuration
GSB_CRX_REPORT_URL = "https://safebrowsing.google.com/safebrowsing/clientreport/crx-report"
WEB_RISK_API_URL = "https://webrisk.googleapis.com/v1/uris:submit"
WEB_RISK_API_KEY = getattr(settings, "GOOGLE_WEB_RISK_API_KEY", None)

# Threat type flags for crx-report
CRX_THREAT_FLAGS = {
    "phishing": "SOCIAL_ENGINEERING",
    "malware": "MALWARE",
    "unwanted_software": "UNWANTED_SOFTWARE",
}


class GSBReporter:
    """
    Reports phishing URLs to Google Safe Browsing.

    Features:
    - Dual-strategy: crx-report (free) with Web Risk API fallback
    - Optional screenshot attachment
    - Submission tracking and logging
    - Rate limiting respect
    """

    def __init__(self, web_risk_api_key: Optional[str] = None):
        """
        Initialize GSB Reporter.

        Args:
            web_risk_api_key: Optional Google Cloud Web Risk API key for fallback
        """
        self.web_risk_api_key = web_risk_api_key or WEB_RISK_API_KEY
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0",
                "Content-Type": "application/json",
            }
        )

        # Statistics
        self.stats = {
            "total_submissions": 0,
            "crx_successes": 0,
            "web_risk_successes": 0,
            "failures": 0,
            "last_submission": None,
        }

    def report_url(
        self,
        url: str,
        threat_type: str = "phishing",
        screenshot_base64: Optional[str] = None,
        dom_content: Optional[str] = None,
        correlation_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Report a URL to Google Safe Browsing.

        Tries crx-report first, falls back to Web Risk API if available.

        Args:
            url: The phishing URL to report
            threat_type: Type of threat (phishing, malware, unwanted_software)
            screenshot_base64: Optional base64-encoded screenshot
            dom_content: Optional HTML DOM content
            correlation_id: Optional correlation ID for logging

        Returns:
            Dict with submission result:
            {
                "success": bool,
                "method": "crx_report" | "web_risk_api" | None,
                "message": str,
                "timestamp": str
            }
        """
        result = {
            "success": False,
            "method": None,
            "message": "",
            "timestamp": datetime.now().isoformat(),
            "url": url,
        }

        self.stats["total_submissions"] += 1

        # Try crx-report first (free, no auth)
        crx_result = self._submit_crx_report(url, threat_type, screenshot_base64, dom_content)

        if crx_result["success"]:
            result["success"] = True
            result["method"] = "crx_report"
            result["message"] = "URL submitted via crx-report API"
            self.stats["crx_successes"] += 1
            self.stats["last_submission"] = datetime.now().isoformat()

            log_with_context(
                logger,
                logging.INFO,
                f"GSB submission successful: {url}",
                url=url,
                method="crx_report",
                threat_type=threat_type,
                correlation_id=correlation_id,
                event_type="gsb_submission_success",
            )
            return result

        # Fallback to Web Risk API if available
        if self.web_risk_api_key:
            web_risk_result = self._submit_web_risk(url, threat_type)

            if web_risk_result["success"]:
                result["success"] = True
                result["method"] = "web_risk_api"
                result["message"] = "URL submitted via Web Risk API"
                self.stats["web_risk_successes"] += 1
                self.stats["last_submission"] = datetime.now().isoformat()

                log_with_context(
                    logger,
                    logging.INFO,
                    f"GSB submission successful (fallback): {url}",
                    url=url,
                    method="web_risk_api",
                    threat_type=threat_type,
                    correlation_id=correlation_id,
                    event_type="gsb_submission_success",
                )
                return result

            result["message"] = (
                f"Both methods failed. crx: {crx_result['error']}, web_risk: {web_risk_result['error']}"
            )
        else:
            result["message"] = (
                f"crx-report failed: {crx_result['error']}. No Web Risk API key configured for fallback."
            )

        self.stats["failures"] += 1

        log_with_context(
            logger,
            logging.WARNING,
            f"GSB submission failed: {url}",
            url=url,
            error=result["message"],
            correlation_id=correlation_id,
            event_type="gsb_submission_failed",
        )

        return result

    def _submit_crx_report(
        self,
        url: str,
        threat_type: str,
        screenshot_base64: Optional[str] = None,
        dom_content: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Submit URL via undocumented crx-report API.

        Request format: JSON array
        [url, null, screenshot_base64, dom_content, null, [flags]]
        """
        try:
            # Build the flags based on threat type
            flags = []
            if threat_type in CRX_THREAT_FLAGS:
                flags.append(CRX_THREAT_FLAGS[threat_type])
            else:
                flags.append("SOCIAL_ENGINEERING")  # Default to phishing

            # Build payload as JSON array (crx-report format)
            payload = [
                url,  # URL to report
                None,  # Unused field
                screenshot_base64 or "",  # Screenshot (base64)
                dom_content or "",  # DOM content
                None,  # Referrer chain
                flags,  # Threat flags
            ]

            response = self.session.post(
                GSB_CRX_REPORT_URL,
                data=json.dumps(payload),
                timeout=30,
            )

            # crx-report returns empty response on success
            if response.status_code in [200, 204]:
                return {"success": True}
            else:
                return {
                    "success": False,
                    "error": f"HTTP {response.status_code}: {response.text[:200]}",
                }

        except requests.RequestException as e:
            return {"success": False, "error": str(e)}
        except Exception as e:
            return {"success": False, "error": f"Unexpected error: {e}"}

    def _submit_web_risk(
        self,
        url: str,
        threat_type: str,
    ) -> Dict[str, Any]:
        """
        Submit URL via Google Web Risk Submission API.

        Requires GOOGLE_WEB_RISK_API_KEY in settings.
        """
        if not self.web_risk_api_key:
            return {"success": False, "error": "No Web Risk API key configured"}

        try:
            # Map threat type to Web Risk threat type
            threat_type_map = {
                "phishing": "SOCIAL_ENGINEERING",
                "malware": "MALWARE",
                "unwanted_software": "UNWANTED_SOFTWARE",
            }
            web_risk_threat = threat_type_map.get(threat_type, "SOCIAL_ENGINEERING")

            payload = {
                "submission": {
                    "uri": url,
                    "threatTypes": [web_risk_threat],
                }
            }

            response = self.session.post(
                f"{WEB_RISK_API_URL}?key={self.web_risk_api_key}",
                json=payload,
                timeout=30,
            )

            if response.status_code == 200:
                return {"success": True, "response": response.json()}
            else:
                return {
                    "success": False,
                    "error": f"HTTP {response.status_code}: {response.text[:200]}",
                }

        except requests.RequestException as e:
            return {"success": False, "error": str(e)}
        except Exception as e:
            return {"success": False, "error": f"Unexpected error: {e}"}

    def report_batch(
        self,
        urls: List[str],
        threat_type: str = "phishing",
        correlation_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Report multiple URLs to Google Safe Browsing.

        Args:
            urls: List of URLs to report
            threat_type: Type of threat
            correlation_id: Optional correlation ID for logging

        Returns:
            Dict with batch results
        """
        results = {
            "total": len(urls),
            "successful": 0,
            "failed": 0,
            "details": [],
        }

        for url in urls:
            result = self.report_url(
                url=url,
                threat_type=threat_type,
                correlation_id=correlation_id,
            )
            results["details"].append(result)

            if result["success"]:
                results["successful"] += 1
            else:
                results["failed"] += 1

        log_with_context(
            logger,
            logging.INFO,
            f"GSB batch submission completed: {results['successful']}/{results['total']} successful",
            total=results["total"],
            successful=results["successful"],
            failed=results["failed"],
            correlation_id=correlation_id,
            event_type="gsb_batch_submission",
        )

        return results

    def get_stats(self) -> Dict[str, Any]:
        """Get submission statistics."""
        return {
            **self.stats,
            "web_risk_configured": bool(self.web_risk_api_key),
        }


# Singleton instance
_gsb_reporter: Optional[GSBReporter] = None


def get_gsb_reporter() -> GSBReporter:
    """Get or create the GSB reporter instance."""
    global _gsb_reporter
    if _gsb_reporter is None:
        _gsb_reporter = GSBReporter()
    return _gsb_reporter


def report_phishing_url(
    url: str,
    screenshot_base64: Optional[str] = None,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Convenience function to report a phishing URL to GSB.

    Args:
        url: The phishing URL to report
        screenshot_base64: Optional screenshot
        correlation_id: Optional correlation ID

    Returns:
        Submission result dict
    """
    reporter = get_gsb_reporter()
    return reporter.report_url(
        url=url,
        threat_type="phishing",
        screenshot_base64=screenshot_base64,
        correlation_id=correlation_id,
    )
