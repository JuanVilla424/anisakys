"""
VirusTotal integration for Anisakys Phishing Detection Engine.

VirusTotal API v3 Integration for comprehensive threat detection using
70+ antivirus engines and URL scanners.
"""

import base64
import logging
import time
from typing import Any, Dict, Optional

import requests

from src.circuit_breaker import CircuitBreaker, CircuitBreakerConfig, CircuitBreakerOpenError
from src.config import settings
from src.logger import logger
from src.observability.structured_logger import log_api_call, log_error, log_with_context

# API Configuration
VIRUSTOTAL_API_KEY = getattr(settings, "VIRUSTOTAL_API_KEY", None)


class VirusTotalIntegration:
    """
    VirusTotal API v3 Integration for comprehensive threat detection.

    Provides multi-engine scanning using 70+ antivirus engines and URL scanners
    for comprehensive threat detection with real-time reputation analysis.
    """

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize VirusTotal integration.

        Args:
            api_key (Optional[str]): VirusTotal API key. If None, uses environment variable.
        """
        self.api_key = api_key or VIRUSTOTAL_API_KEY
        self.base_url = "https://www.virustotal.com/api/v3"
        self.session = requests.Session()
        self.session.headers.update(
            {
                "x-apikey": self.api_key,
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                "Accept": "application/json",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate, br",
                "DNT": "1",
                "Connection": "keep-alive",
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "cross-site",
                "Origin": "https://www.virustotal.com",
                "Referer": "https://www.virustotal.com/",
            }
        )

        # Initialize circuit breaker for API resilience (EPIC-004)
        cb_config = CircuitBreakerConfig(
            failure_threshold=5,  # Higher threshold for VirusTotal (public API)
            recovery_timeout=120,  # Wait 2 minutes before retry (rate limits)
            success_threshold=2,
            max_retries=2,
            retry_backoff_base=3.0,  # Longer backoff for rate-limited API
        )
        self.circuit_breaker = CircuitBreaker("VirusTotal", cb_config, logger)

    def scan_url(self, url: str) -> Dict[str, Any]:
        """
        Submit URL for analysis and get a comprehensive threat assessment.

        Args:
            url (str): URL to scan

        Returns:
            Dict[str, Any]: Detailed threat assessment including detection ratios
        """
        if not self.api_key:
            logger.warning("⚠️  VirusTotal API key not configured, skipping scan")
            return {"error": "API key not configured"}

        try:
            # First, submit the URL for scanning
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

            # Check if URL has been analyzed before (through circuit breaker)
            def _make_request():
                """Internal function for circuit breaker wrapping."""
                start_time = time.time()
                response = self.session.get(f"{self.base_url}/urls/{url_id}")
                response_time_ms = int((time.time() - start_time) * 1000)
                return response, response_time_ms

            response, response_time_ms = self.circuit_breaker.call(_make_request)

            log_api_call(
                logger,
                api_name="VirusTotal",
                url=f"{self.base_url}/urls/{url_id}",
                status_code=response.status_code,
                response_time_ms=response_time_ms,
                target_url=url,
            )

            if response.status_code == 200:
                data = response.json()
                analysis = data.get("data", {}).get("attributes", {})
                last_analysis = analysis.get("last_analysis_stats", {})

                result = {
                    "url": url,
                    "scan_date": analysis.get("last_analysis_date"),
                    "reputation": analysis.get("reputation", 0),
                    "malicious": last_analysis.get("malicious", 0),
                    "suspicious": last_analysis.get("suspicious", 0),
                    "harmless": last_analysis.get("harmless", 0),
                    "undetected": last_analysis.get("undetected", 0),
                    "total_engines": sum(last_analysis.values()) if last_analysis else 0,
                    "threat_level": self._calculate_threat_level(last_analysis),
                    "community_score": analysis.get("total_votes", {}).get("harmless", 0)
                    - analysis.get("total_votes", {}).get("malicious", 0),
                    "categories": analysis.get("categories", {}),
                    "engines_detail": analysis.get("last_analysis_results", {}),
                }

                logger.info(
                    f"🛡️  VirusTotal scan for {url}: {result['malicious']}/{result['total_engines']} engines detected threats"
                )
                return result

            elif response.status_code == 404:
                # URL isn't found, submit for scanning
                scan_response = self.session.post(f"{self.base_url}/urls", data={"url": url})

                if scan_response.status_code == 200:
                    logger.info(f"📤 Submitted {url} to VirusTotal for analysis")
                    return {
                        "status": "submitted",
                        "message": "URL submitted for analysis, check back later",
                    }
                else:
                    logger.error(
                        f"❌ Failed to submit {url} to VirusTotal: {scan_response.status_code}"
                    )
                    return {"error": f"Failed to submit URL: {scan_response.status_code}"}

            else:
                log_with_context(
                    logger,
                    logging.ERROR,
                    "VirusTotal API error",
                    status_code=response.status_code,
                    url=url,
                    event_type="virustotal_api_error",
                )
                return {"error": f"API error: {response.status_code}"}

        except CircuitBreakerOpenError as e:
            # Circuit breaker is open - service is down
            log_with_context(
                logger,
                logging.ERROR,
                "VirusTotal API circuit breaker OPEN - service unavailable",
                url=url,
                circuit_state="OPEN",
                event_type="virustotal_circuit_open",
            )
            return {
                "error": "VirusTotal API temporarily unavailable",
                "status": "circuit_open",
                "details": str(e),
            }

        except Exception as e:
            log_error(
                logger,
                e,
                {
                    "url": url,
                    "api": "VirusTotal",
                    "operation": "url_scan",
                    "event_type": "virustotal_scan_failed",
                },
            )
            return {"error": str(e)}

    @staticmethod
    def _calculate_threat_level(analysis_stats: Dict[str, int]) -> str:
        """
        Calculate threat level based on detection statistics.

        Args:
            analysis_stats (Dict[str, int]): Analysis statistics from VirusTotal

        Returns:
            str: Threat level (high, medium, low, clean)
        """
        if not analysis_stats:
            return "unknown"

        malicious = analysis_stats.get("malicious", 0)
        suspicious = analysis_stats.get("suspicious", 0)
        total = sum(analysis_stats.values())

        if total == 0:
            return "unknown"

        malicious_ratio = malicious / total
        suspicious_ratio = suspicious / total

        if malicious_ratio >= 0.1:  # 10% or more engines detect as malicious
            return "high"
        elif malicious_ratio >= 0.05 or suspicious_ratio >= 0.2:  # 5% malicious or 20% suspicious
            return "medium"
        elif malicious_ratio > 0 or suspicious_ratio > 0:
            return "low"
        else:
            return "clean"

    def get_domain_report(self, domain: str) -> Dict[str, Any]:
        """
        Get a domain reputation and analysis report.

        Args:
            domain (str): Domain to analyze

        Returns:
            Dict[str, Any]: Domain analysis report
        """
        if not self.api_key:
            return {"error": "API key not configured"}

        try:
            response = self.session.get(f"{self.base_url}/domains/{domain}")

            if response.status_code == 200:
                data = response.json()
                attributes = data.get("data", {}).get("attributes", {})

                return {
                    "domain": domain,
                    "reputation": attributes.get("reputation", 0),
                    "categories": attributes.get("categories", {}),
                    "last_analysis_stats": attributes.get("last_analysis_stats", {}),
                    "registrar": attributes.get("registrar"),
                    "creation_date": attributes.get("creation_date"),
                    "last_update_date": attributes.get("last_update_date"),
                }
            else:
                return {"error": f"Domain analysis failed: {response.status_code}"}

        except Exception as e:
            logger.error(f"❌ VirusTotal domain analysis failed for {domain}: {e}")
            return {"error": str(e)}

    def lookup_file_hash(self, file_hash: str) -> Dict[str, Any]:
        """
        Look up a file by its SHA-256 hash in VirusTotal.

        Does NOT upload the file — only queries the existing database by hash.
        Use this for email attachment triage without storing attachment data.

        Args:
            file_hash: SHA-256 hex digest of the file.

        Returns:
            Dict with keys: found, malicious, suspicious, harmless, undetected,
            total_engines, threat_level, file_type, file_name (if known).
        """
        if not self.api_key:
            return {"found": False, "error": "API key not configured"}

        try:
            response = self.session.get(f"{self.base_url}/files/{file_hash}")

            if response.status_code == 404:
                return {"found": False}

            if response.status_code == 200:
                data = response.json()
                attributes = data.get("data", {}).get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})
                return {
                    "found": True,
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "total_engines": sum(stats.values()),
                    "threat_level": self._calculate_threat_level(stats),
                    "file_type": attributes.get("type_description"),
                    "file_name": (attributes.get("names") or [None])[0],
                }

            return {"found": False, "error": f"Unexpected status: {response.status_code}"}

        except Exception as e:
            logger.error(f"❌ VirusTotal file hash lookup failed for {file_hash[:16]}…: {e}")
            return {"found": False, "error": str(e)}
