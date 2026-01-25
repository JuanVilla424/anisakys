"""
Grinder integration for Anisakys Phishing Detection Engine.

HTTP client for reporting malicious IPs to Grinder system with
bidirectional threat intelligence integration.
"""

import datetime
import ipaddress
import logging
import time
from functools import wraps
from typing import Any, Dict, List

import requests
from flask import current_app, jsonify, request

from src.circuit_breaker import CircuitBreaker, CircuitBreakerConfig, CircuitBreakerOpenError
from src.config import settings
from src.logger import logger
from src.observability.structured_logger import log_api_call, log_error, log_with_context

# Grinder Integration Configuration
GRINDER0X_API_URL = getattr(settings, "GRINDER0X_API_URL", None)
GRINDER0X_API_KEY = getattr(settings, "GRINDER0X_API_KEY", None)

# Grinder integration is enabled if both URL and API key are configured
GRINDER_INTEGRATION_ENABLED = bool(GRINDER0X_API_URL and GRINDER0X_API_KEY)

# AbuseIPDB Category mappings for Grinder reports
ABUSEIPDB_CATEGORIES = {
    "phishing": 7,
    "hacking": 15,
    "web_app_attack": 21,
    "bad_web_bot": 19,
    "exploited_host": 20,
    "malware": 16,
    "botnet": 14,
    "spam": 10,
    "fraud": 18,
}


class GrinderReportClient:
    """
    HTTP client for reporting malicious IPs to Grinder system.

    This class handles the bidirectional threat intelligence integration,
    automatically reporting detected phishing infrastructure to Grinder
    for later AbuseIPDB reporting.
    """

    def __init__(self, api_url: str = None, api_key: str = None):
        """
        Initialize Grinder report client.

        Args:
            api_url (str, optional): Grinder API URL. Default to settings.
            api_key (str, optional): Grinder API key. Default to settings.
        """
        self.api_url = api_url or GRINDER0X_API_URL
        self.api_key = api_key or GRINDER0X_API_KEY
        self.session = requests.Session()

        if self.api_key:
            self.session.headers.update(
                {
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                    "Accept": "application/json, text/plain, */*",
                    "Accept-Language": "en-US,en;q=0.9",
                    "Accept-Encoding": "gzip, deflate, br",
                    "DNT": "1",
                    "Connection": "keep-alive",
                    "Sec-Fetch-Dest": "empty",
                    "Sec-Fetch-Mode": "cors",
                    "Sec-Fetch-Site": "cross-site",
                }
            )

        self.enabled = bool(self.api_url and self.api_key)

        # Initialize circuit breaker for API resilience (EPIC-004)
        cb_config = CircuitBreakerConfig(
            failure_threshold=3,  # Open after 3 failures
            recovery_timeout=60,  # Try again after 60 seconds
            success_threshold=2,  # Close after 2 successes in half-open
            max_retries=2,  # Retry failed requests twice
            retry_backoff_base=2.0,  # Exponential backoff starting at 2s
        )
        self.circuit_breaker = CircuitBreaker("Grinder", cb_config, logger)

        if self.enabled:
            logger.info(f"🔗 Grinder integration enabled: {self.api_url}")
        else:
            logger.warning("⚠️  Grinder integration disabled: Missing API URL or key")

    def report_malicious_ip(
        self, ip_address: str, detection_context: Dict[str, Any], confidence: int = 90
    ) -> Dict[str, Any]:
        """
        Report a malicious IP address to a Grinder system.

        Args:
            ip_address (str): The malicious IP address to report
            detection_context (Dict[str, Any]): Context about the detection
            confidence (int): Confidence level (0-100)

        Returns:
            Dict[str, Any]: Report submission result
        """
        if not self.enabled:
            logger.debug("🔗 Grinder integration disabled, skipping IP report")
            return {"status": "disabled", "message": "Grinder integration not configured"}

        if not self._validate_ip_address(ip_address):
            log_with_context(
                logger,
                logging.ERROR,
                "Invalid IP address format for Grinder report",
                ip_address=ip_address,
                event_type="grinder_report_validation_error",
            )
            return {"status": "error", "message": "Invalid IP address format"}

        try:
            # Determine appropriate categories based on detection context
            categories = self._determine_categories(detection_context)

            # Build the report payload
            payload = {
                "ip_address": ip_address,
                "categories": categories,
                "comment": self._build_comment(detection_context),
                "confidence": min(max(confidence, 0), 100),  # Clamp between 0-100
                "source": "anisakys_threat_intelligence",
                "additional_info": {
                    "detection_method": detection_context.get("method", "domain_analysis"),
                    "related_domains": detection_context.get("domains", []),
                    "severity": detection_context.get("severity", "high"),
                    "threat_level": detection_context.get("threat_level", "unknown"),
                    "analysis_timestamp": datetime.datetime.now().isoformat(),
                    "keywords_detected": detection_context.get("keywords", []),
                    "api_confidence": detection_context.get("api_confidence", 0),
                },
            }

            # Send the report through circuit breaker (EPIC-004)
            endpoint_url = f"{self.api_url.rstrip('/')}/api/v1/report-ip"

            def _make_request():
                """Internal function for circuit breaker wrapping."""
                start_time = time.time()
                response = self.session.post(endpoint_url, json=payload, timeout=30)
                response_time_ms = int((time.time() - start_time) * 1000)
                return response, response_time_ms

            # Execute with circuit breaker protection
            response, response_time_ms = self.circuit_breaker.call(_make_request)

            log_api_call(
                logger,
                api_name="Grinder",
                url=endpoint_url,
                status_code=response.status_code,
                response_time_ms=response_time_ms,
                ip_address=ip_address,
                categories=categories,
                confidence=confidence,
            )

            if response.status_code == 200:
                result = response.json()
                logger.info(
                    f"✅ Successfully reported IP {ip_address} to Grinder "
                    f"(Categories: {categories}, Confidence: {confidence}%)"
                )
                return {
                    "status": "success",
                    "ip_address": ip_address,
                    "grinder_response": result,
                    "categories": categories,
                    "confidence": confidence,
                }

            elif response.status_code == 429:
                logger.warning(f"⏰ Rate limited when reporting IP {ip_address} to Grinder")
                return {
                    "status": "rate_limited",
                    "message": "Rate limited by Grinder API",
                    "retry_after": response.headers.get("Retry-After", "Unknown"),
                }

            elif response.status_code == 400:
                error_details = response.json() if response.content else {"error": "Bad request"}
                log_with_context(
                    logger,
                    logging.ERROR,
                    "Bad request when reporting IP to Grinder",
                    ip_address=ip_address,
                    status_code=response.status_code,
                    error_details=error_details,
                    event_type="grinder_bad_request",
                )
                return {
                    "status": "bad_request",
                    "message": error_details.get("error", "Bad request"),
                    "details": error_details,
                }

            else:
                log_with_context(
                    logger,
                    logging.ERROR,
                    "Failed to report IP to Grinder",
                    ip_address=ip_address,
                    status_code=response.status_code,
                    response_text=response.text[:500],  # Limit response text
                    event_type="grinder_report_failed",
                )
                return {
                    "status": "error",
                    "message": f"HTTP {response.status_code}",
                    "response_text": response.text,
                }

        except CircuitBreakerOpenError as e:
            # Circuit breaker is open - service is down
            log_with_context(
                logger,
                logging.ERROR,
                "Grinder API circuit breaker OPEN - service unavailable",
                ip_address=ip_address,
                circuit_state="OPEN",
                event_type="grinder_circuit_open",
            )
            return {
                "status": "circuit_open",
                "message": "Grinder API temporarily unavailable due to repeated failures",
                "details": str(e),
            }

        except requests.exceptions.Timeout as e:
            log_error(
                logger,
                e,
                {"ip_address": ip_address, "api": "Grinder", "event_type": "grinder_timeout"},
            )
            return {"status": "timeout", "message": "Request timeout"}

        except requests.exceptions.ConnectionError as e:
            log_error(
                logger,
                e,
                {
                    "ip_address": ip_address,
                    "api": "Grinder",
                    "event_type": "grinder_connection_error",
                },
            )
            return {"status": "connection_error", "message": str(e)}

        except Exception as e:
            log_error(
                logger,
                e,
                {
                    "ip_address": ip_address,
                    "api": "Grinder",
                    "event_type": "grinder_unexpected_error",
                },
            )
            return {"status": "error", "message": str(e)}

    @staticmethod
    def _validate_ip_address(ip_address: str) -> bool:
        """
        Validate an IP address format.

        Args:
            ip_address (str): IP address to validate

        Returns:
            bool: True if valid, False otherwise
        """
        try:
            ipaddress.ip_address(ip_address)
            return True
        except ValueError:
            return False

    @staticmethod
    def _determine_categories(detection_context: Dict[str, Any]) -> List[int]:
        """
        Determine appropriate AbuseIPDB categories based on detection context.

        Args:
            detection_context (Dict[str, Any]): Detection context information

        Returns:
            List[int]: List of category IDs
        """
        categories = [ABUSEIPDB_CATEGORIES["phishing"]]

        # Always add phishing category for phishing sites

        # Add additional categories based on threat level and context
        threat_level = detection_context.get("threat_level", "").lower()
        keywords = detection_context.get("keywords", [])
        method = detection_context.get("method", "").lower()

        if threat_level in ["critical", "high"]:
            categories.append(ABUSEIPDB_CATEGORIES["hacking"])

        # Web application attack if web-related keywords detected
        web_keywords = ["login", "password", "account", "banking", "payment"]
        if any(kw.lower() in [k.lower() for k in keywords] for kw in web_keywords):
            categories.append(ABUSEIPDB_CATEGORIES["web_app_attack"])

        # Malware if detected through VirusTotal
        if "virustotal" in method:
            categories.append(ABUSEIPDB_CATEGORIES["malware"])

        # Remove duplicates and return
        return list(set(categories))

    @staticmethod
    def _build_comment(detection_context: Dict[str, Any]) -> str:
        """
        Build a comprehensive comment for the abuse report.

        Args:
            detection_context (Dict[str, Any]): Detection context information

        Returns:
            str: Formatted comment for the report
        """
        threat_level = detection_context.get("threat_level", "unknown").upper()
        domains = detection_context.get("domains", [])
        keywords = detection_context.get("keywords", [])
        api_confidence = detection_context.get("api_confidence", 0)

        comment_parts = [
            f"Phishing infrastructure detected by Anisakys threat intelligence system.",
            f"Threat Level: {threat_level}",
        ]

        if api_confidence > 0:
            comment_parts.append(f"API Confidence: {api_confidence}%")

        if domains:
            domain_list = ", ".join(domains[:5])  # Limit to first 5 domains
            if len(domains) > 5:
                domain_list += f" (and {len(domains) - 5} more)"
            comment_parts.append(f"Related domains: {domain_list}")

        if keywords:
            keyword_list = ", ".join(keywords[:5])  # Limit to first 5 keywords
            if len(keywords) > 5:
                keyword_list += f" (and {len(keywords) - 5} more)"
            comment_parts.append(f"Detection keywords: {keyword_list}")

        comment_parts.append("Automated report from Anisakys phishing detection engine.")

        return " | ".join(comment_parts)

    def test_connection(self) -> Dict[str, Any]:
        """
        Test connection to Grinder API.

        Returns:
            Dict[str, Any]: Connection test result
        """
        if not self.enabled:
            return {"status": "disabled", "message": "Grinder integration not configured"}

        try:
            # Try to access a test endpoint or health check
            health_url = f"{self.api_url.rstrip('/')}/api/v1/health"
            response = self.session.get(health_url, timeout=10)

            if response.status_code == 200:
                logger.info("✅ Grinder API connection test successful")
                return {
                    "status": "success",
                    "message": "Successfully connected to Grinder API",
                    "api_url": self.api_url,
                }
            else:
                logger.warning(f"⚠️  Grinder API responded with {response.status_code}")
                return {
                    "status": "warning",
                    "message": f"Grinder API responded with HTTP {response.status_code}",
                    "api_url": self.api_url,
                }

        except Exception as e:
            logger.error(f"❌ Failed to connect to Grinder API: {e}")
            return {
                "status": "error",
                "message": f"Connection failed: {str(e)}",
                "api_url": self.api_url,
            }


def require_api_key(f):
    """
    Decorator to require API key authentication for API endpoints.

    Expects API key in Authorization header: Bearer <key>
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")

        if not auth_header.startswith("Bearer "):
            logger.warning(f"🔐 Unauthorized API access attempt from {request.remote_addr}")
            return jsonify({"error": "Authorization header required with Bearer token"}), 401

        provided_key = auth_header[7:]  # Remove 'Bearer ' prefix

        # Get the expected API key from Flask current_app
        expected_key = getattr(current_app, "api_key", None)

        if not expected_key:
            logger.error("🔐 API key not configured for validation")
            return jsonify({"error": "API authentication not properly configured"}), 500

        if provided_key != expected_key:
            logger.warning(f"🔐 Invalid API key provided from {request.remote_addr}")
            return jsonify({"error": "Invalid API key"}), 401

        logger.debug(f"🔐 Valid API key provided from {request.remote_addr}")
        return f(*args, **kwargs)

    return decorated_function
