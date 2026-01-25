"""
URLVoid integration for Anisakys Phishing Detection Engine.

URLVoid API integration for domain reputation analysis and
blacklist checking across multiple security databases.
"""

import logging
import time
from typing import Any, Dict, Optional

import requests

from src.circuit_breaker import CircuitBreaker, CircuitBreakerConfig, CircuitBreakerOpenError
from src.config import settings
from src.logger import logger
from src.observability.structured_logger import log_api_call, log_error, log_with_context

# API Configuration
URLVOID_API_KEY = getattr(settings, "URLVOID_API_KEY", None)


class URLVoidIntegration:
    """
    URLVoid API Integration for multi-blocklist checking.

    Queries against 30+ reputation engines and blocklist services for
    comprehensive domain reputation analysis.
    """

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize URLVoid integration.

        Args:
            api_key (Optional[str]): URLVoid API key. If None, uses environment variable.
        """
        self.api_key = api_key or URLVOID_API_KEY
        self.base_url = "https://api.urlvoid.com/v1"
        self.session = requests.Session()

        # Initialize circuit breaker for API resilience (EPIC-004)
        cb_config = CircuitBreakerConfig(
            failure_threshold=4,
            recovery_timeout=90,
            success_threshold=2,
            max_retries=2,
            retry_backoff_base=2.5,
        )
        self.circuit_breaker = CircuitBreaker("URLVoid", cb_config, logger)

    def analyze_domain(self, domain: str) -> Dict[str, Any]:
        """
        Analyze domain using multiple reputation engines and blocklist services.

        Args:
            domain (str): Domain to analyze

        Returns:
            Dict[str, Any]: Comprehensive safety score and reputation analysis
        """
        if not self.api_key:
            logger.warning("⚠️  URLVoid API key not configured, skipping analysis")
            return {"error": "API key not configured"}

        try:
            params = {"key": self.api_key, "host": domain}

            # Execute through circuit breaker (EPIC-004)
            def _make_request():
                """Internal function for circuit breaker wrapping."""
                start_time = time.time()
                response = self.session.get(f"{self.base_url}/host/{domain}", params=params)
                response_time_ms = int((time.time() - start_time) * 1000)
                return response, response_time_ms

            response, response_time_ms = self.circuit_breaker.call(_make_request)

            log_api_call(
                logger,
                api_name="URLVoid",
                url=f"{self.base_url}/host/{domain}",
                status_code=response.status_code,
                response_time_ms=response_time_ms,
                target_domain=domain,
            )

            if response.status_code == 200:
                data = response.json()
                details = data.get("data", {}).get("report", {})

                result = {
                    "domain": domain,
                    "safety_score": details.get("safety_score", 0),
                    "domain_age": details.get("domain_age"),
                    "domain_1st_registered": details.get("domain_1st_registered"),
                    "domain_length": details.get("domain_length"),
                    "hostname": details.get("hostname"),
                    "ip_address": details.get("ip_address"),
                    "asn": details.get("asn"),
                    "asn_name": details.get("asn_name"),
                    "country_code": details.get("country_code"),
                    "server_type": details.get("server_type"),
                    "detections": details.get("detections", {}),
                    "blacklists": details.get("blacklists", []),
                    "threat_level": self._calculate_urlvoid_threat_level(details),
                    "ssl_certificate": details.get("ssl_certificate", {}),
                    "redirects": details.get("redirects", []),
                }

                logger.info(
                    f"🔍 URLVoid analysis for {domain}: Safety score {result['safety_score']}"
                )
                return result

            else:
                log_with_context(
                    logger,
                    logging.ERROR,
                    "URLVoid API error",
                    domain=domain,
                    status_code=response.status_code,
                    event_type="urlvoid_api_error",
                )
                return {"error": f"API error: {response.status_code}"}

        except CircuitBreakerOpenError as e:
            # Circuit breaker is open - service is down
            log_with_context(
                logger,
                logging.ERROR,
                "URLVoid API circuit breaker OPEN - service unavailable",
                domain=domain,
                circuit_state="OPEN",
                event_type="urlvoid_circuit_open",
            )
            return {
                "error": "URLVoid API temporarily unavailable",
                "status": "circuit_open",
                "details": str(e),
            }

        except Exception as e:
            log_error(
                logger,
                e,
                {
                    "domain": domain,
                    "api": "URLVoid",
                    "operation": "domain_analysis",
                    "event_type": "urlvoid_analysis_failed",
                },
            )
            return {"error": str(e)}

    @staticmethod
    def _calculate_urlvoid_threat_level(details: Dict[str, Any]) -> str:
        """
        Calculate threat level based on URLVoid analysis.

        Args:
            details (Dict[str, Any]): URLVoid analysis details

        Returns:
            str: Threat level (high, medium, low, clean)
        """
        safety_score = details.get("safety_score", 100)
        detections = details.get("detections", {})
        blacklists = details.get("blacklists", [])

        if safety_score <= 30 or len(blacklists) >= 5:
            return "high"
        elif safety_score <= 60 or len(blacklists) >= 2:
            return "medium"
        elif safety_score <= 80 or len(blacklists) >= 1:
            return "low"
        else:
            return "clean"
