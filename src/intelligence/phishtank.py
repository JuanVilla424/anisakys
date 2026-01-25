"""
PhishTank integration for Anisakys Phishing Detection Engine.

PhishTank API integration for community-driven phishing URL
verification and threat intelligence.
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
PHISHTANK_API_KEY = getattr(settings, "PHISHTANK_API_KEY", None)


class PhishTankIntegration:
    """
    PhishTank API Integration for a community-driven phishing database.

    Provides access to verified phishing URLs from the security community with
    real-time updates and submission capabilities.
    """

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize PhishTank integration.

        Args:
            api_key (Optional[str]): PhishTank API key. If None, uses environment variable.
        """
        self.api_key = api_key or PHISHTANK_API_KEY
        self.base_url = "https://checkurl.phishtank.com/checkurl/"
        self.session = requests.Session()

        # Initialize circuit breaker for API resilience (EPIC-004)
        cb_config = CircuitBreakerConfig(
            failure_threshold=4,
            recovery_timeout=90,
            success_threshold=2,
            max_retries=2,
            retry_backoff_base=2.0,
        )
        self.circuit_breaker = CircuitBreaker("PhishTank", cb_config, logger)

    def check_phishing_status(self, url: str) -> Dict[str, Any]:
        """
        Check if URL is in PhishTank verified a phishing database.

        Args:
            url (str): URL to check

        Returns:
            Dict[str, Any]: Phishing status and verification details
        """
        try:
            data = {"url": url, "format": "json"}

            if self.api_key:
                data["app_key"] = self.api_key

            # Execute through circuit breaker (EPIC-004)
            def _make_request():
                """Internal function for circuit breaker wrapping."""
                start_time = time.time()
                response = self.session.post(self.base_url, data=data)
                response_time_ms = int((time.time() - start_time) * 1000)
                return response, response_time_ms

            response, response_time_ms = self.circuit_breaker.call(_make_request)

            log_api_call(
                logger,
                api_name="PhishTank",
                url=self.base_url,
                status_code=response.status_code,
                response_time_ms=response_time_ms,
                target_url=url,
            )

            if response.status_code == 200:
                result = response.json()

                if "results" in result:
                    phish_details = result["results"]

                    return {
                        "url": url,
                        "is_phishing": phish_details.get("in_database", False),
                        "phish_id": phish_details.get("phish_id"),
                        "verified": phish_details.get("verified", False),
                        "verified_at": phish_details.get("verified_at"),
                        "submission_time": phish_details.get("submission_time"),
                        "target": phish_details.get("target"),
                        "details_url": phish_details.get("phish_detail_url"),
                        "threat_level": (
                            "high" if phish_details.get("verified", False) else "medium"
                        ),
                    }
                else:
                    return {
                        "url": url,
                        "is_phishing": False,
                        "verified": False,
                        "threat_level": "clean",
                    }

            else:
                log_with_context(
                    logger,
                    logging.ERROR,
                    "PhishTank API error",
                    url=url,
                    status_code=response.status_code,
                    event_type="phishtank_api_error",
                )
                return {"error": f"API error: {response.status_code}"}

        except CircuitBreakerOpenError as e:
            # Circuit breaker is open - service is down
            log_with_context(
                logger,
                logging.ERROR,
                "PhishTank API circuit breaker OPEN - service unavailable",
                url=url,
                circuit_state="OPEN",
                event_type="phishtank_circuit_open",
            )
            return {
                "error": "PhishTank API temporarily unavailable",
                "status": "circuit_open",
                "details": str(e),
            }

        except Exception as e:
            log_error(
                logger,
                e,
                {
                    "url": url,
                    "api": "PhishTank",
                    "operation": "check_phishing_status",
                    "event_type": "phishtank_check_failed",
                },
            )
            return {"error": str(e)}

    def submit_phishing_url(self, url: str) -> Dict[str, Any]:
        """
        Submit suspected phishing URL to PhishTank database.

        Args:
            url (str): Suspected phishing URL to submit

        Returns:
            Dict[str, Any]: Submission result
        """
        if not self.api_key:
            logger.warning("⚠️  PhishTank API key not configured, cannot submit URLs")
            return {"error": "API key required for submissions"}

        try:
            submit_url = "https://www.phishtank.com/add_web_phish.php"
            data = {"url": url, "app_key": self.api_key}

            response = self.session.post(submit_url, data=data)

            if response.status_code == 200:
                logger.info(f"✅ Successfully submitted {url} to PhishTank")
                return {"status": "submitted", "url": url}
            else:
                logger.error(f"❌ Failed to submit {url} to PhishTank: {response.status_code}")
                return {"error": f"Submission failed: {response.status_code}"}

        except Exception as e:
            logger.error(f"❌ PhishTank submission failed for {url}: {e}")
            return {"error": str(e)}
