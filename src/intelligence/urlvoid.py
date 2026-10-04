"""
URLVoid integration for Anisakys Phishing Detection Engine.

Domain reputation / blacklist lookups against URLVoid.

**Unverified client, disabled by default.** The endpoint used here
(``api.urlvoid.com/v1/host/{domain}``) and the parsed fields
(``safety_score``, ``blacklists[]``) do not match the vendor's documented
URLVoid/APIVoid APIs and could not be checked against a live account, so the
integration only runs when ``URLVOID_ENABLED=true``. Disabled, unconfigured or
unparseable lookups yield ``status="no_data"``: never a clean verdict and
never a vote in the aggregated threat level.
"""

import logging
import time
from typing import Any, Dict, Optional

import requests

from src.circuit_breaker import CircuitBreaker, CircuitBreakerConfig, CircuitBreakerOpenError
from src.config import settings, secret_value
from src.intelligence.provider_common import ERROR, LISTED, NO_DATA, NOT_LISTED
from src.logger import logger
from src.observability.structured_logger import log_api_call, log_with_context
from src.utils.redaction import redact_secrets

# API Configuration
URLVOID_API_KEY = secret_value(getattr(settings, "URLVOID_API_KEY", None))
URLVOID_ENABLED = bool(getattr(settings, "URLVOID_ENABLED", False))

_startup_warning_logged = False


def _log_startup_warning_once(enabled: bool, has_key: bool) -> None:
    """Explain once per process why URLVoid is (or should not be) used.

    Args:
        enabled: Value of ``URLVOID_ENABLED`` for this client.
        has_key: Whether an API key is configured.
    """
    global _startup_warning_logged
    if _startup_warning_logged:
        return
    _startup_warning_logged = True
    if enabled:
        logger.warning(
            "⚠️  URLVoid is enabled but its endpoint/response schema are unverified against "
            "the vendor documentation; its results may be wrong."
        )
    elif has_key:
        logger.warning(
            "⚠️  URLVOID_API_KEY is set but URLVoid is disabled (URLVOID_ENABLED=false) "
            "because the integration is unverified; it contributes no data."
        )
    else:
        logger.info("URLVoid integration disabled (URLVOID_ENABLED=false)")


class URLVoidIntegration:
    """
    URLVoid API Integration for multi-blocklist checking.

    Queries reputation engines and blocklist services for domain reputation.
    Disabled unless ``URLVOID_ENABLED`` is true (see module docstring).
    """

    def __init__(self, api_key: Optional[str] = None, enabled: Optional[bool] = None):
        """
        Initialize URLVoid integration.

        Args:
            api_key: URLVoid API key. If None, uses the configured setting.
            enabled: Override ``URLVOID_ENABLED`` (mainly for tests).
        """
        self.api_key = api_key or URLVOID_API_KEY
        self.enabled = URLVOID_ENABLED if enabled is None else enabled
        self.base_url = "https://api.urlvoid.com/v1"
        self.session = requests.Session()

        # Initialize circuit breaker for API resilience (EPIC-004)
        cb_config = CircuitBreakerConfig(
            failure_threshold=4,
            recovery_timeout=90,
            success_threshold=2,
            timeout=15.0,
            max_retries=2,
            retry_backoff_base=2.5,
        )
        self.circuit_breaker = CircuitBreaker("URLVoid", cb_config, logger)
        self.timeout = cb_config.timeout
        _log_startup_warning_once(self.enabled, bool(self.api_key))

    def analyze_domain(self, domain: str) -> Dict[str, Any]:
        """
        Analyze a domain using URLVoid's reputation engines.

        Args:
            domain (str): Domain to analyze

        Returns:
            Dict[str, Any]: Result with ``status``. ``no_data`` when the
            integration is disabled/unconfigured or the answer has no usable
            fields; ``error`` on failures; ``listed``/``not_listed`` otherwise.
        """
        if not self.enabled:
            return {
                "domain": domain,
                "status": NO_DATA,
                "enabled": False,
                "reason": "disabled",
                "threat_level": "unknown",
            }
        if not self.api_key:
            logger.warning("⚠️  URLVoid API key not configured, skipping analysis")
            return {
                "domain": domain,
                "status": NO_DATA,
                "reason": "not_configured",
                "threat_level": "unknown",
            }

        params = {"key": self.api_key, "host": domain}

        def _make_request():
            """Internal function for circuit breaker wrapping."""
            start_time = time.time()
            response = self.session.get(
                f"{self.base_url}/host/{domain}", params=params, timeout=self.timeout
            )
            response_time_ms = int((time.time() - start_time) * 1000)
            return response, response_time_ms

        try:
            response, response_time_ms = self.circuit_breaker.call(_make_request)
        except CircuitBreakerOpenError as e:
            log_with_context(
                logger,
                logging.ERROR,
                "URLVoid API circuit breaker OPEN - service unavailable",
                domain=domain,
                circuit_state="OPEN",
                event_type="urlvoid_circuit_open",
            )
            return {
                "status": ERROR,
                "error": "URLVoid API temporarily unavailable",
                "reason": "circuit_open",
                "details": str(e),
                "threat_level": "unknown",
            }
        except requests.RequestException as e:
            # Exception text embeds the request URL, including ?key=...
            message = redact_secrets(e)
            logger.error(f"❌ URLVoid analysis failed for {domain}: {message}")
            return {"status": ERROR, "error": message, "threat_level": "unknown"}

        log_api_call(
            logger,
            api_name="URLVoid",
            url=f"{self.base_url}/host/{domain}",
            status_code=response.status_code,
            response_time_ms=response_time_ms,
            target_domain=domain,
        )

        if response.status_code != 200:
            log_with_context(
                logger,
                logging.ERROR,
                "URLVoid API error",
                domain=domain,
                status_code=response.status_code,
                event_type="urlvoid_api_error",
            )
            return {
                "status": ERROR,
                "error": f"API error: {response.status_code}",
                "threat_level": "unknown",
            }

        try:
            data = response.json()
        except ValueError:
            return {"status": ERROR, "error": "Unparseable response", "threat_level": "unknown"}
        details = data.get("data", {}).get("report", {}) if isinstance(data, dict) else {}
        if not isinstance(details, dict):
            details = {}

        threat_level = self._calculate_urlvoid_threat_level(details)
        if threat_level == "unknown":
            status = NO_DATA
        elif threat_level == "clean":
            status = NOT_LISTED
        else:
            status = LISTED

        result = {
            "domain": domain,
            "status": status,
            "safety_score": details.get("safety_score"),
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
            "blacklists": details.get("blacklists") or [],
            "threat_level": threat_level,
            "ssl_certificate": details.get("ssl_certificate", {}),
            "redirects": details.get("redirects", []),
        }

        logger.info(
            f"🔍 URLVoid analysis for {domain}: safety score {result['safety_score']} "
            f"(status={status})"
        )
        return result

    @staticmethod
    def _calculate_urlvoid_threat_level(details: Dict[str, Any]) -> str:
        """
        Calculate threat level based on URLVoid analysis.

        Missing fields are treated as unknown (no default score), so an empty
        or unexpected answer can never become "clean".

        Args:
            details (Dict[str, Any]): URLVoid analysis details

        Returns:
            str: Threat level (high, medium, low, clean, unknown)
        """
        raw_score = details.get("safety_score")
        blacklists = details.get("blacklists")
        score: Optional[float] = (
            float(raw_score)
            if isinstance(raw_score, (int, float)) and not isinstance(raw_score, bool)
            else None
        )
        if score is None and not isinstance(blacklists, list):
            return "unknown"

        listed = len(blacklists) if isinstance(blacklists, list) else 0
        if (score is not None and score <= 30) or listed >= 5:
            return "high"
        if (score is not None and score <= 60) or listed >= 2:
            return "medium"
        if (score is not None and score <= 80) or listed >= 1:
            return "low"
        if score is None:
            # An empty blacklist without a score is not enough for "clean".
            return "unknown"
        return "clean"
