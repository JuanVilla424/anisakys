"""
PhishTank integration for Anisakys Phishing Detection Engine.

Looks URLs up in the PhishTank community database (``checkurl`` API).

PhishTank only lists reported URLs, so "not in the database" is reported as
``status="not_listed"`` with ``threat_level="unknown"``: it is the absence of
a listing, never a clean verdict. An entry verified by the community as *not*
being a phish (``verified=true, valid=false``) is not treated as phishing, and
neither is a submission that is neither verified nor valid (``verified=false,
valid=false``): a dead or rejected submission is no evidence at all, not even
medium. Only an unverified entry that is still valid (reported and online,
community vote pending) counts, as ``medium``.
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
PHISHTANK_API_KEY = secret_value(getattr(settings, "PHISHTANK_API_KEY", None))
PHISHTANK_USER_AGENT = "phishtank/anisakys-phishing-detector"

_submission_warning_logged = False


def _as_bool(value: Any) -> bool:
    """Interpret PhishTank booleans, which may arrive as JSON or as strings.

    Args:
        value: Raw field value.

    Returns:
        ``True`` for ``True``/``"true"``/``"yes"``/``"y"``/``"1"``.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in ("true", "yes", "y", "1")
    return False


class PhishTankIntegration:
    """
    PhishTank API Integration for a community-driven phishing database.

    Provides access to verified phishing URLs from the security community.
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
        self.session.headers.update({"User-Agent": PHISHTANK_USER_AGENT})

        # Initialize circuit breaker for API resilience (EPIC-004)
        cb_config = CircuitBreakerConfig(
            failure_threshold=4,
            recovery_timeout=90,
            success_threshold=2,
            timeout=15.0,
            max_retries=2,
            retry_backoff_base=2.0,
        )
        self.circuit_breaker = CircuitBreaker("PhishTank", cb_config, logger)
        self.timeout = cb_config.timeout

    @staticmethod
    def _interpret(url: str, details: Dict[str, Any]) -> Dict[str, Any]:
        """Map a ``results`` object to a provider result.

        Args:
            url: The URL that was looked up.
            details: The ``results`` object of the checkurl response.

        Returns:
            Result dict with ``status``, ``is_phishing``, ``verified``,
            ``valid`` and ``threat_level``.
        """
        in_database = _as_bool(details.get("in_database"))
        verified = _as_bool(details.get("verified"))
        valid = _as_bool(details.get("valid"))
        base = {
            "url": url,
            "in_database": in_database,
            "phish_id": details.get("phish_id"),
            "verified": verified,
            "valid": valid,
            "verified_at": details.get("verified_at"),
            "submission_time": details.get("submission_time"),
            "target": details.get("target"),
            "details_url": details.get("phish_detail_page"),
        }

        if not in_database:
            return {**base, "status": NOT_LISTED, "is_phishing": False, "threat_level": "unknown"}
        if verified and not valid:
            # The community verified this URL as NOT a phish.
            return {
                **base,
                "status": NOT_LISTED,
                "is_phishing": False,
                "verified_not_phish": True,
                "threat_level": "unknown",
            }
        if verified:
            return {**base, "status": LISTED, "is_phishing": True, "threat_level": "high"}
        if valid:
            # Reported and still online; the community vote is pending.
            return {**base, "status": LISTED, "is_phishing": True, "threat_level": "medium"}
        # Neither verified nor valid: a dead or rejected submission is no
        # evidence (e.g. example.com with a stale phish_id attached).
        return {
            **base,
            "status": NOT_LISTED,
            "is_phishing": False,
            "stale_submission": True,
            "threat_level": "unknown",
        }

    def check_phishing_status(self, url: str) -> Dict[str, Any]:
        """
        Check if a URL is in the PhishTank database.

        Args:
            url (str): URL to check

        Returns:
            Dict[str, Any]: Result with ``status`` (listed/not_listed/no_data/
            error), ``is_phishing`` (only for an unrefuted, still-valid
            listing), ``verified``, ``valid``, ``details_url`` and
            ``threat_level``. ``stale_submission`` marks an in-database entry
            that is neither verified nor valid (no evidence).
        """
        data = {"url": url, "format": "json"}
        if self.api_key:
            data["app_key"] = self.api_key

        def _make_request():
            """Internal function for circuit breaker wrapping."""
            start_time = time.time()
            response = self.session.post(self.base_url, data=data, timeout=self.timeout)
            response_time_ms = int((time.time() - start_time) * 1000)
            return response, response_time_ms

        try:
            # checkurl is a read-only lookup sent as POST: safe to retry.
            response, response_time_ms = self.circuit_breaker.call(_make_request, idempotent=True)
        except CircuitBreakerOpenError as e:
            log_with_context(
                logger,
                logging.ERROR,
                "PhishTank API circuit breaker OPEN - service unavailable",
                url=url,
                circuit_state="OPEN",
                event_type="phishtank_circuit_open",
            )
            return {
                "status": ERROR,
                "error": "PhishTank API temporarily unavailable",
                "reason": "circuit_open",
                "details": str(e),
                "threat_level": "unknown",
            }
        except requests.RequestException as e:
            message = redact_secrets(e)
            logger.error(f"❌ PhishTank lookup failed for {url}: {message}")
            return {"status": ERROR, "error": message, "threat_level": "unknown"}

        log_api_call(
            logger,
            api_name="PhishTank",
            url=self.base_url,
            status_code=response.status_code,
            response_time_ms=response_time_ms,
            target_url=url,
        )

        if response.status_code != 200:
            log_with_context(
                logger,
                logging.ERROR,
                "PhishTank API error",
                url=url,
                status_code=response.status_code,
                event_type="phishtank_api_error",
            )
            return {
                "status": ERROR,
                "error": f"API error: {response.status_code}",
                "threat_level": "unknown",
            }

        try:
            body = response.json()
        except ValueError:
            return {"status": ERROR, "error": "Unparseable response", "threat_level": "unknown"}

        details = body.get("results") if isinstance(body, dict) else None
        if not isinstance(details, dict):
            # No verdict in the answer: absence of data, not a clean result.
            return {"url": url, "status": NO_DATA, "is_phishing": False, "threat_level": "unknown"}

        return self._interpret(url, details)

    def submit_phishing_url(self, url: str) -> Dict[str, Any]:
        """
        Report that PhishTank submission is not supported.

        PhishTank accepts new phishes only through its login-gated web form;
        there is no submission API, and posting to the form endpoint returns
        HTTP 200 even when nothing was recorded. The previous implementation
        therefore reported false successes and has been disabled.

        Args:
            url (str): Suspected phishing URL.

        Returns:
            Dict[str, Any]: ``{"success": False, "status": "not_supported", ...}``.
        """
        global _submission_warning_logged
        if not _submission_warning_logged:
            _submission_warning_logged = True
            logger.warning(
                "PhishTank submission is not supported (no submission API; the web form "
                "requires an interactive login). Submit manually at https://phishtank.org/."
            )
        return {
            "success": False,
            "status": "not_supported",
            "url": url,
            "error": "PhishTank has no submission API; submit manually via the website",
        }
