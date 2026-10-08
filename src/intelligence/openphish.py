"""
OpenPhish Community feed integration for Anisakys Phishing Detection Engine.

Free, unauthenticated bulk feed of known phishing URLs (refreshed every 12h),
used for corroboration: cross-referenced against phishing_sites already
tracked by anisakys, not for discovery of new candidates (see
src/monitoring/feed_intel.py).
"""

import time
from typing import Set

import requests

from src.circuit_breaker import CircuitBreaker, CircuitBreakerConfig, CircuitBreakerOpenError
from src.logger import logger
from src.observability.structured_logger import log_api_call, log_error

OPENPHISH_FEED_URL = (
    "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"
)


class OpenPhishIntegration:
    """Fetches the OpenPhish Community feed (plain-text, one URL per line)."""

    def __init__(self):
        self.feed_url = OPENPHISH_FEED_URL
        self.session = requests.Session()

        cb_config = CircuitBreakerConfig(
            failure_threshold=4,
            recovery_timeout=90,
            success_threshold=2,
            max_retries=2,
            retry_backoff_base=2.0,
        )
        self.circuit_breaker = CircuitBreaker("OpenPhish", cb_config, logger)

    def fetch_feed(self) -> Set[str]:
        """Fetch the Community feed and return its URLs as a set.

        Returns an empty set on any failure (unreachable, circuit open, non-200)
        -- callers treat this as "no corroboration data this cycle," not fatal.
        """
        try:

            def _make_request():
                start_time = time.time()
                response = self.session.get(self.feed_url, timeout=30)
                response_time_ms = int((time.time() - start_time) * 1000)
                return response, response_time_ms

            response, response_time_ms = self.circuit_breaker.call(_make_request)

            log_api_call(
                logger,
                api_name="OpenPhish",
                url=self.feed_url,
                status_code=response.status_code,
                response_time_ms=response_time_ms,
            )

            if response.status_code != 200:
                logger.error(f"❌ OpenPhish feed fetch failed: {response.status_code}")
                return set()

            return {line.strip() for line in response.text.splitlines() if line.strip()}

        except CircuitBreakerOpenError as e:
            logger.error(f"❌ OpenPhish circuit breaker OPEN - service unavailable: {e}")
            return set()
        except Exception as e:
            log_error(
                logger,
                e,
                {
                    "api": "OpenPhish",
                    "operation": "fetch_feed",
                    "event_type": "openphish_fetch_failed",
                },
            )
            return set()
