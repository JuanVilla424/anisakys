"""
URLhaus (abuse.ch) integration for Anisakys Phishing Detection Engine.

Bulk feed of recently-added malicious URLs (refreshed every 5 min, covers the
last 3 days), used for corroboration: cross-referenced against phishing_sites
already tracked by anisakys, not for discovery of new candidates (see
src/monitoring/feed_intel.py).
"""

import time
from typing import Any, Dict, List, Optional

import requests

from src.circuit_breaker import CircuitBreaker, CircuitBreakerConfig, CircuitBreakerOpenError
from src.config import settings
from src.logger import logger
from src.observability.structured_logger import log_api_call, log_error

URLHAUS_API_KEY = getattr(settings, "URLHAUS_API_KEY", None)
URLHAUS_RECENT_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/"


class URLhausIntegration:
    """Fetches recently-added URLs from the URLhaus bulk query API."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or URLHAUS_API_KEY
        self.recent_url = URLHAUS_RECENT_URL
        self.session = requests.Session()

        cb_config = CircuitBreakerConfig(
            failure_threshold=4,
            recovery_timeout=90,
            success_threshold=2,
            max_retries=2,
            retry_backoff_base=2.0,
        )
        self.circuit_breaker = CircuitBreaker("URLhaus", cb_config, logger)

    def fetch_recent(self, limit: int = 1000) -> List[Dict[str, Any]]:
        """Fetch recently-added URLs (past 3 days, max 1000 entries per the
        API's own limit). Returns an empty list on any failure, including a
        missing API key -- callers treat this as "no corroboration data this
        cycle," not fatal.
        """
        if not self.api_key:
            logger.warning("⚠️  URLhaus API key not configured, skipping fetch")
            return []

        try:

            def _make_request():
                start_time = time.time()
                response = self.session.get(
                    self.recent_url,
                    headers={"Auth-Key": self.api_key},
                    params={"limit": limit},
                    timeout=30,
                )
                response_time_ms = int((time.time() - start_time) * 1000)
                return response, response_time_ms

            response, response_time_ms = self.circuit_breaker.call(_make_request)

            log_api_call(
                logger,
                api_name="URLhaus",
                url=self.recent_url,
                status_code=response.status_code,
                response_time_ms=response_time_ms,
            )

            if response.status_code != 200:
                logger.error(f"❌ URLhaus recent-URLs fetch failed: {response.status_code}")
                return []

            data = response.json()
            if data.get("query_status") != "ok":
                logger.warning(f"⚠️  URLhaus query_status: {data.get('query_status')}")
                return []

            return data.get("urls", [])

        except CircuitBreakerOpenError as e:
            logger.error(f"❌ URLhaus circuit breaker OPEN - service unavailable: {e}")
            return []
        except Exception as e:
            log_error(
                logger,
                e,
                {
                    "api": "URLhaus",
                    "operation": "fetch_recent",
                    "event_type": "urlhaus_fetch_failed",
                },
            )
            return []
