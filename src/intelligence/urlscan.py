"""
urlscan.io integration for Anisakys Phishing Detection Engine.

Free-tier keyword search (no bulk feed exists) used for discovery: pages
recently scanned by the wider urlscan.io community that mention a protected
brand keyword, surfaced as new candidates for human review (see
src/monitoring/feed_intel.py). The paid-only "brand" classification field
isn't used here -- build_brand_query() searches page.domain/page.title
directly instead, which the free tier does support.
"""

import time
from typing import Any, Dict, List, Optional

import requests

from src.circuit_breaker import CircuitBreaker, CircuitBreakerConfig, CircuitBreakerOpenError
from src.config import settings
from src.logger import logger
from src.observability.structured_logger import log_api_call, log_error

URLSCAN_API_KEY = getattr(settings, "URLSCAN_API_KEY", None)
URLSCAN_SEARCH_URL = "https://urlscan.io/api/v1/search/"


def build_brand_query(brand: str) -> str:
    """ElasticSearch query_string targeting a brand keyword in the domain or
    page title of recently-scanned pages (confirmed field names from the
    real urlscan.io search docs: page.domain, page.title)."""
    return f'page.domain:*{brand}* OR page.title:"{brand}"'


class URLscanIntegration:
    """Searches recently-scanned public pages via the urlscan.io search API."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or URLSCAN_API_KEY
        self.search_url = URLSCAN_SEARCH_URL
        self.session = requests.Session()

        cb_config = CircuitBreakerConfig(
            failure_threshold=4,
            recovery_timeout=90,
            success_threshold=2,
            max_retries=2,
            retry_backoff_base=2.0,
        )
        self.circuit_breaker = CircuitBreaker("urlscan.io", cb_config, logger)

    def search(self, query: str, size: int = 100) -> List[Dict[str, Any]]:
        """Run a search query and return its result list. Returns an empty
        list on any failure, including a missing API key -- callers treat
        this as "no discovery data this cycle," not fatal.
        """
        if not self.api_key:
            logger.warning("⚠️  urlscan.io API key not configured, skipping search")
            return []

        try:

            def _make_request():
                start_time = time.time()
                response = self.session.get(
                    self.search_url,
                    headers={"API-Key": self.api_key},
                    params={"q": query, "size": size},
                    timeout=30,
                )
                response_time_ms = int((time.time() - start_time) * 1000)
                return response, response_time_ms

            response, response_time_ms = self.circuit_breaker.call(_make_request)

            log_api_call(
                logger,
                api_name="urlscan.io",
                url=self.search_url,
                status_code=response.status_code,
                response_time_ms=response_time_ms,
            )

            if response.status_code != 200:
                logger.error(f"❌ urlscan.io search failed: {response.status_code}")
                return []

            return response.json().get("results", [])

        except CircuitBreakerOpenError as e:
            logger.error(f"❌ urlscan.io circuit breaker OPEN - service unavailable: {e}")
            return []
        except Exception as e:
            log_error(
                logger,
                e,
                {"api": "urlscan.io", "operation": "search", "event_type": "urlscan_search_failed"},
            )
            return []
