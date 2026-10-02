"""
TAXII 2.1 client for Anisakys Phishing Detection Engine.

Generic, standards-compliant client for any TAXII 2.1 server (discovery,
collections, pull/push of STIX objects) -- confirmed against the real OASIS
TAXII 2.1 spec, not assumed. Hand-rolled with requests (no third-party TAXII
SDK), matching this codebase's convention for every other external
integration (openphish.py/urlhaus.py/urlscan.py): TAXII's REST surface is
small and standardized enough that a dependency isn't warranted.

No production TAXII server exists yet to test against live -- verified via
mocked tests only (see tests/intelligence/test_taxii_client.py).
"""

import time
from typing import Any, Dict, List, Optional

import requests
from requests.auth import HTTPBasicAuth

from src.circuit_breaker import CircuitBreaker, CircuitBreakerConfig, CircuitBreakerOpenError
from src.config import settings
from src.logger import logger
from src.observability.structured_logger import log_api_call, log_error

TAXII_BASE_URL = getattr(settings, "TAXII_BASE_URL", None)
TAXII_USERNAME = getattr(settings, "TAXII_USERNAME", None)
TAXII_PASSWORD = getattr(settings, "TAXII_PASSWORD", None)
TAXII_MEDIA_TYPE = "application/taxii+json;version=2.1"


class TAXIIClient:
    """Discovery + collections + pull/push against a TAXII 2.1 server."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
    ):
        self.base_url = (base_url or TAXII_BASE_URL or "").rstrip("/")
        username = username or TAXII_USERNAME
        password = password or TAXII_PASSWORD
        self.auth = HTTPBasicAuth(username, password or "") if username else None
        self.session = requests.Session()
        self.headers = {"Accept": TAXII_MEDIA_TYPE, "Content-Type": TAXII_MEDIA_TYPE}

        cb_config = CircuitBreakerConfig(
            failure_threshold=4,
            recovery_timeout=90,
            success_threshold=2,
            max_retries=2,
            retry_backoff_base=2.0,
        )
        self.circuit_breaker = CircuitBreaker("TAXII", cb_config, logger)

    def _request(self, method: str, path: str, **kwargs) -> Optional[requests.Response]:
        if not self.base_url:
            logger.warning("⚠️  TAXII base URL not configured, skipping request")
            return None
        url = f"{self.base_url}{path}"
        try:

            def _make_request():
                start_time = time.time()
                response = self.session.request(
                    method, url, headers=self.headers, auth=self.auth, timeout=30, **kwargs
                )
                response_time_ms = int((time.time() - start_time) * 1000)
                return response, response_time_ms

            response, response_time_ms = self.circuit_breaker.call(_make_request)
            log_api_call(
                logger,
                api_name="TAXII",
                url=url,
                status_code=response.status_code,
                response_time_ms=response_time_ms,
            )
            if response.status_code not in (200, 201, 202):
                logger.error(f"❌ TAXII {method} {path} failed: {response.status_code}")
                return None
            return response
        except CircuitBreakerOpenError as e:
            logger.error(f"❌ TAXII circuit breaker OPEN - service unavailable: {e}")
            return None
        except Exception as e:
            log_error(logger, e, {"api": "TAXII", "operation": f"{method} {path}"})
            return None

    def discover(self) -> Dict[str, Any]:
        """GET /taxii2/ -- the discovery resource (title, api_roots, ...)."""
        response = self._request("GET", "/taxii2/")
        return response.json() if response else {}

    def get_collections(self, api_root: str) -> List[Dict[str, Any]]:
        """GET /{api_root}/collections/ -- collections under an API root."""
        response = self._request("GET", f"/{api_root.strip('/')}/collections/")
        return response.json().get("collections", []) if response else []

    def pull_objects(self, api_root: str, collection_id: str) -> List[Dict[str, Any]]:
        """GET /{api_root}/collections/{id}/objects/ -- pull STIX objects."""
        response = self._request(
            "GET", f"/{api_root.strip('/')}/collections/{collection_id}/objects/"
        )
        return response.json().get("objects", []) if response else []

    def push_objects(
        self, api_root: str, collection_id: str, stix_objects: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """POST /{api_root}/collections/{id}/objects/ -- push STIX objects."""
        response = self._request(
            "POST",
            f"/{api_root.strip('/')}/collections/{collection_id}/objects/",
            json={"objects": stix_objects},
        )
        return response.json() if response else {}
