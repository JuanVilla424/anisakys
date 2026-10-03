"""
Google Safe Browsing API Integration
Checks URLs against Google's threat database (Lookup API v4, threatMatches:find).

Results follow the provider vocabulary in :mod:`src.intelligence.provider_common`:
a lookup is ``checked`` only when Google answered HTTP 200 with a parseable
body; every other outcome is an ``error`` (or ``no_data`` when unconfigured)
and never reads as safe. The API key travels in the ``X-Goog-Api-Key`` header,
so it never appears in a URL or in exception text that might be logged.
"""

import logging
import re
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import requests

from src.config import settings
from src.intelligence.provider_common import ERROR, LISTED, NO_DATA, NOT_LISTED
from src.utils.redaction import redact_secrets

logger = logging.getLogger(__name__)

# API Configuration
GOOGLE_SAFE_BROWSING_API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
GOOGLE_API_KEY = settings.GOOGLE_SAFE_BROWSING_API_KEY or ""
REQUEST_TIMEOUT_SECONDS = 10

# threatMatches:find accepts at most 500 threat entries per request.
MAX_URLS_PER_REQUEST = 500

# Upper bound of positive results kept in the in-memory cacheDuration cache.
MAX_CACHE_ENTRIES = 10_000

# Threat types to check
THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",  # Phishing
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
]

# Platform types. One URL listed for several platforms yields one match per
# platform; matches are de-duplicated by threat type before being counted.
PLATFORM_TYPES = [
    "ANY_PLATFORM",
    "WINDOWS",
    "LINUX",
    "OSX",
    "ANDROID",
    "IOS",
]

# Threat entry types
THREAT_ENTRY_TYPES = ["URL"]

_DURATION_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)s\s*$")


def _parse_duration(value: Any) -> Optional[float]:
    """Parse a protobuf JSON duration such as ``"300s"`` or ``"1.5s"``.

    Args:
        value: The ``cacheDuration`` value from a match.

    Returns:
        Seconds as a float, or ``None`` when absent/unparseable.
    """
    if not isinstance(value, str):
        return None
    match = _DURATION_RE.match(value)
    return float(match.group(1)) if match else None


def _utc_now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string without offset.

    Returns:
        Timestamp string (kept naive for backward compatibility).
    """
    return datetime.now(timezone.utc).replace(tzinfo=None).isoformat()


class GoogleSafeBrowsingIntegration:
    """Integration with Google Safe Browsing API v4."""

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize Google Safe Browsing integration.

        Args:
            api_key: Google API key with Safe Browsing API enabled. Defaults to
                ``GOOGLE_SAFE_BROWSING_API_KEY`` from settings.
        """
        self.api_key = api_key or GOOGLE_API_KEY
        self.api_url = GOOGLE_SAFE_BROWSING_API_URL
        self.enabled = bool(self.api_key)
        self._cache: Dict[str, Tuple[float, List[Dict[str, Any]]]] = {}
        self._cache_lock = threading.Lock()

        if not self.enabled:
            logger.warning("Google Safe Browsing API key not configured")

    # ------------------------------------------------------------------
    # Result helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _new_result(urls_checked: int) -> Dict[str, Any]:
        """Build an empty result that does not claim anything yet.

        Args:
            urls_checked: Number of URLs the result covers.

        Returns:
            Result dict with ``checked=False`` and ``safe=None``.
        """
        return {
            "checked": False,
            "status": ERROR,
            "safe": None,
            "threats_found": [],
            "threat_types": [],
            "threat_count": 0,
            "urls_checked": urls_checked,
            "timestamp": _utc_now_iso(),
            "error": None,
            "cached": False,
        }

    @staticmethod
    def _dedupe_matches(url: str, matches: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Collapse the per-platform matches of one URL into one per threat type.

        Args:
            url: The URL the matches belong to.
            matches: Raw ``matches`` entries for that URL.

        Returns:
            One threat dict per distinct ``threatType``, in first-seen order.
        """
        by_type: Dict[str, Dict[str, Any]] = {}
        for match in matches:
            threat_type = match.get("threatType") or "THREAT_TYPE_UNSPECIFIED"
            platform = match.get("platformType")
            entry = by_type.get(threat_type)
            if entry is None:
                entry = {
                    "url": url,
                    "threat_type": threat_type,
                    "platform_type": platform,
                    "platform_types": [],
                    "cache_duration": match.get("cacheDuration"),
                }
                by_type[threat_type] = entry
            if platform and platform not in entry["platform_types"]:
                entry["platform_types"].append(platform)
            # Keep the shortest cache duration so the cache never outlives a match.
            current = _parse_duration(entry.get("cache_duration"))
            candidate = _parse_duration(match.get("cacheDuration"))
            if candidate is not None and (current is None or candidate < current):
                entry["cache_duration"] = match.get("cacheDuration")
        return list(by_type.values())

    def _listed_result(self, threats: List[Dict[str, Any]], cached: bool = False) -> Dict[str, Any]:
        """Build the result for a URL that Google lists.

        Args:
            threats: De-duplicated threats for the URL.
            cached: Whether the threats come from the local cache.

        Returns:
            A ``listed`` result.
        """
        result = self._new_result(1)
        result.update(
            {
                "checked": True,
                "status": LISTED,
                "safe": False,
                "threats_found": threats,
                "threat_types": [t["threat_type"] for t in threats],
                "threat_count": len(threats),
                "cached": cached,
            }
        )
        return result

    def _not_listed_result(self) -> Dict[str, Any]:
        """Build the result for a URL that Google answered for and does not list.

        Returns:
            A ``not_listed`` result.
        """
        result = self._new_result(1)
        result.update({"checked": True, "status": NOT_LISTED, "safe": True})
        return result

    # ------------------------------------------------------------------
    # cacheDuration cache (positive results only)
    # ------------------------------------------------------------------

    def _cache_get(self, url: str) -> Optional[List[Dict[str, Any]]]:
        """Return cached threats for ``url`` if still within ``cacheDuration``.

        Args:
            url: URL to look up.

        Returns:
            Cached threats, or ``None`` on a miss/expiry.
        """
        now = time.monotonic()
        with self._cache_lock:
            entry = self._cache.get(url)
            if entry is None:
                return None
            expires_at, threats = entry
            if expires_at <= now:
                del self._cache[url]
                return None
            return [dict(t) for t in threats]

    def _cache_put(self, url: str, threats: List[Dict[str, Any]]) -> None:
        """Cache a positive result for the shortest ``cacheDuration`` it carries.

        Args:
            url: URL the threats belong to.
            threats: De-duplicated threats (each may carry ``cache_duration``).
        """
        durations = [_parse_duration(t.get("cache_duration")) for t in threats]
        valid = [d for d in durations if d is not None and d > 0]
        if not valid:
            return
        now = time.monotonic()
        with self._cache_lock:
            if len(self._cache) >= MAX_CACHE_ENTRIES:
                for key in [k for k, (exp, _) in self._cache.items() if exp <= now]:
                    del self._cache[key]
                while len(self._cache) >= MAX_CACHE_ENTRIES:
                    del self._cache[next(iter(self._cache))]
            self._cache[url] = (now + min(valid), [dict(t) for t in threats])

    # ------------------------------------------------------------------
    # HTTP
    # ------------------------------------------------------------------

    def _query(self, urls: List[str]) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        """Send one threatMatches:find request.

        Args:
            urls: Up to :data:`MAX_URLS_PER_REQUEST` URLs.

        Returns:
            ``(body, None)`` on HTTP 200 with a JSON object body, otherwise
            ``(None, error_message)``. Error messages are redacted.
        """
        payload = {
            "client": {
                "clientId": "anisakys-phishing-detector",
                "clientVersion": "1.0.0",
            },
            "threatInfo": {
                "threatTypes": THREAT_TYPES,
                "platformTypes": PLATFORM_TYPES,
                "threatEntryTypes": THREAT_ENTRY_TYPES,
                "threatEntries": [{"url": url} for url in urls],
            },
        }
        try:
            response = requests.post(
                self.api_url,
                json=payload,
                headers={"Content-Type": "application/json", "X-Goog-Api-Key": self.api_key},
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
        except requests.exceptions.Timeout:
            logger.error("Google Safe Browsing API timeout")
            return None, "Request timeout"
        except requests.exceptions.RequestException as e:
            message = redact_secrets(e)
            logger.error(f"Google Safe Browsing API request failed: {message}")
            return None, f"Request failed: {message}"

        if response.status_code != 200:
            if response.status_code == 400:
                error = "Invalid request"
            elif response.status_code == 403:
                error = "API key invalid or quota exceeded"
            elif response.status_code == 429:
                error = "Rate limited"
            else:
                error = f"API error: {response.status_code}"
            body = redact_secrets(getattr(response, "text", "") or "")[:200]
            logger.error(
                f"Google Safe Browsing API error: HTTP {response.status_code} ({error}) {body}"
            )
            return None, error

        try:
            data = response.json()
        except ValueError:
            logger.error("Google Safe Browsing API returned an unparseable body")
            return None, "Unparseable response body"
        if not isinstance(data, dict):
            logger.error("Google Safe Browsing API returned an unexpected body shape")
            return None, "Unexpected response body"
        matches = data.get("matches", [])
        if not isinstance(matches, list):
            logger.error("Google Safe Browsing API returned a malformed 'matches' field")
            return None, "Malformed matches field"
        return data, None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def lookup_urls(self, urls: List[str]) -> Dict[str, Dict[str, Any]]:
        """Check URLs in batches and return one result per URL.

        Positive results are served from an in-memory cache while their
        ``cacheDuration`` lasts; everything else is sent in requests of up to
        :data:`MAX_URLS_PER_REQUEST` URLs.

        Args:
            urls: URLs to check (duplicates are checked once).

        Returns:
            Mapping of each input URL to its result dict (see :meth:`check_url`).
        """
        unique = list(dict.fromkeys(u for u in urls if u))
        results: Dict[str, Dict[str, Any]] = {}

        if not self.enabled:
            for url in unique:
                result = self._new_result(1)
                result.update({"status": NO_DATA, "error": "API key not configured"})
                results[url] = result
            return results

        pending: List[str] = []
        for url in unique:
            cached = self._cache_get(url)
            if cached is not None:
                results[url] = self._listed_result(cached, cached=True)
            else:
                pending.append(url)

        for start in range(0, len(pending), MAX_URLS_PER_REQUEST):
            chunk = pending[start : start + MAX_URLS_PER_REQUEST]
            data, error = self._query(chunk)
            if data is None:
                for url in chunk:
                    result = self._new_result(1)
                    result["error"] = error
                    results[url] = result
                continue

            matches_by_url: Dict[str, List[Dict[str, Any]]] = {}
            chunk_set = set(chunk)
            for match in data.get("matches", []):
                if not isinstance(match, dict):
                    continue
                matched_url = (match.get("threat") or {}).get("url")
                if matched_url not in chunk_set and len(chunk) == 1:
                    matched_url = chunk[0]
                if matched_url in chunk_set:
                    matches_by_url.setdefault(matched_url, []).append(match)
                else:
                    logger.debug("Google Safe Browsing match for an URL that was not requested")

            for url in chunk:
                raw = matches_by_url.get(url)
                if raw:
                    threats = self._dedupe_matches(url, raw)
                    self._cache_put(url, threats)
                    results[url] = self._listed_result(threats)
                    logger.warning(
                        f"🚨 Google Safe Browsing threat detected: {url} - "
                        f"{', '.join(t['threat_type'] for t in threats)}"
                    )
                else:
                    results[url] = self._not_listed_result()
        return results

    def check_url(self, url: str) -> Dict[str, Any]:
        """
        Check a single URL against Google Safe Browsing.

        Args:
            url: URL to check.

        Returns:
            Dict with ``checked`` (True only for an HTTP 200 parseable answer),
            ``status`` (listed/not_listed/error/no_data), ``safe`` (``None``
            unless checked), ``threats_found`` (one entry per threat type),
            ``threat_count``, ``threat_types``, ``error`` and ``timestamp``.
        """
        return self.check_urls([url])

    def check_urls(self, urls: List[str]) -> Dict[str, Any]:
        """
        Check multiple URLs and aggregate the outcome into one result.

        Args:
            urls: List of URLs to check.

        Returns:
            Aggregate result: ``checked`` only if every URL was checked;
            ``status`` is ``listed`` if any URL is listed, else ``error`` if
            any lookup failed, else ``not_listed``.
        """
        result = self._new_result(len(urls))
        if not self.enabled:
            result.update({"status": NO_DATA, "error": "API key not configured"})
            return result
        if not urls:
            result["error"] = "No URLs provided"
            return result

        per_url = self.lookup_urls(urls)
        values = list(per_url.values())
        errors = [r for r in values if not r.get("checked")]
        threats = [t for r in values for t in r.get("threats_found", [])]

        result["checked"] = not errors
        result["cached"] = bool(values) and all(r.get("cached") for r in values)
        result["threats_found"] = threats
        result["threat_types"] = list(dict.fromkeys(t["threat_type"] for t in threats))
        result["threat_count"] = len(threats)
        if threats:
            result["status"] = LISTED
            result["safe"] = False
        elif errors:
            result["status"] = ERROR
            result["safe"] = None
        else:
            result["status"] = NOT_LISTED
            result["safe"] = True
        if errors:
            result["error"] = errors[0].get("error")
        return result

    def get_threat_level(self, threat_type: str) -> str:
        """
        Convert Google threat type to internal threat level.

        Args:
            threat_type: Google's threat type string.

        Returns:
            Internal threat level (critical, high, medium, low).
        """
        threat_mapping = {
            "MALWARE": "critical",
            "SOCIAL_ENGINEERING": "high",  # Phishing
            "UNWANTED_SOFTWARE": "medium",
            "POTENTIALLY_HARMFUL_APPLICATION": "medium",
        }
        return threat_mapping.get(threat_type, "medium")

    def is_available(self) -> bool:
        """Check if the API is available and configured."""
        return self.enabled

    def test_connection(self) -> Dict[str, Any]:
        """Test API connectivity.

        Returns:
            Dict with ``success`` and a human-readable ``message``.
        """
        result: Dict[str, Any] = {
            "success": False,
            "message": "",
        }

        if not self.enabled:
            result["message"] = "API key not configured"
            return result

        test_result = self.check_url("https://www.google.com/")
        if test_result.get("checked"):
            result["success"] = True
            result["message"] = "API connection successful"
        else:
            result["message"] = test_result.get("error") or "Unknown error"

        return result


# Singleton instance
google_safe_browsing = GoogleSafeBrowsingIntegration()
