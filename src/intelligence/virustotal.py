"""
VirusTotal integration for Anisakys Phishing Detection Engine.

VirusTotal API v3 integration (URL, domain and file-hash reports).

Every call has an explicit timeout, goes through the circuit breaker and draws
from a process-wide token bucket sized by ``VIRUSTOTAL_REQUESTS_PER_MINUTE``
(4/min on the public API). Results carry a ``status`` from
:mod:`src.intelligence.provider_common`: a pending, empty (0 engines) or
stale (``last_analysis_date`` older than :data:`STALE_AFTER_DAYS`) analysis
without detections is ``no_data``, never ``clean``.
"""

import base64
import logging
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

import requests

from src.circuit_breaker import CircuitBreaker, CircuitBreakerConfig, CircuitBreakerOpenError
from src.config import settings
from src.intelligence.provider_common import ERROR, LISTED, NO_DATA, NOT_LISTED, TokenBucket
from src.logger import logger
from src.observability.structured_logger import log_api_call, log_with_context
from src.utils.redaction import redact_secrets

# API Configuration
VIRUSTOTAL_API_KEY = getattr(settings, "VIRUSTOTAL_API_KEY", None)

# An analysis older than this is not trusted as a "clean" verdict.
STALE_AFTER_DAYS = 7

# Seconds a call may wait for a rate-limit token before giving up.
RATE_LIMIT_MAX_WAIT_SECONDS = 60.0

_rate_limiter: Optional[TokenBucket] = None
_rate_limiter_lock = threading.Lock()


def get_rate_limiter() -> TokenBucket:
    """Return the process-wide VirusTotal token bucket, creating it on first use.

    Returns:
        The shared :class:`TokenBucket`.
    """
    global _rate_limiter
    with _rate_limiter_lock:
        if _rate_limiter is None:
            rate = int(getattr(settings, "VIRUSTOTAL_REQUESTS_PER_MINUTE", 4) or 4)
            _rate_limiter = TokenBucket(rate_per_minute=rate)
        return _rate_limiter


class RateLimitedError(Exception):
    """Raised when no VirusTotal request token became available in time."""


class VirusTotalIntegration:
    """
    VirusTotal API v3 Integration for comprehensive threat detection.

    Provides multi-engine scanning using 70+ antivirus engines and URL scanners
    for comprehensive threat detection with real-time reputation analysis.
    """

    def __init__(self, api_key: Optional[str] = None, rate_limiter: Optional[TokenBucket] = None):
        """
        Initialize VirusTotal integration.

        Args:
            api_key: VirusTotal API key. If None, uses the configured setting.
            rate_limiter: Token bucket to draw from; defaults to the shared one.
        """
        self.api_key = api_key or VIRUSTOTAL_API_KEY
        self.base_url = "https://www.virustotal.com/api/v3"
        self.session = requests.Session()
        self.session.headers.update(
            {
                "x-apikey": self.api_key or "",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                "Accept": "application/json",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate, br",
                "DNT": "1",
                "Connection": "keep-alive",
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "cross-site",
                "Origin": "https://www.virustotal.com",
                "Referer": "https://www.virustotal.com/",
            }
        )
        self._rate_limiter = rate_limiter

        # Initialize circuit breaker for API resilience (EPIC-004)
        cb_config = CircuitBreakerConfig(
            failure_threshold=5,  # Higher threshold for VirusTotal (public API)
            recovery_timeout=120,  # Wait 2 minutes before retry (rate limits)
            success_threshold=2,
            timeout=15.0,
            # One attempt per call: every request spends a token of the shared
            # per-minute quota, so a blind retry would bypass the rate limit.
            max_retries=1,
            retry_backoff_base=3.0,
        )
        self.circuit_breaker = CircuitBreaker("VirusTotal", cb_config, logger)
        self.timeout = cb_config.timeout

    # ------------------------------------------------------------------
    # Transport
    # ------------------------------------------------------------------

    def _request(
        self, method: str, path: str, *, data: Optional[Dict[str, str]] = None
    ) -> Tuple[requests.Response, int]:
        """Send one rate-limited, time-bounded request through the breaker.

        Args:
            method: ``"GET"`` or ``"POST"``.
            path: Path below the API base URL (starting with ``/``).
            data: Form fields for POST requests.

        Returns:
            ``(response, response_time_ms)``.

        Raises:
            RateLimitedError: If no request token was available in time.
            CircuitBreakerOpenError: If the breaker rejects the call.
            requests.RequestException: On transport errors.
        """
        limiter = self._rate_limiter or get_rate_limiter()
        # Taken outside the breaker: waiting for local quota is not an upstream
        # failure and must not count towards opening the circuit.
        if not limiter.acquire(RATE_LIMIT_MAX_WAIT_SECONDS):
            raise RateLimitedError("VirusTotal local rate limit: no request token available")

        def _send() -> Tuple[requests.Response, int]:
            start_time = time.time()
            if method == "POST":
                response = self.session.post(
                    f"{self.base_url}{path}", data=data, timeout=self.timeout
                )
            else:
                response = self.session.get(f"{self.base_url}{path}", timeout=self.timeout)
            return response, int((time.time() - start_time) * 1000)

        # Submissions are not idempotent (each one queues an analysis and uses
        # quota): never retry them.
        return self.circuit_breaker.call(_send, idempotent=method != "POST")

    @staticmethod
    def _error(message: str, **extra: Any) -> Dict[str, Any]:
        """Build an ``error`` result.

        Args:
            message: Human-readable, already redacted error.
            **extra: Additional fields.

        Returns:
            Result dict with ``status="error"`` and ``threat_level="unknown"``.
        """
        return {"status": ERROR, "error": message, "threat_level": "unknown", **extra}

    # ------------------------------------------------------------------
    # Verdict evaluation
    # ------------------------------------------------------------------

    @staticmethod
    def _is_stale(last_analysis_date: Any, now: Optional[datetime] = None) -> bool:
        """Tell whether an analysis is too old to vouch for a clean verdict.

        Args:
            last_analysis_date: Epoch seconds from VirusTotal (may be missing).
            now: Reference time (UTC); defaults to the current time.

        Returns:
            ``True`` if missing/unparseable or older than :data:`STALE_AFTER_DAYS`.
        """
        if not isinstance(last_analysis_date, (int, float)):
            return True
        now = now or datetime.now(timezone.utc)
        analysed = datetime.fromtimestamp(last_analysis_date, tz=timezone.utc)
        return (now - analysed).days >= STALE_AFTER_DAYS

    @classmethod
    def _evaluate(cls, stats: Dict[str, int], last_analysis_date: Any) -> Dict[str, Any]:
        """Turn analysis statistics into a provider status and threat level.

        Args:
            stats: ``last_analysis_stats`` from VirusTotal.
            last_analysis_date: ``last_analysis_date`` (epoch seconds).

        Returns:
            Dict with ``status``, ``threat_level``, ``stale`` and ``total_engines``.
        """
        total = sum(v for v in (stats or {}).values() if isinstance(v, (int, float)))
        stale = cls._is_stale(last_analysis_date)
        if total == 0:
            return {
                "status": NO_DATA,
                "threat_level": "unknown",
                "stale": stale,
                "total_engines": 0,
            }
        threat_level = cls._calculate_threat_level(stats)
        if threat_level not in ("clean", "unknown"):
            # Detections remain evidence even when old; the flag tells consumers.
            return {
                "status": LISTED,
                "threat_level": threat_level,
                "stale": stale,
                "total_engines": total,
            }
        if stale:
            return {
                "status": NO_DATA,
                "threat_level": "unknown",
                "stale": True,
                "total_engines": total,
            }
        return {
            "status": NOT_LISTED,
            "threat_level": "clean",
            "stale": False,
            "total_engines": total,
        }

    @staticmethod
    def _calculate_threat_level(analysis_stats: Dict[str, int]) -> str:
        """
        Calculate threat level based on detection statistics.

        Args:
            analysis_stats (Dict[str, int]): Analysis statistics from VirusTotal

        Returns:
            str: Threat level (high, medium, low, clean, unknown)
        """
        if not analysis_stats:
            return "unknown"

        malicious = analysis_stats.get("malicious", 0)
        suspicious = analysis_stats.get("suspicious", 0)
        total = sum(analysis_stats.values())

        if total == 0:
            return "unknown"

        malicious_ratio = malicious / total
        suspicious_ratio = suspicious / total

        if malicious_ratio >= 0.1:  # 10% or more engines detect as malicious
            return "high"
        elif malicious_ratio >= 0.05 or suspicious_ratio >= 0.2:  # 5% malicious or 20% suspicious
            return "medium"
        elif malicious_ratio > 0 or suspicious_ratio > 0:
            return "low"
        else:
            return "clean"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan_url(self, url: str) -> Dict[str, Any]:
        """
        Get the VirusTotal URL report, submitting the URL when it is unknown.

        Args:
            url (str): URL to scan

        Returns:
            Dict[str, Any]: Report with ``status`` (listed/not_listed/no_data/
            error), detection counts, ``threat_level`` and ``stale``. A newly
            submitted URL yields ``status="no_data"`` with ``submitted=True``.
        """
        if not self.api_key:
            logger.warning("⚠️  VirusTotal API key not configured, skipping scan")
            return {"status": NO_DATA, "error": "API key not configured", "threat_level": "unknown"}

        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        try:
            response, response_time_ms = self._request("GET", f"/urls/{url_id}")
            log_api_call(
                logger,
                api_name="VirusTotal",
                url=f"{self.base_url}/urls/{url_id}",
                status_code=response.status_code,
                response_time_ms=response_time_ms,
                target_url=url,
            )

            if response.status_code == 200:
                data = response.json()
                analysis = data.get("data", {}).get("attributes", {})
                last_analysis = analysis.get("last_analysis_stats", {}) or {}
                verdict = self._evaluate(last_analysis, analysis.get("last_analysis_date"))

                result = {
                    "url": url,
                    "status": verdict["status"],
                    "stale": verdict["stale"],
                    "scan_date": analysis.get("last_analysis_date"),
                    "reputation": analysis.get("reputation", 0),
                    "malicious": last_analysis.get("malicious", 0),
                    "suspicious": last_analysis.get("suspicious", 0),
                    "harmless": last_analysis.get("harmless", 0),
                    "undetected": last_analysis.get("undetected", 0),
                    "total_engines": verdict["total_engines"],
                    "threat_level": verdict["threat_level"],
                    "community_score": analysis.get("total_votes", {}).get("harmless", 0)
                    - analysis.get("total_votes", {}).get("malicious", 0),
                    "categories": analysis.get("categories", {}),
                    "engines_detail": analysis.get("last_analysis_results", {}),
                }

                logger.info(
                    f"🛡️  VirusTotal scan for {url}: {result['malicious']}/"
                    f"{result['total_engines']} engines detected threats "
                    f"(status={result['status']}, stale={result['stale']})"
                )
                return result

            if response.status_code == 404:
                # URL isn't known yet: queue an analysis. No verdict until it runs.
                scan_response, _ = self._request("POST", "/urls", data={"url": url})
                if scan_response.status_code == 200:
                    logger.info(f"📤 Submitted {url} to VirusTotal for analysis")
                    return {
                        "url": url,
                        "status": NO_DATA,
                        "submitted": True,
                        "threat_level": "unknown",
                        "total_engines": 0,
                        "message": "URL submitted for analysis, check back later",
                    }
                logger.error(
                    f"❌ Failed to submit {url} to VirusTotal: {scan_response.status_code}"
                )
                return self._error(f"Failed to submit URL: {scan_response.status_code}")

            log_with_context(
                logger,
                logging.ERROR,
                "VirusTotal API error",
                status_code=response.status_code,
                url=url,
                event_type="virustotal_api_error",
            )
            return self._error(f"API error: {response.status_code}")

        except CircuitBreakerOpenError as e:
            log_with_context(
                logger,
                logging.ERROR,
                "VirusTotal API circuit breaker OPEN - service unavailable",
                url=url,
                circuit_state="OPEN",
                event_type="virustotal_circuit_open",
            )
            return self._error(
                "VirusTotal API temporarily unavailable", reason="circuit_open", details=str(e)
            )
        except RateLimitedError as e:
            logger.warning(f"⏳ {e}")
            return self._error(str(e), reason="rate_limited")
        except (requests.RequestException, ValueError) as e:
            message = redact_secrets(e)
            logger.error(f"❌ VirusTotal URL lookup failed for {url}: {message}")
            return self._error(message)

    def get_domain_report(self, domain: str) -> Dict[str, Any]:
        """
        Get a domain reputation and analysis report.

        Args:
            domain (str): Domain to analyze

        Returns:
            Dict[str, Any]: Domain report with ``status`` and registrar data,
            or an ``error``/``no_data`` result.
        """
        if not self.api_key:
            return {"status": NO_DATA, "error": "API key not configured"}

        try:
            response, _ = self._request("GET", f"/domains/{domain}")
        except CircuitBreakerOpenError:
            return self._error("VirusTotal API temporarily unavailable", reason="circuit_open")
        except RateLimitedError as e:
            return self._error(str(e), reason="rate_limited")
        except requests.RequestException as e:
            message = redact_secrets(e)
            logger.error(f"❌ VirusTotal domain analysis failed for {domain}: {message}")
            return self._error(message)

        if response.status_code == 404:
            return {"domain": domain, "status": NO_DATA, "threat_level": "unknown"}
        if response.status_code != 200:
            return self._error(f"Domain analysis failed: {response.status_code}")

        try:
            data = response.json()
        except ValueError:
            return self._error("Unparseable VirusTotal response")
        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {}) or {}
        verdict = self._evaluate(stats, attributes.get("last_analysis_date"))

        return {
            "domain": domain,
            "status": verdict["status"],
            "stale": verdict["stale"],
            "threat_level": verdict["threat_level"],
            "reputation": attributes.get("reputation", 0),
            "categories": attributes.get("categories", {}),
            "last_analysis_stats": stats,
            "registrar": attributes.get("registrar"),
            "creation_date": attributes.get("creation_date"),
            "last_update_date": attributes.get("last_update_date"),
        }

    def lookup_file_hash(self, file_hash: str) -> Dict[str, Any]:
        """
        Look up a file by its SHA-256 hash in VirusTotal.

        Does NOT upload the file — only queries the existing database by hash.
        Use this for email attachment triage without storing attachment data.

        Args:
            file_hash: SHA-256 hex digest of the file.

        Returns:
            Dict with keys: found, status, malicious, suspicious, harmless,
            undetected, total_engines, threat_level, stale, file_type, file_name.
        """
        if not self.api_key:
            return {"found": False, "status": NO_DATA, "error": "API key not configured"}

        short_hash = f"{file_hash[:16]}…"
        try:
            response, _ = self._request("GET", f"/files/{file_hash}")
        except CircuitBreakerOpenError:
            return {"found": False, **self._error("VirusTotal API temporarily unavailable")}
        except RateLimitedError as e:
            return {"found": False, **self._error(str(e), reason="rate_limited")}
        except requests.RequestException as e:
            message = redact_secrets(e)
            logger.error(f"❌ VirusTotal file hash lookup failed for {short_hash}: {message}")
            return {"found": False, **self._error(message)}

        if response.status_code == 404:
            return {"found": False, "status": NO_DATA, "threat_level": "unknown"}
        if response.status_code != 200:
            return {"found": False, **self._error(f"Unexpected status: {response.status_code}")}

        try:
            data = response.json()
        except ValueError:
            return {"found": False, **self._error("Unparseable VirusTotal response")}
        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {}) or {}
        verdict = self._evaluate(stats, attributes.get("last_analysis_date"))
        return {
            "found": True,
            "status": verdict["status"],
            "stale": verdict["stale"],
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "total_engines": verdict["total_engines"],
            "threat_level": verdict["threat_level"],
            "file_type": attributes.get("type_description"),
            "file_name": (attributes.get("names") or [None])[0],
        }
