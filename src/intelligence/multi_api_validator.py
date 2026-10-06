"""
Multi-API Validator for Anisakys Phishing Detection Engine.

Aggregates results from multiple threat intelligence APIs
(VirusTotal, URLVoid, PhishTank) for comprehensive threat assessment.
"""

import datetime
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Dict, List, Mapping, Optional
from urllib.parse import urlparse

from src.config import settings
from src.logger import logger
from src.observability.structured_logger import log_with_context
from src.observability.metrics import (
    increment_counter,
    observe_histogram,
    METRIC_SCANS_TOTAL,
    METRIC_SCAN_DURATION_SECONDS,
    METRIC_DETECTIONS_TOTAL,
)
from src.capture.service import PageCapture, capture_hashes, fetch_page
from src.detection.features import page_features, page_text
from src.detection.llm_judge import LLMJudge, configured_judge
from src.detection.normalize import normalize_host
from src.detection.visual_brand import identify_brands
from src.intelligence.provider_runtime import cached_call

# Import integrations
from src.intelligence.virustotal import VirusTotalIntegration, VIRUSTOTAL_API_KEY
from src.intelligence.urlvoid import URLVoidIntegration, URLVOID_API_KEY, URLVOID_ENABLED
from src.intelligence.phishtank import PhishTankIntegration, PHISHTANK_API_KEY
from src.intelligence.google_safe_browsing import GoogleSafeBrowsingIntegration
from src.intelligence.provider_common import (
    ERROR,
    LISTED,
    NO_DATA,
    NOT_LISTED,
    PROVIDER_STATUSES,
)
from src.detection.url_analyzer import URLAnalyzer
from src.detection.kit_fingerprint import score_kit_indicators

# Auto-Analysis Configuration
AUTO_MULTI_API_SCAN = getattr(settings, "AUTO_MULTI_API_SCAN", False)
AUTO_REPORT_THRESHOLD_CONFIDENCE = getattr(settings, "AUTO_REPORT_THRESHOLD_CONFIDENCE", 80)
MANUAL_REVIEW_THRESHOLD_CONFIDENCE = getattr(settings, "MANUAL_REVIEW_THRESHOLD_CONFIDENCE", 50)

# Auto-analysis is only truly enabled if we have API keys AND the setting is enabled
# (a URLVoid key only counts while the unverified URLVoid client is enabled).
AUTO_ANALYSIS_ENABLED = AUTO_MULTI_API_SCAN and (
    VIRUSTOTAL_API_KEY or (URLVOID_ENABLED and URLVOID_API_KEY) or PHISHTANK_API_KEY
)


_THREAT_ORDER = ["clean", "low", "medium", "high", "critical"]


def _raise_floor(current: Optional[str], new: str) -> str:
    """Return the more severe of two minimum threat levels.

    Args:
        current: Current floor (``None`` when there is none).
        new: Candidate floor.

    Returns:
        The higher of the two levels.
    """
    if current is None or _THREAT_ORDER.index(new) > _THREAT_ORDER.index(current):
        return new
    return current


def provider_status(result: Optional[Mapping[str, Any]]) -> str:
    """Return the provider status of a VirusTotal/URLVoid/PhishTank result.

    Results produced by the current clients carry ``status``; older stored or
    hand-built results are classified from their legacy fields. Errors and
    missing data never come out as ``not_listed``.

    Args:
        result: Provider result dict (may be ``None``).

    Returns:
        One of ``listed``, ``not_listed``, ``error`` or ``no_data``.
    """
    if not result:
        return NO_DATA
    status = result.get("status")
    if status in PROVIDER_STATUSES:
        return str(status)
    if result.get("error"):
        return ERROR
    if result.get("is_phishing"):
        return LISTED
    threat_level = result.get("threat_level")
    if threat_level in ("critical", "high", "medium", "low"):
        return LISTED
    if threat_level == "clean":
        return NOT_LISTED
    if "is_phishing" in result:
        return NOT_LISTED
    return NO_DATA


def gsb_status(result: Optional[Mapping[str, Any]]) -> str:
    """Return the provider status of a Google Safe Browsing result.

    Only a checked lookup is an answer; ``safe`` is ignored unless
    ``checked`` is true, so an errored lookup can never read as clean.

    Args:
        result: Result from ``GoogleSafeBrowsingIntegration`` (may be ``None``).

    Returns:
        One of ``listed``, ``not_listed``, ``error`` or ``no_data``.
    """
    if not result:
        return NO_DATA
    status = result.get("status")
    if status in PROVIDER_STATUSES:
        if status in (LISTED, NOT_LISTED) and not result.get("checked"):
            return ERROR
        return str(status)
    # Legacy shape (stored before results carried a status): the old client
    # set checked=True even on HTTP errors, so an error message wins.
    if result.get("error"):
        return ERROR
    if not result.get("checked"):
        return NO_DATA
    return LISTED if result.get("safe") is False else NOT_LISTED


def _gsb_threat_types(result: Optional[Mapping[str, Any]]) -> List[str]:
    """List the threat types of a listed GSB result.

    Args:
        result: Google Safe Browsing result.

    Returns:
        Threat types, empty unless the result is ``listed``.
    """
    if gsb_status(result) != LISTED:
        return []
    assert result is not None
    return [t.get("threat_type", "UNKNOWN") for t in result.get("threats_found", []) or []]


def extract_domain(url: str) -> str:
    """Extract the host name of a URL for domain-level lookups.

    Uses ``urllib.parse`` so userinfo, port, path, query and fragment are
    dropped (``http://paypal.com@evil.com:8080/x`` -> ``evil.com``).

    Args:
        url: URL, with or without a scheme.

    Returns:
        Lower-case host name without a trailing dot, or ``""`` if none.
    """
    candidate = url.strip()
    if "://" not in candidate:
        candidate = f"http://{candidate}"
    try:
        host = urlparse(candidate).hostname
    except ValueError:
        host = None
    return (host or "").rstrip(".")


# Seconds the page capture may take (one request plus the favicon).
CAPTURE_TIMEOUT_SECONDS = 15
# A domain registered this long ago is "established" (see kit_brand_hint).
ESTABLISHED_DOMAIN_DAYS = 365
# Longest wait for the WHOIS budget: the domain age is the strongest heuristic signal,
# so a scan under load waits for it as long as for the page capture.
WHOIS_WAIT_SECONDS = 15.0


class _CapturedResponse:
    """The captured page seen through the two attributes the kit fingerprint reads."""

    def __init__(self, capture: PageCapture) -> None:
        self.headers = dict(capture.headers or {})
        self.text = capture.html or ""


def kit_brand_hint(url_analysis: Dict[str, Any], domain_age_days: Optional[int]) -> Optional[str]:
    """The brand the kit fingerprint should look for, if the domain impersonates one.

    The fingerprint's strongest check (the brand's real domain inside the page) proves a
    reverse proxy only on a domain that is not the brand's own. A domain registered for
    over :data:`ESTABLISHED_DOMAIN_DAYS` with the brand in its name is far more often the
    brand's own property (country sites, sister sites such as ``thinkwithgoogle.com``)
    than a reverse proxy, whose domains are fresh. So: a lookalike (typosquatting) always
    counts; the brand plus other words counts unless the domain is established; the
    brand's exact name under another suffix counts only when the domain is known to be
    young.

    Args:
        url_analysis: Lexical analysis of the URL.
        domain_age_days: Registration age from WHOIS (None when unknown).

    Returns:
        The brand slug, or None.
    """
    typo = url_analysis.get("typosquatting") or {}
    if typo.get("detected"):
        return typo.get("target_brand")
    known = domain_age_days is not None
    established = known and domain_age_days >= ESTABLISHED_DOMAIN_DAYS
    combo = url_analysis.get("combo_squatting") or {}
    if combo.get("detected") and not established:
        return combo.get("target_brand")
    swap = url_analysis.get("tld_swap") or {}
    if swap.get("detected") and known and not established:
        return swap.get("target_brand")
    return None


def capture_summary(capture: PageCapture) -> Dict[str, Any]:
    """JSON-safe summary of a page capture (no HTML, no image bytes).

    Args:
        capture: The capture.

    Returns:
        Status, final URL, HTTP status, TLS validity, server IP, redirect chain, favicon URL
        and elapsed milliseconds.
    """
    return {
        "status": capture.status,
        "error": capture.error,
        "final_url": capture.final_url,
        "http_status": capture.http_status,
        "tls_valid": capture.tls_valid,
        "server_ip": capture.server_ip,
        "redirect_chain": capture.redirect_chain,
        "favicon_url": capture.favicon_url,
        "elapsed_ms": capture.elapsed_ms,
    }


def _run_parallel(tasks: Dict[str, Callable[[], Any]], timings: Dict[str, float]) -> Dict[str, Any]:
    """Run the scan's network steps concurrently.

    Args:
        tasks: ``{stage: callable}``.
        timings: Filled with each stage's own wall-clock milliseconds.

    Returns:
        ``{stage: result}``; a step that raises returns an ``error`` result (the
        capture an ``error`` capture) instead of failing the scan.
    """

    def timed(stage: str, task: Callable[[], Any]) -> Any:
        started = time.perf_counter()
        try:
            return task()
        except Exception as e:  # each provider client already maps its own failures
            logger.warning(f"Scan step {stage} failed: {e}")
            if stage == "capture":
                return PageCapture(url="", status="error", error=type(e).__name__)
            if stage == "whois":
                return {}
            return {"status": ERROR, "error": type(e).__name__}
        finally:
            timings[stage] = round((time.perf_counter() - started) * 1000, 1)

    with ThreadPoolExecutor(max_workers=len(tasks), thread_name_prefix="scan") as pool:
        futures = {stage: pool.submit(timed, stage, task) for stage, task in tasks.items()}
        return {stage: future.result() for stage, future in futures.items()}


_shared_validator: Optional["MultiAPIValidator"] = None
_shared_lock = threading.Lock()


def get_shared_validator() -> "MultiAPIValidator":
    """The process-wide validator (one set of provider clients and circuit breakers).

    Returns:
        The shared :class:`MultiAPIValidator`.
    """
    global _shared_validator
    with _shared_lock:
        if _shared_validator is None:
            _shared_validator = MultiAPIValidator()
        return _shared_validator


class MultiAPIValidator:
    """
    Multi-API validation pipeline for comprehensive phishing detection.

    Orchestrates VirusTotal, URLVoid, and PhishTank APIs for enhanced
    threat detection with configurable validation thresholds.
    """

    def __init__(self, judge: Optional[LLMJudge] = None):
        """Initialize multi-API validator with all integrated services.

        Args:
            judge: LLM judge to consult on captured pages (default: the configured one,
                none unless ``LLM_JUDGE_ENABLED`` and an API key is set).
        """
        self.virustotal = VirusTotalIntegration()
        self.urlvoid = URLVoidIntegration()
        self.phishtank = PhishTankIntegration()
        self.google_safe_browsing = GoogleSafeBrowsingIntegration()
        self.url_analyzer = URLAnalyzer()
        self.judge = judge if judge is not None else configured_judge()

    def comprehensive_scan(self, url: str) -> Dict[str, Any]:
        """
        Perform comprehensive multi-API validation scan.

        Args:
            url (str): URL to validate

        Returns:
            Dict[str, Any]: Comprehensive validation report with aggregated results
        """
        logger.info(f"🔍 Starting comprehensive multi-API scan for {url}")
        increment_counter(METRIC_SCANS_TOTAL)
        _scan_start = time.time()

        # Extract domain for domain-specific checks
        domain = extract_domain(url)

        results = {
            "url": url,
            "domain": domain,
            "scan_timestamp": datetime.datetime.now().isoformat(),
            "virustotal": {},
            "urlvoid": {},
            "phishtank": {},
            "google_safe_browsing": {},
            "url_analysis": {},
            "aggregated_threat_level": "unknown",
            "confidence_score": 0,
            "recommendations": [],
        }

        # Wall-clock milliseconds of each step (the evaluation harness reports
        # latency per stage from these).
        stage_timings: Dict[str, float] = {}
        stage_started = time.perf_counter()

        def lap(stage: str) -> None:
            nonlocal stage_started
            finished = time.perf_counter()
            stage_timings[stage] = round((finished - stage_started) * 1000, 1)
            stage_started = finished

        # Step 0: URL Lexical Analysis (fast, no API calls)
        logger.info(f"📊 Step 0: URL lexical analysis for {url}")
        url_analysis = self.url_analyzer.analyze(url)
        results["url_analysis"] = url_analysis
        lap("url_analysis")
        if url_analysis.get("risk_score", 0) > 0:
            logger.warning(f"⚠️ URL analysis risk score: {url_analysis['risk_score']}")
            for factor in url_analysis.get("risk_factors", []):
                logger.warning(f"   - {factor}")

        # Steps 1-5: threat-intel providers, WHOIS and the page capture run in parallel,
        # through the process-wide cache and rate limits (src/intelligence/provider_runtime.py).
        logger.info(f"📊 Steps 1-5: providers, WHOIS and page capture for {url}")
        url_key = url.strip()
        domain_key = domain.lower()

        def no_host() -> Dict[str, Any]:
            return {"status": NO_DATA, "error": "No host name in URL"}

        def lookup(stage: str, key: str, configured: bool, fn: Callable[..., Any], arg: str):
            # A client without key (or disabled) answers "no data" at once: nothing to
            # cache and no request budget to wait for.
            return cached_call(stage, key, fn, arg)[0] if configured else fn(arg)

        vt_configured = bool(getattr(self.virustotal, "api_key", None))
        urlvoid_configured = bool(
            getattr(self.urlvoid, "enabled", False) and getattr(self.urlvoid, "api_key", None)
        )
        gsb_configured = bool(getattr(self.google_safe_browsing, "enabled", False))
        tasks: Dict[str, Callable[[], Any]] = {
            "virustotal_url": lambda: lookup(
                "virustotal_url", url_key, vt_configured, self.virustotal.scan_url, url
            ),
            "virustotal_domain": (
                (
                    lambda: lookup(
                        "virustotal_domain",
                        domain_key,
                        vt_configured,
                        self.virustotal.get_domain_report,
                        domain,
                    )
                )
                if domain
                else no_host
            ),
            "urlvoid": (
                (
                    lambda: lookup(
                        "urlvoid",
                        domain_key,
                        urlvoid_configured,
                        self.urlvoid.analyze_domain,
                        domain,
                    )
                )
                if domain
                else no_host
            ),
            # PhishTank answers lookups without an app key too (with a stricter limit).
            "phishtank": lambda: lookup(
                "phishtank", url_key, True, self.phishtank.check_phishing_status, url
            ),
            "whois": (
                (
                    lambda: cached_call(
                        "whois",
                        domain_key,
                        self._whois_lookup,
                        domain,
                        wait_seconds=WHOIS_WAIT_SECONDS,
                    )[0]
                )
                if domain
                else dict
            ),
            "google_safe_browsing": lambda: lookup(
                "google_safe_browsing",
                url_key,
                gsb_configured,
                self.google_safe_browsing.check_url,
                url,
            ),
            "capture": lambda: fetch_page(url, timeout=CAPTURE_TIMEOUT_SECONDS),
        }
        outputs = _run_parallel(tasks, stage_timings)

        # Cached answers are shared between scans: copy before annotating them.
        vt_result: Dict[str, Any] = dict(outputs["virustotal_url"] or {})
        vt_domain: Dict[str, Any] = dict(outputs["virustotal_domain"] or {})
        uv_result: Dict[str, Any] = dict(outputs["urlvoid"] or {})
        pt_result: Dict[str, Any] = dict(outputs["phishtank"] or {})
        gsb_result: Dict[str, Any] = dict(outputs["google_safe_browsing"] or {})
        # A lookup refused by the rate limit (or failed) is no WHOIS data, not an answer.
        whois_raw: Dict[str, Any] = dict(outputs["whois"] or {})
        whois_info: Dict[str, Any] = (
            {} if whois_raw.get("rate_limited") or whois_raw.get("error") else whois_raw
        )
        capture: PageCapture = outputs["capture"]
        if not vt_domain.get("error"):
            vt_result["registrar"] = vt_domain.get("registrar")
            vt_result["creation_date"] = vt_domain.get("creation_date")
        if not uv_result.get("error"):
            uv_result["registrar_name"] = (
                vt_domain.get("registrar") if not vt_domain.get("error") else None
            )
        results["virustotal"] = vt_result
        results["urlvoid"] = uv_result
        results["phishtank"] = pt_result
        results["whois"] = whois_info
        results["google_safe_browsing"] = gsb_result
        domain_age = whois_info.get("domain_age_days")
        if gsb_status(gsb_result) == LISTED:
            logger.warning(
                f"🚨 Google Safe Browsing threats found: {gsb_result.get('threat_count', 0)}"
            )

        # Step 5.5: AiTM/Evilginx kit fingerprint on the captured page (no second fetch).
        kit_started = time.perf_counter()
        kit_result: Dict[str, Any] = {}
        brand_hint = kit_brand_hint(url_analysis, domain_age)
        if capture.ok:
            try:
                kit_result = score_kit_indicators(
                    url, _CapturedResponse(capture), brand_hint=brand_hint
                )
            except Exception as e:  # attacker-controlled content: never fail the scan
                logger.debug(f"Kit fingerprinting failed for {url}: {e}")
        if kit_result.get("kit_type"):
            logger.warning(
                f"🚨 Kit fingerprint: {kit_result['kit_type']} "
                f"(confidence={kit_result['confidence']}) for {url}"
            )
        results["kit_fingerprint"] = kit_result
        results["detected_kit_type"] = kit_result.get("kit_type")
        results["kit_confidence"] = kit_result.get("confidence")
        results["kit_indicators"] = kit_result.get("indicators")
        stage_timings["kit_fingerprint"] = round((time.perf_counter() - kit_started) * 1000, 1)

        # Step 5.6: content features and reference-based brand identification.
        content_started = time.perf_counter()
        catalog = self.url_analyzer.catalog()
        hashes = capture_hashes(capture) if capture.ok else {}
        features = page_features(capture, catalog)
        visual = identify_brands(
            hashes, features, normalize_host(capture.final_url or url), catalog
        )
        results["capture"] = capture_summary(capture)
        results["capture_hashes"] = hashes
        results["page_features"] = features
        results["visual_brand"] = visual
        stage_timings["content_features"] = round((time.perf_counter() - content_started) * 1000, 1)

        # Step 5.7: optional LLM judge on the captured page. Evidence only: the verdict
        # below does not use it (combining it is the calibrated fusion's job).
        judge_status: Optional[str] = None
        if self.judge is not None:
            judge_started = time.perf_counter()
            if capture.ok:
                title, visible = page_text(capture.html)
                judgement = self.judge.judge(
                    url, capture.final_url, title, visible, capture.screenshot
                ).to_dict()
                decision = (judgement.get("verdict") or {}).get("is_phishing")
                judge_status = (
                    (LISTED if decision else NOT_LISTED)
                    if judgement["status"] == "ok" and decision is not None
                    else (ERROR if judgement["status"] == "error" else NO_DATA)
                )
            else:
                judgement = {"status": "no_capture", "verdict": {}, "cost_usd": 0.0}
                judge_status = NO_DATA
            results["llm_judge"] = judgement
            stage_timings["llm_judge"] = round((time.perf_counter() - judge_started) * 1000, 1)

        results["stage_timings_ms"] = stage_timings
        # Whether each external source answered (listed / not_listed) or not
        # (error / no_data): the evaluation harness counts provider calls and
        # coverage from this.
        results["stage_status"] = {
            "virustotal_url": provider_status(vt_result),
            "virustotal_domain": provider_status(vt_domain),
            "urlvoid": provider_status(uv_result),
            "phishtank": provider_status(pt_result),
            "google_safe_browsing": gsb_status(gsb_result),
            "whois": NOT_LISTED if whois_info else NO_DATA,
            "capture": (
                NOT_LISTED if capture.ok else (NO_DATA if capture.status == "blocked" else ERROR)
            ),
            "kit_fingerprint": (
                LISTED if kit_result.get("kit_type") else (NOT_LISTED if capture.ok else NO_DATA)
            ),
        }
        if judge_status is not None:
            results["stage_status"]["llm_judge"] = judge_status

        # Step 6: Aggregate results and calculate threat level
        results["aggregated_threat_level"] = self._aggregate_threat_level(
            vt_result, uv_result, pt_result, domain_age, url_analysis, gsb_result, kit_result
        )
        results["confidence_score"] = self._calculate_confidence_score(
            vt_result, uv_result, pt_result, domain_age, url_analysis, gsb_result, kit_result
        )

        # If no external source produced evidence (every threat-intel lookup
        # errored or had no data, GSB was not checked and no kit was found),
        # heuristics alone (domain age, lexical score) must not claim a
        # verdict: report unknown, zero trust.
        if not self._has_external_evidence(vt_result, uv_result, pt_result, gsb_result, kit_result):
            results["aggregated_threat_level"] = "unknown"
            results["confidence_score"] = 0

        results["recommendations"] = self._generate_recommendations(
            vt_result, uv_result, pt_result, domain_age, url_analysis, gsb_result, kit_result
        )

        # Add registration info to top-level results for frontend (from WHOIS)
        results["registration_date"] = whois_info.get("creation_date")
        results["registrar_name"] = whois_info.get("registrar")
        results["domain_age_days"] = whois_info.get("domain_age_days")
        results["registrant_org"] = whois_info.get("registrant_org")

        # Lookup registrar abuse form URL (for providers that require web forms)
        from src.data.registrar_form_db import lookup_registrar_form

        form_info = lookup_registrar_form(results.get("registrar_name"))
        results["registrar_abuse_form_url"] = form_info["form_url"] if form_info else None
        results["registrar_abuse_method"] = form_info["method"] if form_info else "email"

        log_with_context(
            logger,
            logging.INFO,
            "Multi-API scan completed",
            url=url,
            domain=domain,
            threat_level=results["aggregated_threat_level"],
            confidence_score=results["confidence_score"],
            virustotal_threat=vt_result.get("threat_level", "unknown"),
            urlvoid_safety_score=uv_result.get("safety_score"),
            phishtank_verified=pt_result.get("verified", False),
            event_type="multi_api_scan_complete",
        )

        elapsed = time.time() - _scan_start
        observe_histogram(METRIC_SCAN_DURATION_SECONDS, elapsed)
        # Wall-clock duration: the network steps overlap, so it is not the sum of the stages.
        results["scan_ms"] = round(elapsed * 1000, 1)
        if results["aggregated_threat_level"] in ("critical", "high"):
            increment_counter(METRIC_DETECTIONS_TOTAL)

        return results

    def _whois_lookup(self, domain: str) -> Dict[str, Any]:
        """WHOIS registration data of a domain (registrar, creation date, age, registrant).

        Args:
            domain: Host name.

        Returns:
            ``{"registrar", "creation_date", "domain_age_days", "registrant_org"}``, or ``{}``
            when the lookup failed.
        """
        logger.info(f"📋 WHOIS lookup for {domain}")
        whois_info: Dict[str, Any] = {}
        try:
            # Lazy import to avoid circular dependency
            from src.reporting.email_detector import EnhancedAbuseEmailDetector

            whois_data = EnhancedAbuseEmailDetector.get_enhanced_whois_info(domain)
            if whois_data:
                # Extract registrar
                registrar = None
                if hasattr(whois_data, "registrar"):
                    registrar = whois_data.registrar
                    if isinstance(registrar, list):
                        registrar = registrar[0] if registrar else None
                elif isinstance(whois_data, dict):
                    registrar = whois_data.get("registrar")

                # Extract creation date
                creation_date = None
                domain_age_days = None
                if hasattr(whois_data, "creation_date"):
                    creation_date = whois_data.creation_date
                    if isinstance(creation_date, list):
                        creation_date = creation_date[0] if creation_date else None
                elif isinstance(whois_data, dict):
                    creation_date = whois_data.get("creation_date")

                # Calculate domain age
                if creation_date:
                    try:
                        parsed_date = None
                        if isinstance(creation_date, datetime.datetime):
                            parsed_date = creation_date
                        elif isinstance(creation_date, str):
                            # Try multiple date formats
                            date_formats = [
                                "%Y-%m-%dT%H:%M:%SZ",
                                "%Y-%m-%dT%H:%M:%S%z",
                                "%Y-%m-%d %H:%M:%S",
                                "%Y-%m-%d",
                                "%d-%b-%Y",
                                "%Y/%m/%d",
                                "%d/%m/%Y",
                            ]
                            date_str = creation_date.replace("Z", "").split(".")[0].strip()
                            for fmt in date_formats:
                                try:
                                    parsed_date = datetime.datetime.strptime(date_str, fmt)
                                    break
                                except ValueError:
                                    continue
                            # Fallback to fromisoformat
                            if not parsed_date:
                                try:
                                    parsed_date = datetime.datetime.fromisoformat(
                                        creation_date.replace("Z", "+00:00")
                                    )
                                except ValueError:
                                    pass

                        if parsed_date:
                            # Make both naive for comparison
                            if parsed_date.tzinfo is not None:
                                parsed_date = parsed_date.replace(tzinfo=None)
                            domain_age_days = (datetime.datetime.now() - parsed_date).days
                    except Exception as date_err:
                        logger.debug(f"Date calculation error: {date_err}")

                # Extract registrant org
                registrant_org = None
                if hasattr(whois_data, "org"):
                    registrant_org = whois_data.org
                elif hasattr(whois_data, "registrant_org"):
                    registrant_org = whois_data.registrant_org
                elif isinstance(whois_data, dict):
                    registrant_org = whois_data.get("org") or whois_data.get("registrant_org")

                whois_info = {
                    "registrar": registrar,
                    "creation_date": str(creation_date) if creation_date else None,
                    "domain_age_days": domain_age_days,
                    "registrant_org": registrant_org,
                }
                logger.info(f"📋 WHOIS for {domain}: registrar={registrar}, age={domain_age_days}d")
        except Exception as e:
            logger.warning(f"⚠️ WHOIS lookup failed for {domain}: {e}")
        return whois_info

    @staticmethod
    def _has_external_evidence(
        vt_result: Dict[str, Any],
        uv_result: Dict[str, Any],
        pt_result: Dict[str, Any],
        gsb_result: Optional[Dict[str, Any]],
        kit_result: Optional[Dict[str, Any]],
    ) -> bool:
        """Tell whether any external source returned usable data.

        Args:
            vt_result: VirusTotal result.
            uv_result: URLVoid result.
            pt_result: PhishTank result.
            gsb_result: Google Safe Browsing result.
            kit_result: Kit fingerprint result.

        Returns:
            ``True`` if a threat-intel provider answered (listed/not_listed),
            GSB was checked, or a phishing kit was detected.
        """
        answered = (LISTED, NOT_LISTED)
        return (
            provider_status(vt_result) in answered
            or provider_status(uv_result) in answered
            or provider_status(pt_result) in answered
            or gsb_status(gsb_result) in answered
            or bool(kit_result and kit_result.get("kit_type"))
        )

    @staticmethod
    def _aggregate_threat_level(
        vt_result: Dict[str, Any],
        uv_result: Dict[str, Any],
        pt_result: Dict[str, Any],
        domain_age_days: Optional[int] = None,
        url_analysis: Optional[Dict[str, Any]] = None,
        gsb_result: Optional[Dict[str, Any]] = None,
        kit_result: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Aggregate threat levels from multiple APIs into single assessment.

        Only provider answers vote: an errored, unconfigured, pending or stale
        lookup is skipped, never counted as a clean vote. A Google Safe
        Browsing SOCIAL_ENGINEERING listing sets a floor of ``high``.

        Args:
            vt_result (Dict[str, Any]): VirusTotal scan result
            uv_result (Dict[str, Any]): URLVoid analysis result
            pt_result (Dict[str, Any]): PhishTank check result
            domain_age_days (Optional[int]): Domain age in days
            url_analysis (Optional[Dict]): URL lexical analysis result
            gsb_result (Optional[Dict]): Google Safe Browsing result
            kit_result (Optional[Dict]): AiTM/Evilginx kit fingerprint result

        Returns:
            str: Aggregated threat level (critical, high, medium, low, clean)
        """
        threat_scores = []

        # An active AiTM/reverse-proxy kit is the most severe possible
        # finding -- it means live credential/session/MFA-token theft in
        # progress, not just a static clone -- so it short-circuits to
        # critical exactly like a verified PhishTank report does below.
        if kit_result and kit_result.get("kit_type"):
            return "critical"

        pt_listed = provider_status(pt_result) == LISTED and pt_result.get("is_phishing")
        # PhishTank has the highest priority (verified community reports)
        if pt_listed and pt_result.get("verified"):
            return "critical"
        elif pt_listed:
            threat_scores.append(4)  # High threat from PhishTank

        min_threat_level: Optional[str] = None

        # Google Safe Browsing threats (very high priority)
        for threat_type in _gsb_threat_types(gsb_result):
            if threat_type == "MALWARE":
                return "critical"
            elif threat_type == "SOCIAL_ENGINEERING":
                threat_scores.append(5)  # Phishing confirmed by Google
                min_threat_level = _raise_floor(min_threat_level, "high")

        # URL Analysis (typosquatting, homoglyphs, etc.)
        if url_analysis:
            url_risk = url_analysis.get("risk_score", 0)
            # Homoglyphs are extremely suspicious - CRITICAL
            if url_analysis.get("homoglyphs", {}).get("detected"):
                return "critical"
            # Typosquatting is a direct impersonation attempt - HIGH minimum
            if url_analysis.get("typosquatting", {}).get("detected"):
                return "high"
            # The brand plus other words, or its exact name under another suffix, is highly
            # suspicious on a young domain; on an established one it is usually the brand's
            # own country or sister site (see kit_brand_hint).
            established = domain_age_days is not None and domain_age_days >= ESTABLISHED_DOMAIN_DAYS
            if url_analysis.get("combo_squatting", {}).get("detected") and not established:
                threat_scores.append(5)
            if (
                (url_analysis.get("tld_swap") or {}).get("detected")
                and domain_age_days is not None
                and not established
            ):
                threat_scores.append(5)
            # Suspicious TLD forces minimum "medium"
            if url_analysis.get("suspicious_tld", {}).get("detected"):
                min_threat_level = _raise_floor(min_threat_level, "medium")
                threat_scores.append(3)
            # High URL risk score
            if url_risk >= 70:
                threat_scores.append(5)
            elif url_risk >= 50:
                threat_scores.append(4)
            elif url_risk >= 30:
                threat_scores.append(3)
            elif url_risk >= 15:
                threat_scores.append(2)

        # Domain age is a strong indicator for phishing
        if domain_age_days is not None:
            if domain_age_days < 7:
                threat_scores.append(4)  # Very new domain = high risk
            elif domain_age_days < 30:
                threat_scores.append(3)  # New domain = medium risk
            elif domain_age_days < 90:
                threat_scores.append(2)  # Relatively new = low risk
            else:
                threat_scores.append(1)  # Established domain = clean

        # VirusTotal threat level mapping (answers only: no vote on error/no data)
        vt_answered = provider_status(vt_result) in (LISTED, NOT_LISTED)
        vt_threat = vt_result.get("threat_level", "unknown") if vt_answered else "unknown"
        if vt_threat == "high":
            threat_scores.append(4)
        elif vt_threat == "medium":
            threat_scores.append(3)
        elif vt_threat == "low":
            threat_scores.append(2)
        elif vt_threat == "clean":
            threat_scores.append(1)

        # URLVoid threat level mapping (answers only: no vote on error/no data)
        uv_answered = provider_status(uv_result) in (LISTED, NOT_LISTED)
        uv_threat = uv_result.get("threat_level", "unknown") if uv_answered else "unknown"
        if uv_threat == "high":
            threat_scores.append(4)
        elif uv_threat == "medium":
            threat_scores.append(3)
        elif uv_threat == "low":
            threat_scores.append(2)
        elif uv_threat == "clean":
            threat_scores.append(1)

        if not threat_scores:
            return min_threat_level or "unknown"

        avg_score = sum(threat_scores) / len(threat_scores)

        if avg_score >= 4.5:
            result = "critical"
        elif avg_score >= 3.5:
            result = "high"
        elif avg_score >= 2.5:
            result = "medium"
        elif avg_score >= 1.5:
            result = "low"
        else:
            result = "clean"

        # Enforce minimum threat level from suspicious indicators
        if min_threat_level and _THREAT_ORDER.index(result) < _THREAT_ORDER.index(min_threat_level):
            return min_threat_level

        return result

    @staticmethod
    def _calculate_confidence_score(
        vt_result: Dict[str, Any],
        uv_result: Dict[str, Any],
        pt_result: Dict[str, Any],
        domain_age_days: Optional[int] = None,
        url_analysis: Optional[Dict[str, Any]] = None,
        gsb_result: Optional[Dict[str, Any]] = None,
        kit_result: Optional[Dict[str, Any]] = None,
    ) -> int:
        """
        Calculate confidence score based on API response quality and agreement.

        Only provider answers contribute: errored or unconfigured lookups,
        pending/stale analyses and the mere absence of a PhishTank listing are
        not counted as (clean) evidence.

        Args:
            vt_result: VirusTotal result.
            uv_result: URLVoid result.
            pt_result: PhishTank result.
            domain_age_days: Domain age in days.
            url_analysis: URL lexical analysis result.
            gsb_result: Google Safe Browsing result.
            kit_result: Kit fingerprint result.

        Returns:
            int: Confidence score (0-100)
        """
        confidence = 0
        factors = 0

        # Kit fingerprint confidence -- its own score IS the confidence
        # contribution (a header IoC or brand-domain-leak is concrete
        # technical evidence, not a heuristic needing separate scaling).
        if kit_result and kit_result.get("kit_type"):
            factors += 1
            confidence += kit_result.get("confidence", 0)

        # URL Analysis confidence (local analysis, always available)
        if url_analysis:
            factors += 1
            url_risk = url_analysis.get("risk_score", 0)
            if url_risk >= 70:
                confidence += 95  # Very high confidence for obvious threats
            elif url_risk >= 50:
                confidence += 85
            elif url_risk >= 30:
                confidence += 75
            else:
                confidence += 60

        # Google Safe Browsing confidence (checked lookups only)
        gsb = gsb_status(gsb_result)
        if gsb in (LISTED, NOT_LISTED):
            factors += 1
            if gsb == LISTED:
                confidence += 98  # Very high confidence from Google
            else:
                confidence += 70  # Base confidence for clean result

        # Domain age provides reliable signal
        if domain_age_days is not None:
            factors += 1
            if domain_age_days < 7:
                confidence += 85  # Very confident about new domain risk
            elif domain_age_days < 30:
                confidence += 75  # Confident about new domain
            elif domain_age_days < 90:
                confidence += 65  # Moderate confidence
            else:
                confidence += 70  # Established domain

        # PhishTank confidence: a listing, or an explicit community verdict
        # that the URL is not a phish. Absence from the database is no evidence.
        pt = provider_status(pt_result)
        if pt == LISTED and pt_result.get("is_phishing"):
            factors += 1
            if pt_result.get("verified"):
                confidence += 95  # High confidence for verified reports
            else:
                confidence += 75  # Medium confidence for unverified reports
        elif pt == NOT_LISTED and pt_result.get("verified_not_phish"):
            factors += 1
            confidence += 60  # Community verified the URL is not a phish

        # VirusTotal confidence (answers with engine results only)
        total_engines = vt_result.get("total_engines", 0) or 0
        if provider_status(vt_result) in (LISTED, NOT_LISTED) and total_engines > 0:
            factors += 1
            if total_engines >= 50:
                confidence += 90  # High confidence with many engines
            elif total_engines >= 20:
                confidence += 75  # Medium confidence
            else:
                confidence += 60  # Low confidence

        # URLVoid confidence (answers with a numeric safety score only)
        safety_score = uv_result.get("safety_score")
        if (
            provider_status(uv_result) in (LISTED, NOT_LISTED)
            and isinstance(safety_score, (int, float))
            and not isinstance(safety_score, bool)
        ):
            factors += 1
            confidence += min(90, safety_score + 20)  # Scale safety score

        return int(confidence / factors) if factors > 0 else 0

    @staticmethod
    def _generate_recommendations(
        vt_result: Dict[str, Any],
        uv_result: Dict[str, Any],
        pt_result: Dict[str, Any],
        domain_age_days: Optional[int] = None,
        url_analysis: Optional[Dict[str, Any]] = None,
        gsb_result: Optional[Dict[str, Any]] = None,
        kit_result: Optional[Dict[str, Any]] = None,
    ) -> List[str]:
        """
        Generate actionable recommendations based on scan results.

        Args:
            vt_result: VirusTotal result.
            uv_result: URLVoid result.
            pt_result: PhishTank result.
            domain_age_days: Domain age in days.
            url_analysis: URL lexical analysis result.
            gsb_result: Google Safe Browsing result.
            kit_result: Kit fingerprint result.

        Returns:
            List[str]: List of recommendations
        """
        recommendations = []

        # Kit fingerprint recommendations (highest priority -- active proxy)
        if kit_result and kit_result.get("kit_type"):
            recommendations.append(
                f"🚨 CRITICAL: Active AiTM proxy detected ({kit_result['kit_type']}) - "
                "this captures live sessions/MFA tokens, prioritize takedown"
            )
            indicators = kit_result.get("indicators", [])
            if indicators:
                recommendations.append(f"   Indicators: {', '.join(indicators)}")

        # URL Analysis recommendations (highest priority - local detection)
        if url_analysis:
            # Homoglyphs (IDN attack)
            if url_analysis.get("homoglyphs", {}).get("detected"):
                homoglyphs = url_analysis["homoglyphs"]
                recommendations.append(
                    "🚨 CRITICAL: Homoglyph/IDN attack detected - URL uses deceptive Unicode characters"
                )
                if homoglyphs.get("target_brand"):
                    recommendations.append(f"🎯 Impersonating brand: {homoglyphs['target_brand']}")

            # Typosquatting
            if url_analysis.get("typosquatting", {}).get("detected"):
                typo = url_analysis["typosquatting"]
                recommendations.append(f"🚨 TYPOSQUATTING: Domain mimics '{typo['target_brand']}'")
                techniques = ", ".join(typo.get("techniques", []))
                if techniques:
                    recommendations.append(f"   Techniques: {techniques}")

            # Combo-squatting
            if url_analysis.get("combo_squatting", {}).get("detected"):
                combo = url_analysis["combo_squatting"]
                recommendations.append(
                    f"⚠️ COMBO-SQUATTING: Domain contains '{combo['target_brand']}' with extra text"
                )

            # The brand's exact name under another suffix
            if (url_analysis.get("tld_swap") or {}).get("detected"):
                swap = url_analysis["tld_swap"]
                recommendations.append(
                    f"⚠️ TLD SWAP: '{swap['target_brand']}' under .{swap['suffix']}, a suffix "
                    "the brand catalogue does not list as its own"
                )

            # Suspicious keywords
            if url_analysis.get("suspicious_keywords", {}).get("detected"):
                keywords = url_analysis["suspicious_keywords"]["keywords_found"][:5]
                recommendations.append(f"⚠️ Suspicious keywords in URL: {', '.join(keywords)}")

            # Suspicious TLD
            if url_analysis.get("suspicious_tld", {}).get("detected"):
                tld = url_analysis["suspicious_tld"]["tld"]
                recommendations.append(f"⚠️ Suspicious TLD: {tld} (commonly used in phishing)")

            # Excessive subdomains with brand
            if url_analysis.get("excessive_subdomains", {}).get("brand_in_subdomain"):
                brand = url_analysis["excessive_subdomains"]["brand_in_subdomain"]
                recommendations.append(
                    f"🚨 Brand '{brand}' hidden in subdomain - common phishing technique"
                )

        # Google Safe Browsing recommendations
        for threat_type in _gsb_threat_types(gsb_result):
            if threat_type == "SOCIAL_ENGINEERING":
                recommendations.append("🚨 GOOGLE SAFE BROWSING: Confirmed phishing site")
            elif threat_type == "MALWARE":
                recommendations.append("🚨 GOOGLE SAFE BROWSING: Malware distribution detected")
            else:
                recommendations.append(f"🚨 GOOGLE SAFE BROWSING: {threat_type} detected")

        # Domain age recommendations
        if domain_age_days is not None:
            if domain_age_days < 7:
                recommendations.append(
                    f"🚨 SUSPICIOUS: Domain registered only {domain_age_days} days ago"
                )
                recommendations.append("⚠️ Very new domains are commonly used for phishing attacks")
            elif domain_age_days < 30:
                recommendations.append(f"⚠️ CAUTION: New domain ({domain_age_days} days old)")

        # PhishTank recommendations
        if provider_status(pt_result) == LISTED and pt_result.get("is_phishing"):
            if pt_result.get("verified"):
                recommendations.append(
                    "🚨 CRITICAL: URL verified as phishing by PhishTank community"
                )
                recommendations.append(
                    "🔒 IMMEDIATE ACTION: Block URL and report to hosting provider"
                )
            else:
                recommendations.append("⚠️ WARNING: URL reported as phishing (unverified)")

        # VirusTotal recommendations
        if provider_status(vt_result) in (LISTED, NOT_LISTED):
            malicious = vt_result.get("malicious", 0)
            total = vt_result.get("total_engines", 0)

            if malicious > 0:
                recommendations.append(
                    f"🛡️ VirusTotal: {malicious}/{total} engines flagged as malicious"
                )
                if malicious >= 5:
                    recommendations.append(
                        "🚨 HIGH RISK: Multiple security engines detected threats"
                    )

        # URLVoid recommendations
        if provider_status(uv_result) in (LISTED, NOT_LISTED):
            safety_score = uv_result.get("safety_score")
            blacklists = uv_result.get("blacklists") or []

            if isinstance(safety_score, (int, float)) and safety_score <= 50:
                recommendations.append(f"⚠️ URLVoid: Low safety score ({safety_score}/100)")

            if blacklists:
                recommendations.append(
                    f"🚫 Found on {len(blacklists)} blacklist(s): {', '.join(blacklists[:3])}"
                )

        # General recommendations
        if not recommendations:
            recommendations.append("✅ No immediate threats detected by available scanners")
            recommendations.append("🔍 Continue monitoring for changes")

        return recommendations
