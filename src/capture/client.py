"""Client for the sandboxed multi-profile capture worker (phase 2, WS3).

The browser runs in its own container/process (src/capture/worker.py), reached
over a Unix socket shared by volume -- the same frontier as the screenshot
worker. This client turns the worker's bundles into what the detection
pipeline already consumes:

* the PRIMARY profile's bundle becomes a :class:`src.capture.service.PageCapture`
  (HTML, headers, redirect chain, TLS, favicon, screenshot), so content
  features, brand identification, kit fingerprinting and the fusion work
  unchanged on a real-browser capture;
* every profile's summary, the cloaking comparison and the CAPTCHA walls ride
  along in ``capture_profiles`` / ``cloaking`` / ``captcha`` for storage and
  (in phase 2's second training round) the fusion vector;
* the server IP is enriched with its ASN (RDAP, src/capture/asn.py).

``get_capture_worker()`` is the single construction point: without
``CAPTURE_WORKER_SOCKET`` every scan uses today's plain fetch (the worker is
opt-in per deployment, never a hard dependency).
"""

from __future__ import annotations

import base64
import json
import logging
import time
from typing import Any, Dict, Mapping, Optional, Tuple

from src.capture.asn import asn_of
from src.capture.profiles import PRIMARY_PROFILE
from src.capture.service import PageCapture
from src.screenshot_client import _UnixSocketHTTPConnection

logger = logging.getLogger(__name__)

# Headroom over the worker's worst case (3 profiles, semaphore 2, one engine
# launch): the worker's own error response must win over a client cutoff.
CLIENT_TIMEOUT_SECONDS = 90


class CaptureWorkerClient:
    """Talks to the capture worker over the shared Unix socket."""

    def __init__(self, socket_path: str, timeout: int = CLIENT_TIMEOUT_SECONDS) -> None:
        self.socket_path = socket_path
        self.timeout = timeout

    def capture(
        self, url: str, proxies: Optional[Mapping[str, str]] = None
    ) -> Optional[Dict[str, Any]]:
        """Run every profile against ``url`` in the worker.

        Args:
            url: URL to capture.
            proxies: Optional ``{profile: proxy URL}`` (``CAPTURE_PROXIES``).

        Returns:
            The worker's response (``profiles``, ``cloaking``, ...) or None
            when the worker is unreachable (the caller falls back to fetch).
        """
        try:
            conn = _UnixSocketHTTPConnection(self.socket_path, timeout=self.timeout)
            conn.request(
                "POST",
                "/capture",
                body=json.dumps({"url": url, "proxies": dict(proxies) if proxies else None}),
                headers={"Content-Type": "application/json"},
            )
            response = conn.getresponse()
            data = json.loads(response.read())
            conn.close()
            return data
        except (OSError, json.JSONDecodeError) as exc:
            logger.error(f"Capture worker unreachable at {self.socket_path}: {exc}")
            return None


_WORKER: Optional[CaptureWorkerClient] = None


def get_capture_worker() -> Optional[CaptureWorkerClient]:
    """The configured capture worker, or None when the deployment has none.

    Returns:
        A client for ``CAPTURE_WORKER_SOCKET`` (built once, it is stateless).
    """
    global _WORKER  # pylint: disable=global-statement
    from src.config import settings

    socket_path = getattr(settings, "CAPTURE_WORKER_SOCKET", None)
    if not socket_path:
        return None
    if _WORKER is None or _WORKER.socket_path != socket_path:
        _WORKER = CaptureWorkerClient(socket_path)
    return _WORKER


def _proxies_from_settings() -> Optional[Dict[str, str]]:
    """``CAPTURE_PROXIES`` (JSON ``{profile: proxy}``), or None to run proxyless."""
    from src.config import settings

    raw = getattr(settings, "CAPTURE_PROXIES", None)
    if not raw:
        return None
    try:
        parsed = json.loads(raw)
        return {str(k): str(v) for k, v in parsed.items()} if isinstance(parsed, dict) else None
    except ValueError:
        logger.warning("CAPTURE_PROXIES is not valid JSON -- capturing proxyless")
        return None


def page_capture_from_bundle(url: str, bundle: Mapping[str, Any]) -> PageCapture:
    """Rebuild the pipeline's capture from a worker bundle.

    Args:
        url: The requested URL.
        bundle: One profile's bundle (``src/capture/worker.py``).

    Returns:
        A PageCapture with the bundle's transport facts; ``status`` keeps
        whatever the worker reported.
    """
    tls = bundle.get("tls") or {}
    valid_to = tls.get("valid_to")
    # Without security details the validity is unknown (None), never assumed
    # valid or invalid from the scheme alone -- redirects break that inference.
    tls_valid: Optional[bool] = None
    if tls.get("present"):
        tls_valid = bool(valid_to and valid_to > time.time())
    screenshots = bundle.get("screenshots") or {}
    screenshot = base64.b64decode(screenshots["viewport"]) if screenshots.get("viewport") else None
    favicon = base64.b64decode(bundle["favicon_b64"]) if bundle.get("favicon_b64") else None
    html = ""
    if bundle.get("html_b64"):
        html = base64.b64decode(bundle["html_b64"]).decode("utf-8", errors="replace")
    status = str(bundle.get("status") or "error")
    return PageCapture(
        url=url,
        status=status if status in ("ok", "error", "blocked", "timeout") else "error",
        error=bundle.get("error"),
        final_url=bundle.get("final_url"),
        http_status=bundle.get("http_status"),
        headers={str(k).lower(): str(v) for k, v in (bundle.get("headers") or {}).items()},
        redirect_chain=list(bundle.get("redirect_chain") or []),
        html=html,
        tls_valid=tls_valid,
        server_ip=bundle.get("server_ip"),
        favicon=favicon,
        favicon_url=bundle.get("favicon_url"),
        screenshot=screenshot,
        elapsed_ms=float(bundle.get("elapsed_ms") or 0.0),
    )


def worker_capture(url: str, worker: CaptureWorkerClient) -> Tuple[PageCapture, Dict[str, Any]]:
    """Capture ``url`` with the worker: primary PageCapture plus the extras.

    Args:
        url: URL to capture.
        worker: The configured worker client.

    Returns:
        ``(primary_capture, extras)`` where extras carries the per-profile
        summaries (with hashes and CAPTCHA walls), the cloaking comparison and
        whether geography was measured. Unreachable worker or failed capture
        degrades to an error PageCapture -- never to a missing one.
    """
    extras: Dict[str, Any] = {"engine": "browser", "profiles": {}, "measured_geo": False}
    response = worker.capture(url, proxies=_proxies_from_settings())
    if not response:
        extras["engine"] = "fetch-fallback"
        from src.capture.service import fetch_page

        return fetch_page(url), extras
    bundles = response.get("profiles") or {}
    primary = bundles.get(PRIMARY_PROFILE)
    capture = (
        page_capture_from_bundle(url, primary)
        if primary
        else PageCapture(url=url, status="error", error="worker returned no profiles")
    )
    extras["cloaking"] = response.get("cloaking") or {}
    from src.capture.service import capture_hashes
    from src.intelligence.multi_api_validator import capture_summary

    for name, bundle in bundles.items():
        if name == PRIMARY_PROFILE:
            summary = capture_summary(capture)
        else:
            profile_capture = page_capture_from_bundle(url, bundle)
            summary = capture_summary(profile_capture)
            summary["hashes"] = capture_hashes(profile_capture)
        summary["captcha"] = bundle.get("captcha") or {}
        summary["navigations"] = bundle.get("navigations") or []
        summary["iframes"] = bundle.get("iframes") or []
        summary["blocked_requests"] = int(bundle.get("blocked_requests") or 0)
        extras["profiles"][name] = summary
    extras["measured_geo"] = bool(_proxies_from_settings())
    if capture.server_ip:
        capture_asn, capture_asn_org = asn_of(capture.server_ip)
        if capture_asn:
            extras["asn"] = capture_asn
            extras["asn_org"] = capture_asn_org
    return capture, extras
