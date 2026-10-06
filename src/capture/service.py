"""Page capture for detection: HTML, redirect chain, headers, favicon and screenshot.

Built on the tools the project already uses for attacker-controlled pages:

* the HTML comes from :func:`src.dns.network_utils.safe_get_with_redirects`, which checks
  the URL and every redirect target against private networks before requesting it;
* the screenshot comes from the existing screenshot service (the sandboxed worker when
  ``SCREENSHOT_WORKER_SOCKET`` is set, see src/screenshot_client.py);
* the favicon is fetched with the same SSRF guard.

:func:`store_scan_capture` keeps what a scan extracted in ``captures`` (migration 007):
hashes, features, brand identification and the redirect chain, never the page itself.
"""

from __future__ import annotations

import hashlib
import json
import socket
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional
from urllib.parse import urljoin, urlsplit

import requests
from bs4 import BeautifulSoup
from sqlalchemy import text
from sqlalchemy.engine import Connection

from src.detection.imagehash import ImageRejected, favicon_mmh3, fingerprint
from src.detection.tlsh import tlsh_hash
from src.dns.network_utils import SSRFRedirectError, safe_get_with_redirects
from src.logger import logger

CAPTURE_STATUSES = ("ok", "error", "blocked", "timeout")
CAPTURE_HASH_COLUMNS = (
    "html_sha256",
    "html_tlsh",
    "screenshot_phash",
    "favicon_mmh3",
    "favicon_phash",
)
MAX_CAPTURES_PER_SITE = 20
MAX_HTML_BYTES = 2 * 1024 * 1024
MAX_FAVICON_BYTES = 256 * 1024
MAX_FAVICON_CANDIDATES = 3
REQUEST_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "es-CO,es;q=0.9,en;q=0.8",
}


@dataclass
class PageCapture:
    """What a URL served."""

    url: str
    status: str  # ok | error | blocked | timeout
    error: Optional[str] = None
    final_url: Optional[str] = None
    http_status: Optional[int] = None
    headers: Dict[str, str] = field(default_factory=dict)
    redirect_chain: List[Dict[str, Any]] = field(default_factory=list)
    html: str = ""
    tls_valid: Optional[bool] = None
    server_ip: Optional[str] = None
    favicon: Optional[bytes] = None
    favicon_url: Optional[str] = None
    screenshot: Optional[bytes] = None
    elapsed_ms: float = 0.0

    @property
    def ok(self) -> bool:
        """Whether a page was received."""
        return self.status == "ok"


def _read_capped(response: requests.Response, limit: int) -> bytes:
    chunks: List[bytes] = []
    size = 0
    for chunk in response.iter_content(chunk_size=65536):
        if not chunk:
            continue
        chunks.append(chunk)
        size += len(chunk)
        if size >= limit:
            break
    response.close()
    return b"".join(chunks)[:limit]


def _decode(response: requests.Response, body: bytes) -> str:
    encoding = response.encoding or "utf-8"
    try:
        return body.decode(encoding, errors="replace")
    except LookupError:
        return body.decode("utf-8", errors="replace")


def _server_ip(url: str) -> Optional[str]:
    host = urlsplit(url).hostname
    if not host:
        return None
    try:
        infos = socket.getaddrinfo(host, None)
    except (OSError, UnicodeError):
        return None
    addresses = sorted({str(info[4][0]) for info in infos}, key=lambda a: (":" in a, a))
    return addresses[0] if addresses else None


def favicon_urls(html: str, page_url: str) -> List[str]:
    """Favicon URLs a page declares (``<link rel="icon">``), then ``/favicon.ico``.

    Args:
        html: Page HTML.
        page_url: URL the HTML came from.

    Returns:
        Up to :data:`MAX_FAVICON_CANDIDATES` absolute http(s) URLs.
    """
    urls: List[str] = []
    try:
        soup = BeautifulSoup(html, "html.parser")
        for link in soup.find_all("link", href=True):
            rel = " ".join(link.get("rel") or []).lower()
            if "icon" in rel:
                urls.append(urljoin(page_url, str(link["href"]).strip()))
    except Exception:  # pylint: disable=broad-except
        pass
    urls.append(urljoin(page_url, "/favicon.ico"))
    unique = []
    for url in urls:
        if urlsplit(url).scheme in ("http", "https") and url not in unique:
            unique.append(url)
    return unique[:MAX_FAVICON_CANDIDATES]


def _fetch_favicon(html: str, page_url: str, timeout: int) -> tuple:
    for url in favicon_urls(html, page_url):
        try:
            response = safe_get_with_redirects(
                url, headers=REQUEST_HEADERS, timeout=timeout, stream=True, verify=False
            )
        except (SSRFRedirectError, requests.RequestException):
            continue
        if response.status_code != 200:
            response.close()
            continue
        data = _read_capped(response, MAX_FAVICON_BYTES)
        if data:
            return data, url
    return None, None


def _screenshot(url: str, service: Any) -> Optional[bytes]:
    try:
        result = service.capture_screenshot(url)
    except Exception:  # pylint: disable=broad-except
        return None
    if not result or not result.get("success") or not result.get("screenshot_path"):
        return None
    path = Path(str(result["screenshot_path"]))
    try:
        return path.read_bytes()
    except OSError:
        return None


def fetch_page(
    url: str,
    timeout: int = 15,
    screenshot_service: Optional[Any] = None,
    with_favicon: bool = True,
) -> PageCapture:
    """Fetch a page and what detection needs from it.

    Args:
        url: URL to capture.
        timeout: Seconds per request.
        screenshot_service: Object with ``capture_screenshot(url)`` (None = no screenshot).
        with_favicon: Also fetch the favicon.

    Returns:
        The capture; ``status`` says why when no page was received.
    """
    started = time.monotonic()
    capture = PageCapture(url=url, status="ok")
    hops: List[Dict[str, Any]] = []
    response: Optional[requests.Response] = None
    try:
        try:
            response = safe_get_with_redirects(
                url, headers=REQUEST_HEADERS, timeout=timeout, stream=True, hops=hops
            )
            capture.tls_valid = True if url.startswith("https") else None
        except requests.exceptions.SSLError:
            # Phishing pages often have invalid certificates. Nothing is sent to them, the
            # page is only read for analysis, and the invalid certificate is itself a feature.
            hops.clear()
            response = safe_get_with_redirects(
                url, headers=REQUEST_HEADERS, timeout=timeout, stream=True, hops=hops, verify=False
            )
            capture.tls_valid = False
    except SSRFRedirectError as e:
        capture.status, capture.error = "blocked", str(e)
    except requests.Timeout:
        capture.status, capture.error = "timeout", f"no answer within {timeout}s"
    except requests.RequestException as e:
        capture.status, capture.error = "error", type(e).__name__
    capture.redirect_chain = hops
    if response is not None:
        final_url = str(hops[-1]["url"]) if hops else url
        capture.final_url = final_url
        capture.http_status = response.status_code
        capture.headers = {k.lower(): v for k, v in response.headers.items()}
        capture.html = _decode(response, _read_capped(response, MAX_HTML_BYTES))
        capture.server_ip = _server_ip(final_url)
        if with_favicon:
            capture.favicon, capture.favicon_url = _fetch_favicon(capture.html, final_url, timeout)
        if screenshot_service is not None:
            capture.screenshot = _screenshot(final_url, screenshot_service)
    capture.elapsed_ms = round((time.monotonic() - started) * 1000, 1)
    return capture


def capture_hashes(capture: PageCapture) -> Dict[str, Any]:
    """Hashes of a capture (HTML SHA-256 and TLSH, screenshot and favicon fingerprints).

    Args:
        capture: The capture.

    Returns:
        ``{"html_sha256", "html_tlsh", "screenshot_phash", "favicon_mmh3", "favicon_phash"}``
        (``None`` when unavailable).
    """
    html_bytes = capture.html.encode("utf-8", errors="replace") if capture.html else b""
    hashes: Dict[str, Any] = {
        "html_sha256": hashlib.sha256(html_bytes).hexdigest() if html_bytes else None,
        "html_tlsh": tlsh_hash(html_bytes) if html_bytes else None,
        "screenshot_phash": None,
        "favicon_mmh3": favicon_mmh3(capture.favicon) if capture.favicon else None,
        "favicon_phash": None,
    }
    for name, data in (
        ("screenshot_phash", capture.screenshot),
        ("favicon_phash", capture.favicon),
    ):
        if data:
            try:
                hashes[name] = fingerprint(data).phash
            except ImageRejected:
                pass
    return hashes


def store_scan_capture(
    conn: Connection, scan: Mapping[str, Any], site_id: Optional[int] = None
) -> Optional[int]:
    """Keep the capture of a comprehensive scan in ``captures`` (and point the site at it).

    Only what the scan already extracted is kept: the capture summary, its hashes, the
    content features and the brand identification, never the page itself. A site keeps
    its newest :data:`MAX_CAPTURES_PER_SITE` captures.

    Args:
        conn: Open connection, inside the caller's transaction.
        scan: Result of ``MultiAPIValidator.comprehensive_scan``.
        site_id: ``phishing_sites.id`` the scan belongs to.

    Returns:
        The capture id, or None when the scan carries no capture.
    """
    summary = scan.get("capture")
    url = scan.get("url")
    if not isinstance(summary, Mapping) or summary.get("status") not in CAPTURE_STATUSES or not url:
        return None
    hashes = scan.get("capture_hashes") or {}
    features = dict(scan.get("page_features") or {})
    features["visual_brand"] = scan.get("visual_brand") or {}
    capture_id = int(
        conn.execute(
            text(
                "INSERT INTO captures (site_id, url, profile, status, error, final_url, "
                "http_status, server_ip, tls, redirect_chain, features, "
                "html_sha256, html_tlsh, screenshot_phash, favicon_mmh3, favicon_phash) "
                "VALUES (:site_id, :url, 'default', :status, :error, :final_url, :http_status, "
                ":server_ip, CAST(:tls AS JSONB), CAST(:chain AS JSONB), "
                "CAST(:features AS JSONB), :html_sha256, :html_tlsh, :screenshot_phash, "
                ":favicon_mmh3, :favicon_phash) RETURNING id"
            ),
            {
                "site_id": site_id,
                "url": url,
                "status": summary["status"],
                "error": summary.get("error"),
                "final_url": summary.get("final_url"),
                "http_status": summary.get("http_status"),
                "server_ip": summary.get("server_ip"),
                "tls": json.dumps({"valid": summary.get("tls_valid")}),
                "chain": json.dumps(summary.get("redirect_chain") or []),
                "features": json.dumps(features, default=str),
                **{name: hashes.get(name) for name in CAPTURE_HASH_COLUMNS},
            },
        ).scalar_one()
    )
    if site_id is not None:
        conn.execute(
            text("UPDATE phishing_sites SET last_capture_id = :c WHERE id = :s"),
            {"c": capture_id, "s": site_id},
        )
        conn.execute(
            text(
                "DELETE FROM captures WHERE site_id = :s AND id NOT IN ("
                "SELECT id FROM captures WHERE site_id = :s "
                "ORDER BY captured_at DESC, id DESC LIMIT :keep)"
            ),
            {"s": site_id, "keep": MAX_CAPTURES_PER_SITE},
        )
    return capture_id


def record_scan_capture(conn: Connection, url: str, scan: Mapping[str, Any]) -> Optional[int]:
    """Keep a scan's capture for the site with this URL, without failing the caller.

    Runs in a savepoint: a capture that cannot be stored is logged and the caller's own
    writes in the same transaction are kept. A URL without a site row stores nothing.

    Args:
        conn: Open connection, inside the caller's transaction.
        url: ``phishing_sites.url`` of the scanned site.
        scan: Result of the comprehensive scan.

    Returns:
        The capture id, or None.
    """
    if not isinstance(scan.get("capture"), Mapping):
        return None
    try:
        with conn.begin_nested():
            site = conn.execute(
                text("SELECT id FROM phishing_sites WHERE url = :url"), {"url": url}
            ).first()
            if site is None:
                return None
            return store_scan_capture(conn, scan, int(site[0]))
    except Exception as e:  # pylint: disable=broad-except  (auxiliary: keep the scan results)
        logger.warning(f"Capture of {url} not stored: {e}")
        return None


def latest_capture(conn: Connection, site_id: int) -> Optional[Dict[str, Any]]:
    """The newest stored capture of a site, as JSON-safe data.

    Args:
        conn: Open connection.
        site_id: ``phishing_sites.id``.

    Returns:
        Capture summary, hashes, content features and brand identification, or None when
        the site has no capture.
    """
    row = (
        conn.execute(
            text(
                "SELECT c.id, c.url, c.profile, c.status, c.error, c.final_url, c.http_status, "
                "c.server_ip, c.asn, c.asn_org, c.tls, c.redirect_chain, c.features, "
                "c.html_sha256, c.html_tlsh, c.screenshot_phash, c.favicon_mmh3, "
                "c.favicon_phash, c.captured_at "
                "FROM phishing_sites s JOIN captures c ON c.id = s.last_capture_id "
                "WHERE s.id = :s"
            ),
            {"s": site_id},
        )
        .mappings()
        .first()
    )
    if row is None:
        return None
    features = dict(row["features"] or {})
    visual = features.pop("visual_brand", None) or {}
    return {
        "id": int(row["id"]),
        "url": row["url"],
        "profile": row["profile"],
        "status": row["status"],
        "error": row["error"],
        "final_url": row["final_url"],
        "http_status": row["http_status"],
        "server_ip": row["server_ip"],
        "asn": row["asn"],
        "asn_org": row["asn_org"],
        "tls_valid": (row["tls"] or {}).get("valid"),
        "redirect_chain": row["redirect_chain"] or [],
        "hashes": {name: row[name] for name in CAPTURE_HASH_COLUMNS},
        "features": features,
        "visual_brand": visual,
        "captured_at": row["captured_at"].isoformat() if row["captured_at"] else None,
    }
