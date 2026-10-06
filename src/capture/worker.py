"""Sandboxed multi-profile browser capture worker (phase 2, WS3).

Runs Playwright Chromium in this separate, low-privilege process -- the same
process frontier as the screenshot worker (src/screenshot_worker.py), which
contains attacker-controlled HTML/JS/redirects instead of running it next to
the API/reporting code that holds every secret. Transport is a Unix-socket-only
HTTP endpoint; the socket is shared by volume with the backend and scheduler.

``POST /capture {"url": ...}`` navigates one ephemeral context per client
profile (desktop/mobile/bot, src/capture/profiles.py) and returns a bundle per
profile plus the cloaking comparison between them:

* redirect chain (HTTP 3xx), meta-refresh and JS navigations, iframe URLs;
* final URL, HTML (capped), visible text hash and length;
* response headers, TLS ``security_details`` and the server IP (from the HAR);
* viewport and full-page screenshots, favicon, HAR (gzipped, capped);
* CAPTCHA / Turnstile / Cloudflare-interstitial signals;
* cloaking: divergences in final URL, text hash and screenshot pHash.

Safety, in order of depth:

* every browser request (documents, subresources, xhr) passes the existing
  SSRF guard (``assess_url_target``) through ``context.route`` before the
  network sees it -- verdicts cached per hostname;
* no downloads, no popups (closed on open), ephemeral profile per request;
* navigation, request and size caps on everything the page controls.

Chromium runs with ``--no-sandbox`` (the base image has no privilege for the
setuid sandbox); the container compensates: read-only rootfs, ``cap_drop:
ALL``, ``no-new-privileges``, own network without a route to postgres, CPU and
memory limits.
"""

from __future__ import annotations

import asyncio
import base64
import gzip
import hashlib
import json
import logging
import os
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from flask import Flask, jsonify, request
from werkzeug.serving import run_simple

from src.capture.profiles import PROFILES, CaptureProfile, profiles_with_proxies
from src.dns.network_utils import assess_url_target

logger = logging.getLogger(__name__)

MAX_HTML_BYTES = 2 * 1024 * 1024
MAX_TEXT_CHARS = 20_000
MAX_HAR_BYTES = 512 * 1024  # gzipped; larger HARs are truncated (flagged)
MAX_SCREENSHOT_HEIGHT = 8000  # full-page clips are capped (tall pages OOM otherwise)
SETTLE_MS = 1200  # quiet-ish wait after DOMContentLoaded for JS renders
# Fixed viewport for the cloaking-only screenshot: the profiles' own viewports
# differ by design, so only same-viewport renders are comparable.
CANONICAL_VIEWPORT = {"width": 1024, "height": 768}
CHROMIUM_ARGS = [
    "--disable-dev-shm-usage",
    "--disable-gpu",
    "--disable-blink-features=AutomationControlled",
    "--disable-extensions",
    "--no-first-run",
    "--disable-default-apps",
    "--disable-component-extensions-with-background-pages",
    "--disable-background-timer-throttling",
    "--disable-backgrounding-occluded-windows",
    "--disable-renderer-backgrounding",
    "--disable-field-trial-config",
    "--disable-back-forward-cache",
    "--disable-ipc-flooding-protection",
    "--force-color-profile=srgb",
    "--metrics-recording-only",
    "--use-mock-keychain",
    "--disable-file-system",
    "--disable-permissions-api",
    "--disable-notifications",
    "--disable-translate",
    "--disable-sync",
    "--disable-reading-from-canvas",
    "--no-pings",
    "--js-flags=--max-old-space-size=256",
]
# Anti-webdriver: the whole point of the profiles is to look like the clients
# they impersonate (a webdriver flag breaks that and unmasks the scanner).
HIDE_WEBDRIVER = "Object.defineProperty(navigator, 'webdriver', {get: () => undefined});"
HIDE_WEBDIVER = "Object.defineProperty(navigator, 'webdriver', {get: () => undefined});"

_CAPTCHA_PATTERNS = {
    "recaptcha": ("recaptcha/api.js", "g-recaptcha", "grecaptcha.execute"),
    "turnstile": ("challenges.cloudflare.com/turnstile", "cf-turnstile"),
    "hcaptcha": ("hcaptcha.com/1/api.js", "h-captcha", "hcaptcha"),
}
_CF_CHALLENGE_MARKS = (
    "just a moment",
    "attention required",
    "cf-browser-verification",
    "cdn-cgi/challenge-platform",
    "enable javascript and cookies to continue",
)

# SSRF verdicts are process-wide, not per-context: pages pull from the same
# CDNs, and without this every profile (context) re-resolved every hostname --
# seconds of pure DNS on asset-heavy pages.
_VERDICT_CACHE: Dict[str, str] = {}
_VERDICT_LOCK = threading.Lock()


def ssrf_verdict_of(url: str) -> str:
    """The SSRF guard's verdict for a URL, memoised per hostname."""
    host = url.split("/")[2] if "://" in url else ""
    with _VERDICT_LOCK:
        verdict = _VERDICT_CACHE.get(host)
    if verdict is None:
        verdict = assess_url_target(url)
        with _VERDICT_LOCK:
            _VERDICT_CACHE[host] = verdict
    return verdict


def _cap_bytes(data: bytes, limit: int) -> Tuple[bytes, bool]:
    truncated = len(data) > limit
    return (data[:limit], truncated) if truncated else (data, False)


def captcha_signals(
    html: str, title: str, final_url: str, http_status: Optional[int]
) -> Dict[str, Any]:
    """Human-verification walls the page showed.

    Args:
        html: Page HTML.
        title: Page title.
        final_url: URL the page settled on.
        http_status: Main document status.

    Returns:
        ``{"cloudflare_challenge", "recaptcha", "turnstile", "hcaptcha"}`` flags
        plus where it was seen; all false when the page showed none.
    """
    haystack = f"{html}\n{title}\n{final_url}".lower()
    signals: Dict[str, Any] = {}
    for name, marks in _CAPTCHA_PATTERNS.items():
        signals[name] = any(mark in haystack for mark in marks)
    cf = any(mark in haystack for mark in _CF_CHALLENGE_MARKS) or (
        http_status in (403, 503) and "cloudflare" in haystack
    )
    signals["cloudflare_challenge"] = bool(cf)
    return signals


class ProfileEngine:
    """One Chromium instance capturing URLs profile by profile."""

    def __init__(self, timeout_ms: int = 20_000, settle_ms: int = SETTLE_MS) -> None:
        self.timeout_ms = timeout_ms
        self.settle_ms = settle_ms
        self._browser: Optional[Any] = None
        self._playwright: Optional[Any] = None

    async def _ensure_browser(self) -> Any:
        if self._browser is None or not self._browser.is_connected():
            from playwright.async_api import async_playwright

            if self._playwright is not None:
                try:
                    await self._playwright.stop()
                except Exception:  # pylint: disable=broad-except
                    pass
            self._playwright = await async_playwright().start()
            # --no-sandbox unconditionally: this worker only ever runs inside
            # its locked-down container (read-only rootfs, cap_drop ALL, no
            # NewPrivileges, own network), which replaces Chromium's own
            # setuid sandbox -- the documented WS3 trade-off.
            self._browser = await self._playwright.chromium.launch(
                headless=True, args=["--no-sandbox"] + CHROMIUM_ARGS
            )
        return self._browser

    async def stop(self) -> None:
        if self._browser is not None:
            try:
                await self._browser.close()
            except Exception:  # pylint: disable=broad-except
                pass
            self._browser = None
        if self._playwright is not None:
            try:
                await self._playwright.stop()
            except Exception:  # pylint: disable=broad-except
                pass
            self._playwright = None

    async def capture(self, profile: CaptureProfile, url: str) -> Dict[str, Any]:
        """Navigate ``url`` as ``profile`` and collect everything detection needs.

        Args:
            profile: Client to impersonate.
            url: URL to capture.

        Returns:
            The profile's bundle (``status`` explains every failure).
        """
        bundle: Dict[str, Any] = {
            "profile": profile.name,
            "status": "ok",
            "error": None,
            "url": url,
            "headers": {},
            "tls": {},
            "screenshots": {"viewport": None, "full": None},
            "captcha": {},
            "redirect_chain": [],
            "navigations": [],
            "iframes": [],
            "har_gzip_b64": None,
            "favicon_b64": None,
            "favicon_url": None,
        }
        started = time.monotonic()
        blocked_requests = 0
        navigations: List[str] = []
        iframes: List[str] = []
        har_path = Path(tempfile.mkstemp(prefix="anisakys_har_", suffix=".har")[1])

        async def guard(route: Any) -> None:
            # Every request the page triggers: documents, subresources, xhr.
            nonlocal blocked_requests
            target = route.request.url
            if ssrf_verdict_of(target) == "blocked":
                blocked_requests += 1
                await route.abort()
                return
            await route.continue_()

        try:
            browser = await self._ensure_browser()
            context = await browser.new_context(
                user_agent=profile.user_agent,
                viewport=profile.viewport,
                locale=profile.locale,
                timezone_id=profile.timezone_id,
                is_mobile=profile.is_mobile,
                has_touch=profile.has_touch,
                device_scale_factor=profile.device_scale_factor,
                extra_http_headers=profile.headers,
                accept_downloads=False,
                record_har_path=str(har_path),
                record_har_content="omit",  # bodies bloat the HAR; metadata is enough
                **({"proxy": {"server": profile.proxy}} if profile.proxy else {}),
            )
        except Exception as exc:  # browser/launch failure: the whole capture fails
            bundle.update(status="error", error=f"engine:{type(exc).__name__}")
            bundle["elapsed_ms"] = round((time.monotonic() - started) * 1000, 1)
            return bundle

        try:
            await context.add_init_script(HIDE_WEBDRIVER)
            await context.route("**/*", guard)
            page = await context.new_page()

            def on_popup(popup: Any) -> None:
                asyncio.ensure_future(popup.close())

            def on_download(download: Any) -> None:
                asyncio.ensure_future(download.cancel())

            page.on("popup", on_popup)
            page.on("download", on_download)

            def on_frameNavigated(frame: Any) -> None:  # noqa: N803 (Playwright event name)
                target = frame.url
                if target and target != "about:blank":
                    if frame is page.main_frame:
                        navigations.append(target)
                    elif target not in iframes:
                        iframes.append(target)

            page.on("framenavigated", on_frameNavigated)

            response = await page.goto(url, wait_until="domcontentloaded", timeout=self.timeout_ms)
            if self.settle_ms:
                await page.wait_for_timeout(self.settle_ms)

            final_url = page.url
            bundle.update(
                final_url=final_url,
                http_status=response.status if response else None,
            )

            html, truncated = _cap_bytes(
                (await page.content()).encode("utf-8", errors="replace"), MAX_HTML_BYTES
            )
            bundle["html_b64"] = base64.b64encode(html).decode()
            bundle["html_truncated"] = truncated
            title = await page.title()
            bundle["title"] = title[:300]
            try:
                text = await page.evaluate("document.body ? document.body.innerText : ''")
            except Exception:  # pylint: disable=broad-except
                text = ""
            text = (text or "")[:MAX_TEXT_CHARS]
            normalized = " ".join(text.split()).lower()
            bundle.update(
                text_chars=len(text),
                text_sha256=hashlib.sha256(normalized.encode()).hexdigest(),
            )

            if response is not None:
                try:
                    bundle["headers"] = dict(await response.all_headers())
                except Exception:  # pylint: disable=broad-except
                    bundle["headers"] = {}
                try:
                    details = await response.security_details() or {}
                except Exception:  # pylint: disable=broad-except
                    details = {}
                bundle["tls"] = {
                    "present": bool(details),
                    "issuer": details.get("issuer"),
                    "protocol": details.get("protocol"),
                    "valid_to": details.get("validTo"),
                }

            bundle["screenshots"] = await self._screenshots(page)
            favicon_b64, favicon_url = await self._favicon(
                context, html.decode("utf-8", "replace"), final_url
            )
            bundle["favicon_b64"] = favicon_b64
            bundle["favicon_url"] = favicon_url
            bundle["captcha"] = captcha_signals(
                html.decode("utf-8", "replace"), title, final_url, bundle.get("http_status")
            )
            bundle["redirect_chain"] = self._redirect_chain(response)
            bundle["navigations"] = navigations[:30]
            bundle["iframes"] = iframes[:30]
        except Exception as exc:  # navigation/render failures are per-profile data
            name = type(exc).__name__
            if "Timeout" in name:
                bundle.update(status="timeout", error=f"navigation exceeded {self.timeout_ms}ms")
            elif getattr(exc, "message", "") and "ERR_BLOCKED_BY_CLIENT" in str(
                getattr(exc, "message")
            ):
                bundle.update(status="blocked", error="navigation refused by the SSRF guard")
            else:
                bundle.update(status="error", error=name)
        finally:
            har_gzip, server_ip = await self._close_context(context, har_path)
            bundle["har_gzip_b64"] = har_gzip
            bundle["server_ip"] = server_ip
            bundle["blocked_requests"] = blocked_requests
            bundle["elapsed_ms"] = round((time.monotonic() - started) * 1000, 1)
        return bundle

    async def _screenshots(self, page: Any) -> Dict[str, Optional[str]]:
        viewport_shot = full_shot = None
        try:
            viewport_shot = base64.b64encode(
                await page.screenshot(type="png", timeout=self.timeout_ms)
            ).decode()
        except Exception:  # pylint: disable=broad-except
            pass
        try:
            height = await page.evaluate("Math.max(document.body.scrollHeight, 0)")
            clip = None
            if isinstance(height, (int, float)) and height > MAX_SCREENSHOT_HEIGHT:
                width = (page.viewport_size or {}).get("width", 1280)
                clip = {"x": 0, "y": 0, "width": width, "height": MAX_SCREENSHOT_HEIGHT}
            full_shot = base64.b64encode(
                await page.screenshot(
                    type="png", full_page=clip is None, clip=clip, timeout=self.timeout_ms
                )
            ).decode()
        except Exception:  # pylint: disable=broad-except
            pass
        # Canonical viewport for the CLOAKING comparison only: the profiles'
        # own viewports differ by design (1920 vs 390 px), so comparing their
        # screenshots would flag every responsive page. Same page + same
        # viewport renders near-identically; a real divergence survives.
        canonical = None
        try:
            await page.set_viewport_size(CANONICAL_VIEWPORT)
            await page.wait_for_timeout(150)
            canonical = base64.b64encode(
                await page.screenshot(type="png", timeout=self.timeout_ms)
            ).decode()
        except Exception:  # pylint: disable=broad-except
            pass
        return {"viewport": viewport_shot, "full": full_shot, "canonical": canonical}

    async def _favicon(
        self, context: Any, html: str, page_url: str
    ) -> Tuple[Optional[str], Optional[str]]:
        """The page's favicon, fetched with the same SSRF guard (attacker-declared URL)."""
        from urllib.parse import urljoin

        from bs4 import BeautifulSoup

        candidates: List[str] = []
        try:
            soup = BeautifulSoup(html, "html.parser")
            for link in soup.find_all("link", href=True):
                if "icon" in " ".join(link.get("rel") or []).lower():
                    candidates.append(urljoin(page_url, str(link["href"]).strip()))
        except Exception:  # pylint: disable=broad-except
            pass
        candidates.append(urljoin(page_url, "/favicon.ico"))
        for candidate in candidates[:3]:
            if not candidate.startswith(("http://", "https://")):
                continue
            if assess_url_target(candidate) == "blocked":
                continue
            try:
                response = await context.request.get(
                    candidate, timeout=self.timeout_ms, max_redirects=3
                )
                if response.ok:
                    body = await response.body()
                    if body:
                        capped, _ = _cap_bytes(body, 256 * 1024)
                        return base64.b64encode(capped).decode(), candidate
            except Exception:  # pylint: disable=broad-except
                continue
        return None, None

    @staticmethod
    def _redirect_chain(response: Any) -> List[Dict[str, Any]]:
        """The full HTTP redirect chain of the main document (oldest first).

        Same shape as ``fetch_page``'s hops: every hop including the landing
        (``redirect_features`` derives the hop count as ``len(chain) - 1``).
        """
        chain: List[Dict[str, Any]] = []
        request = getattr(response, "request", None) if response is not None else None
        while request is not None:
            chain.append({"url": request.url, "status": None})
            try:
                request = request.redirected_from
            except Exception:  # pylint: disable=broad-except
                request = None
        chain.reverse()
        # Every hop except the landing was a redirect; the exact code lives on
        # the response side we cannot see from the request, so keep the shape.
        for hop in chain[:-1]:
            hop["status"] = 302
        return chain

    async def _close_context(
        self, context: Any, har_path: Path
    ) -> Tuple[Optional[str], Optional[str]]:
        """Close the context (flushing the HAR); return it gzipped plus the server IP.

        An oversized HAR is dropped (the capture keeps everything else); the
        server IP survives because it is read before compressing.
        """
        try:
            await context.close()
        except Exception:  # pylint: disable=broad-except
            pass
        try:
            raw = har_path.read_bytes()
        except OSError:
            return None, None
        finally:
            har_path.unlink(missing_ok=True)
        server_ip = server_ip_from_har(raw)
        gzip_har = gzip.compress(raw)
        if len(gzip_har) > MAX_HAR_BYTES:
            return None, server_ip
        return base64.b64encode(gzip_har).decode(), server_ip


def server_ip_from_har(har_bytes: bytes) -> Optional[str]:
    """The server IP of a HAR's main document.

    Args:
        har_bytes: Raw (uncompressed) HAR JSON.

    Returns:
        The ``serverIPAddress`` of the last HTML entry (the landing page), or
        of the first entry when no entry declares HTML (pure redirect chains);
        None when nothing usable is there.
    """
    try:
        entries = json.loads(har_bytes)["log"]["entries"]
    except (ValueError, KeyError, TypeError):
        return None
    if not entries:
        return None

    def ip_of(entry: dict) -> Optional[str]:
        ip = entry.get("serverIPAddress")
        return str(ip) if ip and ip not in ("", "unknown") else None

    documents = [
        e
        for e in entries
        if (e.get("response", {}).get("content", {}).get("mimeType") or "").startswith("text/html")
    ]
    pool = documents or entries
    for entry in reversed(pool) if documents else pool[:1]:
        ip = ip_of(entry)
        if ip:
            return ip
    return None


def _phash_of(screenshot_b64: Optional[str]) -> Optional[str]:
    if not screenshot_b64:
        return None
    try:
        from src.detection.imagehash import fingerprint

        return fingerprint(base64.b64decode(screenshot_b64)).phash
    except Exception:  # pylint: disable=broad-except  (bad image: no phash, not a failure)
        return None


def cloaking_signals(bundles: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """Divergences between what the profiles were served.

    Args:
        bundles: Bundle per profile name (only ``status == ok`` ones compared).

    Returns:
        ``{"measured_profiles", "final_url_divergence", "text_divergence",
        "visual_divergence", "bot_served_different_content"}``; comparisons on
        fewer than two complete profiles read as not measured.
    """
    ok = {name: b for name, b in bundles.items() if b.get("status") == "ok"}
    result: Dict[str, Any] = {
        "measured_profiles": sorted(ok),
        "final_url_divergence": False,
        "text_divergence": False,
        "visual_divergence": False,
        "bot_served_different_content": False,
    }
    if len(ok) < 2:
        return result
    final_urls = {b.get("final_url") for b in ok.values()}
    text_hashes = {b.get("text_sha256") for b in ok.values()}
    phashes = {name: _phash_of(b.get("screenshots", {}).get("canonical")) for name, b in ok.items()}
    result["final_url_divergence"] = len(final_urls) > 1
    result["text_divergence"] = len(text_hashes) > 1
    from src.detection.imagehash import hamming

    distances = [
        distance
        for distance in (
            hamming(phashes[a], phashes[b])
            for i, a in enumerate(sorted(phashes))
            for b in sorted(phashes)[i + 1 :]
            if phashes[a] and phashes[b]
        )
        if distance is not None
    ]
    result["visual_divergence"] = any(d >= 8 for d in distances)
    desktop = ok.get("desktop")
    bot = ok.get("bot")
    if desktop and bot:
        result["bot_served_different_content"] = desktop.get("final_url") != bot.get(
            "final_url"
        ) or desktop.get("text_sha256") != bot.get("text_sha256")
    return result


def capture_url(
    url: str,
    engine: ProfileEngine,
    profiles: Optional[Dict[str, CaptureProfile]] = None,
    max_concurrency: int = 3,
) -> Dict[str, Any]:
    """Capture ``url`` with every profile and compare them (cloaking).

    Args:
        url: URL to capture.
        engine: Chromium engine (one browser, one context per profile).
        profiles: Profiles to run (default: the three, proxyless).
        max_concurrency: Profiles navigating at once.

    Returns:
        ``{"success", "url", "profiles", "cloaking", "elapsed_ms"}``.
    """
    started = time.monotonic()

    async def run() -> Dict[str, Dict[str, Any]]:
        # The whole engine lifecycle (launch, capture, close) stays in THIS
        # loop: Playwright objects are loop-bound, and stopping the browser
        # from a second asyncio.run() deadlocks.
        try:
            semaphore = asyncio.Semaphore(max(1, max_concurrency))

            async def one(profile: CaptureProfile) -> Dict[str, Any]:
                async with semaphore:
                    return await engine.capture(profile, url)

            names = list(profiles or PROFILES)
            tasks = [one(profiles[name]) if profiles else one(PROFILES[name]) for name in names]
            results = await asyncio.gather(*tasks)
            return dict(zip(names, results))
        finally:
            await engine.stop()

    bundles = asyncio.run(run())
    return {
        "success": any(b.get("status") == "ok" for b in bundles.values()),
        "url": url,
        "profiles": bundles,
        "cloaking": cloaking_signals(bundles),
        "elapsed_ms": round((time.monotonic() - started) * 1000, 1),
    }


def create_capture_app(timeout_ms: int = 20_000, max_concurrency: int = 3) -> Flask:
    """The worker's HTTP app (served over a Unix socket by :func:`run_worker`).

    One Chromium engine per request: Playwright objects are bound to the event
    loop that created them, and Werkzeug serves each request on its own thread
    with its own ``asyncio.run`` loop -- a per-request engine (and browser)
    keeps concurrent requests from sharing loop-bound state.
    """
    app = Flask(__name__)

    @app.route("/health", methods=["GET"])
    def health():
        return jsonify({"status": "healthy", "engine": "playwright-chromium"})

    @app.route("/capture", methods=["POST"])
    def capture():
        data = request.get_json(silent=True) or {}
        url = data.get("url")
        if not url:
            return jsonify({"success": False, "error": "url required"}), 400
        proxies = data.get("proxies")
        profiles = profiles_with_proxies(proxies if isinstance(proxies, dict) else None)
        engine = ProfileEngine(timeout_ms=timeout_ms)
        result = capture_url(url, engine, profiles, max_concurrency=max_concurrency)
        return jsonify(result)

    return app


def run_worker(socket_path: str, timeout_ms: int = 20_000, max_concurrency: int = 3) -> None:
    """Serve the capture app over a Unix domain socket (stale socket removed)."""
    if os.path.exists(socket_path):
        os.unlink(socket_path)
    app = create_capture_app(timeout_ms=timeout_ms, max_concurrency=max_concurrency)
    # The socket must be reachable by the backend/scheduler processes through
    # the shared volume: group-readable, not world-readable.
    os.umask(0o007)
    run_simple(f"unix://{socket_path}", 0, app, threaded=True)


def main() -> None:
    """Entry point (``anisakys.py --start-capture-worker`` or the container).

    Configuration comes only from this process's environment, never from the
    app Settings/.env: the worker holds no secrets.
    """
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
    socket_path = os.environ.get("CAPTURE_WORKER_SOCKET") or "/tmp/anisakys/capture-worker.sock"
    timeout_ms = int(os.environ.get("CAPTURE_PROFILE_TIMEOUT_MS", "20000"))
    max_concurrency = int(os.environ.get("CAPTURE_MAX_CONCURRENCY", "3"))
    Path(socket_path).parent.mkdir(parents=True, exist_ok=True)
    logger.info("Starting multi-profile capture worker on unix://%s", socket_path)
    run_worker(socket_path, timeout_ms=timeout_ms, max_concurrency=max_concurrency)


if __name__ == "__main__":
    main()
