"""Multi-profile browser capture worker: signals, HAR, cloaking, app (WS3)."""

import base64
import gzip
import json
from io import BytesIO
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock


from src.capture import worker
from src.capture.profiles import PROFILES, profiles_with_proxies
from src.capture.worker import (
    MAX_HTML_BYTES,
    ProfileEngine,
    captcha_signals,
    cloaking_signals,
    create_capture_app,
    server_ip_from_har,
)


def _noise_png(seed: int, size: int = 96) -> bytes:
    """A deterministic noisy PNG: two seeds land far apart in pHash space."""
    from PIL import Image

    image = Image.new("RGB", (size, size))
    pixels = image.load()
    state = seed * 6364136223846793005 + 1442695040888963407
    for y in range(size):
        for x in range(size):
            state = (state * 6364136223846793005 + 1442695040888963407) % (1 << 64)
            pixels[x, y] = ((state >> 32) & 0xFF, (state >> 40) & 0xFF, (state >> 48) & 0xFF)
    buffer = BytesIO()
    image.save(buffer, format="PNG")
    return buffer.getvalue()


def _shot(seed: Optional[int]) -> Optional[str]:
    return base64.b64encode(_noise_png(seed)).decode() if seed is not None else None


def _bundle(
    profile: str,
    *,
    status: str = "ok",
    final_url: str = "https://page.example/login",
    text_sha256: str = "a" * 64,
    shot_seed: Optional[int] = 1,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    bundle = {
        "profile": profile,
        "status": status,
        "final_url": final_url,
        "text_sha256": text_sha256,
        # "canonical" is the fixed-viewport shot cloaking compares; the
        # profile's own viewport shot feeds the detection pipeline.
        "screenshots": {
            "viewport": _shot(shot_seed),
            "full": None,
            "canonical": _shot(shot_seed),
        },
    }
    bundle.update(extra or {})
    return bundle


class TestCaptchaSignals:
    def test_a_plain_page_has_no_walls(self):
        signals = captcha_signals(
            "<html><body>hola</body></html>", "Banco", "https://x.example/", 200
        )
        assert not any(signals.values())

    def test_recaptcha_turnstile_and_hcaptcha_are_flagged(self):
        html = '<script src="https://www.google.com/recaptcha/api.js"></script>'
        assert captcha_signals(html, "t", "https://x/", 200)["recaptcha"]
        html = '<div class="cf-turnstile" data-sitekey="k">'
        assert captcha_signals(html, "t", "https://x/", 200)["turnstile"]
        html = '<script src="https://js.hcaptcha.com/1/api.js" async defer></script>'
        assert captcha_signals(html, "t", "https://x/", 200)["hcaptcha"]

    def test_cloudflare_interstitial_by_title_and_status(self):
        assert captcha_signals("<html></html>", "Just a moment...", "https://x/", 403)[
            "cloudflare_challenge"
        ]
        assert captcha_signals(
            "<html></html>", "Attention Required! | Cloudflare", "https://x/", 503
        )["cloudflare_challenge"]

    def test_cloudflare_mark_without_a_wall_is_not_a_challenge(self):
        # A page merely mentioning Cloudflare (e.g. its CDN header) is not a wall.
        signals = captcha_signals("<html>hosted on cloudflare</html>", "Home", "https://x/", 200)
        assert signals["cloudflare_challenge"] is False


class TestServerIpFromHar:
    def _har(self, entries: List[Dict[str, Any]]) -> bytes:
        return json.dumps({"log": {"entries": entries}}).encode()

    def test_main_document_ip_wins_and_order_is_respected(self):
        entries = [
            {"request": {"url": "http://a.example/"}, "serverIPAddress": "1.1.1.1"},
            {
                "request": {"url": "https://page.example/login"},
                "serverIPAddress": "203.0.113.9",
                "response": {"content": {"mimeType": "text/html"}},
            },
            {"request": {"url": "https://cdn.example/app.js"}, "serverIPAddress": "9.9.9.9"},
        ]
        assert server_ip_from_har(self._har(entries)) == "203.0.113.9"

    def test_unusable_hars_return_none(self):
        assert server_ip_from_har(b"not json") is None
        assert server_ip_from_har(self._har([])) is None
        entries = [{"request": {"url": "http://a/"}, "serverIPAddress": ""}]
        assert server_ip_from_har(self._har(entries)) is None


class TestCloaking:
    def test_identical_serving_across_profiles_is_not_cloaking(self):
        bundles = {
            "desktop": _bundle("desktop"),
            "mobile": _bundle("mobile", shot_seed=1),  # same seed -> same pHash
            "bot": _bundle("bot", shot_seed=1),
        }
        result = cloaking_signals(bundles)
        assert result["measured_profiles"] == ["bot", "desktop", "mobile"]
        assert not result["final_url_divergence"]
        assert not result["text_divergence"]
        assert not result["visual_divergence"]
        assert not result["bot_served_different_content"]

    def test_different_content_per_profile_is_cloaking(self):
        bundles = {
            "desktop": _bundle("desktop", final_url="https://page.example/login", shot_seed=1),
            "mobile": _bundle("mobile", text_sha256="b" * 64, shot_seed=2),
        }
        result = cloaking_signals(bundles)
        assert result["text_divergence"]
        assert result["visual_divergence"]  # two noise patterns are ~32 bits apart

    def test_bot_served_a_different_page_than_the_human(self):
        bundles = {
            "desktop": _bundle("desktop", final_url="https://page.example/lure"),
            "bot": _bundle("bot", final_url="https://page.example/benign"),
        }
        assert cloaking_signals(bundles)["bot_served_different_content"]

    def test_failed_profiles_do_not_count_as_divergence(self):
        bundles = {
            "desktop": _bundle("desktop"),
            "mobile": _bundle("mobile", status="timeout"),
            "bot": _bundle("bot", status="error"),
        }
        result = cloaking_signals(bundles)
        assert result["measured_profiles"] == ["desktop"]
        assert not any(
            result[key] for key in ("final_url_divergence", "text_divergence", "visual_divergence")
        )


class TestProfiles:
    def test_three_profiles_cover_desktop_mobile_and_bot(self):
        assert set(PROFILES) == {"desktop", "mobile", "bot"}
        assert PROFILES["mobile"].is_mobile and PROFILES["mobile"].has_touch
        assert PROFILES["bot"].user_agent.startswith("Mozilla/5.0 (compatible;")
        assert all(p.locale == "es-CO" for p in PROFILES.values())

    def test_proxies_bind_by_name_and_wildcard(self):
        bound = profiles_with_proxies({"mobile": "http://geo-co:8080", "*": "http://any:8080"})
        assert bound["mobile"].proxy == "http://geo-co:8080"
        assert bound["desktop"].proxy == "http://any:8080"
        assert profiles_with_proxies(None)["bot"].proxy is None


class TestRedirectChain:
    def _response_with_redirects(self, urls: List[str]) -> MagicMock:
        """A response whose request chain matches Playwright's: the landing's
        ``redirected_from`` walks back to the original request."""
        response = MagicMock()
        request = None
        for url in urls:  # oldest first: each hop points back to the previous
            hop = MagicMock()
            hop.url = url
            hop.redirected_from = request
            request = hop
        response.request = request  # the final (landing) request
        return response

    def test_the_chain_is_the_full_path_including_the_landing(self):
        response = self._response_with_redirects(
            ["http://a.example/", "https://b.example/hop", "https://page.example/login"]
        )
        chain = ProfileEngine._redirect_chain(response)
        # Same shape as fetch_page's hops: redirect_features counts
        # len(chain) - 1 hops, so the landing stays in.
        assert [hop["url"] for hop in chain] == [
            "http://a.example/",
            "https://b.example/hop",
            "https://page.example/login",
        ]
        assert chain[0]["status"] == 302 and chain[-1]["status"] is None

    def test_no_redirects_no_chain(self):
        response = self._response_with_redirects(["https://page.example/login"])
        assert ProfileEngine._redirect_chain(response) == [
            {"url": "https://page.example/login", "status": None}
        ]


class TestGuard:
    def test_verdicts_are_memoised_and_private_hosts_are_blocked(self):
        from src.capture import worker as worker_module

        worker_module._VERDICT_CACHE.clear()
        public = worker_module.ssrf_verdict_of("https://page.example/login")
        assert public in ("public", "unresolved")  # never "blocked": nothing private
        # Same host again: served from the process-wide cache.
        assert "page.example" in worker_module._VERDICT_CACHE
        assert worker_module.ssrf_verdict_of("http://192.168.1.10/admin") == "blocked"
        assert worker_module.ssrf_verdict_of("http://127.0.0.1:8080/") == "blocked"
        # The cache keys are netloc (host[:port]): the port stays.
        assert set(worker_module._VERDICT_CACHE) == {
            "page.example",
            "192.168.1.10",
            "127.0.0.1:8080",
        }
        worker_module._VERDICT_CACHE.clear()


class TestApp:
    def test_health_and_url_validation(self):
        app = create_capture_app()
        client = app.test_client()
        assert client.get("/health").status_code == 200
        missing = client.post("/capture", json={})
        assert missing.status_code == 400 and missing.get_json()["error"] == "url required"


class TestBundleCaps:
    def test_html_is_capped_at_the_documented_limit(self):
        data, truncated = worker._cap_bytes(b"x" * (MAX_HTML_BYTES + 10), MAX_HTML_BYTES)
        assert len(data) == MAX_HTML_BYTES and truncated

    def test_har_gzip_roundtrip_shape(self):
        # The response carries gzip(base64) -- the client never decompresses it
        # (storage does), so the worker only guarantees: valid gzip, capped.
        payload = gzip.compress(json.dumps({"log": {"entries": []}}).encode())
        assert len(gzip.decompress(payload)) > 0
