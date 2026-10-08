"""Capture worker client: bundle -> PageCapture, extras, fallback, settings."""

import base64
import json
from typing import Any, Dict, Optional
from unittest.mock import patch


from src.capture import client
from src.capture.client import (
    get_capture_worker,
    page_capture_from_bundle,
    worker_capture,
)
from src.capture.service import PageCapture
from src.config import settings


def _bundle(**overrides: Any) -> Dict[str, Any]:
    bundle: Dict[str, Any] = {
        "profile": "desktop",
        "status": "ok",
        "url": "https://page.example/login",
        "final_url": "https://page.example/login",
        "http_status": 200,
        "headers": {"Content-Type": "text/html", "X-Foo": "bar"},
        "tls": {
            "present": True,
            "issuer": "CN=Example CA",
            "protocol": "TLS 1.3",
            "valid_to": 4102444800,
        },
        "server_ip": "203.0.113.9",
        "redirect_chain": [{"url": "https://page.example/", "status": 302}],
        "html_b64": base64.b64encode(b"<html><body>hola</body></html>").decode(),
        "text_sha256": "a" * 64,
        "text_chars": 4,
        "screenshots": {"viewport": None, "full": None},
        "favicon_b64": None,
        "favicon_url": None,
        "captcha": {"recaptcha": False},
        "elapsed_ms": 900.0,
    }
    bundle.update(overrides)
    return bundle


class FakeWorker:
    def __init__(self, response: Optional[Dict[str, Any]] = None, socket: str = "/tmp/x.sock"):
        self.response = response
        self.socket_path = socket
        self.calls: list = []

    def capture(self, url: str, proxies=None):
        self.calls.append((url, proxies))
        return self.response


def _worker_response(**extra: Any) -> Dict[str, Any]:
    mobile = _bundle(
        profile="mobile",
        final_url="https://page.example/m",
        text_sha256="b" * 64,
        server_ip="203.0.113.9",
    )
    bot = _bundle(profile="bot")
    profiles = {"desktop": _bundle(), "mobile": mobile, "bot": bot}
    profiles.update(extra.pop("profiles", {}) or {})
    return {
        "success": True,
        "url": "https://page.example/login",
        "profiles": profiles,
        "cloaking": {
            "measured_profiles": ["bot", "desktop", "mobile"],
            "final_url_divergence": True,
            "text_divergence": True,
            "visual_divergence": False,
            "bot_served_different_content": False,
        },
        "elapsed_ms": 3000.0,
        **extra,
    }


class TestPageCaptureFromBundle:
    def test_the_primary_bundle_becomes_a_page_capture(self):
        capture = page_capture_from_bundle("https://page.example/login", _bundle())
        assert isinstance(capture, PageCapture)
        assert capture.ok and capture.final_url == "https://page.example/login"
        assert capture.http_status == 200
        assert capture.headers == {"content-type": "text/html", "x-foo": "bar"}
        assert capture.html == "<html><body>hola</body></html>"
        assert capture.tls_valid is True
        assert capture.server_ip == "203.0.113.9"
        assert capture.redirect_chain == [{"url": "https://page.example/", "status": 302}]

    def test_tls_semantics(self):
        expired = _bundle(tls={"present": True, "valid_to": 100})
        assert page_capture_from_bundle("https://x/", expired).tls_valid is False
        plain = _bundle(tls={"present": False})
        assert page_capture_from_bundle("https://x/", plain).tls_valid is None

    def test_unknown_statuses_read_as_error_and_bad_utf8_survives(self):
        weird = _bundle(status="strange", html_b64=base64.b64encode(b"\xff\xfe\x00bad").decode())
        capture = page_capture_from_bundle("https://x/", weird)
        assert capture.status == "error"
        assert capture.html  # replacement decoding, never an exception

    def test_screenshot_and_favicon_decode(self):
        shot = base64.b64encode(b"\x89PNG-not-really").decode()
        favicon = base64.b64encode(b"\x00\x00\x01\x00icon").decode()
        bundle = _bundle(screenshots={"viewport": shot, "full": None}, favicon_b64=favicon)
        capture = page_capture_from_bundle("https://x/", bundle)
        assert capture.screenshot == b"\x89PNG-not-really"
        assert capture.favicon == b"\x00\x00\x01\x00icon"


class TestWorkerCapture:
    def test_primary_capture_plus_extras(self):
        worker = FakeWorker(_worker_response())
        with patch.object(client, "asn_of", return_value=("64512", "Example Telecom")):
            capture, extras = worker_capture("https://page.example/login", worker)
        assert capture.ok and capture.final_url == "https://page.example/login"
        assert extras["engine"] == "browser"
        assert set(extras["profiles"]) == {"desktop", "mobile", "bot"}
        assert extras["profiles"]["mobile"]["hashes"]["html_sha256"]
        assert extras["cloaking"]["final_url_divergence"] is True
        assert extras["asn"] == "64512" and extras["asn_org"] == "Example Telecom"
        assert extras["measured_geo"] is False  # no CAPTURE_PROXIES: not measured

    def test_unreachable_worker_falls_back_to_the_plain_fetch(self):
        worker = FakeWorker(response=None)
        with patch("src.capture.service.fetch_page") as fetch:
            fetch.return_value = PageCapture(url="https://x/", status="error", error="down")
            capture, extras = worker_capture("https://x/", worker)
        assert extras["engine"] == "fetch-fallback"
        assert capture.status == "error"

    def test_geo_measured_only_when_proxies_are_configured(self):
        worker = FakeWorker(_worker_response())
        with (
            patch.object(settings, "CAPTURE_PROXIES", json.dumps({"mobile": "http://geo:8080"})),
            patch.object(client, "asn_of", return_value=(None, None)),
        ):
            _, extras = worker_capture("https://x/", worker)
        assert extras["measured_geo"] is True


class TestFactory:
    def test_no_socket_no_worker(self):
        with patch.object(settings, "CAPTURE_WORKER_SOCKET", None):
            assert get_capture_worker() is None

    def test_socket_builds_one_stateless_client(self):
        with patch.object(settings, "CAPTURE_WORKER_SOCKET", "/tmp/cap.sock"):
            first = get_capture_worker()
            second = get_capture_worker()
        assert first is not None and first is second
        assert first.socket_path == "/tmp/cap.sock"

    def test_proxies_parse_and_tolerate_garbage(self):
        with patch.object(settings, "CAPTURE_PROXIES", json.dumps({"desktop": "http://p:1"})):
            assert client._proxies_from_settings() == {"desktop": "http://p:1"}
        with patch.object(settings, "CAPTURE_PROXIES", "not-json{"):
            assert client._proxies_from_settings() is None
        with patch.object(settings, "CAPTURE_PROXIES", None):
            assert client._proxies_from_settings() is None


class TestScanIntegration:
    def _scan(self):
        from src.eval.predictors import offline_validator

        return offline_validator()

    def test_without_a_worker_the_scan_keeps_its_fetch_shape(self, monkeypatch):
        monkeypatch.setattr("src.capture.client.get_capture_worker", lambda: None)
        with patch("src.intelligence.multi_api_validator.fetch_page") as fetch:
            fetch.return_value = PageCapture(
                url="https://x/", status="ok", http_status=200, html="<html></html>"
            )
            scan = self._scan().comprehensive_scan("https://x/")
        assert "capture_profiles" not in scan
        assert "cloaking" not in scan
        assert scan["capture"]["status"] == "ok"

    def test_with_a_worker_the_extras_ride_along(self, monkeypatch):
        worker = FakeWorker(_worker_response())
        monkeypatch.setattr("src.capture.client.get_capture_worker", lambda: worker)
        with patch.object(client, "asn_of", return_value=(None, None)):
            scan = self._scan().comprehensive_scan("https://page.example/login")
        assert scan["capture_engine"] == "browser"
        assert set(scan["capture_profiles"]) == {"desktop", "mobile", "bot"}
        assert scan["cloaking"]["final_url_divergence"] is True
        assert scan["page_features"]["captcha_walls"]["recaptcha"] is False
        assert scan["page_features"]["cloaking"]["final_url_divergence"] is True
        assert "measured_profiles" not in scan["page_features"]["cloaking"]
