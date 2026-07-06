"""
Unit tests for src/screenshot_worker.py -- the Flask app wrapping
ScreenshotService that runs inside the sandboxed worker process.
ScreenshotService.capture_screenshot is mocked here; its own logic (SSRF
guards, engine dispatch) is already covered by tests/test_screenshot_ssrf.py
-- this file only tests the worker's HTTP/base64/cleanup layer.
"""

import base64
import unittest
from unittest.mock import patch

from src.screenshot_worker import create_worker_app, run_worker


class TestScreenshotWorker(unittest.TestCase):
    def setUp(self):
        patcher = patch("src.screenshot_worker.ScreenshotService")
        self.mock_service_cls = patcher.start()
        self.addCleanup(patcher.stop)
        self.mock_service = self.mock_service_cls.return_value
        self.mock_service.preferred_engine = "playwright"
        app = create_worker_app("/tmp/whatever", timeout=10)
        app.config["TESTING"] = True
        self.client = app.test_client()

    def test_missing_url_returns_400(self):
        resp = self.client.post("/capture", json={})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("url required", resp.get_json()["error"])

    def test_capture_failure_passes_through_unchanged(self):
        self.mock_service.capture_screenshot.return_value = {
            "success": False,
            "error": "ssrf_blocked:blocked",
            "engine": "playwright",
        }
        resp = self.client.post("/capture", json={"url": "http://169.254.169.254/"})
        data = resp.get_json()
        self.assertFalse(data["success"])
        self.assertEqual(data["error"], "ssrf_blocked:blocked")

    def test_capture_none_result_returns_generic_failure(self):
        self.mock_service.capture_screenshot.return_value = None
        resp = self.client.post("/capture", json={"url": "https://example.com"})
        data = resp.get_json()
        self.assertFalse(data["success"])
        self.assertEqual(data["error"], "capture_failed")

    def test_success_base64_encodes_and_deletes_local_file(self):
        fake_png = b"\x89PNG real bytes"
        with patch("src.screenshot_worker.Path") as mock_path_cls:
            mock_path = mock_path_cls.return_value
            mock_path.read_bytes.return_value = fake_png
            self.mock_service.capture_screenshot.return_value = {
                "success": True,
                "screenshot_path": "/tmp/whatever/shot.png",
                "engine": "playwright",
                "page_info": {"title": "Example"},
            }
            resp = self.client.post("/capture", json={"url": "https://example.com"})

        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(base64.b64decode(data["screenshot_b64"]), fake_png)
        self.assertEqual(data["engine"], "playwright")
        mock_path.unlink.assert_called_once_with(missing_ok=True)

    def test_deletes_local_file_even_if_encoding_raises(self):
        with patch("src.screenshot_worker.Path") as mock_path_cls:
            mock_path = mock_path_cls.return_value
            mock_path.read_bytes.side_effect = OSError("disk gone")
            self.mock_service.capture_screenshot.return_value = {
                "success": True,
                "screenshot_path": "/tmp/whatever/shot.png",
                "engine": "playwright",
            }
            with self.assertRaises(OSError):
                self.client.post("/capture", json={"url": "https://example.com"})
            mock_path.unlink.assert_called_once_with(missing_ok=True)

    def test_health_endpoint_reports_preferred_engine(self):
        resp = self.client.get("/health")
        data = resp.get_json()
        self.assertEqual(data["status"], "healthy")
        self.assertEqual(data["engine"], "playwright")

    def test_use_async_defaults_true_when_omitted(self):
        self.mock_service.capture_screenshot.return_value = {"success": False, "error": "x"}
        self.client.post("/capture", json={"url": "https://example.com"})
        _, kwargs = self.mock_service.capture_screenshot.call_args
        self.assertEqual(kwargs["use_async"], True)


class TestRunWorker(unittest.TestCase):
    """run_worker() binds create_worker_app() to a Unix socket via Werkzeug's
    run_simple -- confirmed empirically (not assumed) that this transport is
    required: IPAddressDeny=127.0.0.0/8 on the real unit blocks a loopback-TCP
    listener's own inbound connections too, but AF_UNIX isn't IP traffic."""

    @patch("src.screenshot_worker.run_simple")
    @patch("src.screenshot_worker.create_worker_app")
    @patch("src.screenshot_worker.os.path.exists", return_value=True)
    @patch("src.screenshot_worker.os.unlink")
    def test_removes_stale_socket_before_binding(
        self, mock_unlink, mock_exists, mock_create_app, mock_run_simple
    ):
        run_worker("/run/anisakys/screenshot-worker.sock", "/tmp/whatever", timeout=15)
        mock_unlink.assert_called_once_with("/run/anisakys/screenshot-worker.sock")
        mock_create_app.assert_called_once_with("/tmp/whatever", timeout=15)
        args, _ = mock_run_simple.call_args
        self.assertEqual(args[0], "unix:///run/anisakys/screenshot-worker.sock")

    @patch("src.screenshot_worker.run_simple")
    @patch("src.screenshot_worker.create_worker_app")
    @patch("src.screenshot_worker.os.path.exists", return_value=False)
    @patch("src.screenshot_worker.os.unlink")
    def test_no_stale_socket_skips_unlink(
        self, mock_unlink, mock_exists, mock_create_app, mock_run_simple
    ):
        run_worker("/run/anisakys/screenshot-worker.sock", "/tmp/whatever")
        mock_unlink.assert_not_called()


if __name__ == "__main__":
    unittest.main()
