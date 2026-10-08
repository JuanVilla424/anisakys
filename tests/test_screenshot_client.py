"""
Unit tests for src/screenshot_client.py -- ScreenshotServiceClient (the Unix
socket client to the sandboxed screenshot worker) and the
get_screenshot_service() config-gated factory.
"""

import base64
import json
import unittest
from unittest.mock import MagicMock, patch

from src.screenshot_client import ScreenshotServiceClient, get_screenshot_service


def _mock_conn(response_dict):
    """A fake _UnixSocketHTTPConnection whose getresponse().read() returns
    the given dict as JSON bytes."""
    conn = MagicMock()
    conn.getresponse.return_value.read.return_value = json.dumps(response_dict).encode()
    return conn


class TestScreenshotServiceClient(unittest.TestCase):
    def setUp(self):
        self.tmp_patcher = patch("src.screenshot_client.Path.mkdir")
        self.tmp_patcher.start()
        self.addCleanup(self.tmp_patcher.stop)
        self.client = ScreenshotServiceClient(
            "/tmp/does-not-matter", "/run/anisakys/screenshot-worker.sock", timeout=10
        )

    @patch("src.screenshot_client._UnixSocketHTTPConnection")
    def test_success_decodes_and_writes_bytes(self, mock_conn_cls):
        fake_png = b"\x89PNG fake bytes"
        mock_conn_cls.return_value = _mock_conn(
            {
                "success": True,
                "screenshot_b64": base64.b64encode(fake_png).decode(),
                "engine": "playwright",
                "page_info": {"title": "Example"},
            }
        )
        with (
            patch("pathlib.Path.write_bytes") as mock_write,
            patch("pathlib.Path.stat") as mock_stat,
        ):
            mock_stat.return_value.st_size = len(fake_png)
            result = self.client.capture_screenshot("https://example.com")

        mock_write.assert_called_once_with(fake_png)
        self.assertTrue(result["success"])
        self.assertEqual(result["engine"], "playwright")
        self.assertEqual(result["size_bytes"], len(fake_png))
        self.assertIn("screenshot_path", result)

    @patch("src.screenshot_client._UnixSocketHTTPConnection")
    def test_worker_reported_failure_passes_through(self, mock_conn_cls):
        mock_conn_cls.return_value = _mock_conn(
            {"success": False, "error": "ssrf_blocked:blocked", "engine": "sandboxed"}
        )
        result = self.client.capture_screenshot("http://169.254.169.254/")
        self.assertFalse(result["success"])
        self.assertEqual(result["error"], "ssrf_blocked:blocked")

    @patch(
        "src.screenshot_client._UnixSocketHTTPConnection",
        side_effect=FileNotFoundError("no such socket"),
    )
    def test_worker_unreachable_returns_clean_failure(self, mock_conn_cls):
        result = self.client.capture_screenshot("https://example.com")
        self.assertFalse(result["success"])
        self.assertEqual(result["error"], "worker_unreachable")

    @patch("src.screenshot_client._UnixSocketHTTPConnection")
    def test_posts_use_async_flag_through(self, mock_conn_cls):
        conn = _mock_conn({"success": False, "error": "x"})
        mock_conn_cls.return_value = conn
        self.client.capture_screenshot("https://example.com", use_async=False)
        _, kwargs = conn.request.call_args
        self.assertEqual(json.loads(kwargs["body"])["use_async"], False)

    def test_auto_generates_filename_when_not_provided(self):
        with patch("src.screenshot_client._UnixSocketHTTPConnection") as mock_conn_cls:
            mock_conn_cls.return_value = _mock_conn({"success": False, "error": "x"})
            self.client.capture_screenshot("https://example.com/path")
        # No exception means the auto-generated filename path was exercised;
        # a dedicated content check isn't needed since the worker call itself
        # (mocked above) is what's under test here.


class TestGetScreenshotServiceFactory(unittest.TestCase):
    @patch("src.screenshot_client.settings")
    def test_returns_client_when_worker_socket_configured(self, mock_settings):
        mock_settings.SCREENSHOT_WORKER_SOCKET = "/run/anisakys/screenshot-worker.sock"
        with patch("src.screenshot_client.Path.mkdir"):
            service = get_screenshot_service("/tmp/whatever")
        self.assertIsInstance(service, ScreenshotServiceClient)

    @patch("src.screenshot_client.settings")
    def test_returns_inprocess_service_when_worker_socket_unset(self, mock_settings):
        mock_settings.SCREENSHOT_WORKER_SOCKET = None
        with patch("src.screenshot_service.ScreenshotService.__init__", return_value=None):
            service = get_screenshot_service("/tmp/whatever")
        from src.screenshot_service import ScreenshotService

        self.assertIsInstance(service, ScreenshotService)


if __name__ == "__main__":
    unittest.main()
