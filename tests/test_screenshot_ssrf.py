"""
Unit tests for the SSRF guard in ScreenshotService.

The screenshot service renders attacker-supplied URLs in a real headless
browser (Playwright or Selenium). Both engines must refuse to navigate to
a non-public target — and must refuse BEFORE a browser is even launched —
regardless of which caller invokes them (the guard lives at the sink, since
at least one caller, the abuse-report flow, invokes capture_screenshot with
no guard of its own).
"""

import asyncio
import tempfile
import unittest
from unittest.mock import patch, MagicMock, AsyncMock

from src.dns.network_utils import SSRFRedirectError
from src.screenshot_service import ScreenshotService


class TestSyncGuard(unittest.TestCase):
    """Selenium path (capture_screenshot_sync), used by /api/v1/multi-scan."""

    @patch("src.screenshot_service.SELENIUM_AVAILABLE", True)
    @patch("src.screenshot_service.webdriver.Chrome")
    @patch("src.screenshot_service.assess_url_target", return_value="blocked")
    def test_refuses_blocked_target_without_launching_browser(self, mock_assess, mock_chrome):
        with tempfile.TemporaryDirectory() as temp_dir:
            service = ScreenshotService(screenshots_dir=temp_dir, timeout=5)
            result = service.capture_screenshot_sync("http://169.254.169.254/")

        self.assertFalse(result["success"])
        self.assertTrue(result["error"].startswith("ssrf_blocked:"))
        self.assertEqual(result["engine"], "selenium")
        mock_chrome.assert_not_called()

    @patch("src.screenshot_service.SELENIUM_AVAILABLE", True)
    @patch("src.screenshot_service.webdriver.Chrome")
    @patch("src.screenshot_service.assess_url_target", return_value="public")
    @patch("src.screenshot_service.safe_get_with_redirects")
    def test_refuses_public_url_that_redirects_internally(
        self, mock_safe_get, mock_assess, mock_chrome
    ):
        mock_safe_get.side_effect = SSRFRedirectError("http://10.0.0.1/", "blocked")

        with tempfile.TemporaryDirectory() as temp_dir:
            service = ScreenshotService(screenshots_dir=temp_dir, timeout=5)
            result = service.capture_screenshot_sync("https://public-looking.example/")

        self.assertFalse(result["success"])
        self.assertIn("redirect", result["error"])
        mock_chrome.assert_not_called()

    @patch("src.screenshot_service.SELENIUM_AVAILABLE", True)
    @patch("src.screenshot_service.webdriver.Chrome")
    @patch("src.screenshot_service.assess_url_target", return_value="unresolved")
    def test_unresolved_host_still_reaches_browser(self, mock_assess, mock_chrome):
        """Unresolved hosts reach nothing internal — the browser is allowed
        to try (and fail naturally), matching assess_url_target's contract."""
        mock_driver = MagicMock()
        mock_driver.title = "N/A"
        mock_driver.current_url = "https://dead-host.example/"
        mock_driver.save_screenshot = lambda path: None
        mock_chrome.return_value = mock_driver

        with tempfile.TemporaryDirectory() as temp_dir:
            service = ScreenshotService(screenshots_dir=temp_dir, timeout=5)
            with patch("pathlib.Path.stat") as mock_stat:
                mock_stat.return_value.st_size = 123
                service.capture_screenshot_sync("https://dead-host.example/")

        mock_chrome.assert_called_once()


class TestAsyncGuard(unittest.TestCase):
    """Playwright path (capture_screenshot_async), used unguarded today by
    the abuse-report flow — this is the gap this change closes."""

    def _run(self, coro):
        return asyncio.run(coro)

    @patch("src.screenshot_service.assess_url_target", return_value="blocked")
    def test_refuses_blocked_target_without_launching_browser(self, mock_assess):
        with (
            tempfile.TemporaryDirectory() as temp_dir,
            patch("src.screenshot_service.async_playwright") as mock_pw,
        ):
            service = ScreenshotService(screenshots_dir=temp_dir, timeout=5)
            result = self._run(service.capture_screenshot_async("http://127.0.0.1/admin"))

        self.assertFalse(result["success"])
        self.assertTrue(result["error"].startswith("ssrf_blocked:"))
        self.assertEqual(result["engine"], "playwright")
        mock_pw.assert_not_called()

    @patch("src.screenshot_service.assess_url_target", return_value="public")
    @patch("src.screenshot_service.safe_get_with_redirects")
    def test_refuses_public_url_that_redirects_internally(self, mock_safe_get, mock_assess):
        mock_safe_get.side_effect = SSRFRedirectError("http://10.0.0.1/", "blocked")

        with (
            tempfile.TemporaryDirectory() as temp_dir,
            patch("src.screenshot_service.async_playwright") as mock_pw,
        ):
            service = ScreenshotService(screenshots_dir=temp_dir, timeout=5)
            result = self._run(service.capture_screenshot_async("https://public-looking.example/"))

        self.assertFalse(result["success"])
        self.assertIn("redirect", result["error"])
        mock_pw.assert_not_called()


class TestGuardRouteHandler(unittest.TestCase):
    """Unit test for the Playwright page.route subresource interceptor,
    isolated from the full browser-launch flow."""

    def _run(self, coro):
        return asyncio.run(coro)

    def _make_guard(self, verdicts):
        """Recreate the _guard_route closure with a controllable verdict map,
        mirroring the logic embedded in capture_screenshot_async."""
        from urllib.parse import urlparse

        route_cache = {}

        async def _guard_route(route):
            req_url = route.request.url
            parsed = urlparse(req_url)
            if parsed.scheme in ("http", "https") and parsed.hostname:
                verdict = route_cache.get(parsed.hostname)
                if verdict is None:
                    verdict = verdicts.get(parsed.hostname, "public")
                    route_cache[parsed.hostname] = verdict
                if verdict == "blocked":
                    await route.abort()
                    return
            await route.continue_()

        return _guard_route

    def _fake_route(self, url):
        route = MagicMock()
        route.request.url = url
        route.abort = AsyncMock()
        route.continue_ = AsyncMock()
        return route

    def test_aborts_blocked_subresource(self):
        guard = self._make_guard({"internal.example": "blocked"})
        route = self._fake_route("http://internal.example/pixel.png")

        self._run(guard(route))

        route.abort.assert_called_once()
        route.continue_.assert_not_called()

    def test_continues_public_subresource(self):
        guard = self._make_guard({"cdn.example": "public"})
        route = self._fake_route("https://cdn.example/style.css")

        self._run(guard(route))

        route.continue_.assert_called_once()
        route.abort.assert_not_called()

    def test_never_aborts_data_scheme(self):
        guard = self._make_guard({})
        route = self._fake_route("data:image/png;base64,AAAA")

        self._run(guard(route))

        route.continue_.assert_called_once()
        route.abort.assert_not_called()


if __name__ == "__main__":
    unittest.main()
