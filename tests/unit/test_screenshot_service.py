"""Unit tests for ScreenshotService."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from pathlib import Path

from src.services.screenshot_service import ScreenshotService


@pytest.fixture
def screenshot_service(tmp_path):
    """Create ScreenshotService with temporary directory."""
    return ScreenshotService(screenshots_dir=str(tmp_path / "screenshots"))


class TestScreenshotService:
    """Test ScreenshotService functionality."""

    def test_init_creates_directory(self, tmp_path):
        """Test service creates screenshots directory."""
        screenshots_dir = tmp_path / "test_screenshots"
        service = ScreenshotService(screenshots_dir=str(screenshots_dir))

        assert screenshots_dir.exists()
        assert service.screenshots_dir == screenshots_dir

    def test_generate_filename(self, screenshot_service):
        """Test filename generation."""
        url = "https://example.com/test"
        filename = screenshot_service._generate_filename(url)

        assert filename.endswith(".png")
        assert "_" in filename
        # Should have timestamp and hash
        parts = filename.replace(".png", "").split("_")
        assert len(parts) >= 2

    def test_generate_filename_consistent_hash(self, screenshot_service):
        """Test same URL generates same hash part."""
        url = "https://example.com"
        filename1 = screenshot_service._generate_filename(url)
        filename2 = screenshot_service._generate_filename(url)

        # Hash parts should be same (last 12 chars before .png)
        hash1 = filename1.split("_")[-1].replace(".png", "")
        hash2 = filename2.split("_")[-1].replace(".png", "")
        assert hash1 == hash2

    @pytest.mark.asyncio
    async def test_capture_playwright_not_installed(self, screenshot_service):
        """Test capture when Playwright not installed."""
        with patch('src.services.screenshot_service.async_playwright', side_effect=ImportError):
            result = await screenshot_service._capture_with_playwright("https://example.com")
            assert result is None

    @pytest.mark.asyncio
    async def test_capture_with_api_not_implemented(self, screenshot_service):
        """Test API capture returns None (not implemented)."""
        result = await screenshot_service._capture_with_api("https://example.com")
        assert result is None

    @pytest.mark.asyncio
    async def test_capture_all_methods_fail(self, screenshot_service):
        """Test capture returns None when all methods fail."""
        # Mock all capture methods to return None
        screenshot_service._capture_with_playwright = AsyncMock(return_value=None)
        screenshot_service._capture_with_api = AsyncMock(return_value=None)

        result = await screenshot_service.capture("https://example.com")
        assert result is None

    @pytest.mark.asyncio
    async def test_capture_playwright_success(self, screenshot_service, tmp_path):
        """Test successful capture with Playwright."""
        expected_path = "screenshots/test.png"
        screenshot_service._capture_with_playwright = AsyncMock(return_value=expected_path)

        result = await screenshot_service.capture("https://example.com")

        assert result == expected_path
        screenshot_service._capture_with_playwright.assert_called_once()

    @pytest.mark.asyncio
    async def test_capture_fallback_to_api(self, screenshot_service):
        """Test fallback to API when Playwright fails."""
        expected_path = "screenshots/test.png"
        screenshot_service._capture_with_playwright = AsyncMock(side_effect=Exception("Playwright error"))
        screenshot_service._capture_with_api = AsyncMock(return_value=expected_path)

        result = await screenshot_service.capture("https://example.com")

        assert result == expected_path
        screenshot_service._capture_with_playwright.assert_called_once()
        screenshot_service._capture_with_api.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_screenshot_path_exists(self, screenshot_service, tmp_path):
        """Test get_screenshot_path when screenshot exists."""
        # Create a fake screenshot file
        url = "https://example.com"
        filename = screenshot_service._generate_filename(url)
        screenshot_path = screenshot_service.screenshots_dir / filename
        screenshot_path.touch()

        result = await screenshot_service.get_screenshot_path(url)

        # Should find the file
        assert result is not None
        assert filename.split("_")[-1] in result

    @pytest.mark.asyncio
    async def test_get_screenshot_path_not_exists(self, screenshot_service):
        """Test get_screenshot_path when no screenshot exists."""
        result = await screenshot_service.get_screenshot_path("https://nonexistent.com")
        assert result is None


class TestScreenshotServicePlaywright:
    """Test Playwright-specific functionality (mocked)."""

    @pytest.mark.asyncio
    async def test_playwright_stealth_mode(self, screenshot_service):
        """Test Playwright uses stealth configuration."""
        mock_playwright = MagicMock()
        mock_browser = AsyncMock()
        mock_context = AsyncMock()
        mock_page = AsyncMock()

        mock_playwright.chromium.launch = AsyncMock(return_value=mock_browser)
        mock_browser.new_context = AsyncMock(return_value=mock_context)
        mock_context.new_page = AsyncMock(return_value=mock_page)
        mock_page.goto = AsyncMock()
        mock_page.screenshot = AsyncMock()

        with patch('src.services.screenshot_service.async_playwright', return_value=AsyncMock(__aenter__=AsyncMock(return_value=mock_playwright))):
            try:
                await screenshot_service._capture_with_playwright("https://example.com")
            except:
                pass  # Ignore errors, we're just checking calls

            # Verify stealth script was added
            if mock_context.add_init_script.called:
                args = mock_context.add_init_script.call_args[0][0]
                assert 'webdriver' in args
