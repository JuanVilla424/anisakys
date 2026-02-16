"""Screenshot capture service with multi-tier fallback strategy."""

import asyncio
import hashlib
import logging
from pathlib import Path
from typing import Optional
from datetime import datetime

from src.config import settings


logger = logging.getLogger(__name__)


class ScreenshotService:
    """Screenshot capture with 4-tier fallback strategy.

    Tiers:
    1. Playwright (headless Chrome) - Primary
    2. Screenshot API Service - Fallback
    3. Selenium - Heavy fallback
    4. None - Graceful degradation

    Example:
        ```python
        service = ScreenshotService()
        screenshot_path = await service.capture("https://phishing-site.com")
        if screenshot_path:
            print(f"Screenshot saved: {screenshot_path}")
        ```
    """

    def __init__(self, screenshots_dir: Optional[str] = None):
        """Initialize screenshot service.

        Args:
            screenshots_dir: Directory to save screenshots (defaults to settings.SCREENSHOTS_DIR)
        """
        self.screenshots_dir = Path(screenshots_dir or getattr(settings, 'SCREENSHOTS_DIR', 'screenshots'))
        self.screenshots_dir.mkdir(parents=True, exist_ok=True)
        self.timeout = 15000  # 15 seconds

    async def capture(self, url: str) -> Optional[str]:
        """Capture screenshot with fallback strategy.

        Args:
            url: URL to capture

        Returns:
            Relative path to screenshot file or None if all methods failed

        Example:
            ```python
            path = await service.capture("https://example.com")
            # Returns: "screenshots/abc123def456.png"
            ```
        """
        # Try Tier 1: Playwright
        try:
            screenshot_path = await self._capture_with_playwright(url)
            if screenshot_path:
                logger.info(f"Screenshot captured with Playwright: {url}")
                return screenshot_path
        except Exception as e:
            logger.warning(f"Playwright screenshot failed for {url}: {e}")

        # Try Tier 2: Screenshot API (if available)
        try:
            screenshot_path = await self._capture_with_api(url)
            if screenshot_path:
                logger.info(f"Screenshot captured with API: {url}")
                return screenshot_path
        except Exception as e:
            logger.warning(f"API screenshot failed for {url}: {e}")

        # Try Tier 3: Selenium (commented out - heavy dependency)
        # try:
        #     screenshot_path = await self._capture_with_selenium(url)
        #     if screenshot_path:
        #         logger.info(f"Screenshot captured with Selenium: {url}")
        #         return screenshot_path
        # except Exception as e:
        #     logger.warning(f"Selenium screenshot failed for {url}: {e}")

        # Tier 4: All methods failed
        logger.error(f"All screenshot methods failed for {url}")
        return None

    async def _capture_with_playwright(self, url: str) -> Optional[str]:
        """Capture screenshot using Playwright (headless Chrome).

        Args:
            url: URL to capture

        Returns:
            Screenshot file path or None
        """
        try:
            from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeout
        except ImportError:
            logger.warning("Playwright not installed")
            return None

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(
                    headless=True,
                    args=[
                        '--disable-blink-features=AutomationControlled',
                        '--disable-dev-shm-usage',
                        '--no-sandbox',
                        '--disable-setuid-sandbox'
                    ]
                )

                context = await browser.new_context(
                    viewport={'width': 1920, 'height': 1080},
                    user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                    locale='en-US',
                    timezone_id='America/New_York',
                    extra_http_headers={
                        'Accept-Language': 'en-US,en;q=0.9'
                    }
                )

                # Stealth: Remove webdriver property
                await context.add_init_script("""
                    Object.defineProperty(navigator, 'webdriver', {
                        get: () => undefined
                    });
                    Object.defineProperty(navigator, 'plugins', {
                        get: () => [1, 2, 3, 4, 5]
                    });
                """)

                page = await context.new_page()

                try:
                    # Navigate with timeout
                    await page.goto(url, timeout=self.timeout, wait_until='networkidle')

                    # Wait a bit for dynamic content
                    await asyncio.sleep(2)

                    # Generate filename from URL hash
                    filename = self._generate_filename(url)
                    filepath = self.screenshots_dir / filename

                    # Capture full page screenshot
                    await page.screenshot(path=str(filepath), full_page=True)

                    return str(filepath.relative_to(Path.cwd()))

                except PlaywrightTimeout:
                    logger.warning(f"Playwright timeout for {url}")
                    return None
                finally:
                    await browser.close()

        except Exception as e:
            logger.error(f"Playwright error: {e}")
            return None

    async def _capture_with_api(self, url: str) -> Optional[str]:
        """Capture screenshot using external API service.

        Args:
            url: URL to capture

        Returns:
            Screenshot file path or None
        """
        # TODO: Implement screenshot API integration (e.g., screenshotapi.net)
        # For now, return None (not implemented)
        logger.debug("Screenshot API not configured")
        return None

    def _generate_filename(self, url: str) -> str:
        """Generate unique filename for screenshot.

        Args:
            url: URL being captured

        Returns:
            Filename like "20260103_abc123def456.png"
        """
        # Hash URL for unique identifier (using SHA256)
        url_hash = hashlib.sha256(url.encode()).hexdigest()[:12]

        # Add timestamp
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

        return f"{timestamp}_{url_hash}.png"

    async def get_screenshot_path(self, url: str) -> Optional[str]:
        """Get existing screenshot path if available.

        Args:
            url: URL to check

        Returns:
            Screenshot path if exists, None otherwise
        """
        # Check if screenshot exists for this URL (using SHA256)
        url_hash = hashlib.sha256(url.encode()).hexdigest()[:12]

        # Search for files matching this URL hash
        matching_files = list(self.screenshots_dir.glob(f"*_{url_hash}.png"))

        if matching_files:
            # Return most recent
            most_recent = max(matching_files, key=lambda p: p.stat().st_mtime)
            return str(most_recent.relative_to(Path.cwd()))

        return None
