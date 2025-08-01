"""
Screenshot service for ICANN compliance - captures visual evidence of phishing sites
"""

import asyncio
import logging
import os
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any
from urllib.parse import urlparse

try:
    from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeoutError

    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options as ChromeOptions
    from selenium.webdriver.firefox.options import Options as FirefoxOptions
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.common.exceptions import TimeoutException, WebDriverException

    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

logger = logging.getLogger(__name__)


class ScreenshotService:
    """Service for capturing screenshots of phishing sites"""

    def __init__(self, screenshots_dir: str = None, timeout: int = 30):
        """
        Initialize screenshot service

        Args:
            screenshots_dir: Directory to save screenshots
            timeout: Page load timeout in seconds
        """
        self.timeout = timeout
        self.screenshots_dir = (
            Path(screenshots_dir)
            if screenshots_dir
            else Path(tempfile.gettempdir()) / "anisakys_screenshots"
        )
        self.screenshots_dir.mkdir(parents=True, exist_ok=True)

        # Prefer Playwright over Selenium for better reliability
        self.preferred_engine = (
            "playwright" if PLAYWRIGHT_AVAILABLE else "selenium" if SELENIUM_AVAILABLE else None
        )

        if not self.preferred_engine:
            logger.warning(
                "Neither Playwright nor Selenium available. Screenshot functionality disabled."
            )

    async def capture_screenshot_async(
        self, url: str, filename: str = None
    ) -> Optional[Dict[str, Any]]:
        """
        Capture screenshot using Playwright (async)

        Args:
            url: URL to capture
            filename: Optional filename (auto-generated if not provided)

        Returns:
            Dict with screenshot info or None if failed
        """
        if not PLAYWRIGHT_AVAILABLE:
            logger.error("Playwright not available for async screenshot capture")
            return None

        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            domain = urlparse(url).netloc.replace(".", "_")
            filename = f"phishing_{domain}_{timestamp}.png"

        screenshot_path = self.screenshots_dir / filename

        try:
            async with async_playwright() as p:
                # Use Chromium for better compatibility
                browser = await p.chromium.launch(
                    headless=True,
                    args=[
                        "--no-sandbox",
                        "--disable-dev-shm-usage",
                        "--disable-gpu",
                        "--disable-web-security",
                        "--disable-features=VizDisplayCompositor",
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
                        "--enable-features=NetworkService,NetworkServiceInProcess",
                        "--force-color-profile=srgb",
                        "--metrics-recording-only",
                        "--use-mock-keychain",
                    ],
                )

                context = await browser.new_context(
                    viewport={"width": 1920, "height": 1080},
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                    extra_http_headers={
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                        "Accept-Language": "en-US,en;q=0.9",
                        "Accept-Encoding": "gzip, deflate, br",
                        "DNT": "1",
                        "Connection": "keep-alive",
                        "Upgrade-Insecure-Requests": "1",
                        "Sec-Fetch-Dest": "document",
                        "Sec-Fetch-Mode": "navigate",
                        "Sec-Fetch-Site": "none",
                        "Sec-Fetch-User": "?1",
                        "Cache-Control": "max-age=0",
                    },
                )

                page = await context.new_page()

                # Set longer timeout for phishing sites that might be slow
                page.set_default_timeout(self.timeout * 1000)

                # Remove webdriver detection
                await page.add_init_script(
                    """
                    Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
                    delete window.cdc_adoQpoasnfa76pfcZLmcfl_Array;
                    delete window.cdc_adoQpoasnfa76pfcZLmcfl_Promise;
                    delete window.cdc_adoQpoasnfa76pfcZLmcfl_Symbol;
                """
                )

                try:
                    await page.goto(url, wait_until="domcontentloaded")

                    # Wait for dynamic content to load
                    await page.wait_for_timeout(6000)

                    # Capture full page screenshot
                    await page.screenshot(path=str(screenshot_path), full_page=True, type="png")

                    # Get page title and metadata
                    title = await page.title()
                    page_info = {
                        "title": title,
                        "url": page.url,  # Final URL after redirects
                        "timestamp": datetime.now().isoformat(),
                    }

                    logger.info(f"Screenshot captured successfully: {screenshot_path}")

                    return {
                        "success": True,
                        "screenshot_path": str(screenshot_path),
                        "filename": filename,
                        "size_bytes": screenshot_path.stat().st_size,
                        "page_info": page_info,
                        "engine": "playwright",
                    }

                except PlaywrightTimeoutError:
                    logger.error(f"Timeout capturing screenshot for {url}")
                    return {"success": False, "error": "timeout", "engine": "playwright"}

                finally:
                    await browser.close()

        except Exception as e:
            logger.error(f"Error capturing screenshot with Playwright: {e}")
            return {"success": False, "error": str(e), "engine": "playwright"}

    def capture_screenshot_sync(self, url: str, filename: str = None) -> Optional[Dict[str, Any]]:
        """
        Capture screenshot using Selenium (sync)

        Args:
            url: URL to capture
            filename: Optional filename (auto-generated if not provided)

        Returns:
            Dict with screenshot info or None if failed
        """
        if not SELENIUM_AVAILABLE:
            logger.error("Selenium not available for screenshot capture")
            return None

        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            domain = urlparse(url).netloc.replace(".", "_")
            filename = f"phishing_{domain}_{timestamp}.png"

        screenshot_path = self.screenshots_dir / filename

        # Configure Chrome options for headless operation with anti-detection measures
        chrome_options = ChromeOptions()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--window-size=1920,1080")
        chrome_options.add_argument("--disable-blink-features=AutomationControlled")
        chrome_options.add_argument("--disable-extensions")
        chrome_options.add_argument("--no-first-run")
        chrome_options.add_argument("--disable-default-apps")
        chrome_options.add_argument("--disable-component-extensions-with-background-pages")
        chrome_options.add_argument("--disable-background-timer-throttling")
        chrome_options.add_argument("--disable-backgrounding-occluded-windows")
        chrome_options.add_argument("--disable-renderer-backgrounding")
        chrome_options.add_argument("--disable-field-trial-config")
        chrome_options.add_argument("--disable-back-forward-cache")
        chrome_options.add_argument("--disable-ipc-flooding-protection")
        chrome_options.add_argument("--enable-features=NetworkService,NetworkServiceInProcess")
        chrome_options.add_argument("--force-color-profile=srgb")
        chrome_options.add_argument("--metrics-recording-only")
        chrome_options.add_argument("--use-mock-keychain")
        chrome_options.add_argument(
            "--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
        )

        # Exclude automation switches and add preferences to appear more human-like
        chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
        chrome_options.add_experimental_option("useAutomationExtension", False)
        chrome_options.add_experimental_option(
            "prefs",
            {
                "profile.default_content_setting_values.notifications": 2,
                "profile.default_content_settings.popups": 0,
                "profile.managed_default_content_settings.images": 2,
            },
        )

        driver = None
        try:
            # Try Chrome first, fallback to Firefox
            try:
                driver = webdriver.Chrome(options=chrome_options)
            except WebDriverException:
                logger.warning("Chrome WebDriver not available, trying Firefox")
                firefox_options = FirefoxOptions()
                firefox_options.add_argument("--headless")
                driver = webdriver.Firefox(options=firefox_options)

            driver.set_page_load_timeout(self.timeout)
            driver.implicitly_wait(5)

            # Execute JavaScript to remove webdriver detection
            driver.execute_script(
                "Object.defineProperty(navigator, 'webdriver', {get: () => undefined})"
            )
            driver.execute_script("delete window.cdc_adoQpoasnfa76pfcZLmcfl_Array")
            driver.execute_script("delete window.cdc_adoQpoasnfa76pfcZLmcfl_Promise")
            driver.execute_script("delete window.cdc_adoQpoasnfa76pfcZLmcfl_Symbol")

            # Navigate to the URL
            driver.get(url)

            # Wait for page to load
            WebDriverWait(driver, 5).until(EC.presence_of_element_located((By.TAG_NAME, "body")))

            # Wait 6 seconds for dynamic content to load
            import time

            time.sleep(6)

            # Get page info
            title = driver.title
            final_url = driver.current_url

            # Take screenshot
            driver.save_screenshot(str(screenshot_path))

            logger.info(f"Screenshot captured successfully: {screenshot_path}")

            return {
                "success": True,
                "screenshot_path": str(screenshot_path),
                "filename": filename,
                "size_bytes": screenshot_path.stat().st_size,
                "page_info": {
                    "title": title,
                    "url": final_url,
                    "timestamp": datetime.now().isoformat(),
                },
                "engine": "selenium",
            }

        except TimeoutException:
            logger.error(f"Timeout capturing screenshot for {url}")
            return {"success": False, "error": "timeout", "engine": "selenium"}

        except Exception as e:
            logger.error(f"Error capturing screenshot with Selenium: {e}")
            return {"success": False, "error": str(e), "engine": "selenium"}

        finally:
            if driver:
                driver.quit()

    def capture_screenshot(
        self, url: str, filename: str = None, use_async: bool = True
    ) -> Optional[Dict[str, Any]]:
        """
        Capture screenshot of a phishing site

        Args:
            url: URL to capture
            filename: Optional filename
            use_async: Whether to use async Playwright (preferred) or sync Selenium

        Returns:
            Dict with screenshot info or None if failed
        """
        if not self.preferred_engine:
            logger.error("No screenshot engine available")
            return None

        logger.info(f"Capturing screenshot for {url}")

        # Use async Playwright if available and requested
        if use_async and PLAYWRIGHT_AVAILABLE:
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    # If we're in an async context, create a new task
                    future = asyncio.create_task(self.capture_screenshot_async(url, filename))
                    return None  # Will need to be awaited by caller
                else:
                    return loop.run_until_complete(self.capture_screenshot_async(url, filename))
            except Exception as e:
                logger.error(f"Error with async screenshot: {e}, falling back to sync")
                return self.capture_screenshot_sync(url, filename)
        else:
            return self.capture_screenshot_sync(url, filename)

    def cleanup_old_screenshots(self, days_old: int = 7):
        """
        Clean up screenshots older than specified days

        Args:
            days_old: Delete screenshots older than this many days
        """
        if not self.screenshots_dir.exists():
            return

        import time

        cutoff_time = time.time() - (days_old * 24 * 60 * 60)

        deleted_count = 0
        for screenshot_file in self.screenshots_dir.glob("*.png"):
            if screenshot_file.stat().st_mtime < cutoff_time:
                try:
                    screenshot_file.unlink()
                    deleted_count += 1
                except Exception as e:
                    logger.error(f"Error deleting old screenshot {screenshot_file}: {e}")

        if deleted_count > 0:
            logger.info(f"Cleaned up {deleted_count} old screenshots")


# Convenience function for simple usage
def capture_phishing_screenshot(
    url: str, screenshots_dir: str = None, timeout: int = 30
) -> Optional[Dict[str, Any]]:
    """
    Simple function to capture a screenshot of a phishing site

    Args:
        url: URL to capture
        screenshots_dir: Directory to save screenshot
        timeout: Timeout in seconds

    Returns:
        Dict with screenshot info or None if failed
    """
    service = ScreenshotService(screenshots_dir, timeout)
    return service.capture_screenshot(url, use_async=False)


if __name__ == "__main__":
    # Test the screenshot service
    import sys

    if len(sys.argv) != 2:
        print("Usage: python screenshot_service.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    result = capture_phishing_screenshot(url)

    if result and result["success"]:
        print(f"Screenshot saved: {result['screenshot_path']}")
        print(f"Page title: {result['page_info']['title']}")
    else:
        print(
            f"Failed to capture screenshot: {result.get('error', 'Unknown error') if result else 'Service unavailable'}"
        )
