"""Integration tests for scanning service with screenshot and WHOIS."""

import pytest
from unittest.mock import AsyncMock, MagicMock
from datetime import datetime

from src.services.scanning_service import ScanningService
from src.services.screenshot_service import ScreenshotService
from src.services.whois_service import WHOISService


@pytest.fixture
def mock_db():
    """Mock database session."""
    db = AsyncMock()
    db.add = MagicMock()
    db.commit = AsyncMock()
    db.refresh = AsyncMock()
    return db


@pytest.fixture
def mock_screenshot_service():
    """Mock screenshot service."""
    service = AsyncMock(spec=ScreenshotService)
    service.capture = AsyncMock()
    return service


@pytest.fixture
def mock_whois_service():
    """Mock WHOIS service."""
    service = AsyncMock(spec=WHOISService)
    service.lookup = AsyncMock()
    return service


@pytest.fixture
def scanning_service_with_mocks(mock_db, mock_screenshot_service, mock_whois_service):
    """Create scanning service with mocked dependencies."""
    from src.integrations import VirusTotalClient, URLVoidClient, PhishTankClient

    mock_vt = AsyncMock(spec=VirusTotalClient)
    mock_vt.scan_url = AsyncMock()

    mock_uv = AsyncMock(spec=URLVoidClient)
    mock_uv.check_reputation = AsyncMock()

    mock_pt = AsyncMock(spec=PhishTankClient)
    mock_pt.check_url = AsyncMock()

    return ScanningService(
        db=mock_db,
        vt_client=mock_vt,
        urlvoid_client=mock_uv,
        phishtank_client=mock_pt,
        screenshot_service=mock_screenshot_service,
        whois_service=mock_whois_service
    )


class TestScanningWithScreenshot:
    """Test scanning service with screenshot capture."""

    @pytest.mark.asyncio
    async def test_scan_includes_screenshot(self, scanning_service_with_mocks, mock_screenshot_service):
        """Test scan captures screenshot."""
        # Setup mocks
        scanning_service_with_mocks.vt_client.scan_url.return_value = {"positives": 10, "total": 70}
        scanning_service_with_mocks.urlvoid_client.check_reputation.return_value = {"blacklists": 5, "engines": 30}
        scanning_service_with_mocks.phishtank_client.check_url.return_value = {"is_phishing": False, "verified": False}
        mock_screenshot_service.capture.return_value = "screenshots/test.png"

        # Execute scan
        await scanning_service_with_mocks.scan_url("https://example.com", user_id=1)

        # Verify screenshot was captured
        mock_screenshot_service.capture.assert_called_once_with("https://example.com")

        # Verify scan was saved with screenshot
        assert scanning_service_with_mocks.db.add.called
        scan_arg = scanning_service_with_mocks.db.add.call_args[0][0]
        assert scan_arg.screenshot_url == "screenshots/test.png"

    @pytest.mark.asyncio
    async def test_scan_continues_if_screenshot_fails(self, scanning_service_with_mocks, mock_screenshot_service):
        """Test scan continues even if screenshot fails."""
        # Setup mocks
        scanning_service_with_mocks.vt_client.scan_url.return_value = {"positives": 10, "total": 70}
        scanning_service_with_mocks.urlvoid_client.check_reputation.return_value = {"blacklists": 5, "engines": 30}
        scanning_service_with_mocks.phishtank_client.check_url.return_value = {"is_phishing": False, "verified": False}
        mock_screenshot_service.capture.return_value = None  # Screenshot failed

        # Execute scan - should NOT raise exception
        await scanning_service_with_mocks.scan_url("https://example.com", user_id=1)

        # Verify scan was still saved
        assert scanning_service_with_mocks.db.add.called
        scan_arg = scanning_service_with_mocks.db.add.call_args[0][0]
        assert scan_arg.screenshot_url is None


class TestScanningWithWHOIS:
    """Test scanning service with WHOIS lookup."""

    @pytest.mark.asyncio
    async def test_scan_includes_whois(self, scanning_service_with_mocks, mock_whois_service):
        """Test scan performs WHOIS lookup."""
        # Setup mocks
        scanning_service_with_mocks.vt_client.scan_url.return_value = {"positives": 10, "total": 70}
        scanning_service_with_mocks.urlvoid_client.check_reputation.return_value = {"blacklists": 5, "engines": 30}
        scanning_service_with_mocks.phishtank_client.check_url.return_value = {"is_phishing": False, "verified": False}

        whois_data = {
            "domain": "example.com",
            "registrar": "Example Registrar",
            "creation_date": "2020-01-01T00:00:00",
            "abuse_email": "abuse@registrar.com"
        }
        mock_whois_service.lookup.return_value = whois_data

        # Execute scan
        await scanning_service_with_mocks.scan_url("https://example.com", user_id=1)

        # Verify WHOIS was looked up
        mock_whois_service.lookup.assert_called_once_with("example.com")

        # Verify scan was saved with WHOIS data
        assert scanning_service_with_mocks.db.add.called
        scan_arg = scanning_service_with_mocks.db.add.call_args[0][0]
        assert scan_arg.whois_data == whois_data

    @pytest.mark.asyncio
    async def test_scan_continues_if_whois_fails(self, scanning_service_with_mocks, mock_whois_service):
        """Test scan continues even if WHOIS fails."""
        # Setup mocks
        scanning_service_with_mocks.vt_client.scan_url.return_value = {"positives": 10, "total": 70}
        scanning_service_with_mocks.urlvoid_client.check_reputation.return_value = {"blacklists": 5, "engines": 30}
        scanning_service_with_mocks.phishtank_client.check_url.return_value = {"is_phishing": False, "verified": False}
        mock_whois_service.lookup.return_value = None  # WHOIS failed

        # Execute scan - should NOT raise exception
        await scanning_service_with_mocks.scan_url("https://example.com", user_id=1)

        # Verify scan was still saved
        assert scanning_service_with_mocks.db.add.called
        scan_arg = scanning_service_with_mocks.db.add.call_args[0][0]
        assert scan_arg.whois_data is None


class TestScanningFullPipeline:
    """Test complete scanning pipeline with all features."""

    @pytest.mark.asyncio
    async def test_full_scan_pipeline(self, scanning_service_with_mocks, mock_screenshot_service, mock_whois_service):
        """Test complete scan with all APIs + screenshot + WHOIS."""
        # Setup all mocks
        scanning_service_with_mocks.vt_client.scan_url.return_value = {"positives": 35, "total": 70}
        scanning_service_with_mocks.urlvoid_client.check_reputation.return_value = {"blacklists": 10, "engines": 30}
        scanning_service_with_mocks.phishtank_client.check_url.return_value = {"is_phishing": True, "verified": True}
        mock_screenshot_service.capture.return_value = "screenshots/20260103_abc123.png"
        mock_whois_service.lookup.return_value = {
            "domain": "phishing-site.com",
            "registrar": "Suspicious Registrar",
            "creation_date": "2026-01-01T00:00:00",
            "abuse_email": "abuse@registrar.com"
        }

        # Execute scan
        await scanning_service_with_mocks.scan_url("https://phishing-site.com", user_id=123)

        # Verify ALL components were called
        scanning_service_with_mocks.vt_client.scan_url.assert_called_once()
        scanning_service_with_mocks.urlvoid_client.check_reputation.assert_called_once()
        scanning_service_with_mocks.phishtank_client.check_url.assert_called_once()
        mock_screenshot_service.capture.assert_called_once()
        mock_whois_service.lookup.assert_called_once()

        # Verify scan was saved with ALL data
        assert scanning_service_with_mocks.db.add.called
        scan_arg = scanning_service_with_mocks.db.add.call_args[0][0]

        assert scan_arg.url == "https://phishing-site.com"
        assert scan_arg.user_id == 123
        assert scan_arg.virustotal_result["positives"] == 35
        assert scan_arg.urlvoid_result["blacklists"] == 10
        assert scan_arg.phishtank_result["is_phishing"] is True
        assert scan_arg.screenshot_url == "screenshots/20260103_abc123.png"
        assert scan_arg.whois_data["domain"] == "phishing-site.com"
        assert scan_arg.confidence_score > 0

    @pytest.mark.asyncio
    async def test_parallel_execution(self, scanning_service_with_mocks, mock_screenshot_service, mock_whois_service):
        """Test that APIs, screenshot, and WHOIS execute in parallel."""
        import asyncio

        # Setup mocks with delays to verify parallel execution
        async def delayed_vt():
            await asyncio.sleep(0.1)
            return {"positives": 10, "total": 70}

        async def delayed_screenshot():
            await asyncio.sleep(0.1)
            return "screenshots/test.png"

        async def delayed_whois():
            await asyncio.sleep(0.1)
            return {"domain": "example.com"}

        scanning_service_with_mocks.vt_client.scan_url = delayed_vt
        scanning_service_with_mocks.urlvoid_client.check_reputation.return_value = {"blacklists": 0, "engines": 30}
        scanning_service_with_mocks.phishtank_client.check_url.return_value = {"is_phishing": False}
        mock_screenshot_service.capture = delayed_screenshot
        mock_whois_service.lookup = delayed_whois

        # Measure execution time
        start = asyncio.get_event_loop().time()
        await scanning_service_with_mocks.scan_url("https://example.com", user_id=1)
        duration = asyncio.get_event_loop().time() - start

        # If truly parallel, should be ~0.1s, not 0.5s (0.1 * 5)
        # Allow some overhead
        assert duration < 0.3, f"Not parallel! Took {duration}s"
