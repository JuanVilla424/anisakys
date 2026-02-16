"""Minimal Sprint 2 validation - tests core functionality."""

import asyncio
from decimal import Decimal
from unittest.mock import AsyncMock, MagicMock, patch


async def test_scan_model_fields():
    """Test that Scan can be created with correct fields."""
    from src.models.scan import Scan
    import hashlib

    # Create a scan directly
    url = "https://example.com"
    url_hash = hashlib.sha256(url.encode()).hexdigest()

    scan = Scan(
        user_id=1,
        url=url,
        url_hash=url_hash,
        scan_type="manual",
        status="completed",
        domain="example.com",
        confidence_score=Decimal("75.50"),
        threat_level="medium",
        is_phishing=False,
        virustotal_result={"positives": 10, "total": 70},
        urlvoid_result={"blacklists": 5, "engines": 30},
        phishtank_result={"is_phishing": False},
        screenshot_url="screenshots/test.png",
        whois_data={"domain": "example.com", "registrar": "Test"}
    )

    # Verify all fields
    assert scan.user_id == 1
    assert scan.url == url
    assert scan.url_hash == url_hash
    assert scan.scan_type == "manual"
    assert scan.status == "completed"
    assert scan.domain == "example.com"
    assert scan.confidence_score == Decimal("75.50")
    assert scan.threat_level == "medium"
    assert scan.is_phishing is False
    assert scan.virustotal_result["positives"] == 10
    assert scan.urlvoid_result["blacklists"] == 5
    assert scan.phishtank_result["is_phishing"] is False
    assert scan.screenshot_url == "screenshots/test.png"
    assert scan.whois_data["domain"] == "example.com"

    print("✅ Scan model fields test PASSED")


async def test_scanning_service_integration():
    """Test ScanningService with all mocked dependencies."""
    from src.services.scanning_service import ScanningService

    # Create fully mocked service
    mock_db = AsyncMock()
    mock_db.add = MagicMock()
    mock_db.commit = AsyncMock()
    mock_db.refresh = AsyncMock()

    # Create mock API clients with AsyncMock
    from src.integrations import VirusTotalClient, URLVoidClient, PhishTankClient
    from src.services.screenshot_service import ScreenshotService
    from src.services.whois_service import WHOISService

    with patch.object(VirusTotalClient, 'scan_url', new=AsyncMock(return_value={"positives": 15, "total": 70})), \
         patch.object(URLVoidClient, 'check_reputation', new=AsyncMock(return_value={"blacklists": 3, "engines": 30})), \
         patch.object(PhishTankClient, 'check_url', new=AsyncMock(return_value={"is_phishing": True, "verified": True})), \
         patch.object(ScreenshotService, 'capture', new=AsyncMock(return_value="screenshots/test.png")), \
         patch.object(WHOISService, 'lookup', new=AsyncMock(return_value={"domain": "example.com", "registrar": "Test Registrar"})):

        service = ScanningService(db=mock_db)
        await service.scan_url("https://example.com/page", user_id=100)

        # Verify scan was saved
        assert mock_db.add.called, "db.add should be called"
        assert mock_db.commit.called, "db.commit should be called"

        # Get scan
        scan = mock_db.add.call_args[0][0]

        # Verify scan fields
        assert scan.url == "https://example.com/page"
        assert scan.user_id == 100
        assert scan.scan_type == "manual"
        assert scan.domain == "example.com"
        assert scan.virustotal_result is not None
        assert scan.urlvoid_result is not None
        assert scan.phishtank_result is not None
        assert scan.screenshot_url == "screenshots/test.png"
        assert scan.whois_data is not None
        assert scan.whois_data["domain"] == "example.com"

        print("✅ Scanning service integration test PASSED")


if __name__ == "__main__":
    print("\n🚀 Sprint 2 Minimal Validation\n")

    asyncio.run(test_scan_model_fields())
    asyncio.run(test_scanning_service_integration())

    print("\n✨ ALL MINIMAL TESTS PASSED!")
    print("📊 Scan model: VALIDATED")
    print("📊 Scanning service: VALIDATED")
    print("📊 Screenshot + WHOIS integration: VALIDATED")
    print("\n🎯 SPRINT 2 CORE FUNCTIONALITY VALIDATED!")
