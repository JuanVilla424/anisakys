"""Simple Sprint 2 validation - just test the service creates scans correctly."""

import asyncio
from decimal import Decimal
from unittest.mock import AsyncMock, MagicMock


async def test_scanning_service_creates_scan_with_correct_fields():
    """Test that scanning service creates Scan with correct model fields."""
    from src.services.scanning_service import ScanningService

    # Mock database
    mock_db = AsyncMock()
    mock_db.add = MagicMock()
    mock_db.commit = AsyncMock()
    mock_db.refresh = AsyncMock()

    # Create service with default clients (they will fail but that's OK)
    service = ScanningService(db=mock_db)

    # Mock the actual API clients to avoid real API calls
    async def mock_scan_url(url):
        return {"positives": 10, "total": 70}

    async def mock_check_reputation(host):
        return {"blacklists": 5, "engines": 30}

    async def mock_check_url(url):
        return {"is_phishing": False, "verified": True}

    async def mock_capture(url):
        return None  # Gracefully fail

    async def mock_lookup(domain):
        return None  # Gracefully fail

    service.vt_client.scan_url = mock_scan_url
    service.urlvoid_client.check_reputation = mock_check_reputation
    service.phishtank_client.check_url = mock_check_url
    service.screenshot_service.capture = mock_capture
    service.whois_service.lookup = mock_lookup

    # Execute scan
    await service.scan_url("https://example.com", user_id=1)

    # Verify scan was created and saved
    assert mock_db.add.called, "db.add() should be called"
    assert mock_db.commit.called, "db.commit() should be called"

    # Get the scan object that was added
    scan = mock_db.add.call_args[0][0]

    # Verify required fields are present
    assert scan.url == "https://example.com", f"url should be https://example.com, got {scan.url}"
    assert scan.user_id == 1, f"user_id should be 1, got {scan.user_id}"
    assert scan.url_hash is not None, "url_hash should not be None"
    assert scan.scan_type == "manual", f"scan_type should be 'manual', got {scan.scan_type}"
    assert scan.status == "completed", f"status should be 'completed', got {scan.status}"
    assert scan.domain == "example.com", f"domain should be 'example.com', got {scan.domain}"

    # Verify confidence score
    assert scan.confidence_score is not None, "confidence_score should not be None"
    assert isinstance(scan.confidence_score, Decimal), f"confidence_score should be Decimal, got {type(scan.confidence_score)}"
    assert scan.confidence_score >= 0, f"confidence_score should be >= 0, got {scan.confidence_score}"

    # Verify threat level
    assert scan.threat_level in ["safe", "low", "medium", "high", "critical"], f"Invalid threat_level: {scan.threat_level}"

    # Verify API results are stored in JSONB fields
    assert scan.virustotal_result is not None, "virustotal_result should not be None"
    assert scan.urlvoid_result is not None, "urlvoid_result should not be None"
    assert scan.phishtank_result is not None, "phishtank_result should not be None"

    # Verify API result values
    assert scan.virustotal_result["positives"] == 10, f"Expected VT positives 10, got {scan.virustotal_result.get('positives')}"
    assert scan.urlvoid_result["blacklists"] == 5, f"Expected UV blacklists 5, got {scan.urlvoid_result.get('blacklists')}"
    assert scan.phishtank_result["is_phishing"] is False, f"Expected PT is_phishing False, got {scan.phishtank_result.get('is_phishing')}"

    # Verify screenshot and WHOIS gracefully degraded
    assert scan.screenshot_url is None, f"screenshot_url should be None (graceful degradation), got {scan.screenshot_url}"
    assert scan.whois_data is None, f"whois_data should be None (graceful degradation), got {scan.whois_data}"

    print("✅ Scanning service creates Scan with correct fields PASSED")


async def test_scanning_service_with_screenshot_and_whois():
    """Test that scanning service saves screenshot and WHOIS when available."""
    from src.services.scanning_service import ScanningService

    # Mock database
    mock_db = AsyncMock()
    mock_db.add = MagicMock()
    mock_db.commit = AsyncMock()
    mock_db.refresh = AsyncMock()

    # Create service
    service = ScanningService(db=mock_db)

    # Mock the clients with successful responses
    async def mock_scan_url(url):
        return {"positives": 15, "total": 70}

    async def mock_check_reputation(host):
        return {"blacklists": 2, "engines": 30}

    async def mock_check_url(url):
        return {"is_phishing": True, "verified": True}

    async def mock_capture(url):
        return "screenshots/test_example.png"  # Success

    async def mock_lookup(domain):
        return {
            "domain": "example.com",
            "registrar": "Example Registrar",
            "creation_date": "2020-01-01T00:00:00",
            "abuse_email": "abuse@example.com"
        }

    service.vt_client.scan_url = mock_scan_url
    service.urlvoid_client.check_reputation = mock_check_reputation
    service.phishtank_client.check_url = mock_check_url
    service.screenshot_service.capture = mock_capture
    service.whois_service.lookup = mock_lookup

    # Execute scan
    await service.scan_url("https://example.com/page", user_id=42)

    # Get the scan object
    scan = mock_db.add.call_args[0][0]

    # Verify screenshot was saved
    assert scan.screenshot_url == "screenshots/test_example.png", f"Expected screenshot_url, got {scan.screenshot_url}"

    # Verify WHOIS was saved
    assert scan.whois_data is not None, "whois_data should not be None"
    assert scan.whois_data["domain"] == "example.com", f"Expected WHOIS domain 'example.com', got {scan.whois_data.get('domain')}"
    assert scan.whois_data["registrar"] == "Example Registrar", f"Expected registrar, got {scan.whois_data.get('registrar')}"

    # Verify is_phishing is set correctly
    assert scan.is_phishing is True, f"Expected is_phishing True, got {scan.is_phishing}"

    print("✅ Scanning service with screenshot and WHOIS PASSED")


if __name__ == "__main__":
    print("\n🚀 Sprint 2 Simple Validation\n")

    asyncio.run(test_scanning_service_creates_scan_with_correct_fields())
    asyncio.run(test_scanning_service_with_screenshot_and_whois())

    print("\n✨ ALL SPRINT 2 SIMPLE TESTS PASSED!")
    print("📊 Scan model fields: VALIDATED")
    print("📊 API results storage: VALIDATED")
    print("📊 Screenshot integration: VALIDATED")
    print("📊 WHOIS integration: VALIDATED")
    print("⚡ Graceful degradation: VALIDATED")
    print("\n🎯 SPRINT 2 READY FOR VALIDATION!")
