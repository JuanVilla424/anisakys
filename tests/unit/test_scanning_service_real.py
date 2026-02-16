"""Unit tests for ScanningService."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime

from src.services.scanning_service import ScanningService
from src.models.scan import Scan


@pytest.fixture
def mock_db():
    """Mock database session."""
    db = AsyncMock()
    db.add = MagicMock()
    db.commit = AsyncMock()
    db.refresh = AsyncMock()
    db.execute = AsyncMock()
    return db


@pytest.fixture
def mock_vt_client():
    """Mock VirusTotal client."""
    client = AsyncMock()
    client.scan_url = AsyncMock()
    return client


@pytest.fixture
def mock_urlvoid_client():
    """Mock URLVoid client."""
    client = AsyncMock()
    client.check_reputation = AsyncMock()
    return client


@pytest.fixture
def mock_phishtank_client():
    """Mock PhishTank client."""
    client = AsyncMock()
    client.check_url = AsyncMock()
    return client


@pytest.fixture
def scanning_service(mock_db, mock_vt_client, mock_urlvoid_client, mock_phishtank_client):
    """Create ScanningService with mocked clients."""
    return ScanningService(
        db=mock_db,
        vt_client=mock_vt_client,
        urlvoid_client=mock_urlvoid_client,
        phishtank_client=mock_phishtank_client
    )


class TestScanURL:
    """Test URL scanning."""

    @pytest.mark.asyncio
    async def test_scan_url_all_apis_success(self, scanning_service, mock_vt_client, mock_urlvoid_client, mock_phishtank_client, mock_db):
        """Scan with all APIs responding successfully."""
        # Setup mock responses
        mock_vt_client.scan_url.return_value = {"positives": 35, "total": 70}
        mock_urlvoid_client.check_reputation.return_value = {"blacklists": 10, "engines": 30}
        mock_phishtank_client.check_url.return_value = {"is_phishing": False, "verified": False}

        # Execute scan
        scan = await scanning_service.scan_url(
            url="https://suspicious-site.com",
            user_id=123
        )

        # Verify API calls
        mock_vt_client.scan_url.assert_called_once_with("https://suspicious-site.com")
        mock_urlvoid_client.check_reputation.assert_called_once_with("suspicious-site.com")
        mock_phishtank_client.check_url.assert_called_once_with("https://suspicious-site.com")

        # Verify database save
        mock_db.add.assert_called_once()
        mock_db.commit.assert_called_once()
        assert isinstance(scan, Scan)
        assert scan.url == "https://suspicious-site.com"
        assert scan.user_id == 123

    @pytest.mark.asyncio
    async def test_scan_url_partial_api_failure(self, scanning_service, mock_vt_client, mock_urlvoid_client, mock_phishtank_client):
        """Scan with one API failing."""
        mock_vt_client.scan_url.return_value = {"positives": 35, "total": 70}
        mock_urlvoid_client.check_reputation.return_value = None  # Failed
        mock_phishtank_client.check_url.return_value = {"is_phishing": False, "verified": False}

        scan = await scanning_service.scan_url(
            url="https://test.com",
            user_id=123
        )

        assert isinstance(scan, Scan)
        # Should still create scan with available data
        assert scan.virustotal_positives == 35
        assert scan.urlvoid_blacklists is None

    @pytest.mark.asyncio
    async def test_scan_url_invalid_url(self, scanning_service):
        """Scan with invalid URL."""
        with pytest.raises(ValueError, match="Invalid URL"):
            await scanning_service.scan_url(
                url="not-a-valid-url",
                user_id=123
            )

    @pytest.mark.asyncio
    async def test_scan_url_no_protocol(self, scanning_service):
        """Scan with URL missing protocol."""
        with pytest.raises(ValueError, match="Invalid URL"):
            await scanning_service.scan_url(
                url="example.com",
                user_id=123
            )


class TestURLValidation:
    """Test URL validation logic."""

    @pytest.fixture
    def service(self, mock_db):
        return ScanningService(db=mock_db)

    def test_validate_url_valid_https(self, service):
        """Valid HTTPS URL."""
        parsed = service._validate_url("https://example.com")
        assert parsed is not None
        assert parsed.scheme == "https"
        assert parsed.netloc == "example.com"

    def test_validate_url_valid_http(self, service):
        """Valid HTTP URL."""
        parsed = service._validate_url("http://example.com")
        assert parsed is not None

    def test_validate_url_with_path(self, service):
        """Valid URL with path."""
        parsed = service._validate_url("https://example.com/path/to/page")
        assert parsed is not None
        assert parsed.path == "/path/to/page"

    def test_validate_url_missing_protocol(self, service):
        """Invalid URL missing protocol."""
        parsed = service._validate_url("example.com")
        assert parsed is None

    def test_validate_url_invalid_protocol(self, service):
        """Invalid URL with wrong protocol."""
        parsed = service._validate_url("ftp://example.com")
        assert parsed is None

    def test_validate_url_empty(self, service):
        """Empty URL."""
        parsed = service._validate_url("")
        assert parsed is None


class TestCaching:
    """Test scan caching logic."""

    @pytest.mark.asyncio
    async def test_recent_scan_returned_if_cached(self, scanning_service, mock_db):
        """Return recent scan if exists and not force_rescan."""
        # Mock recent scan exists
        recent_scan = Scan(
            id=1,
            user_id=123,
            url="https://example.com",
            host="example.com",
            confidence_score=50.0,
            threat_level="suspicious",
            scanned_at=datetime.utcnow()
        )

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = recent_scan
        mock_db.execute.return_value = mock_result

        scan = await scanning_service.scan_url(
            url="https://example.com",
            user_id=123,
            force_rescan=False
        )

        # Should return cached scan
        assert scan == recent_scan
        # Should not call APIs
        assert not scanning_service.vt_client.scan_url.called


class TestGetScanByID:
    """Test retrieving scan by ID."""

    @pytest.mark.asyncio
    async def test_get_scan_by_id_exists(self, scanning_service, mock_db):
        """Get scan by ID when it exists."""
        scan = Scan(
            id=1,
            user_id=123,
            url="https://example.com",
            host="example.com",
            confidence_score=75.0,
            threat_level="malicious",
            scanned_at=datetime.utcnow()
        )

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = scan
        mock_db.execute.return_value = mock_result

        result = await scanning_service.get_scan_by_id(1, 123)
        assert result == scan

    @pytest.mark.asyncio
    async def test_get_scan_by_id_not_found(self, scanning_service, mock_db):
        """Get scan by ID when it doesn't exist."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db.execute.return_value = mock_result

        result = await scanning_service.get_scan_by_id(999, 123)
        assert result is None


class TestGetUserScans:
    """Test retrieving user scan history."""

    @pytest.mark.asyncio
    async def test_get_user_scans(self, scanning_service, mock_db):
        """Get user's scan history."""
        scans = [
            Scan(id=1, user_id=123, url="https://site1.com", host="site1.com", confidence_score=25.0, threat_level="suspicious", scanned_at=datetime.utcnow()),
            Scan(id=2, user_id=123, url="https://site2.com", host="site2.com", confidence_score=80.0, threat_level="malicious", scanned_at=datetime.utcnow()),
        ]

        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = scans
        mock_db.execute.return_value = mock_result

        result = await scanning_service.get_user_scans(user_id=123, limit=50, offset=0)
        assert len(result) == 2
        assert result == scans
