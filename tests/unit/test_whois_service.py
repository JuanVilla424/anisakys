"""Unit tests for WHOISService."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timedelta

from src.services.whois_service import WHOISService


@pytest.fixture
def whois_service():
    """Create WHOISService instance."""
    return WHOISService(timeout=10)


@pytest.fixture
def mock_whois_data():
    """Mock WHOIS data."""
    mock = MagicMock()
    mock.domain = "example.com"
    mock.registrar = "Example Registrar LLC"
    mock.creation_date = datetime(2020, 1, 15, 10, 30, 0)
    mock.expiration_date = datetime(2027, 1, 15, 10, 30, 0)
    mock.updated_date = datetime(2025, 12, 1, 8, 15, 0)
    mock.name_servers = ["ns1.example.com", "ns2.example.com"]
    mock.registrant = "REDACTED FOR PRIVACY"
    mock.status = ["clientTransferProhibited"]
    mock.dnssec = "unsigned"
    mock.whois_server = "whois.example.com"
    mock.emails = ["abuse@example.com"]
    return mock


class TestWHOISService:
    """Test WHOISService functionality."""

    def test_init(self):
        """Test service initialization."""
        service = WHOISService(timeout=15)
        assert service.timeout == 15

    def test_extract_domain_from_url(self, whois_service):
        """Test domain extraction from URL."""
        assert whois_service._extract_domain("https://example.com/path") == "example.com"
        assert whois_service._extract_domain("http://www.example.com") == "example.com"
        assert whois_service._extract_domain("https://example.com:8080") == "example.com"

    def test_extract_domain_from_domain(self, whois_service):
        """Test domain extraction from plain domain."""
        assert whois_service._extract_domain("example.com") == "example.com"
        assert whois_service._extract_domain("www.example.com") == "example.com"

    def test_extract_domain_invalid(self, whois_service):
        """Test domain extraction with invalid input."""
        assert whois_service._extract_domain("invalid") is None
        assert whois_service._extract_domain("a") is None
        assert whois_service._extract_domain("") is None

    def test_normalize_whois_data(self, whois_service, mock_whois_data):
        """Test WHOIS data normalization."""
        result = whois_service._normalize_whois_data("example.com", mock_whois_data)

        assert result["domain"] == "example.com"
        assert result["registrar"] == "Example Registrar LLC"
        assert "2020-01-15" in result["creation_date"]
        assert result["name_servers"] == ["ns1.example.com", "ns2.example.com"]
        assert result["abuse_email"] == "abuse@example.com"
        assert result["status"] == ["clientTransferProhibited"]

    def test_normalize_whois_data_list_dates(self, whois_service):
        """Test normalization with list of dates."""
        mock = MagicMock()
        mock.domain = "test.com"
        mock.registrar = "Test Registrar"
        mock.creation_date = [datetime(2020, 1, 1), datetime(2020, 1, 2)]  # List
        mock.expiration_date = None
        mock.updated_date = None
        mock.name_servers = None
        mock.registrant = None
        mock.status = None
        mock.dnssec = None
        mock.whois_server = None
        mock.emails = None

        result = whois_service._normalize_whois_data("test.com", mock)

        # Should take first date from list
        assert "2020-01-01" in result["creation_date"]

    def test_normalize_whois_data_single_nameserver(self, whois_service):
        """Test normalization with single nameserver."""
        mock = MagicMock()
        mock.domain = "test.com"
        mock.registrar = "Test"
        mock.creation_date = None
        mock.expiration_date = None
        mock.updated_date = None
        mock.name_servers = "ns1.example.com"  # Single value
        mock.registrant = None
        mock.status = None
        mock.dnssec = None
        mock.whois_server = None
        mock.emails = None

        result = whois_service._normalize_whois_data("test.com", mock)

        assert result["name_servers"] == ["ns1.example.com"]

    def test_extract_abuse_email_from_list(self, whois_service):
        """Test abuse email extraction from email list."""
        mock = MagicMock()
        mock.emails = ["contact@example.com", "abuse@example.com", "admin@example.com"]

        result = whois_service._extract_abuse_email(mock)
        assert result == "abuse@example.com"

    def test_extract_abuse_email_no_abuse(self, whois_service):
        """Test abuse email extraction when no abuse email."""
        mock = MagicMock()
        mock.emails = ["contact@example.com"]

        result = whois_service._extract_abuse_email(mock)
        assert result == "contact@example.com"  # Returns first email

    def test_extract_abuse_email_none(self, whois_service):
        """Test abuse email extraction with no emails."""
        mock = MagicMock()
        mock.emails = None

        result = whois_service._extract_abuse_email(mock)
        assert result is None

    @pytest.mark.asyncio
    async def test_lookup_success(self, whois_service, mock_whois_data):
        """Test successful WHOIS lookup."""
        with patch.object(whois_service, '_perform_whois_lookup', return_value=mock_whois_data):
            result = await whois_service.lookup("example.com")

            assert result is not None
            assert result["domain"] == "example.com"
            assert result["registrar"] == "Example Registrar LLC"

    @pytest.mark.asyncio
    async def test_lookup_invalid_domain(self, whois_service):
        """Test WHOIS lookup with invalid domain."""
        result = await whois_service.lookup("invalid")
        assert result is None

    @pytest.mark.asyncio
    async def test_lookup_with_url(self, whois_service, mock_whois_data):
        """Test WHOIS lookup extracts domain from URL."""
        with patch.object(whois_service, '_perform_whois_lookup', return_value=mock_whois_data):
            result = await whois_service.lookup("https://example.com/path")

            assert result is not None
            assert result["domain"] == "example.com"

    @pytest.mark.asyncio
    async def test_lookup_exception(self, whois_service):
        """Test WHOIS lookup handles exceptions."""
        with patch.object(whois_service, '_perform_whois_lookup', side_effect=Exception("Network error")):
            result = await whois_service.lookup("example.com")
            assert result is None

    @pytest.mark.asyncio
    async def test_get_domain_age_days(self, whois_service, mock_whois_data):
        """Test domain age calculation."""
        # Set creation date to 30 days ago
        mock_whois_data.creation_date = datetime.now() - timedelta(days=30)

        with patch.object(whois_service, '_perform_whois_lookup', return_value=mock_whois_data):
            age = await whois_service.get_domain_age_days("example.com")

            assert age is not None
            assert 29 <= age <= 31  # Allow for timing differences

    @pytest.mark.asyncio
    async def test_get_domain_age_no_creation_date(self, whois_service):
        """Test domain age when creation date unavailable."""
        mock = MagicMock()
        mock.creation_date = None
        mock.registrar = "Test"
        mock.expiration_date = None
        mock.updated_date = None
        mock.name_servers = None
        mock.registrant = None
        mock.status = None
        mock.dnssec = None
        mock.whois_server = None
        mock.emails = None

        with patch.object(whois_service, '_perform_whois_lookup', return_value=mock):
            age = await whois_service.get_domain_age_days("example.com")
            assert age is None

    @pytest.mark.asyncio
    async def test_is_recently_registered_true(self, whois_service, mock_whois_data):
        """Test recently registered detection (< 30 days)."""
        # Set creation date to 15 days ago
        mock_whois_data.creation_date = datetime.now() - timedelta(days=15)

        with patch.object(whois_service, '_perform_whois_lookup', return_value=mock_whois_data):
            is_recent = await whois_service.is_recently_registered("example.com", threshold_days=30)
            assert is_recent is True

    @pytest.mark.asyncio
    async def test_is_recently_registered_false(self, whois_service, mock_whois_data):
        """Test recently registered detection (> 30 days)."""
        # Set creation date to 60 days ago
        mock_whois_data.creation_date = datetime.now() - timedelta(days=60)

        with patch.object(whois_service, '_perform_whois_lookup', return_value=mock_whois_data):
            is_recent = await whois_service.is_recently_registered("example.com", threshold_days=30)
            assert is_recent is False

    @pytest.mark.asyncio
    async def test_is_recently_registered_unknown(self, whois_service):
        """Test recently registered when age unknown."""
        with patch.object(whois_service, '_perform_whois_lookup', return_value=None):
            is_recent = await whois_service.is_recently_registered("example.com")
            assert is_recent is False  # Unknown age = not flagged as recent
