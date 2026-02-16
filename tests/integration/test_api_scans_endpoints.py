"""Integration tests for scanning API endpoints."""

import pytest
from httpx import AsyncClient
from fastapi import status
from unittest.mock import patch, AsyncMock

from src.api.v1.app import create_app


@pytest.fixture
def app():
    """Create FastAPI app for testing."""
    return create_app()


@pytest.fixture
async def auth_token(app):
    """Get authentication token for testing."""
    async with AsyncClient(app=app, base_url="http://test") as client:
        # Register user
        await client.post(
            "/api/v1/auth/register",
            json={
                "email": "scantest@example.com",
                "password": "SecurePass123!",
                "full_name": "Scan Test"
            }
        )

        # Login
        login_response = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "scantest@example.com",
                "password": "SecurePass123!"
            }
        )

        return login_response.json()["access_token"]


@pytest.mark.asyncio
class TestCreateScanEndpoint:
    """Test POST /api/v1/scans endpoint."""

    @patch('src.services.scanning_service.VirusTotalClient')
    @patch('src.services.scanning_service.URLVoidClient')
    @patch('src.services.scanning_service.PhishTankClient')
    async def test_create_scan_success(self, mock_pt, mock_uv, mock_vt, app, auth_token):
        """Create scan successfully."""
        # Mock API responses
        mock_vt_instance = AsyncMock()
        mock_vt_instance.scan_url.return_value = {"positives": 35, "total": 70}
        mock_vt.return_value = mock_vt_instance

        mock_uv_instance = AsyncMock()
        mock_uv_instance.check_reputation.return_value = {"blacklists": 10, "engines": 30}
        mock_uv.return_value = mock_uv_instance

        mock_pt_instance = AsyncMock()
        mock_pt_instance.check_url.return_value = {"is_phishing": False, "verified": False}
        mock_pt.return_value = mock_pt_instance

        async with AsyncClient(app=app, base_url="http://test") as client:
            response = await client.post(
                "/api/v1/scans/",
                json={"url": "https://suspicious-site.com", "force_rescan": False},
                headers={"Authorization": f"Bearer {auth_token}"}
            )

        assert response.status_code == status.HTTP_201_CREATED
        data = response.json()
        assert data["url"] == "https://suspicious-site.com"
        assert data["host"] == "suspicious-site.com"
        assert "confidence_score" in data
        assert "threat_level" in data

    async def test_create_scan_no_auth(self, app):
        """Create scan without authentication."""
        async with AsyncClient(app=app, base_url="http://test") as client:
            response = await client.post(
                "/api/v1/scans/",
                json={"url": "https://test.com", "force_rescan": False}
            )

        assert response.status_code == status.HTTP_403_FORBIDDEN

    async def test_create_scan_invalid_url(self, app, auth_token):
        """Create scan with invalid URL."""
        async with AsyncClient(app=app, base_url="http://test") as client:
            response = await client.post(
                "/api/v1/scans/",
                json={"url": "not-a-valid-url", "force_rescan": False},
                headers={"Authorization": f"Bearer {auth_token}"}
            )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


@pytest.mark.asyncio
class TestGetScanEndpoint:
    """Test GET /api/v1/scans/{scan_id} endpoint."""

    @patch('src.services.scanning_service.VirusTotalClient')
    @patch('src.services.scanning_service.URLVoidClient')
    @patch('src.services.scanning_service.PhishTankClient')
    async def test_get_scan_success(self, mock_pt, mock_uv, mock_vt, app, auth_token):
        """Get scan by ID successfully."""
        # Mock API responses
        mock_vt_instance = AsyncMock()
        mock_vt_instance.scan_url.return_value = {"positives": 35, "total": 70}
        mock_vt.return_value = mock_vt_instance

        mock_uv_instance = AsyncMock()
        mock_uv_instance.check_reputation.return_value = {"blacklists": 10, "engines": 30}
        mock_uv.return_value = mock_uv_instance

        mock_pt_instance = AsyncMock()
        mock_pt_instance.check_url.return_value = {"is_phishing": False, "verified": False}
        mock_pt.return_value = mock_pt_instance

        async with AsyncClient(app=app, base_url="http://test") as client:
            # Create scan
            create_response = await client.post(
                "/api/v1/scans/",
                json={"url": "https://test-get.com", "force_rescan": False},
                headers={"Authorization": f"Bearer {auth_token}"}
            )
            scan_id = create_response.json()["id"]

            # Get scan
            response = await client.get(
                f"/api/v1/scans/{scan_id}",
                headers={"Authorization": f"Bearer {auth_token}"}
            )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["id"] == scan_id

    async def test_get_scan_not_found(self, app, auth_token):
        """Get non-existent scan."""
        async with AsyncClient(app=app, base_url="http://test") as client:
            response = await client.get(
                "/api/v1/scans/99999",
                headers={"Authorization": f"Bearer {auth_token}"}
            )

        assert response.status_code == status.HTTP_404_NOT_FOUND

    async def test_get_scan_no_auth(self, app):
        """Get scan without authentication."""
        async with AsyncClient(app=app, base_url="http://test") as client:
            response = await client.get("/api/v1/scans/1")

        assert response.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.asyncio
class TestListScansEndpoint:
    """Test GET /api/v1/scans endpoint."""

    @patch('src.services.scanning_service.VirusTotalClient')
    @patch('src.services.scanning_service.URLVoidClient')
    @patch('src.services.scanning_service.PhishTankClient')
    async def test_list_scans_success(self, mock_pt, mock_uv, mock_vt, app, auth_token):
        """List user's scans successfully."""
        # Mock API responses
        mock_vt_instance = AsyncMock()
        mock_vt_instance.scan_url.return_value = {"positives": 35, "total": 70}
        mock_vt.return_value = mock_vt_instance

        mock_uv_instance = AsyncMock()
        mock_uv_instance.check_reputation.return_value = {"blacklists": 10, "engines": 30}
        mock_uv.return_value = mock_uv_instance

        mock_pt_instance = AsyncMock()
        mock_pt_instance.check_url.return_value = {"is_phishing": False, "verified": False}
        mock_pt.return_value = mock_pt_instance

        async with AsyncClient(app=app, base_url="http://test") as client:
            # Create a couple of scans
            await client.post(
                "/api/v1/scans/",
                json={"url": "https://site1.com", "force_rescan": False},
                headers={"Authorization": f"Bearer {auth_token}"}
            )
            await client.post(
                "/api/v1/scans/",
                json={"url": "https://site2.com", "force_rescan": False},
                headers={"Authorization": f"Bearer {auth_token}"}
            )

            # List scans
            response = await client.get(
                "/api/v1/scans/",
                headers={"Authorization": f"Bearer {auth_token}"}
            )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "scans" in data
        assert len(data["scans"]) >= 2
        assert data["limit"] == 50
        assert data["offset"] == 0

    async def test_list_scans_with_pagination(self, app, auth_token):
        """List scans with pagination parameters."""
        async with AsyncClient(app=app, base_url="http://test") as client:
            response = await client.get(
                "/api/v1/scans/?limit=10&offset=5",
                headers={"Authorization": f"Bearer {auth_token}"}
            )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["limit"] == 10
        assert data["offset"] == 5

    async def test_list_scans_no_auth(self, app):
        """List scans without authentication."""
        async with AsyncClient(app=app, base_url="http://test") as client:
            response = await client.get("/api/v1/scans/")

        assert response.status_code == status.HTTP_403_FORBIDDEN
