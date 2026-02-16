"""Integration tests for authentication API endpoints."""

import pytest
from httpx import AsyncClient
from fastapi import status

from src.api.v1.app import create_app


@pytest.fixture
def app():
    """Create FastAPI app for testing."""
    return create_app()


@pytest.mark.asyncio
class TestRegisterEndpoint:
    """Test /api/v1/auth/register endpoint."""

    async def test_register_new_user_success(self, app):
        """Register new user successfully."""
        async with AsyncClient(app=app, base_url="http://test") as client:
            response = await client.post(
                "/api/v1/auth/register",
                json={
                    "email": "newuser@example.com",
                    "password": "SecurePass123!",
                    "full_name": "Test User"
                }
            )

        assert response.status_code == status.HTTP_201_CREATED
        data = response.json()
        assert data["email"] == "newuser@example.com"
        assert data["full_name"] == "Test User"
        assert "id" in data

    async def test_register_duplicate_email(self, app):
        """Register with already registered email."""
        async with AsyncClient(app=app, base_url="http://test") as client:
            # First registration
            await client.post(
                "/api/v1/auth/register",
                json={
                    "email": "duplicate@example.com",
                    "password": "SecurePass123!",
                    "full_name": "User One"
                }
            )

            # Duplicate registration
            response = await client.post(
                "/api/v1/auth/register",
                json={
                    "email": "duplicate@example.com",
                    "password": "AnotherPass456!",
                    "full_name": "User Two"
                }
            )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "already registered" in response.json()["detail"].lower()

    async def test_register_invalid_email(self, app):
        """Register with invalid email format."""
        async with AsyncClient(app=app, base_url="http://test") as client:
            response = await client.post(
                "/api/v1/auth/register",
                json={
                    "email": "not-an-email",
                    "password": "SecurePass123!",
                    "full_name": "Test User"
                }
            )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    async def test_register_weak_password(self, app):
        """Register with password < 8 characters."""
        async with AsyncClient(app=app, base_url="http://test") as client:
            response = await client.post(
                "/api/v1/auth/register",
                json={
                    "email": "test@example.com",
                    "password": "weak",
                    "full_name": "Test User"
                }
            )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


@pytest.mark.asyncio
class TestLoginEndpoint:
    """Test /api/v1/auth/login endpoint."""

    async def test_login_success(self, app):
        """Login with valid credentials."""
        async with AsyncClient(app=app, base_url="http://test") as client:
            # Register user first
            await client.post(
                "/api/v1/auth/register",
                json={
                    "email": "logintest@example.com",
                    "password": "SecurePass123!",
                    "full_name": "Login Test"
                }
            )

            # Login
            response = await client.post(
                "/api/v1/auth/login",
                json={
                    "email": "logintest@example.com",
                    "password": "SecurePass123!"
                }
            )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert data["expires_in"] == 3600

    async def test_login_wrong_password(self, app):
        """Login with incorrect password."""
        async with AsyncClient(app=app, base_url="http://test") as client:
            # Register user
            await client.post(
                "/api/v1/auth/register",
                json={
                    "email": "wrongpass@example.com",
                    "password": "CorrectPass123!",
                    "full_name": "Test User"
                }
            )

            # Login with wrong password
            response = await client.post(
                "/api/v1/auth/login",
                json={
                    "email": "wrongpass@example.com",
                    "password": "WrongPass456!"
                }
            )

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    async def test_login_nonexistent_user(self, app):
        """Login with non-existent email."""
        async with AsyncClient(app=app, base_url="http://test") as client:
            response = await client.post(
                "/api/v1/auth/login",
                json={
                    "email": "nonexistent@example.com",
                    "password": "SomePass123!"
                }
            )

        assert response.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.asyncio
class TestMeEndpoint:
    """Test /api/v1/auth/me endpoint."""

    async def test_get_current_user_authenticated(self, app):
        """Get current user profile with valid token."""
        async with AsyncClient(app=app, base_url="http://test") as client:
            # Register and login
            await client.post(
                "/api/v1/auth/register",
                json={
                    "email": "metest@example.com",
                    "password": "SecurePass123!",
                    "full_name": "Me Test"
                }
            )

            login_response = await client.post(
                "/api/v1/auth/login",
                json={
                    "email": "metest@example.com",
                    "password": "SecurePass123!"
                }
            )
            token = login_response.json()["access_token"]

            # Get profile
            response = await client.get(
                "/api/v1/auth/me",
                headers={"Authorization": f"Bearer {token}"}
            )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["email"] == "metest@example.com"
        assert data["full_name"] == "Me Test"

    async def test_get_current_user_no_token(self, app):
        """Get current user without authentication."""
        async with AsyncClient(app=app, base_url="http://test") as client:
            response = await client.get("/api/v1/auth/me")

        assert response.status_code == status.HTTP_403_FORBIDDEN

    async def test_get_current_user_invalid_token(self, app):
        """Get current user with invalid token."""
        async with AsyncClient(app=app, base_url="http://test") as client:
            response = await client.get(
                "/api/v1/auth/me",
                headers={"Authorization": "Bearer invalid_token_here"}
            )

        assert response.status_code == status.HTTP_401_UNAUTHORIZED
