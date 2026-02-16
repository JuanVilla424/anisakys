"""
Enterprise-grade authentication module with httpOnly cookies.

Security features:
- httpOnly cookies (XSS protection)
- Secure flag (HTTPS only)
- SameSite=Strict (CSRF protection)
- JWT tokens with expiration
- Refresh token mechanism
"""

import secrets
import hashlib
from datetime import datetime, timedelta
from functools import wraps
from typing import Optional, Dict, Any

from flask import request, jsonify, make_response
import jwt

# Configuration
SECRET_KEY = secrets.token_hex(32)  # Should be loaded from environment
JWT_ALGORITHM = "HS256"
JWT_ACCESS_TOKEN_EXPIRE_MINUTES = 60  # 1 hour
JWT_REFRESH_TOKEN_EXPIRE_DAYS = 30  # 30 days
COOKIE_SECURE = True  # Set to False for local development
COOKIE_SAMESITE = "Strict"


def generate_jwt_token(
    api_key: str, token_type: str = "access", expires_delta: Optional[timedelta] = None
) -> str:
    """
    Generate JWT token with API key as payload.

    Args:
        api_key: The API key to encode
        token_type: 'access' or 'refresh'
        expires_delta: Optional custom expiration time

    Returns:
        JWT token string
    """
    if expires_delta is None:
        if token_type == "access":
            expires_delta = timedelta(minutes=JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
        else:  # refresh
            expires_delta = timedelta(days=JWT_REFRESH_TOKEN_EXPIRE_DAYS)

    expire = datetime.utcnow() + expires_delta

    # Hash the API key for security (don't store plaintext in JWT)
    api_key_hash = hashlib.sha256(api_key.encode()).hexdigest()

    payload = {
        "api_key_hash": api_key_hash,
        "type": token_type,
        "exp": expire,
        "iat": datetime.utcnow(),
    }

    token = jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALGORITHM)
    return token


def verify_jwt_token(token: str, expected_api_key: str) -> Optional[Dict[str, Any]]:
    """
    Verify JWT token and validate against expected API key.

    Args:
        token: JWT token to verify
        expected_api_key: The API key to validate against

    Returns:
        Decoded payload if valid, None otherwise
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])

        # Verify the API key hash matches
        expected_hash = hashlib.sha256(expected_api_key.encode()).hexdigest()
        if payload.get("api_key_hash") != expected_hash:
            return None

        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def set_auth_cookies(response, api_key: str):
    """
    Set httpOnly authentication cookies on response.

    Args:
        response: Flask response object
        api_key: API key to encode in tokens
    """
    # Generate access token
    access_token = generate_jwt_token(api_key, token_type="access")

    # Generate refresh token
    refresh_token = generate_jwt_token(api_key, token_type="refresh")

    # Set access token cookie (short-lived)
    response.set_cookie(
        "access_token",
        value=access_token,
        max_age=JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,  # seconds
        httponly=True,
        secure=COOKIE_SECURE,
        samesite=COOKIE_SAMESITE,
        path="/api",
    )

    # Set refresh token cookie (long-lived)
    response.set_cookie(
        "refresh_token",
        value=refresh_token,
        max_age=JWT_REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,  # seconds
        httponly=True,
        secure=COOKIE_SECURE,
        samesite=COOKIE_SAMESITE,
        path="/api/v1/refresh",
    )


def clear_auth_cookies(response):
    """Clear authentication cookies on logout."""
    response.set_cookie("access_token", value="", max_age=0, path="/api")
    response.set_cookie("refresh_token", value="", max_age=0, path="/api/v1/refresh")


def require_auth(f):
    """
    Enhanced authentication decorator with cookie support.

    Supports both:
    1. httpOnly cookies (preferred)
    2. Bearer token in Authorization header (API clients)
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Get expected API key from app config
        from src.config import settings
        expected_api_key = settings.ANISAKYS_API_KEY

        if not expected_api_key:
            return jsonify({"error": "API authentication not configured"}), 500

        # Method 1: Check for httpOnly cookie (browser clients)
        access_token = request.cookies.get("access_token")
        if access_token:
            payload = verify_jwt_token(access_token, expected_api_key)
            if payload:
                # Valid cookie authentication
                return f(*args, **kwargs)
            else:
                # Token expired or invalid - try to refresh
                return jsonify({
                    "error": "Token expired",
                    "message": "Please refresh your session"
                }), 401

        # Method 2: Check for Bearer token (API clients)
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            provided_key = auth_header[7:]

            if secrets.compare_digest(provided_key, expected_api_key):
                # Valid API key
                return f(*args, **kwargs)
            else:
                return jsonify({"error": "Invalid API key"}), 401

        # No valid authentication found
        return jsonify({
            "error": "Authentication required",
            "message": "Please provide valid credentials"
        }), 401

    return decorated_function


def login_endpoint(api_key: str) -> tuple:
    """
    Handle login and set authentication cookies.

    Args:
        api_key: API key provided by user

    Returns:
        Tuple of (response, status_code)
    """
    from src.config import settings
    expected_api_key = settings.ANISAKYS_API_KEY

    # Verify API key
    if not secrets.compare_digest(api_key, expected_api_key):
        return jsonify({"error": "Invalid API key"}), 401

    # Create response with success message
    response_data = {
        "success": True,
        "message": "Authentication successful",
        "expires_in": JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    }

    response = make_response(jsonify(response_data), 200)

    # Set httpOnly cookies
    set_auth_cookies(response, api_key)

    return response


def logout_endpoint():
    """Handle logout and clear cookies."""
    response = make_response(jsonify({
        "success": True,
        "message": "Logged out successfully"
    }), 200)

    clear_auth_cookies(response)
    return response


def refresh_token_endpoint():
    """Refresh access token using refresh token."""
    from src.config import settings
    expected_api_key = settings.ANISAKYS_API_KEY

    # Get refresh token from cookie
    refresh_token = request.cookies.get("refresh_token")

    if not refresh_token:
        return jsonify({"error": "Refresh token required"}), 401

    # Verify refresh token
    payload = verify_jwt_token(refresh_token, expected_api_key)

    if not payload or payload.get("type") != "refresh":
        return jsonify({"error": "Invalid refresh token"}), 401

    # Generate new access token
    response_data = {
        "success": True,
        "message": "Token refreshed successfully",
        "expires_in": JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    }

    response = make_response(jsonify(response_data), 200)

    # Set new access token cookie
    access_token = generate_jwt_token(expected_api_key, token_type="access")
    response.set_cookie(
        "access_token",
        value=access_token,
        max_age=JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite=COOKIE_SAMESITE,
        path="/api",
    )

    return response
