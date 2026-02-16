"""Middleware for FastAPI app."""

from typing import Callable
from fastapi import Request, Response, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
import time
from collections import defaultdict
from datetime import datetime, timedelta


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Rate limiting middleware using in-memory storage.

    For production, use Redis-based rate limiting.

    Configuration:
        - Authenticated users: 100 requests/minute
        - Unauthenticated: 20 requests/minute
        - Per API key: Custom limits (from database)
    """

    def __init__(self, app):
        super().__init__(app)
        self.requests = defaultdict(list)
        self.cleanup_interval = 60  # Clean up every 60 seconds
        self.last_cleanup = time.time()

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request with rate limiting.

        Args:
            request: Incoming request
            call_next: Next middleware/handler

        Returns:
            Response

        Raises:
            HTTPException: If rate limit exceeded
        """
        # Skip rate limiting for health check
        if request.url.path == "/health":
            return await call_next(request)

        # Determine client identifier and limit
        client_id = self._get_client_id(request)
        limit = self._get_rate_limit(request)

        # Clean up old entries periodically
        if time.time() - self.last_cleanup > self.cleanup_interval:
            self._cleanup_old_requests()

        # Check rate limit
        now = time.time()
        minute_ago = now - 60

        # Filter requests in last minute
        recent_requests = [
            req_time for req_time in self.requests[client_id]
            if req_time > minute_ago
        ]

        if len(recent_requests) >= limit:
            # Rate limit exceeded
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded: {limit} requests per minute",
                headers={"Retry-After": "60"}
            )

        # Record request
        self.requests[client_id] = recent_requests + [now]

        # Process request
        response = await call_next(request)
        return response

    def _get_client_id(self, request: Request) -> str:
        """Get client identifier for rate limiting.

        Args:
            request: Incoming request

        Returns:
            Client identifier string
        """
        # Check for API key
        api_key = request.headers.get("X-API-Key")
        if api_key:
            return f"apikey:{api_key}"

        # Check for JWT token
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header.replace("Bearer ", "")
            return f"token:{token}"

        # Fall back to IP address
        client_ip = request.client.host if request.client else "unknown"
        return f"ip:{client_ip}"

    def _get_rate_limit(self, request: Request) -> int:
        """Determine rate limit for request.

        Args:
            request: Incoming request

        Returns:
            Requests per minute limit
        """
        # Check for authentication
        has_auth = (
            request.headers.get("Authorization") or
            request.headers.get("X-API-Key")
        )

        # Authenticated: 100/min, Unauthenticated: 20/min
        return 100 if has_auth else 20

    def _cleanup_old_requests(self):
        """Remove requests older than 1 minute."""
        now = time.time()
        minute_ago = now - 60

        for client_id in list(self.requests.keys()):
            self.requests[client_id] = [
                req_time for req_time in self.requests[client_id]
                if req_time > minute_ago
            ]

            # Remove empty entries
            if not self.requests[client_id]:
                del self.requests[client_id]

        self.last_cleanup = now


async def add_process_time_header(request: Request, call_next: Callable) -> Response:
    """Add X-Process-Time header to responses.

    Args:
        request: Incoming request
        call_next: Next middleware/handler

    Returns:
        Response with X-Process-Time header
    """
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = f"{process_time:.4f}"
    return response
