"""URLVoid API integration client."""

import asyncio
from typing import Optional

import httpx
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
)

from src.config import settings


class URLVoidClient:
    """URLVoid API client for reputation checking.

    Example:
        ```python
        urlvoid_client = URLVoidClient()
        result = await urlvoid_client.check_reputation("suspicious-site.com")
        if result:
            print(f"Blacklists: {result['blacklists']}/{result['engines']}")
        ```
    """

    BASE_URL = "https://api.urlvoid.com/api1000"

    def __init__(self, api_key: Optional[str] = None):
        """Initialize URLVoid client.

        Args:
            api_key: Optional API key (defaults to settings.URLVOID_API_KEY)
        """
        self.api_key = api_key or settings.URLVOID_API_KEY
        self.timeout = 10.0

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type((httpx.TimeoutException, httpx.HTTPError)),
    )
    async def check_reputation(self, host: str) -> Optional[dict]:
        """Check domain reputation using URLVoid API.

        Args:
            host: Domain/hostname to check (e.g., "example.com")

        Returns:
            Dict with reputation data or None if error:
            {
                "blacklists": 5,     # Number of blacklists flagging this domain
                "engines": 30,       # Total blacklist engines checked
                "reputation": 83.3,  # Reputation score (0-100)
                "detections": ["Engine1", "Engine2"],  # List of detecting engines
                "status": "success"
            }

        Example:
            ```python
            result = await urlvoid_client.check_reputation("malicious-site.com")
            if result and result["blacklists"] > 0:
                print(f"Found on {result['blacklists']} blacklists")
            ```
        """
        if not self.api_key or self.api_key == "your_urlvoid_api_key":
            # API key not configured, return None
            return None

        # Remove protocol if present
        if "://" in host:
            host = host.split("://")[1]

        # Remove path if present
        host = host.split("/")[0]

        url = f"{self.BASE_URL}/{self.api_key}/host/{host}"

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                response = await client.get(url)
                response.raise_for_status()

                data = response.json()

                # URLVoid returns nested structure
                if "data" not in data:
                    return None

                details = data["data"]["report"]
                blacklists_data = details.get("blacklists", {})

                # Extract detection engines
                detections = []
                if "engines" in blacklists_data:
                    for engine_name, engine_data in blacklists_data["engines"].items():
                        if engine_data.get("detected"):
                            detections.append(engine_name)

                # Calculate counts
                blacklist_count = blacklists_data.get("detections", 0)
                engines_count = blacklists_data.get("engines_count", 0)

                # Calculate reputation (100 = clean, 0 = all blacklisted)
                if engines_count > 0:
                    reputation = ((engines_count - blacklist_count) / engines_count) * 100
                else:
                    reputation = 100.0

                return {
                    "blacklists": blacklist_count,
                    "engines": engines_count,
                    "reputation": round(reputation, 2),
                    "detections": detections,
                    "status": "success",
                    "domain_age": details.get("domain_age"),
                    "alexa_rank": details.get("alexa_rank"),
                }

            except httpx.HTTPStatusError as e:
                if e.response.status_code in (401, 403):
                    # Authentication error, don't retry
                    return None
                raise
            except Exception:
                return None

    async def host_scan(self, host: str) -> Optional[dict]:
        """Alias for check_reputation for consistency with other APIs.

        Args:
            host: Domain/hostname to check

        Returns:
            Dict with reputation data or None if error
        """
        return await self.check_reputation(host)
