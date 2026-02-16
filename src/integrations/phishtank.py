"""PhishTank API integration client."""

import asyncio
from typing import Optional
from urllib.parse import quote

import httpx
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
)

from src.config import settings


class PhishTankClient:
    """PhishTank API client for phishing URL detection.

    Example:
        ```python
        pt_client = PhishTankClient()
        result = await pt_client.check_url("https://suspicious-site.com")
        if result and result["is_phishing"]:
            print(f"Phishing detected! Verified: {result['verified']}")
        ```
    """

    BASE_URL = "https://checkurl.phishtank.com/checkurl/"

    def __init__(self, api_key: Optional[str] = None):
        """Initialize PhishTank client.

        Args:
            api_key: Optional API key (defaults to settings.PHISHTANK_API_KEY)
        """
        self.api_key = api_key or settings.PHISHTANK_API_KEY
        self.timeout = 10.0

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type((httpx.TimeoutException, httpx.HTTPError)),
    )
    async def check_url(self, url: str) -> Optional[dict]:
        """Check if URL is reported as phishing in PhishTank.

        Args:
            url: URL to check

        Returns:
            Dict with phishing check results or None if error:
            {
                "is_phishing": True,        # Whether URL is confirmed phishing
                "verified": True,           # Whether detection is verified
                "phish_id": 12345,          # PhishTank ID
                "submission_time": "...",   # When reported
                "verification_time": "...", # When verified
                "in_database": True,        # Whether found in PhishTank DB
                "status": "success"
            }

        Example:
            ```python
            result = await pt_client.check_url("https://phishing-example.com")
            if result and result["is_phishing"]:
                print(f"Phishing confirmed! ID: {result['phish_id']}")
            ```
        """
        # PhishTank has both API key and non-API key modes
        # API key provides higher rate limits
        headers = {
            "User-Agent": "phishtank/anisakys"
        }

        # Build request data
        data = {
            "url": url,
            "format": "json"
        }

        if self.api_key and self.api_key != "your_phishtank_api_key":
            data["app_key"] = self.api_key

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                response = await client.post(
                    self.BASE_URL,
                    headers=headers,
                    data=data
                )
                response.raise_for_status()

                result = response.json()

                # PhishTank returns results directly
                meta = result.get("meta", {})
                results_data = result.get("results", {})

                # Not found in database
                if not results_data.get("in_database", False):
                    return {
                        "is_phishing": False,
                        "verified": False,
                        "in_database": False,
                        "status": "clean"
                    }

                # Found in database
                return {
                    "is_phishing": True,
                    "verified": results_data.get("verified", False),
                    "phish_id": results_data.get("phish_id"),
                    "submission_time": results_data.get("submission_time"),
                    "verification_time": results_data.get("verification_time"),
                    "in_database": True,
                    "phish_detail_url": results_data.get("phish_detail_page"),
                    "status": "phishing"
                }

            except httpx.HTTPStatusError as e:
                if e.response.status_code in (401, 403, 509):
                    # Authentication error or rate limited, don't retry
                    return None
                raise
            except Exception:
                return None

    async def is_phishing(self, url: str) -> bool:
        """Simple boolean check if URL is phishing.

        Args:
            url: URL to check

        Returns:
            True if confirmed phishing, False otherwise

        Example:
            ```python
            if await pt_client.is_phishing("https://suspicious.com"):
                print("PHISHING DETECTED!")
            ```
        """
        result = await self.check_url(url)
        return result.get("is_phishing", False) if result else False
