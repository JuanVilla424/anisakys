"""VirusTotal API integration client."""

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


class VirusTotalClient:
    """VirusTotal API v3 client for URL scanning.

    Example:
        ```python
        vt_client = VirusTotalClient()
        result = await vt_client.scan_url("https://suspicious-site.com")
        if result:
            print(f"Positives: {result['positives']}/{result['total']}")
        ```
    """

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: Optional[str] = None):
        """Initialize VirusTotal client.

        Args:
            api_key: Optional API key (defaults to settings.VIRUSTOTAL_API_KEY)
        """
        self.api_key = api_key or settings.VIRUSTOTAL_API_KEY
        self.timeout = 10.0

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type((httpx.TimeoutException, httpx.HTTPError)),
    )
    async def scan_url(self, url: str) -> Optional[dict]:
        """Scan a URL using VirusTotal API.

        Args:
            url: URL to scan

        Returns:
            Dict with scan results or None if error:
            {
                "positives": 45,  # Number of AV engines flagging as malicious
                "total": 70,      # Total AV engines
                "permalink": "https://virustotal.com/...",
                "scan_date": "2026-01-03 19:00:00",
                "status": "completed"
            }

        Example:
            ```python
            result = await vt_client.scan_url("https://example.com")
            if result and result["positives"] > 0:
                print(f"Malicious: {result['positives']}/{result['total']}")
            ```
        """
        if not self.api_key or self.api_key == "your_virustotal_api_key":
            # API key not configured, return None
            return None

        headers = {"x-apikey": self.api_key}

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                # Submit URL for scanning
                response = await client.post(
                    f"{self.BASE_URL}/urls",
                    headers=headers,
                    data={"url": url},
                )
                response.raise_for_status()

                # Get analysis ID
                data = response.json()
                analysis_id = data["data"]["id"]

                # Wait a bit for analysis (VirusTotal needs time)
                await asyncio.sleep(2)

                # Get analysis results
                analysis_response = await client.get(
                    f"{self.BASE_URL}/analyses/{analysis_id}",
                    headers=headers,
                )
                analysis_response.raise_for_status()

                analysis_data = analysis_response.json()
                stats = analysis_data["data"]["attributes"]["stats"]

                return {
                    "positives": stats.get("malicious", 0) + stats.get("suspicious", 0),
                    "total": sum(stats.values()),
                    "permalink": analysis_data["data"]["links"]["self"],
                    "scan_date": analysis_data["data"]["attributes"]["date"],
                    "status": analysis_data["data"]["attributes"]["status"],
                    "raw_stats": stats,
                }

            except httpx.HTTPStatusError as e:
                if e.response.status_code in (401, 403):
                    # Authentication error, don't retry
                    return None
                raise
            except Exception:
                return None

    async def get_url_report(self, url: str) -> Optional[dict]:
        """Get existing report for a URL (without re-scanning).

        Args:
            url: URL to check

        Returns:
            Dict with scan results or None if not found/error

        Example:
            ```python
            report = await vt_client.get_url_report("https://example.com")
            ```
        """
        if not self.api_key or self.api_key == "your_virustotal_api_key":
            return None

        headers = {"x-apikey": self.api_key}

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                # Get URL ID (base64 URL without padding)
                import base64
                url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

                response = await client.get(
                    f"{self.BASE_URL}/urls/{url_id}",
                    headers=headers,
                )
                response.raise_for_status()

                data = response.json()
                stats = data["data"]["attributes"]["last_analysis_stats"]

                return {
                    "positives": stats.get("malicious", 0) + stats.get("suspicious", 0),
                    "total": sum(stats.values()),
                    "permalink": data["data"]["links"]["self"],
                    "scan_date": data["data"]["attributes"]["last_analysis_date"],
                    "status": "completed",
                    "raw_stats": stats,
                }

            except httpx.HTTPStatusError:
                return None
            except Exception:
                return None
