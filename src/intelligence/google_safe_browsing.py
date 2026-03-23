"""
Google Safe Browsing API Integration
Checks URLs against Google's threat database
"""

import logging
import requests
from typing import Dict, List, Optional
from datetime import datetime
from src.config import settings

logger = logging.getLogger(__name__)

# API Configuration
GOOGLE_SAFE_BROWSING_API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
GOOGLE_API_KEY = settings.GOOGLE_SAFE_BROWSING_API_KEY or ""

# Threat types to check
THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",  # Phishing
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
]

# Platform types
PLATFORM_TYPES = [
    "ANY_PLATFORM",
    "WINDOWS",
    "LINUX",
    "OSX",
    "ANDROID",
    "IOS",
]

# Threat entry types
THREAT_ENTRY_TYPES = ["URL"]


class GoogleSafeBrowsingIntegration:
    """Integration with Google Safe Browsing API v4"""

    def __init__(self, api_key: str = None):
        """
        Initialize Google Safe Browsing integration

        Args:
            api_key: Google API key with Safe Browsing API enabled
        """
        self.api_key = api_key or GOOGLE_API_KEY
        self.api_url = GOOGLE_SAFE_BROWSING_API_URL
        self.enabled = bool(self.api_key)

        if not self.enabled:
            logger.warning("Google Safe Browsing API key not configured")

    def check_url(self, url: str) -> Dict:
        """
        Check a single URL against Google Safe Browsing

        Args:
            url: URL to check

        Returns:
            Dict with check results
        """
        return self.check_urls([url])

    def check_urls(self, urls: List[str]) -> Dict:
        """
        Check multiple URLs against Google Safe Browsing

        Args:
            urls: List of URLs to check

        Returns:
            Dict with check results
        """
        result = {
            "checked": False,
            "safe": True,
            "threats_found": [],
            "threat_count": 0,
            "urls_checked": len(urls),
            "timestamp": datetime.utcnow().isoformat(),
            "error": None,
        }

        if not self.enabled:
            result["error"] = "API key not configured"
            return result

        if not urls:
            result["error"] = "No URLs provided"
            return result

        try:
            # Build request payload
            payload = {
                "client": {
                    "clientId": "anisakys-phishing-detector",
                    "clientVersion": "1.0.0",
                },
                "threatInfo": {
                    "threatTypes": THREAT_TYPES,
                    "platformTypes": PLATFORM_TYPES,
                    "threatEntryTypes": THREAT_ENTRY_TYPES,
                    "threatEntries": [{"url": url} for url in urls],
                },
            }

            # Make API request
            response = requests.post(
                f"{self.api_url}?key={self.api_key}",
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=10,
            )

            result["checked"] = True

            if response.status_code == 200:
                data = response.json()

                if "matches" in data and data["matches"]:
                    result["safe"] = False
                    result["threat_count"] = len(data["matches"])

                    for match in data["matches"]:
                        threat_info = {
                            "url": match.get("threat", {}).get("url"),
                            "threat_type": match.get("threatType"),
                            "platform_type": match.get("platformType"),
                            "cache_duration": match.get("cacheDuration"),
                        }
                        result["threats_found"].append(threat_info)

                        logger.warning(
                            f"🚨 Google Safe Browsing threat detected: "
                            f"{threat_info['url']} - {threat_info['threat_type']}"
                        )

            elif response.status_code == 400:
                result["error"] = "Invalid request"
                logger.error(f"Google Safe Browsing API error: {response.text}")

            elif response.status_code == 403:
                result["error"] = "API key invalid or quota exceeded"
                logger.error("Google Safe Browsing API: Invalid key or quota exceeded")

            else:
                result["error"] = f"API error: {response.status_code}"
                logger.error(f"Google Safe Browsing API error: {response.status_code}")

        except requests.exceptions.Timeout:
            result["error"] = "Request timeout"
            logger.error("Google Safe Browsing API timeout")

        except requests.exceptions.RequestException as e:
            result["error"] = f"Request failed: {str(e)}"
            logger.error(f"Google Safe Browsing API request failed: {e}")

        except Exception as e:
            result["error"] = f"Unexpected error: {str(e)}"
            logger.error(f"Google Safe Browsing unexpected error: {e}")

        return result

    def get_threat_level(self, threat_type: str) -> str:
        """
        Convert Google threat type to internal threat level

        Args:
            threat_type: Google's threat type string

        Returns:
            Internal threat level (critical, high, medium, low)
        """
        threat_mapping = {
            "MALWARE": "critical",
            "SOCIAL_ENGINEERING": "high",  # Phishing
            "UNWANTED_SOFTWARE": "medium",
            "POTENTIALLY_HARMFUL_APPLICATION": "medium",
        }
        return threat_mapping.get(threat_type, "medium")

    def is_available(self) -> bool:
        """Check if the API is available and configured"""
        return self.enabled

    def test_connection(self) -> Dict:
        """Test API connectivity"""
        result = {
            "success": False,
            "message": "",
        }

        if not self.enabled:
            result["message"] = "API key not configured"
            return result

        try:
            # Test with a known safe URL
            test_result = self.check_url("https://www.google.com/")

            if test_result.get("checked"):
                result["success"] = True
                result["message"] = "API connection successful"
            else:
                result["message"] = test_result.get("error", "Unknown error")

        except Exception as e:
            result["message"] = f"Connection test failed: {str(e)}"

        return result


# Singleton instance
google_safe_browsing = GoogleSafeBrowsingIntegration()
