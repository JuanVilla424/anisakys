"""Ads search client — extensible base for Google, Instagram, and Facebook ad platforms."""

import serpapi
from typing import List
from src.logger import logger


class AdsSearchClient:
    """Searches for ads using SerpApi. Designed to extend to Instagram (Meta Ads Library API)
    and Facebook by adding platform-specific search methods below."""

    def __init__(self, api_key: str):
        self.api_key = api_key
        self._client = serpapi.Client(api_key=api_key)

    def search_ads(
        self,
        keyword: str,
        location: str,
        country_code: str = "us",
        language: str = "en",
        num_results: int = 10,
    ) -> List[dict]:
        """Search Google for ads matching keyword from a specific location.

        Args:
            keyword: Search term to look for ads.
            location: Geographic location string (e.g. "Bogota, Colombia").
            country_code: ISO country code for geo-targeting (gl param).
            language: Language code for results (hl param).
            num_results: Max number of results to request from SerpApi.

        Returns:
            List of ad dicts with keys: url, title, displayed_link, description,
            position, ad_type, sitelinks.
        """
        results: List[dict] = []
        seen_urls: set = set()

        def _add(url, title, displayed_link, description, position, ad_type, sitelinks=None):
            if url and url not in seen_urls:
                seen_urls.add(url)
                results.append(
                    {
                        "url": url,
                        "title": title,
                        "displayed_link": displayed_link,
                        "description": description,
                        "position": position,
                        "ad_type": ad_type,
                        "sitelinks": sitelinks or [],
                    }
                )

        try:
            data = dict(
                self._client.search(
                    {
                        "engine": "google",
                        "q": keyword,
                        "location": location,
                        "gl": country_code,
                        "hl": language,
                        "num": str(num_results),
                    }
                )
            )

            if "error" in data:
                logger.error(f"serpapi error: {data['error']}")
                raise Exception(data["error"])

            # Primary ads (top and bottom positions)
            for ad in data.get("ads", []):
                _add(
                    ad.get("link") or ad.get("tracking_link"),
                    ad.get("title", ""),
                    ad.get("displayed_link"),
                    ad.get("description"),
                    ad.get("position"),
                    "google_search_ad",
                    [
                        {"title": sl.get("title"), "link": sl.get("link")}
                        for sl in ad.get("sitelinks", {}).get("inline", [])
                    ],
                )

            # Shopping ads as secondary results
            for item in data.get("shopping_results", []):
                _add(
                    item.get("link"),
                    item.get("title", ""),
                    item.get("source"),
                    item.get("price"),
                    item.get("position"),
                    "google_shopping_ad",
                )

            logger.info(f"AdsSearchClient google '{keyword}' @ '{location}': {len(results)} ads")
            return results

        except Exception as e:
            logger.error(f"search_ads failed for '{keyword}' @ '{location}': {e}")
            raise
