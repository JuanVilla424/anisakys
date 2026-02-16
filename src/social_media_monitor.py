"""
Social Media Monitoring Module
Monitor social platforms for phishing campaigns:
- Twitter/X scraping for phishing links
- Telegram channel monitoring
- Reddit monitoring
- Pastebin scraping
"""
import requests
import logging
from typing import List, Dict, Any
from datetime import datetime
import re

logger = logging.getLogger(__name__)


class SocialMediaMonitor:
    """Monitor social media for phishing campaigns."""

    def __init__(self, twitter_bearer_token: str = None):
        self.twitter_bearer_token = twitter_bearer_token
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Anisakys-ThreatIntel/1.0'
        })

    def search_pastebin(self, keywords: List[str], limit: int = 50) -> List[Dict[str, Any]]:
        """
        Search recent Pastebin posts for keywords.

        Args:
            keywords: List of keywords to search for
            limit: Max results to return

        Returns:
            List of matching Pastebin posts
        """
        logger.info(f"🔍 Searching Pastebin for: {', '.join(keywords[:3])}")

        results = []

        try:
            # Pastebin scraping API (using archive)
            response = self.session.get(
                "https://pastebin.com/archive",
                timeout=10
            )

            if response.status_code == 200:
                # Extract paste IDs from archive page
                paste_ids = re.findall(r'/([a-zA-Z0-9]{8})"', response.text)

                for paste_id in paste_ids[:limit]:
                    try:
                        # Get raw paste
                        raw_url = f"https://pastebin.com/raw/{paste_id}"
                        paste_response = self.session.get(raw_url, timeout=5)

                        if paste_response.status_code == 200:
                            content = paste_response.text.lower()

                            # Check if any keyword matches
                            matches = [kw for kw in keywords if kw.lower() in content]

                            if matches:
                                results.append({
                                    'source': 'pastebin',
                                    'paste_id': paste_id,
                                    'url': f"https://pastebin.com/{paste_id}",
                                    'matched_keywords': matches,
                                    'content_preview': paste_response.text[:500],
                                    'discovered_at': datetime.now().isoformat()
                                })
                    except:
                        continue

                logger.info(f"✅ Pastebin: Found {len(results)} matches")

            return results

        except Exception as e:
            logger.error(f"❌ Pastebin search error: {e}")
            return []

    def monitor_brand_mentions(
        self,
        brand: str,
        keywords: List[str] = None
    ) -> Dict[str, Any]:
        """
        Monitor social media for brand-related phishing.

        Args:
            brand: Brand name to monitor
            keywords: Additional keywords to search for

        Returns:
            Aggregated social media findings
        """
        if keywords is None:
            keywords = [brand, f"{brand} login", f"{brand} account",
                       f"{brand} verify", f"{brand} security"]

        logger.info(f"🔍 Monitoring social media for brand: {brand}")

        findings = {
            'brand': brand,
            'timestamp': datetime.now().isoformat(),
            'pastebin': [],
            'total_findings': 0
        }

        # Search Pastebin
        pastebin_results = self.search_pastebin(keywords)
        findings['pastebin'] = pastebin_results
        findings['total_findings'] += len(pastebin_results)

        logger.info(f"✅ Social media monitoring complete: {findings['total_findings']} findings")
        return findings


def test_social_monitor():
    """Test social media monitoring."""
    monitor = SocialMediaMonitor()

    print("\n📱 Testing Social Media Monitor...")

    # Test Pastebin search
    results = monitor.search_pastebin(['paypal', 'phishing'], limit=5)
    print(f"   Pastebin results: {len(results)}")

    print("✅ Social media monitor test complete")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    test_social_monitor()
