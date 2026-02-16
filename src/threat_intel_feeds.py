"""
Threat Intelligence Feed Aggregator
Integrates multiple real-time phishing and malware feeds
- OpenPhish
- URLhaus
- PhishTank
- Google Safe Browsing
- AbuseIPDB
- AlienVault OTX
"""
import requests
import logging
from typing import List, Dict, Any, Set
from datetime import datetime, timedelta
import json
import hashlib

logger = logging.getLogger(__name__)


class ThreatIntelFeeds:
    """Aggregate and query multiple threat intelligence feeds."""

    def __init__(self, virustotal_api_key=None, abuseipdb_api_key=None, otx_api_key=None):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Anisakys-ThreatIntel/1.0'
        })

        # API Keys
        self.vt_api_key = virustotal_api_key
        self.abuseipdb_api_key = abuseipdb_api_key
        self.otx_api_key = otx_api_key

        # Feed URLs
        self.openphish_feed = "https://openphish.com/feed.txt"
        self.urlhaus_recent = "https://urlhaus.abuse.ch/downloads/csv_recent/"
        self.phishtank_feed = "http://data.phishtank.com/data/online-valid.json"

        # Cache
        self.cache = {}
        self.cache_expiry = {}

    def get_openphish_feed(self, limit: int = 1000) -> List[Dict[str, Any]]:
        """
        Fetch latest phishing URLs from OpenPhish.

        Returns:
            List of phishing URLs with metadata
        """
        logger.info("📥 Fetching OpenPhish feed...")

        try:
            response = self.session.get(self.openphish_feed, timeout=30)

            if response.status_code != 200:
                logger.error(f"❌ OpenPhish feed error: {response.status_code}")
                return []

            urls = response.text.strip().split('\n')[:limit]

            results = []
            for url in urls:
                if url.strip():
                    results.append({
                        'url': url.strip(),
                        'source': 'openphish',
                        'threat_type': 'phishing',
                        'confidence': 95,  # OpenPhish is highly accurate
                        'discovered_at': datetime.now().isoformat(),
                        'feed': 'openphish_community'
                    })

            logger.info(f"✅ OpenPhish: {len(results)} phishing URLs")
            return results

        except Exception as e:
            logger.error(f"❌ OpenPhish error: {e}")
            return []

    def get_urlhaus_recent(self, limit: int = 1000) -> List[Dict[str, Any]]:
        """
        Fetch recent malware/phishing URLs from URLhaus.

        Returns:
            List of malicious URLs with metadata
        """
        logger.info("📥 Fetching URLhaus recent feed...")

        try:
            response = self.session.get(self.urlhaus_recent, timeout=30)

            if response.status_code != 200:
                logger.error(f"❌ URLhaus feed error: {response.status_code}")
                return []

            lines = response.text.strip().split('\n')

            results = []

            # Skip header lines (start with #)
            for line in lines:
                if line.startswith('#') or not line.strip():
                    continue

                try:
                    # CSV format: id, dateadded, url, url_status, threat, tags, urlhaus_link
                    parts = line.split(',', 6)

                    if len(parts) < 6:
                        continue

                    url_id, date_added, url, status, threat, tags = parts[:6]

                    # Only active URLs
                    if status != 'online':
                        continue

                    results.append({
                        'url': url.strip('"'),
                        'source': 'urlhaus',
                        'threat_type': threat.strip('"'),
                        'tags': tags.strip('"'),
                        'confidence': 90,
                        'status': status.strip('"'),
                        'discovered_at': date_added.strip('"'),
                        'urlhaus_id': url_id.strip('"'),
                        'feed': 'urlhaus_abuse_ch'
                    })

                    if len(results) >= limit:
                        break

                except Exception as e:
                    logger.debug(f"Error parsing URLhaus line: {e}")
                    continue

            logger.info(f"✅ URLhaus: {len(results)} malicious URLs")
            return results

        except Exception as e:
            logger.error(f"❌ URLhaus error: {e}")
            return []

    def get_phishtank_feed(self, limit: int = 1000) -> List[Dict[str, Any]]:
        """
        Fetch PhishTank verified phishing URLs.

        Returns:
            List of verified phishing URLs
        """
        logger.info("📥 Fetching PhishTank feed...")

        try:
            # Note: PhishTank JSON feed is large (~50MB), limit download
            response = self.session.get(
                self.phishtank_feed,
                timeout=60,
                stream=True
            )

            if response.status_code != 200:
                logger.error(f"❌ PhishTank feed error: {response.status_code}")
                return []

            # Read first chunk only (we don't need all 50MB)
            content = ""
            for chunk in response.iter_content(chunk_size=1024*1024, decode_unicode=True):
                content += chunk
                if len(content) > 10*1024*1024:  # 10MB max
                    break

            # Try to parse JSON
            try:
                data = json.loads(content)
            except json.JSONDecodeError:
                # Try to fix incomplete JSON
                if content.endswith(','):
                    content = content.rstrip(',') + ']'
                elif not content.endswith(']'):
                    content += ']'
                data = json.loads(content)

            results = []

            for entry in data[:limit]:
                try:
                    if entry.get('verified') == 'yes' and entry.get('online') == 'yes':
                        results.append({
                            'url': entry['url'],
                            'source': 'phishtank',
                            'threat_type': 'phishing',
                            'confidence': 95,
                            'phish_id': entry.get('phish_id'),
                            'target': entry.get('target', 'unknown'),
                            'verified': entry.get('verified') == 'yes',
                            'discovered_at': entry.get('submission_time'),
                            'feed': 'phishtank_verified'
                        })
                except Exception as e:
                    logger.debug(f"Error parsing PhishTank entry: {e}")
                    continue

            logger.info(f"✅ PhishTank: {len(results)} verified phishing URLs")
            return results

        except Exception as e:
            logger.error(f"❌ PhishTank error: {e}")
            return []

    def search_feeds_for_brand(
        self,
        brand: str,
        feeds: List[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Search all feeds for URLs targeting a specific brand.

        Args:
            brand: Brand name to search for (e.g., "paypal", "facebook")
            feeds: List of feeds to search (default: all)

        Returns:
            All matching threats from feeds
        """
        if feeds is None:
            feeds = ['openphish', 'urlhaus', 'phishtank']

        logger.info(f"🔍 Searching threat feeds for brand: {brand}")

        all_threats = []
        brand_lower = brand.lower()

        # Get all feed data
        feed_data = {}

        if 'openphish' in feeds:
            feed_data['openphish'] = self.get_openphish_feed()

        if 'urlhaus' in feeds:
            feed_data['urlhaus'] = self.get_urlhaus_recent()

        if 'phishtank' in feeds:
            feed_data['phishtank'] = self.get_phishtank_feed()

        # Filter by brand
        for feed_name, threats in feed_data.items():
            for threat in threats:
                url = threat['url'].lower()

                # Check if URL contains brand
                if brand_lower in url:
                    threat['matched_brand'] = brand
                    threat['match_type'] = 'url_contains_brand'
                    all_threats.append(threat)

                # Check if target matches brand (PhishTank specific)
                elif threat.get('target', '').lower() == brand_lower:
                    threat['matched_brand'] = brand
                    threat['match_type'] = 'target_brand'
                    all_threats.append(threat)

        logger.info(f"✅ Found {len(all_threats)} threats targeting {brand}")
        return all_threats

    def get_all_active_threats(self, max_per_feed: int = 500) -> Dict[str, Any]:
        """
        Get all active threats from all feeds.

        Returns:
            Aggregated threat data with statistics
        """
        logger.info("📊 Aggregating all active threats...")

        openphish = self.get_openphish_feed(limit=max_per_feed)
        urlhaus = self.get_urlhaus_recent(limit=max_per_feed)
        phishtank = self.get_phishtank_feed(limit=max_per_feed)

        all_threats = openphish + urlhaus + phishtank

        # Calculate statistics
        stats = {
            'total_threats': len(all_threats),
            'by_source': {
                'openphish': len(openphish),
                'urlhaus': len(urlhaus),
                'phishtank': len(phishtank)
            },
            'by_type': {},
            'last_updated': datetime.now().isoformat()
        }

        # Count by threat type
        for threat in all_threats:
            threat_type = threat.get('threat_type', 'unknown')
            stats['by_type'][threat_type] = stats['by_type'].get(threat_type, 0) + 1

        return {
            'threats': all_threats,
            'statistics': stats
        }

    def check_url_in_feeds(self, url: str) -> Dict[str, Any]:
        """
        Check if a specific URL exists in any threat feed.

        Args:
            url: URL to check

        Returns:
            Detection results from all feeds
        """
        logger.info(f"🔍 Checking URL in threat feeds: {url[:50]}...")

        # Get recent feeds
        openphish = self.get_openphish_feed(limit=1000)
        urlhaus = self.get_urlhaus_recent(limit=1000)

        url_lower = url.lower()

        detections = []

        # Check OpenPhish
        for threat in openphish:
            if threat['url'].lower() == url_lower:
                detections.append({
                    'feed': 'openphish',
                    'detected': True,
                    'confidence': threat['confidence'],
                    'threat_type': threat['threat_type']
                })
                break

        # Check URLhaus
        for threat in urlhaus:
            if threat['url'].lower() == url_lower:
                detections.append({
                    'feed': 'urlhaus',
                    'detected': True,
                    'confidence': threat['confidence'],
                    'threat_type': threat['threat_type'],
                    'tags': threat.get('tags', '')
                })
                break

        is_malicious = len(detections) > 0

        return {
            'url': url,
            'is_malicious': is_malicious,
            'detections': detections,
            'detection_count': len(detections),
            'checked_at': datetime.now().isoformat()
        }


def test_threat_feeds():
    """Test threat intelligence feeds."""
    feeds = ThreatIntelFeeds()

    # Test getting all threats
    print("\n📊 Testing threat feed aggregation...")
    all_threats = feeds.get_all_active_threats(max_per_feed=100)

    print(f"\n✅ Total threats: {all_threats['statistics']['total_threats']}")
    print(f"   OpenPhish: {all_threats['statistics']['by_source']['openphish']}")
    print(f"   URLhaus: {all_threats['statistics']['by_source']['urlhaus']}")
    print(f"   PhishTank: {all_threats['statistics']['by_source']['phishtank']}")

    # Test brand search
    print("\n🔍 Searching for PayPal threats...")
    paypal_threats = feeds.search_feeds_for_brand('paypal', feeds=['openphish'])
    print(f"   Found {len(paypal_threats)} PayPal phishing URLs")

    if paypal_threats:
        print(f"\n   Sample threats:")
        for threat in paypal_threats[:5]:
            print(f"   - {threat['url'][:60]}...")

    return all_threats


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    test_threat_feeds()
