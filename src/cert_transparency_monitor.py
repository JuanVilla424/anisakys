"""
Certificate Transparency Log Monitor
Monitors CT logs for newly issued SSL certificates matching brand patterns
Real-time detection of potential phishing domains
"""
import requests
import logging
import time
from typing import List, Dict, Any, Set
from datetime import datetime, timedelta
import re

logger = logging.getLogger(__name__)


class CertTransparencyMonitor:
    """Monitor Certificate Transparency logs for suspicious certificates."""

    def __init__(self):
        self.crtsh_api = "https://crt.sh/"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Anisakys-ThreatIntel/1.0'
        })

    def search_certificates(
        self,
        brand: str,
        days_back: int = 7,
        include_expired: bool = False,
        exclude_legit_domains: List[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Search CT logs for certificates matching brand pattern.

        Args:
            brand: Brand name to search for (e.g., "paypal", "facebook")
            days_back: How many days back to search
            include_expired: Include expired certificates
            exclude_legit_domains: List of legitimate domains to exclude

        Returns:
            List of suspicious certificates
        """
        logger.info(f"🔍 Searching CT logs for brand: {brand} (last {days_back} days)")

        exclude_legit_domains = exclude_legit_domains or []

        results = []

        # Search patterns
        patterns = [
            f"%{brand}%",
            f"%{brand}-login%",
            f"%{brand}login%",
            f"%{brand}-secure%",
            f"%{brand}secure%",
            f"%{brand}-verify%",
            f"%{brand}verify%",
            f"%{brand}-account%",
            f"%{brand}account%",
            f"%{brand}-support%",
        ]

        for pattern in patterns:
            try:
                logger.info(f"   Searching pattern: {pattern}")

                # crt.sh API
                params = {
                    'q': pattern,
                    'output': 'json',
                    'exclude': 'expired' if not include_expired else None
                }

                response = self.session.get(
                    self.crtsh_api,
                    params=params,
                    timeout=30
                )

                if response.status_code != 200:
                    logger.warning(f"⚠️ crt.sh returned status {response.status_code}")
                    continue

                certs = response.json() if response.text else []

                for cert in certs:
                    try:
                        # Parse certificate data
                        common_name = cert.get('common_name', '') or cert.get('name_value', '')
                        issuer_name = cert.get('issuer_name', '')
                        not_before = cert.get('not_before', '')
                        not_after = cert.get('not_after', '')
                        cert_id = cert.get('id', '')

                        # Skip if no common name
                        if not common_name:
                            continue

                        # Clean common name (might have wildcards)
                        domain = common_name.replace('*.', '').lower()

                        # Skip legitimate domains
                        if any(legit in domain for legit in exclude_legit_domains):
                            continue

                        # Check if certificate is recent
                        if not_before:
                            try:
                                cert_date = datetime.fromisoformat(not_before.replace('Z', '+00:00'))
                                cutoff_date = datetime.now().astimezone() - timedelta(days=days_back)

                                if cert_date < cutoff_date:
                                    continue  # Too old
                            except:
                                pass

                        # Calculate suspicion score
                        suspicion_score = self._calculate_suspicion_score(
                            domain, brand, issuer_name
                        )

                        if suspicion_score >= 50:  # Only high suspicion
                            results.append({
                                'domain': domain,
                                'common_name': common_name,
                                'cert_id': cert_id,
                                'issuer': issuer_name,
                                'not_before': not_before,
                                'not_after': not_after,
                                'suspicion_score': suspicion_score,
                                'detection_method': 'certificate_transparency',
                                'crtsh_url': f"https://crt.sh/?id={cert_id}",
                                'discovered_at': datetime.now().isoformat()
                            })

                    except Exception as e:
                        logger.debug(f"Error parsing cert: {e}")
                        continue

                # Rate limiting
                time.sleep(1)

            except Exception as e:
                logger.error(f"❌ Error searching pattern {pattern}: {e}")
                continue

        # Deduplicate by domain
        seen_domains = set()
        unique_results = []

        for result in sorted(results, key=lambda x: x['suspicion_score'], reverse=True):
            if result['domain'] not in seen_domains:
                seen_domains.add(result['domain'])
                unique_results.append(result)

        logger.info(f"✅ Found {len(unique_results)} suspicious certificates")
        return unique_results

    def _calculate_suspicion_score(self, domain: str, brand: str, issuer: str) -> int:
        """Calculate suspicion score for a certificate."""
        score = 0

        domain_lower = domain.lower()
        brand_lower = brand.lower()

        # High risk patterns
        if f"{brand_lower}-login" in domain_lower:
            score += 40
        if f"{brand_lower}login" in domain_lower:
            score += 35
        if f"{brand_lower}-secure" in domain_lower:
            score += 35
        if f"{brand_lower}secure" in domain_lower:
            score += 30
        if f"{brand_lower}-verify" in domain_lower:
            score += 35
        if f"{brand_lower}account" in domain_lower:
            score += 30
        if f"{brand_lower}-support" in domain_lower:
            score += 25

        # Suspicious TLDs
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.top', '.xyz',
                          '.club', '.work', '.click', '.link', '.info', '.online']
        if any(domain_lower.endswith(tld) for tld in suspicious_tlds):
            score += 25

        # Homograph attacks (numbers replacing letters)
        if '0' in domain_lower or '1' in domain_lower:  # O->0, I->1
            score += 15

        # Multiple hyphens (suspicious)
        if domain_lower.count('-') >= 2:
            score += 15

        # Free SSL issuers (Let's Encrypt is most common for phishing)
        if issuer and "Let's Encrypt" in issuer:
            score += 10
        elif issuer and any(x in issuer.lower() for x in ['cloudflare', 'google', 'digicert']):
            score += 5

        # Very long domains
        if len(domain_lower) > 30:
            score += 10

        # Contains brand but not exact match
        if brand_lower in domain_lower and domain_lower != f"{brand_lower}.com":
            score += 20

        return min(score, 100)

    def monitor_brand_continuous(
        self,
        brands: List[str],
        legitimate_domains: Dict[str, List[str]],
        callback=None
    ) -> List[Dict[str, Any]]:
        """
        Monitor multiple brands continuously.

        Args:
            brands: List of brand names to monitor
            legitimate_domains: Dict mapping brand -> list of legit domains
            callback: Optional callback function for real-time alerts

        Returns:
            All suspicious certificates found
        """
        all_results = []

        for brand in brands:
            logger.info(f"🔍 Monitoring brand: {brand}")

            legit = legitimate_domains.get(brand, [])

            certs = self.search_certificates(
                brand=brand,
                days_back=30,  # Last 30 days
                exclude_legit_domains=legit
            )

            for cert in certs:
                cert['monitored_brand'] = brand
                all_results.append(cert)

                # Call callback if provided
                if callback:
                    try:
                        callback(cert)
                    except Exception as e:
                        logger.error(f"Callback error: {e}")

        return all_results


def test_ct_monitor():
    """Test CT monitoring functionality."""
    monitor = CertTransparencyMonitor()

    # Test with PayPal
    results = monitor.search_certificates(
        brand="paypal",
        days_back=7,
        exclude_legit_domains=["paypal.com", "paypal.me", "paypalobjects.com"]
    )

    print(f"\n🔍 Found {len(results)} suspicious PayPal certificates:")
    for cert in results[:10]:  # Top 10
        print(f"   [{cert['suspicion_score']}] {cert['domain']} - Issued: {cert['not_before']}")

    return results


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    test_ct_monitor()
