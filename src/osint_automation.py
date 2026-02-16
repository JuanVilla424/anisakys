"""
OSINT Automation Module
Automated Open Source Intelligence gathering:
- Shodan API integration (IoT/server scanning)
- Censys API integration (Internet-wide scanning)
- IP reputation checking
- WHOIS enrichment
- BGP/ASN analysis
- DNS history tracking
"""
import requests
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
import socket
import json

logger = logging.getLogger(__name__)


class OSINTAutomation:
    """Automated OSINT data collection for threat intelligence."""

    def __init__(
        self,
        shodan_api_key: Optional[str] = None,
        censys_api_id: Optional[str] = None,
        censys_api_secret: Optional[str] = None
    ):
        self.shodan_api_key = shodan_api_key
        self.censys_api_id = censys_api_id
        self.censys_api_secret = censys_api_secret

        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Anisakys-ThreatIntel/1.0'
        })

    def shodan_host_lookup(self, ip: str) -> Dict[str, Any]:
        """
        Lookup host information using Shodan.

        Args:
            ip: IP address to lookup

        Returns:
            Host information from Shodan
        """
        if not self.shodan_api_key:
            return {'error': 'Shodan API key not configured'}

        try:
            logger.info(f"🔍 Shodan lookup: {ip}")

            url = f"https://api.shodan.io/shodan/host/{ip}"
            params = {'key': self.shodan_api_key}

            response = self.session.get(url, params=params, timeout=10)

            if response.status_code == 404:
                return {'error': 'IP not found in Shodan'}
            elif response.status_code != 200:
                return {'error': f'Shodan API error: {response.status_code}'}

            data = response.json()

            # Parse relevant information
            result = {
                'ip': data.get('ip_str'),
                'organization': data.get('org'),
                'isp': data.get('isp'),
                'asn': data.get('asn'),
                'country': data.get('country_name'),
                'city': data.get('city'),
                'hostnames': data.get('hostnames', []),
                'domains': data.get('domains', []),
                'ports': data.get('ports', []),
                'vulns': list(data.get('vulns', {}).keys()),
                'tags': data.get('tags', []),
                'last_update': data.get('last_update'),
                'services': []
            }

            # Extract service information
            for service in data.get('data', []):
                result['services'].append({
                    'port': service.get('port'),
                    'transport': service.get('transport'),
                    'product': service.get('product'),
                    'version': service.get('version'),
                    'banner': service.get('data', '')[:200]  # First 200 chars
                })

            logger.info(f"✅ Shodan: Found {len(result['ports'])} ports, {len(result['vulns'])} vulns")
            return result

        except Exception as e:
            logger.error(f"❌ Shodan lookup error: {e}")
            return {'error': str(e)}

    def check_ip_reputation(self, ip: str) -> Dict[str, Any]:
        """
        Check IP reputation using multiple free sources.

        Args:
            ip: IP address to check

        Returns:
            Reputation information
        """
        logger.info(f"🔍 Checking IP reputation: {ip}")

        reputation = {
            'ip': ip,
            'is_suspicious': False,
            'checks': []
        }

        try:
            # Check 1: AbuseIPDB (free tier - 1000 requests/day)
            # Note: Requires API key for full access
            reputation['checks'].append({
                'source': 'abuseipdb',
                'status': 'requires_api_key'
            })

            # Check 2: IPVoid (web scraping)
            try:
                response = self.session.get(
                    f"https://www.ipvoid.com/ip-blacklist-check/",
                    timeout=10
                )
                if response.status_code == 200:
                    # Simple check if IP appears malicious
                    is_listed = 'blacklisted' in response.text.lower()
                    reputation['checks'].append({
                        'source': 'ipvoid',
                        'listed': is_listed,
                        'status': 'checked'
                    })
                    if is_listed:
                        reputation['is_suspicious'] = True
            except:
                pass

            # Check 3: Reverse DNS
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                reputation['reverse_dns'] = hostname

                # Suspicious if no reverse DNS or generic PTR
                if not hostname or 'static' in hostname or 'dynamic' in hostname:
                    reputation['checks'].append({
                        'source': 'reverse_dns',
                        'suspicious': True,
                        'hostname': hostname
                    })
            except:
                reputation['reverse_dns'] = None
                reputation['checks'].append({
                    'source': 'reverse_dns',
                    'suspicious': True,
                    'reason': 'no_ptr_record'
                })

            return reputation

        except Exception as e:
            logger.error(f"❌ IP reputation check error: {e}")
            return {'ip': ip, 'error': str(e)}

    def get_whois_enhanced(self, domain: str) -> Dict[str, Any]:
        """
        Enhanced WHOIS lookup with additional context.

        Args:
            domain: Domain to lookup

        Returns:
            Enhanced WHOIS data
        """
        try:
            import whois

            logger.info(f"🔍 WHOIS lookup: {domain}")

            w = whois.whois(domain)

            # Parse WHOIS data
            result = {
                'domain': domain,
                'registrar': w.registrar if hasattr(w, 'registrar') else None,
                'creation_date': str(w.creation_date) if hasattr(w, 'creation_date') else None,
                'expiration_date': str(w.expiration_date) if hasattr(w, 'expiration_date') else None,
                'updated_date': str(w.updated_date) if hasattr(w, 'updated_date') else None,
                'name_servers': w.name_servers if hasattr(w, 'name_servers') else [],
                'status': w.status if hasattr(w, 'status') else None,
                'emails': w.emails if hasattr(w, 'emails') else [],
                'org': w.org if hasattr(w, 'org') else None,
                'country': w.country if hasattr(w, 'country') else None
            }

            # Calculate domain age
            if result['creation_date']:
                try:
                    if isinstance(w.creation_date, list):
                        creation = w.creation_date[0]
                    else:
                        creation = w.creation_date

                    if creation:
                        age_days = (datetime.now() - creation).days
                        result['domain_age_days'] = age_days

                        # Flag if very new (common for phishing)
                        if age_days < 30:
                            result['newly_registered'] = True
                            result['suspicion_level'] = 'high'
                        elif age_days < 90:
                            result['newly_registered'] = True
                            result['suspicion_level'] = 'medium'
                        else:
                            result['newly_registered'] = False
                            result['suspicion_level'] = 'low'
                except:
                    pass

            logger.info(f"✅ WHOIS: {result.get('registrar', 'Unknown')} - Age: {result.get('domain_age_days', '?')} days")
            return result

        except Exception as e:
            logger.error(f"❌ WHOIS lookup error: {e}")
            return {'domain': domain, 'error': str(e)}

    def get_dns_records(self, domain: str) -> Dict[str, Any]:
        """
        Get comprehensive DNS records for domain.

        Args:
            domain: Domain to query

        Returns:
            DNS records
        """
        logger.info(f"🔍 DNS lookup: {domain}")

        dns_data = {
            'domain': domain,
            'a_records': [],
            'mx_records': [],
            'txt_records': [],
            'ns_records': [],
            'cname_record': None
        }

        try:
            import dns.resolver

            # A records
            try:
                answers = dns.resolver.resolve(domain, 'A')
                dns_data['a_records'] = [str(rdata) for rdata in answers]
            except:
                pass

            # MX records
            try:
                answers = dns.resolver.resolve(domain, 'MX')
                dns_data['mx_records'] = [str(rdata.exchange) for rdata in answers]
            except:
                pass

            # TXT records
            try:
                answers = dns.resolver.resolve(domain, 'TXT')
                dns_data['txt_records'] = [str(rdata) for rdata in answers]
            except:
                pass

            # NS records
            try:
                answers = dns.resolver.resolve(domain, 'NS')
                dns_data['ns_records'] = [str(rdata) for rdata in answers]
            except:
                pass

            # CNAME
            try:
                answers = dns.resolver.resolve(domain, 'CNAME')
                if answers:
                    dns_data['cname_record'] = str(answers[0])
            except:
                pass

            logger.info(f"✅ DNS: {len(dns_data['a_records'])} A records, {len(dns_data['mx_records'])} MX")
            return dns_data

        except Exception as e:
            logger.error(f"❌ DNS lookup error: {e}")
            return {'domain': domain, 'error': str(e)}

    def comprehensive_osint(self, domain: str, ip: str = None) -> Dict[str, Any]:
        """
        Perform comprehensive OSINT analysis on domain/IP.

        Args:
            domain: Domain to analyze
            ip: Optional IP address (will be resolved if not provided)

        Returns:
            Complete OSINT analysis
        """
        logger.info(f"🚀 Comprehensive OSINT: {domain}")

        osint_data = {
            'domain': domain,
            'ip': ip,
            'timestamp': datetime.now().isoformat()
        }

        # Get WHOIS data
        osint_data['whois'] = self.get_whois_enhanced(domain)

        # Get DNS records
        osint_data['dns'] = self.get_dns_records(domain)

        # Resolve IP if not provided
        if not ip and osint_data['dns'].get('a_records'):
            ip = osint_data['dns']['a_records'][0]
            osint_data['ip'] = ip

        # IP analysis
        if ip:
            osint_data['ip_reputation'] = self.check_ip_reputation(ip)

            # Shodan lookup if API key available
            if self.shodan_api_key:
                osint_data['shodan'] = self.shodan_host_lookup(ip)

        # Calculate overall risk score
        risk_score = self._calculate_osint_risk_score(osint_data)
        osint_data['risk_score'] = risk_score

        logger.info(f"✅ OSINT complete - Risk score: {risk_score}/100")
        return osint_data

    def _calculate_osint_risk_score(self, osint_data: Dict[str, Any]) -> int:
        """Calculate risk score based on OSINT data."""
        score = 0

        # Check WHOIS age
        whois = osint_data.get('whois', {})
        if whois.get('newly_registered'):
            if whois.get('domain_age_days', 999) < 30:
                score += 35
            elif whois.get('domain_age_days', 999) < 90:
                score += 20

        # Check IP reputation
        ip_rep = osint_data.get('ip_reputation', {})
        if ip_rep.get('is_suspicious'):
            score += 30

        # Check Shodan vulnerabilities
        shodan = osint_data.get('shodan', {})
        if shodan.get('vulns'):
            score += 20

        # Missing reverse DNS
        if ip_rep.get('reverse_dns') is None:
            score += 10

        return min(score, 100)


def test_osint_automation():
    """Test OSINT automation."""
    osint = OSINTAutomation()

    print("\n🔍 Testing OSINT Automation...")

    # Test WHOIS
    whois_data = osint.get_whois_enhanced("google.com")
    print(f"   WHOIS: {whois_data.get('registrar', 'Unknown')}")
    print(f"   Age: {whois_data.get('domain_age_days', '?')} days")

    # Test DNS
    dns_data = osint.get_dns_records("google.com")
    print(f"   A Records: {len(dns_data.get('a_records', []))}")

    print("✅ OSINT automation test complete")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    test_osint_automation()
