#!/usr/bin/env python3
"""
Google Ads Phishing Detection Module
Defensive security tool to identify potential phishing campaigns in Google Ads
Integrates with existing Anisakys infrastructure
"""

import re
import requests
import urllib.parse
from typing import Dict, List, Optional, Set
import hashlib
import json
from datetime import datetime, timedelta
import dns.resolver
import whois
from bs4 import BeautifulSoup
import asyncio
import time
from urllib.parse import quote, parse_qs
import os

from src.config import settings
from src.dns.network_utils import (
    assess_url_target,
    safe_get_with_redirects,
    SSRFRedirectError,
    REDIRECT_STATUS_CODES,
)
from src.logger import logger


class GoogleAdsPhishingDetector:
    """Detect phishing attempts in Google Ads campaigns using existing config"""

    def __init__(self):
        # Load keywords from config
        self.keywords = [k.strip().lower() for k in settings.KEYWORDS.split(",")]
        self.domains = [d.strip().lower() for d in settings.DOMAINS.split(",")]

        # Load allowed sites from config
        self.allowed_sites = []
        if settings.ALLOWED_SITES:
            self.allowed_sites = [s.strip().lower() for s in settings.ALLOWED_SITES.split(",")]

        self.suspicious_patterns = {
            "url_shorteners": [
                r"bit\.ly",
                r"tinyurl\.com",
                r"goo\.gl",
                r"ow\.ly",
                r"is\.gd",
                r"buff\.ly",
                r"adf\.ly",
                r"bit\.do",
                r"short\.link",
                r"rebrand\.ly",
                r"bl\.ink",
            ],
            "homoglyphs": {
                "fcm": ["fcn", "fcnn", "fcrn", "fcm1", "fcm0"],
                "runt": ["run7", "runl", "runt1", "r0nt"],
                "simit": ["sim1t", "sirnit", "slmit", "simlt"],
                "google": ["g00gle", "googIe", "goog1e", "g0ogle"],
                "microsoft": ["microsofl", "micr0soft", "mlcrosoft"],
                "amazon": ["amaz0n", "arnazon", "amazom"],
                "paypal": ["paypaI", "payp4l", "paipal"],
                "facebook": ["faceb00k", "faceboak", "faceboook"],
            },
            "suspicious_tlds": [
                ".tk",
                ".ml",
                ".ga",
                ".cf",
                ".click",
                ".download",
                ".review",
                ".work",
                ".party",
                ".science",
                ".study",
                ".buzz",
                ".site",
                ".website",
                ".space",
                ".live",
            ],
            "phishing_keywords": self.keywords
            + [
                "verify-account",
                "suspended",
                "confirm-identity",
                "update-payment",
                "security-alert",
                "unusual-activity",
                "limited-time",
                "act-now",
                "urgent-action",
                "prize",
                "winner",
                "congratulations",
                "free-gift",
            ],
        }

        self.tracking_parameters = [
            "utm_source",
            "utm_medium",
            "utm_campaign",
            "gclid",
            "fbclid",
            "msclkid",
            "ef_id",
            "dclid",
        ]

        self.timeout = settings.TIMEOUT
        self.scan_interval = settings.SCAN_INTERVAL

        # Extended search terms for Colombian context
        self.search_templates = [
            "{keyword}",
            "{keyword} pagar",
            "{keyword} consulta",
            "{keyword} descuento",
            "pagar {keyword}",
            "consultar {keyword}",
            "{keyword} colombia",
            "{keyword} bogota",
            "{keyword} en linea",
            "{keyword} online",
            "{keyword} oficial",
            "{keyword} gov co",
            "{keyword} gratis",
            "{keyword} rapido",
            "{keyword} facil",
        ]

        # Google domains to search
        self.google_domains = [
            "google.com",
            "google.com.co",  # Colombia
            "google.es",  # Spain
            "google.com.mx",  # Mexico
        ]

        # Cache to avoid duplicate processing
        self.processed_ads = set()
        self.results_cache = {}

    def analyze_ad_url(self, ad_url: str, display_url: str = None) -> Dict:
        """Analyze a Google Ad URL for phishing indicators"""
        logger.info(f"🔍 Analyzing Google Ad URL: {ad_url}")

        results = {
            "url": ad_url,
            "display_url": display_url,
            "risk_score": 0,
            "indicators": [],
            "final_destination": None,
            "redirect_chain": [],
            "timestamp": datetime.now().isoformat(),
            "keywords_found": [],
        }

        # Check if URL is in allowed sites
        if self._is_allowed_site(ad_url):
            logger.info(f"✅ URL is in allowed sites list: {ad_url}")
            results["risk_level"] = "SAFE"
            results["indicators"].append("ALLOWED_SITE")
            return results

        # Check for URL shorteners
        if self._check_url_shortener(ad_url):
            results["indicators"].append("URL_SHORTENER_DETECTED")
            results["risk_score"] += 30
            logger.warning(f"⚠️ URL shortener detected: {ad_url}")

        # Follow redirects and analyze chain
        redirect_info = self._follow_redirects(ad_url)
        results["redirect_chain"] = redirect_info["chain"]
        results["final_destination"] = redirect_info["final_url"]

        if len(redirect_info["chain"]) > 3:
            results["indicators"].append("EXCESSIVE_REDIRECTS")
            results["risk_score"] += 20
            logger.warning(f"⚠️ Excessive redirects ({len(redirect_info['chain'])})")

        # Check for configured keywords in URL
        found_keywords = self._check_configured_keywords(results["final_destination"])
        if found_keywords:
            results["keywords_found"] = found_keywords
            results["indicators"].append(f'SUSPICIOUS_KEYWORDS: {", ".join(found_keywords)}')
            results["risk_score"] += 25 * len(found_keywords)
            logger.warning(f"🚨 Found configured keywords: {found_keywords}")

        # Check for homoglyphs and typosquatting
        homoglyph_check = self._check_homoglyphs(results["final_destination"])
        if homoglyph_check:
            results["indicators"].append(f"POSSIBLE_TYPOSQUATTING: {homoglyph_check}")
            results["risk_score"] += 40
            logger.warning(f"🚨 Possible typosquatting: {homoglyph_check}")

        # Check TLD
        if self._check_suspicious_tld(results["final_destination"]):
            results["indicators"].append("SUSPICIOUS_TLD")
            results["risk_score"] += 25
            logger.warning(f"⚠️ Suspicious TLD detected")

        # Check for phishing keywords in URL
        phishing_keywords = self._check_phishing_keywords(results["final_destination"])
        if phishing_keywords:
            results["indicators"].append(f'PHISHING_KEYWORDS: {", ".join(phishing_keywords)}')
            results["risk_score"] += 15 * len(phishing_keywords)
            logger.warning(f"⚠️ Phishing keywords found: {phishing_keywords}")

        # Check domain age and registration
        domain_info = self._check_domain_info(results["final_destination"])
        if domain_info:
            results["domain_info"] = domain_info
            if domain_info.get("days_old", 365) < 30:
                results["indicators"].append("NEWLY_REGISTERED_DOMAIN")
                results["risk_score"] += 35
                logger.warning(f"🚨 Newly registered domain ({domain_info['days_old']} days old)")

        # Check SSL certificate
        ssl_info = self._check_ssl_certificate(results["final_destination"])
        results["ssl_info"] = ssl_info
        if not ssl_info.get("valid", False):
            results["indicators"].append("INVALID_SSL_CERTIFICATE")
            results["risk_score"] += 25
            logger.warning(f"⚠️ Invalid SSL certificate")

        # Analyze landing page content
        page_analysis = self._analyze_landing_page(results["final_destination"])
        if page_analysis:
            results["page_analysis"] = page_analysis
            results["risk_score"] += page_analysis.get("risk_score", 0)
            results["indicators"].extend(page_analysis.get("indicators", []))

        # Calculate final risk level
        if results["risk_score"] >= 70:
            results["risk_level"] = "HIGH"
            logger.error(f"🚨 HIGH RISK Google Ad detected: {ad_url}")
        elif results["risk_score"] >= 40:
            results["risk_level"] = "MEDIUM"
            logger.warning(f"⚠️ MEDIUM RISK Google Ad: {ad_url}")
        elif results["risk_score"] >= 20:
            results["risk_level"] = "LOW"
            logger.info(f"ℹ️ LOW RISK Google Ad: {ad_url}")
        else:
            results["risk_level"] = "MINIMAL"
            logger.info(f"✅ MINIMAL RISK Google Ad: {ad_url}")

        return results

    def _is_allowed_site(self, url: str) -> bool:
        """Check if URL is in allowed sites list"""
        domain = urllib.parse.urlparse(url).netloc.lower()
        return domain in self.allowed_sites

    def _check_configured_keywords(self, url: str) -> List[str]:
        """Check for configured keywords in URL"""
        found = []
        url_lower = url.lower()

        for keyword in self.keywords:
            if keyword in url_lower:
                found.append(keyword)

        return found

    def _check_url_shortener(self, url: str) -> bool:
        """Check if URL uses a known URL shortener"""
        for pattern in self.suspicious_patterns["url_shorteners"]:
            if re.search(pattern, url, re.IGNORECASE):
                return True
        return False

    def _follow_redirects(self, url: str, max_redirects: int = 10) -> Dict:
        """Follow URL redirects and return the chain.

        Walks hops manually (rather than requests' own allow_redirects=True)
        so each hop can be checked against the SSRF guard BEFORE it's fetched
        — letting requests follow redirects itself would silently reach an
        internal address before we ever got a chance to refuse it.
        """
        redirect_chain = []
        final_url = url
        current_url = url

        try:
            session = requests.Session()
            session.headers.update(
                {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
            )

            for _ in range(max_redirects):
                if assess_url_target(current_url) in ("blocked", "invalid"):
                    logger.warning(f"🛑 SSRF: refusing redirect to {current_url}")
                    break

                response = session.get(current_url, allow_redirects=False, timeout=self.timeout)
                redirect_chain.append({"url": current_url, "status_code": response.status_code})
                final_url = current_url

                if response.status_code not in REDIRECT_STATUS_CODES:
                    break

                location = response.headers.get("Location")
                if not location:
                    break

                current_url = urllib.parse.urljoin(current_url, location)

        except Exception as e:
            logger.error(f"Error following redirects: {e}")

        return {"chain": redirect_chain, "final_url": final_url}

    def _check_homoglyphs(self, url: str) -> Optional[str]:
        """Check for homoglyph attacks and typosquatting"""
        domain = urllib.parse.urlparse(url).netloc.lower()

        for legitimate, variations in self.suspicious_patterns["homoglyphs"].items():
            for variant in variations:
                if variant in domain:
                    return f"Mimicking {legitimate}"

            # Check Levenshtein distance for close matches
            domain_parts = domain.split(".")[0]
            if self._levenshtein_distance(legitimate, domain_parts) <= 2:
                if legitimate != domain_parts:
                    return f"Similar to {legitimate}"

        return None

    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """Calculate Levenshtein distance between two strings"""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)

        if len(s2) == 0:
            return len(s1)

        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row

        return previous_row[-1]

    def _check_suspicious_tld(self, url: str) -> bool:
        """Check if URL uses suspicious TLD"""
        for tld in self.suspicious_patterns["suspicious_tlds"]:
            if tld in url.lower():
                return True

        # Also check against configured domains
        domain = urllib.parse.urlparse(url).netloc.lower()
        for allowed_tld in self.domains:
            if domain.endswith(allowed_tld):
                return False  # It's using an allowed TLD

        return False

    def _check_phishing_keywords(self, url: str) -> List[str]:
        """Check for phishing keywords in URL"""
        found_keywords = []
        url_lower = url.lower()

        for keyword in self.suspicious_patterns["phishing_keywords"]:
            if keyword in url_lower:
                found_keywords.append(keyword)

        return found_keywords

    def _check_domain_info(self, url: str) -> Optional[Dict]:
        """Check domain registration information"""
        try:
            domain = urllib.parse.urlparse(url).netloc
            w = whois.whois(domain)

            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            if creation_date:
                days_old = (datetime.now() - creation_date).days
                return {
                    "domain": domain,
                    "creation_date": creation_date.isoformat(),
                    "days_old": days_old,
                    "registrar": w.registrar,
                }
        except Exception as e:
            logger.error(f"Error checking domain info: {e}")

        return None

    def _check_ssl_certificate(self, url: str) -> Dict:
        """Check SSL certificate validity"""
        result = {"valid": False, "issuer": None, "expires": None}

        try:
            import ssl
            import socket

            domain = urllib.parse.urlparse(url).netloc
            context = ssl.create_default_context()

            with socket.create_connection((domain, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    result["valid"] = True
                    result["issuer"] = dict(x[0] for x in cert["issuer"])
                    result["expires"] = cert["notAfter"]
        except Exception as e:
            logger.debug(f"SSL check failed: {e}")

        return result

    def _analyze_landing_page(self, url: str) -> Optional[Dict]:
        """Analyze landing page for phishing indicators"""
        try:
            try:
                response = safe_get_with_redirects(
                    url,
                    timeout=self.timeout,
                    headers={
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                    },
                    max_hops=5,
                )
            except SSRFRedirectError as exc:
                logger.warning(f"🛑 SSRF: skipping landing-page analysis of {exc.blocked_url}")
                return None

            soup = BeautifulSoup(response.text, "html.parser")
            analysis = {
                "risk_score": 0,
                "indicators": [],
                "forms_found": 0,
                "password_fields": 0,
                "external_resources": [],
                "keywords_in_page": [],
            }

            # Check for forms
            forms = soup.find_all("form")
            analysis["forms_found"] = len(forms)

            # Check for password fields
            password_fields = soup.find_all("input", {"type": "password"})
            analysis["password_fields"] = len(password_fields)

            if analysis["password_fields"] > 0:
                analysis["indicators"].append("PASSWORD_FIELD_PRESENT")
                analysis["risk_score"] += 15

            # Check for configured keywords in page content
            page_text = soup.get_text().lower()
            for keyword in self.keywords:
                if keyword in page_text:
                    analysis["keywords_in_page"].append(keyword)

            if analysis["keywords_in_page"]:
                analysis["indicators"].append(
                    f'CONFIGURED_KEYWORDS_IN_PAGE: {", ".join(analysis["keywords_in_page"])}'
                )
                analysis["risk_score"] += 20

            # Check for urgency language
            urgency_patterns = [
                r"urgent",
                r"immediate",
                r"expire",
                r"suspend",
                r"verify now",
                r"act now",
                r"limited time",
                r"paga",
                r"multa",
                r"comparendo",  # Spanish urgency terms
            ]

            for pattern in urgency_patterns:
                if re.search(pattern, page_text):
                    analysis["indicators"].append(f"URGENCY_LANGUAGE: {pattern}")
                    analysis["risk_score"] += 10
                    break

            # Check for external resources from suspicious domains
            for tag in soup.find_all(["script", "link", "img"]):
                src = tag.get("src") or tag.get("href")
                if src and src.startswith("http"):
                    domain = urllib.parse.urlparse(src).netloc
                    if self._check_suspicious_tld(domain):
                        analysis["external_resources"].append(src)
                        analysis["risk_score"] += 5

            if analysis["external_resources"]:
                analysis["indicators"].append("SUSPICIOUS_EXTERNAL_RESOURCES")

            return analysis

        except Exception as e:
            logger.error(f"Error analyzing landing page: {e}")
            return None

    def scan_google_ads_campaign(self, campaign_data: List[Dict]) -> List[Dict]:
        """Scan multiple Google Ads for phishing"""
        results = []

        logger.info(f"🔍 Scanning {len(campaign_data)} Google Ads...")

        for ad in campaign_data:
            ad_url = ad.get("final_url") or ad.get("url")
            display_url = ad.get("display_url")

            if ad_url:
                analysis = self.analyze_ad_url(ad_url, display_url)
                analysis["ad_id"] = ad.get("id")
                analysis["ad_text"] = ad.get("headline")
                results.append(analysis)

        return results

    def generate_report(self, scan_results: List[Dict], output_file: str = None):
        """Generate a detailed report of scan results"""
        report = {
            "scan_date": datetime.now().isoformat(),
            "total_ads_scanned": len(scan_results),
            "high_risk_ads": [],
            "medium_risk_ads": [],
            "low_risk_ads": [],
            "safe_ads": [],
            "statistics": {
                "high_risk_count": 0,
                "medium_risk_count": 0,
                "low_risk_count": 0,
                "safe_count": 0,
                "common_indicators": {},
                "keywords_detected": {},
            },
        }

        # Categorize results
        for result in scan_results:
            risk_level = result.get("risk_level", "MINIMAL")

            if risk_level == "SAFE":
                report["safe_ads"].append(result)
                report["statistics"]["safe_count"] += 1
            elif risk_level == "HIGH":
                report["high_risk_ads"].append(result)
                report["statistics"]["high_risk_count"] += 1
            elif risk_level == "MEDIUM":
                report["medium_risk_ads"].append(result)
                report["statistics"]["medium_risk_count"] += 1
            elif risk_level == "LOW":
                report["low_risk_ads"].append(result)
                report["statistics"]["low_risk_count"] += 1

            # Count indicators
            for indicator in result.get("indicators", []):
                indicator_type = indicator.split(":")[0]
                if indicator_type not in report["statistics"]["common_indicators"]:
                    report["statistics"]["common_indicators"][indicator_type] = 0
                report["statistics"]["common_indicators"][indicator_type] += 1

            # Count keywords
            for keyword in result.get("keywords_found", []):
                if keyword not in report["statistics"]["keywords_detected"]:
                    report["statistics"]["keywords_detected"][keyword] = 0
                report["statistics"]["keywords_detected"][keyword] += 1

        # Log summary
        logger.info("=" * 50)
        logger.info("📊 Google Ads Phishing Scan Summary")
        logger.info(f"  Total Ads Scanned: {report['total_ads_scanned']}")
        logger.info(f"  🚨 High Risk: {report['statistics']['high_risk_count']}")
        logger.info(f"  ⚠️  Medium Risk: {report['statistics']['medium_risk_count']}")
        logger.info(f"  ℹ️  Low Risk: {report['statistics']['low_risk_count']}")
        logger.info(f"  ✅ Safe: {report['statistics']['safe_count']}")

        if report["statistics"]["keywords_detected"]:
            logger.info("\n🔍 Keywords Detected:")
            for keyword, count in sorted(
                report["statistics"]["keywords_detected"].items(), key=lambda x: x[1], reverse=True
            ):
                logger.info(f"  - {keyword}: {count}")

        # Save report
        if output_file:
            with open(output_file, "w") as f:
                json.dump(report, f, indent=2, default=str)
            logger.info(f"\n💾 Report saved to {output_file}")

        return report

    def _get_random_headers(self) -> Dict[str, str]:
        """Get randomized headers to avoid detection"""
        import random

        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2.1 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/121.0.2277.83",
        ]

        accept_languages = [
            "es-CO,es;q=0.9,en;q=0.8",
            "es-ES,es;q=0.9,en;q=0.8",
            "es-MX,es;q=0.9,en;q=0.8",
            "es;q=0.9,en;q=0.8",
            "en-US,en;q=0.9,es;q=0.8",
        ]

        return {
            "User-Agent": random.choice(user_agents),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": random.choice(accept_languages),
            "Accept-Encoding": "gzip, deflate, br",
            "DNT": "1",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Cache-Control": "max-age=0",
        }

    def _get_session_with_proxy(self):
        """Create session with proxy rotation if available"""
        session = requests.Session()

        # List of free proxy servers (you can expand this)
        proxies_list = [
            None,  # No proxy
            # Add your proxy servers here
            # {'http': 'http://proxy1:port', 'https': 'https://proxy1:port'},
            # {'http': 'http://proxy2:port', 'https': 'https://proxy2:port'},
        ]

        import random

        proxy = random.choice(proxies_list)

        if proxy:
            session.proxies.update(proxy)
            logger.debug(f"Using proxy: {proxy}")

        return session

    def search_google_ads(self, keyword: str, domain: str = "google.com") -> List[Dict]:
        """Search for ads on Google using a specific keyword with anti-detection measures"""
        ads_found = []

        try:
            # Use random delays to appear more human
            import random

            time.sleep(random.uniform(2, 8))

            search_url = f"https://www.{domain}/search?q={quote(keyword)}"
            logger.info(f"🔍 Searching Google Ads for: '{keyword}' on {domain}")

            # Get randomized headers
            headers = self._get_random_headers()

            # Create session with potential proxy
            session = self._get_session_with_proxy()

            # Add random parameters to look more natural
            params = {
                "q": keyword,
                "hl": random.choice(["es", "es-CO", "es-ES"]),
                "gl": random.choice(["CO", "ES", "MX"]),
                "num": random.choice([10, 20]),
                "start": 0,
            }

            response = session.get(
                f"https://www.{domain}/search", headers=headers, params=params, timeout=self.timeout
            )

            if response.status_code == 200:
                soup = BeautifulSoup(response.text, "html.parser")
                ads = self._extract_google_ads(soup)

                for ad in ads:
                    ad["keyword"] = keyword
                    ad["search_domain"] = domain
                    ad["timestamp"] = datetime.now().isoformat()

                    ad_id = hashlib.md5(
                        f"{ad.get('url', '')}{ad.get('title', '')}".encode()
                    ).hexdigest()

                    if ad_id not in self.processed_ads:
                        self.processed_ads.add(ad_id)
                        ads_found.append(ad)
                        logger.info(
                            f"📢 Found ad: {ad.get('title', 'Unknown')} - {ad.get('display_url', '')}"
                        )
            elif response.status_code == 429:
                logger.warning(f"Rate limited on {domain}. Waiting longer...")
                time.sleep(random.uniform(30, 60))
            else:
                logger.warning(f"Unexpected response {response.status_code} from {domain}")

        except Exception as e:
            logger.error(f"Error searching Google Ads: {e}")
            # Wait before retry on error
            time.sleep(random.uniform(10, 30))

        return ads_found

    def _extract_google_ads(self, soup: BeautifulSoup) -> List[Dict]:
        """Extract ad information from Google search results page"""
        ads = []

        try:
            # Method 1: Look for Google ads click tracking URLs
            google_ad_links = soup.find_all(
                "a", href=lambda href: href and ("/aclk?" in href or "/url?" in href)
            )

            for link in google_ad_links:
                href = link.get("href")
                if href:
                    # Extract actual URL from Google's tracking
                    actual_url = self._extract_actual_url(href)

                    # Get the ad container
                    ad_container = link
                    for _ in range(5):  # Go up max 5 levels to find container
                        ad_container = ad_container.parent
                        if not ad_container:
                            break

                        # Check if this container has ad markers
                        container_text = ad_container.get_text()
                        if any(
                            marker in container_text
                            for marker in ["Anuncio", "Patrocinado", "Sponsored", "Ad"]
                        ):
                            break

                    if ad_container:
                        ad_data = {
                            "url": actual_url,
                            "title": link.get_text(strip=True),
                            "display_url": "",
                            "description": "",
                            "is_ad": True,
                        }

                        # Find cite element for display URL
                        cite = ad_container.find("cite")
                        if cite:
                            ad_data["display_url"] = cite.get_text(strip=True)

                        # Find description
                        desc_selectors = [".VwiC3b", ".MUxGbd", ".s", 'span[style*="color"]']
                        for selector in desc_selectors:
                            desc_elem = ad_container.select_one(selector)
                            if desc_elem:
                                ad_data["description"] = desc_elem.get_text(strip=True)
                                break

                        if ad_data["url"] and ad_data["title"] and actual_url.startswith("http"):
                            ads.append(ad_data)

            # Method 2: Look for ads in top section (typical ad placement)
            top_ads_section = soup.find("div", {"id": "tads"}) or soup.select_one(
                ".commercial-unit-desktop-top"
            )
            if top_ads_section:
                ad_links = top_ads_section.find_all("a", href=True)
                for link in ad_links:
                    href = link.get("href")
                    if href and href.startswith("http"):
                        ad_data = {
                            "url": href,
                            "title": link.get_text(strip=True),
                            "display_url": "",
                            "description": "",
                            "is_ad": True,
                        }

                        # Look for cite in parent
                        parent = link.parent
                        for _ in range(3):
                            if parent:
                                cite = parent.find("cite")
                                if cite:
                                    ad_data["display_url"] = cite.get_text(strip=True)
                                    break
                                parent = parent.parent

                        if ad_data["url"] and ad_data["title"]:
                            ads.append(ad_data)

            # Method 3: Look for right sidebar ads
            right_ads = soup.select(".mnr-c a[href], .pla-unit a[href]")
            for link in right_ads:
                href = link.get("href")
                if href:
                    actual_url = (
                        self._extract_actual_url(href)
                        if ("/aclk?" in href or "/url?" in href)
                        else href
                    )

                    if actual_url.startswith("http"):
                        ad_data = {
                            "url": actual_url,
                            "title": link.get_text(strip=True),
                            "display_url": "",
                            "description": "",
                            "is_ad": True,
                        }

                        # Find cite in parent container
                        container = link.parent
                        for _ in range(4):
                            if container:
                                cite = container.find("cite")
                                if cite:
                                    ad_data["display_url"] = cite.get_text(strip=True)
                                    break
                                container = container.parent

                        if ad_data["url"] and ad_data["title"]:
                            ads.append(ad_data)

            # Method 4: Look for data-text-ad elements
            text_ads = soup.select("[data-text-ad] a[href], [data-ad-result] a[href]")
            for link in text_ads:
                href = link.get("href")
                if href:
                    actual_url = (
                        self._extract_actual_url(href)
                        if ("/aclk?" in href or "/url?" in href)
                        else href
                    )

                    if actual_url.startswith("http"):
                        ad_data = {
                            "url": actual_url,
                            "title": link.get_text(strip=True),
                            "display_url": "",
                            "description": "",
                            "is_ad": True,
                        }

                        if ad_data["url"] and ad_data["title"]:
                            ads.append(ad_data)

            # Remove duplicates based on URL
            seen_urls = set()
            unique_ads = []
            for ad in ads:
                url = ad.get("url", "")
                if url not in seen_urls and url and url.startswith("http"):
                    seen_urls.add(url)
                    unique_ads.append(ad)
                    logger.debug(f"✅ Valid ad found: {ad['title']} -> {url}")

            logger.info(f"📢 Extracted {len(unique_ads)} unique ads with valid URLs")

            # If no ads found, attempt alternative extraction methods
            if not unique_ads:
                logger.warning("⚠️ No ads with URLs detected. Attempting fallback extraction...")

                # Fallback: Look for any links in containers with ad-like text
                all_divs = soup.find_all("div")
                for div in all_divs:
                    div_text = div.get_text().lower()
                    if any(
                        marker in div_text for marker in ["anuncio", "patrocinado", "sponsored"]
                    ):
                        links = div.find_all("a", href=True)
                        for link in links:
                            href = link.get("href")
                            if href and href.startswith("http"):
                                unique_ads.append(
                                    {
                                        "url": href,
                                        "title": link.get_text(strip=True),
                                        "display_url": "",
                                        "description": "",
                                        "is_ad": True,
                                    }
                                )

                logger.info(f"📢 Fallback extraction found {len(unique_ads)} additional ads")

        except Exception as e:
            logger.error(f"Error extracting ads: {e}")

        return unique_ads

    def _parse_ad_element(self, element) -> Optional[Dict]:
        """Parse individual ad element to extract information"""
        try:
            ad_info = {}

            title_selectors = ["h3", ".ad-title", ".LC20lb", ".r a"]
            for selector in title_selectors:
                title_elem = element.select_one(selector)
                if title_elem:
                    ad_info["title"] = title_elem.get_text(strip=True)
                    break

            link_selectors = ["a[href]", ".ad-link", ".r a"]
            for selector in link_selectors:
                link_elem = element.select_one(selector)
                if link_elem:
                    href = link_elem.get("href")
                    if href:
                        if "/aclk?" in href or "/url?" in href:
                            ad_info["url"] = self._extract_actual_url(href)
                        else:
                            ad_info["url"] = href
                        break

            display_url_selectors = ["cite", ".qLRx3b", ".ad-visurl", ".UPmit"]
            for selector in display_url_selectors:
                display_url_elem = element.select_one(selector)
                if display_url_elem:
                    ad_info["display_url"] = display_url_elem.get_text(strip=True)
                    break

            desc_selectors = [".VwiC3b", ".MUxGbd", ".ad-desc", ".s"]
            for selector in desc_selectors:
                desc_elem = element.select_one(selector)
                if desc_elem:
                    ad_info["description"] = desc_elem.get_text(strip=True)
                    break

            return ad_info if ad_info.get("url") else None

        except Exception as e:
            return None

    def _extract_actual_url(self, google_url: str) -> str:
        """Extract actual URL from Google's redirect URL"""
        try:
            parsed = urllib.parse.urlparse(google_url)
            params = parse_qs(parsed.query)

            for param in ["adurl", "url", "q", "dest"]:
                if param in params:
                    return params[param][0]

            return google_url
        except:
            return google_url

    def _generate_search_combinations(self) -> List[str]:
        """Generate all possible combinations of keywords up to 4 words"""
        search_terms = []

        # Single keywords
        search_terms.extend(self.keywords)

        # Extended terms for combinations
        extended_terms = self.keywords + [
            "pagar",
            "consulta",
            "descuento",
            "colombia",
            "bogota",
            "online",
            "gratis",
            "rapido",
            "facil",
            "gov",
            "gobierno",
            "oficial",
            "certificado",
            "verificar",
            "registro",
            "portal",
            "tramite",
            "multa",
            "infracciones",
            "vehiculo",
            "licencia",
            "cedula",
            "renovar",
            "actualizar",
            "vencimiento",
            "suspension",
        ]

        # 2-word combinations
        for i, word1 in enumerate(extended_terms):
            for j, word2 in enumerate(extended_terms):
                if i != j:
                    search_terms.append(f"{word1} {word2}")

        # 3-word combinations (focused on main keywords)
        for i, word1 in enumerate(self.keywords):
            for j, word2 in enumerate(extended_terms):
                for k, word3 in enumerate(extended_terms):
                    if i != j and i != k and j != k:
                        search_terms.append(f"{word1} {word2} {word3}")

        # 4-word combinations (main keywords + 3 descriptive terms)
        descriptive_terms = [
            "pagar",
            "consulta",
            "descuento",
            "online",
            "gratis",
            "rapido",
            "oficial",
            "gobierno",
            "tramite",
            "renovar",
            "verificar",
        ]

        for main_keyword in self.keywords[:3]:  # Limit to first 3 main keywords
            for i, term1 in enumerate(descriptive_terms):
                for j, term2 in enumerate(descriptive_terms):
                    for k, term3 in enumerate(descriptive_terms):
                        if i != j and i != k and j != k:
                            search_terms.append(f"{main_keyword} {term1} {term2} {term3}")

        # Remove duplicates and empty strings
        search_terms = list(set([term.strip() for term in search_terms if term.strip()]))

        logger.info(f"🔍 Generated {len(search_terms)} total search combinations")
        return search_terms

    def monitor_ads_continuously(self):
        """Monitor for new ads continuously"""
        logger.info("🚀 Starting continuous Google Ads monitoring...")

        # Generate all keyword combinations
        search_terms = self._generate_search_combinations()
        logger.info(f"🔍 Generated {len(search_terms)} search combinations")

        while True:
            try:
                all_ads = []
                suspicious_ads = []

                # Search with all combinations
                for i, search_term in enumerate(search_terms):
                    logger.info(f"🔍 Searching [{i+1}/{len(search_terms)}]: '{search_term}'")

                    # Search on Colombian Google
                    ads = self.search_google_ads(search_term, "google.com.co")
                    all_ads.extend(ads)

                    # Also search on main Google
                    ads = self.search_google_ads(search_term, "google.com")
                    all_ads.extend(ads)

                    time.sleep(7)  # Increased delay to avoid rate limiting

                logger.info(f"📊 Analyzing {len(all_ads)} ads found...")

                for ad in all_ads:
                    if ad.get("url"):
                        analysis = self.analyze_ad_url(ad["url"], ad.get("display_url"))
                        analysis["ad_info"] = ad

                        if analysis.get("risk_level") in ["HIGH", "MEDIUM"]:
                            suspicious_ads.append(analysis)

                if suspicious_ads:
                    self._generate_alert_report(suspicious_ads)

                logger.info(
                    f"✅ Scan complete. Found {len(suspicious_ads)} suspicious ads. Next scan in {self.scan_interval} seconds..."
                )
                time.sleep(self.scan_interval)

            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                time.sleep(60)

    def _generate_alert_report(self, suspicious_ads: List[Dict]):
        """Generate alert report for suspicious ads"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        os.makedirs("alerts", exist_ok=True)
        report_file = f"alerts/google_ads_alert_{timestamp}.json"

        report = {
            "timestamp": datetime.now().isoformat(),
            "total_suspicious_ads": len(suspicious_ads),
            "high_risk_count": sum(1 for ad in suspicious_ads if ad.get("risk_level") == "HIGH"),
            "medium_risk_count": sum(
                1 for ad in suspicious_ads if ad.get("risk_level") == "MEDIUM"
            ),
            "ads": suspicious_ads,
        }

        with open(report_file, "w") as f:
            json.dump(report, f, indent=2, default=str)

        logger.error(
            f"⚠️ ALERT: {len(suspicious_ads)} suspicious Google Ads detected! Report: {report_file}"
        )

        for ad in suspicious_ads:
            if ad.get("risk_level") == "HIGH":
                logger.error(
                    f"🚨 HIGH RISK AD: {ad['ad_info'].get('title')} - URL: {ad.get('url')}"
                )

    def quick_scan(self) -> Dict:
        """Perform a quick scan of current ads"""
        logger.info("🚀 Starting quick Google Ads scan...")
        all_ads = []
        suspicious_ads = []

        # Generate combinations for quick scan (limited)
        search_terms = self._generate_search_combinations()[:20]  # Limit to first 20 combinations

        logger.info(f"🔍 Quick scan using {len(search_terms)} search terms...")

        for i, search_term in enumerate(search_terms):
            logger.info(f"🔍 Searching [{i+1}/{len(search_terms)}]: '{search_term}'")

            # Search on Colombian Google
            ads = self.search_google_ads(search_term, "google.com.co")

            for ad in ads:
                if ad.get("url"):
                    analysis = self.analyze_ad_url(ad["url"], ad.get("display_url"))
                    analysis["ad_info"] = ad
                    all_ads.append(analysis)

                    if analysis.get("risk_level") in ["HIGH", "MEDIUM"]:
                        suspicious_ads.append(analysis)

            time.sleep(3)

        return {
            "total_ads": len(all_ads),
            "suspicious_count": len(suspicious_ads),
            "ads_analyzed": all_ads,
            "timestamp": datetime.now().isoformat(),
        }


def main():
    """Main function for Google Ads monitoring system"""
    detector = GoogleAdsPhishingDetector()

    logger.info("🛡️ Google Ads Active Monitoring System")
    logger.info("=" * 50)
    logger.info(f"Keywords: {', '.join(detector.keywords)}")
    logger.info(f"Scan interval: {detector.scan_interval} seconds")
    logger.info("=" * 50)

    # Run active Google Ads search and monitoring
    logger.info("🔍 Starting active Google Ads search...")

    # Perform quick scan
    scan_results = detector.quick_scan()

    logger.info(f"📊 Quick scan completed:")
    logger.info(f"  Total ads found: {scan_results['total_ads']}")
    logger.info(f"  Suspicious ads: {scan_results['suspicious_count']}")

    # Generate report if ads were found
    if scan_results["total_ads"] > 0:
        report = detector.generate_report(
            scan_results["ads_analyzed"], "google_ads_monitoring_report.json"
        )

    # Start continuous monitoring
    logger.info("\n" + "=" * 50)
    logger.info("🚀 Starting continuous monitoring...")
    logger.info("⚠️  Press Ctrl+C to stop monitoring")

    try:
        detector.monitor_ads_continuously()
    except KeyboardInterrupt:
        logger.info("\n✅ Monitoring stopped by user")

    logger.info("\n🛡️ Defensive security tool - ICANN compliance ready")


if __name__ == "__main__":
    main()
