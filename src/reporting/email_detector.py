"""
Enhanced Abuse Email Detector for Anisakys Phishing Detection Engine.

Provides enhanced abuse email detection with multiple sources and validation.
"""

import datetime
import re
import subprocess
from typing import Any, Dict, List, Optional, Tuple

import dns.exception
import dns.resolver
import requests
import whois
from ipwhois import IPWhois

from src.config import settings
from src.data import (
    ASN_ABUSE_EMAIL_DB,
    PROVIDER_ABUSE_EMAIL_DB,
    ENHANCED_REGISTRAR_ABUSE_DB,
    TLD_WHOIS_SERVERS,
)
from src.logger import logger

# RDAP Bootstrap cache (TLD -> RDAP server URL)
_RDAP_BOOTSTRAP_CACHE: Dict[str, str] = {}


class EnhancedAbuseEmailDetector:
    """Enhanced abuse email detection with multiple sources and validation."""

    def __init__(self, db_manager):
        self.db_manager = db_manager
        self.dns_resolver = dns.resolver.Resolver()
        self.dns_resolver.timeout = 5
        self.dns_resolver.lifetime = 10

    def validate_email(self, email: str) -> bool:
        """Validate email address format and domain."""
        if not validators.email(email):
            return False

        # Additional validation for domain existence
        try:
            domain = email.split("@")[1]
            self.dns_resolver.resolve(domain, "MX")
            return True
        except (dns.exception.DNSException, IndexError):
            logger.debug(f"Domain validation failed for email: {email}")
            return False

    def extract_emails_from_whois(self, whois_info: Any) -> List[str]:
        """Extract email addresses from WHOIS data using enhanced patterns."""
        emails = []
        whois_str = str(whois_info).lower()

        # Use multiple patterns to find emails
        for pattern in ABUSE_EMAIL_PATTERNS:
            found_emails = re.findall(pattern, whois_str, re.IGNORECASE)
            emails.extend(found_emails)

        # General email pattern as fallback
        general_pattern = r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
        all_emails = re.findall(general_pattern, whois_str)

        # Filter for abuse-related emails
        abuse_keywords = ["abuse", "security", "admin", "postmaster", "hostmaster", "webmaster"]
        abuse_emails = [
            email
            for email in all_emails
            if any(keyword in email.lower() for keyword in abuse_keywords)
        ]

        emails.extend(abuse_emails)

        # Remove duplicates and validate
        unique_emails = list(set(emails))
        validated_emails = [email for email in unique_emails if self.validate_email(email)]

        return validated_emails

    def get_abuse_email_from_dns(self, domain: str) -> Optional[str]:
        """Try to get abuse email from DNS TXT records."""
        try:
            txt_records = self.dns_resolver.resolve(domain, "TXT")
            for record in txt_records:
                record_str = str(record).lower()
                if "abuse" in record_str:
                    email_match = re.search(
                        r"([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})", record_str
                    )
                    if email_match and self.validate_email(email_match.group(1)):
                        logger.info(
                            f"🔍 Found abuse email in DNS TXT for {domain}: {email_match.group(1)}"
                        )
                        return email_match.group(1)
        except dns.exception.DNSException:
            logger.debug(f"DNS TXT query failed for {domain}")
        return None

    def get_abuse_email_from_whois_servers(self, domain: str) -> Optional[str]:
        """Query multiple WHOIS servers for abuse information."""
        whois_servers = [
            f"whois.{domain.split('.')[-1]}",
            "whois.internic.net",
            "whois.arin.net",
            "whois.ripe.net",
            "whois.apnic.net",
            "whois.lacnic.net",
            "whois.afrinic.net",
        ]

        for server in whois_servers:
            try:
                result = subprocess.run(
                    ["whois", "-h", server, domain], capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0:
                    emails = self.extract_emails_from_whois(result.stdout)
                    if emails:
                        logger.info(f"🔍 Found abuse email from WHOIS server {server}: {emails[0]}")
                        return emails[0]
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
        return None

    def get_abuse_email_by_registrar(self, registrar: str) -> Optional[str]:
        """Get abuse email from registrar database (cached + enhanced)."""
        # Check the database cache first
        with self.db_manager.engine.begin() as conn:
            result = conn.execute(
                text(
                    "SELECT abuse_emails FROM registrar_abuse WHERE LOWER(registrar_name) LIKE :param"
                ),
                {"param": "%" + registrar.lower() + "%"},
            ).fetchone()
            if result:
                logger.info(f"📚 Found cached abuse email for registrar '{registrar}': {result[0]}")
                return result[0]

        # Check enhanced static database
        for reg_name, email in ENHANCED_REGISTRAR_ABUSE_DB.items():
            if reg_name.lower() in registrar.lower():
                # Cache the result (PostgreSQL compatible)
                try:
                    with self.db_manager.engine.begin() as conn:
                        conn.execute(
                            text(
                                "INSERT INTO registrar_abuse (registrar_name, abuse_emails) VALUES (:registrar, :email) ON CONFLICT (registrar_name) DO NOTHING"
                            ),
                            {"registrar": registrar, "email": email},
                        )
                except Exception as e:
                    # If ON CONFLICT is not supported, handle duplicate key error
                    logger.debug(f"Failed to cache registrar abuse email (likely duplicate): {e}")
                logger.info(f"📚 Found enhanced abuse email for registrar '{registrar}': {email}")
                return email

        return None

    def get_enhanced_abuse_email(
        self, domain: str, whois_info: Any = None, registrar: str = None
    ) -> List[str]:
        """Get abuse email using multiple enhanced detection methods."""
        logger.info(f"🔍 Starting enhanced abuse email detection for domain: {domain}")
        abuse_emails = []

        # 1. Check a cached registrar database
        if registrar:
            registrar_email = self.get_abuse_email_by_registrar(registrar)
            if registrar_email and self.validate_abuse_email_domain(registrar_email, domain):
                abuse_emails.append(registrar_email)
                logger.info(f"✅ Added registrar abuse email: {registrar_email}")

        # 2. Extract from WHOIS data (exclude same domain)
        if whois_info:
            whois_emails = self.extract_emails_from_whois(whois_info)
            for email in whois_emails:
                if self.validate_abuse_email_domain(email, domain):
                    abuse_emails.append(email)
                    logger.info(f"✅ Added WHOIS abuse email: {email}")

        # 3. Try DNS TXT records
        dns_email = self.get_abuse_email_from_dns(domain)
        if dns_email and self.validate_abuse_email_domain(dns_email, domain):
            abuse_emails.append(dns_email)

        # 4. Try alternative WHOIS servers
        if not abuse_emails:
            whois_server_email = self.get_abuse_email_from_whois_servers(domain)
            if whois_server_email and self.validate_abuse_email_domain(whois_server_email, domain):
                abuse_emails.append(whois_server_email)

        # 5. Check hosting provider and ASN information
        try:
            domain_ip = socket.gethostbyname(domain)
            logger.info(f"🌐 Resolved {domain} to IP: {domain_ip}")

            if is_cloudflare_ip(domain_ip):
                logger.info(
                    f"☁️  Domain {domain} is behind Cloudflare, investigating real hosting..."
                )

                # Try to find real IP behind Cloudflare
                real_ip = self.get_real_ip_behind_cloudflare(domain)
                if real_ip:
                    logger.info(f"🔍 Found potential real IP behind Cloudflare: {real_ip}")
                    provider_name, provider_abuse, asn, asn_abuse_email = (
                        self.get_hosting_provider_info(real_ip)
                    )

                    # Add provider abuse email
                    if provider_abuse and self.validate_abuse_email_domain(provider_abuse, domain):
                        abuse_emails.append(provider_abuse)
                        logger.info(
                            f"🏢 Found hosting provider abuse email: {provider_abuse} (Provider: {provider_name})"
                        )

                    # Add ASN abuse emails (handle both string and list)
                    if asn_abuse_email:
                        # Handle both single string and list of emails
                        asn_emails = (
                            asn_abuse_email
                            if isinstance(asn_abuse_email, list)
                            else [asn_abuse_email]
                        )
                        for email in asn_emails:
                            if email and self.validate_abuse_email_domain(email, domain):
                                abuse_emails.append(email)
                                logger.info(f"🏷️  Found ASN abuse email: {email} (ASN: {asn})")
                else:
                    logger.warning(f"⚠️  Could not find real IP behind Cloudflare for {domain}")

                # Always add Cloudflare as a secondary option
                cloudflare_email = "abuse@cloudflare.com"
                if cloudflare_email not in abuse_emails:
                    abuse_emails.append(cloudflare_email)
                    logger.info(
                        f"☁️  Added Cloudflare abuse email as secondary option: {cloudflare_email}"
                    )
            else:
                # Not behind Cloudflare, check hosting provider directly
                logger.info(f"🏢 Checking hosting provider for IP: {domain_ip}")
                provider_name, provider_abuse, asn, asn_abuse_email = (
                    self.get_hosting_provider_info(domain_ip)
                )

                logger.info(f"🏢 Hosting Provider: {provider_name or 'Unknown'}")
                logger.info(f"🏷️  ASN: {asn or 'Unknown'}")

                # Add provider abuse email
                if provider_abuse and self.validate_abuse_email_domain(provider_abuse, domain):
                    abuse_emails.append(provider_abuse)
                    logger.info(
                        f"✅ Found hosting provider abuse email: {provider_abuse} (Provider: {provider_name})"
                    )
                else:
                    if provider_abuse:
                        logger.warning(
                            f"❌ Provider abuse email rejected (same domain): {provider_abuse}"
                        )
                    else:
                        logger.warning(f"⚠️  No provider abuse email found in WHOIS data")

                # Add ASN abuse emails (handle both string and list)
                asn_emails_added = False
                if asn_abuse_email:
                    # Handle both single string and list of emails
                    asn_emails = (
                        asn_abuse_email if isinstance(asn_abuse_email, list) else [asn_abuse_email]
                    )
                    for email in asn_emails:
                        if email and self.validate_abuse_email_domain(email, domain):
                            abuse_emails.append(email)
                            logger.info(f"✅ Found ASN abuse email: {email} (ASN: {asn})")
                            asn_emails_added = True
                        elif email:
                            logger.warning(f"❌ ASN abuse email rejected (same domain): {email}")

                if not asn_emails_added:
                    if asn_abuse_email:
                        logger.debug("All ASN abuse emails were rejected (same domain)")
                    else:
                        logger.warning(f"⚠️  No ASN abuse email found for ASN: {asn}")

                        # EPIC-005: Try provider-based fallback if ASN lookup failed using resolver
                        provider_abuse_emails = self.abuse_resolver.resolve(
                            provider_name=provider_name, target_domain=domain
                        )
                        if provider_abuse_emails:
                            for email in provider_abuse_emails:
                                if email and self.validate_abuse_email_domain(email, domain):
                                    abuse_emails.append(email)
                                    logger.info(
                                        f"✅ Found provider fallback abuse email: {email} (Provider: {provider_name})"
                                    )

        except Exception as e:
            logger.debug(f"Failed to get IP/hosting info for {domain}: {e}")

        # 6. Generate common abuse email patterns (exclude same domain)
        if not abuse_emails:
            logger.warning(f"⚠️  No abuse emails found through other methods for {domain}")
            # Try parent domain or known hosting providers
            try:
                # Get hosting info from IP WHOIS
                domain_ip = socket.gethostbyname(domain)
                provider_name, provider_abuse, asn, asn_abuse_email = (
                    self.get_hosting_provider_info(domain_ip)
                )

                # Add both provider and ASN emails if available
                if provider_abuse and self.validate_abuse_email_domain(provider_abuse, domain):
                    abuse_emails.append(provider_abuse)

                # Handle ASN abuse emails (both string and list)
                if asn_abuse_email:
                    asn_emails = (
                        asn_abuse_email if isinstance(asn_abuse_email, list) else [asn_abuse_email]
                    )
                    for email in asn_emails:
                        if email and self.validate_abuse_email_domain(email, domain):
                            abuse_emails.append(email)

            except:
                pass

        # Remove duplicates while preserving order
        unique_emails = []
        seen = set()
        for email in abuse_emails:
            if email not in seen:
                unique_emails.append(email)
                seen.add(email)

        # Enhanced logging with final results
        if unique_emails:
            logger.info(
                f"✅ Found {len(unique_emails)} valid abuse email(s) for {domain}: {unique_emails}"
            )
        else:
            logger.warning(f"❌ No valid abuse emails found for {domain}")

        return unique_emails

    @staticmethod
    def extract_registrar(whois_info) -> Optional[str]:
        """Extract registrar from WHOIS data."""
        if isinstance(whois_info, dict):
            registrar = whois_info.get("registrar")
            if registrar:
                if isinstance(registrar, list):
                    return registrar[0].strip()
                else:
                    return str(registrar).strip()
        whois_str = str(whois_info)
        match = re.search(r"Registrar:\s*(.+)", whois_str, re.IGNORECASE)
        if match:
            return match.group(1).strip()
        return None

    @staticmethod
    def validate_abuse_email_domain(email: str, reported_domain: str) -> bool:
        """
        Validate that abuse email is not from the same domain being reported.

        Args:
            email (str): Abuse email to validate
            reported_domain (str): Domain being reported for phishing

        Returns:
            bool: True if email is valid for reporting, False if same domain
        """
        try:
            email_domain = email.split("@")[1].lower()
            reported_domain_clean = reported_domain.lower().replace("www.", "")

            # Check if it's the same domain
            if email_domain == reported_domain_clean:
                logger.warning(
                    f"❌ Cannot send abuse report to same domain: {email} for {reported_domain}"
                )
                return False

            # Check if it's a subdomain of the reported domain
            if email_domain.endswith("." + reported_domain_clean):
                logger.warning(
                    f"❌ Cannot send abuse report to subdomain: {email} for {reported_domain}"
                )
                return False

            return True
        except IndexError:
            return False

    @staticmethod
    def parse_stored_abuse_emails(stored_abuse: str) -> List[str]:
        """
        Parse stored abuse emails from database, handling various formats:
        - Single email: 'abuse@example.com' -> ['abuse@example.com']
        - JSON list: '["abuse@example.com", "security@example.com"]' -> ['abuse@example.com', 'security@example.com']
        - Python list string: "['abuse@example.com']" -> ['abuse@example.com']
        - Comma separated: 'abuse@example.com, security@example.com' -> ['abuse@example.com', 'security@example.com']

        Args:
            stored_abuse (str): Stored abuse email string from database

        Returns:
            List[str]: List of parsed email addresses
        """
        if not stored_abuse or stored_abuse.strip() == "":
            return []

        stored_abuse = stored_abuse.strip()

        try:
            # Try JSON parsing first (handles ["email1", "email2"] format)
            import json

            if stored_abuse.startswith("[") and stored_abuse.endswith("]"):
                try:
                    parsed = json.loads(stored_abuse)
                    if isinstance(parsed, list):
                        return [
                            str(email).strip() for email in parsed if email and str(email).strip()
                        ]
                except json.JSONDecodeError:
                    # If JSON parsing fails, try Python literal_eval for ['email'] format
                    try:
                        import ast

                        parsed = ast.literal_eval(stored_abuse)
                        if isinstance(parsed, list):
                            return [
                                str(email).strip()
                                for email in parsed
                                if email and str(email).strip()
                            ]
                    except (ValueError, SyntaxError):
                        pass

            # Handle comma-separated emails
            if "," in stored_abuse:
                return [email.strip() for email in stored_abuse.split(",") if email.strip()]

            # Single email
            return [stored_abuse]

        except Exception as e:
            logger.warning(f"⚠️ Failed to parse stored abuse emails '{stored_abuse}': {e}")
            # Fallback: treat as single email
            return [stored_abuse]

    def get_real_ip_behind_cloudflare(self, domain: str) -> Optional[str]:
        """
        Try to get the real IP behind Cloudflare using various methods.

        Args:
            domain (str): Domain to investigate

        Returns:
            Optional[str]: Real IP if found, None otherwise
        """
        real_ips = []

        # Method 1: Check common subdomains that might not be behind Cloudflare
        common_subdomains = ["direct", "origin", "real", "server", "host", "main", "www-origin"]

        for subdomain in common_subdomains:
            try:
                test_domain = f"{subdomain}.{domain}"
                ip = socket.gethostbyname(test_domain)
                if not is_cloudflare_ip(ip):
                    real_ips.append(ip)
                    logger.info(f"🔍 Found potential real IP via subdomain {test_domain}: {ip}")
            except:
                continue

        # Method 2: Check MX records (mail servers often reveal real hosting)
        try:
            mx_records = self.dns_resolver.resolve(domain, "MX")
            for mx in mx_records:
                mx_domain = str(mx.exchange).rstrip(".")
                try:
                    ip = socket.gethostbyname(mx_domain)
                    if not is_cloudflare_ip(ip):
                        real_ips.append(ip)
                        logger.info(f"🔍 Found potential real IP via MX record {mx_domain}: {ip}")
                except:
                    continue
        except:
            pass

        return real_ips[0] if real_ips else None

    def get_hosting_provider_info(
        self, ip: str
    ) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
        """
        Get hosting provider information from IP address with enhanced ASN support.

        Args:
            ip (str): IP address to investigate

        Returns:
            Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
            (provider_name, provider_abuse_email, asn, asn_abuse_email)
        """
        try:
            logger.info(f"🔍 Looking up hosting information for IP: {ip}")
            obj = IPWhois(ip)
            res = obj.lookup_rdap(depth=1)

            # Get provider name - handle None values safely
            provider_name = ""
            network_info = res.get("network", {})
            if network_info and isinstance(network_info, dict):
                provider_name = network_info.get("name") or ""
                if not provider_name:
                    provider_name = res.get("asn_description") or ""

            # Ensure provider_name is string and handle None
            if provider_name is None:
                provider_name = ""

            # Safely convert to string and handle potential None
            provider_name = str(provider_name) if provider_name else "Unknown"

            # Get ASN information
            asn = res.get("asn", "")
            if asn and not str(asn).startswith("AS"):
                asn = f"AS{asn}"

            # Clean ASN format for lookup
            asn_clean = str(asn).replace("AS", "").strip() if asn else ""

            logger.info(f"🏢 Provider: {provider_name}, ASN: {asn}")

            # EPIC-005: Use AbuseContactResolver to get all abuse emails
            # This consolidates ASN, provider, and WHOIS lookups with deduplication
            all_abuse_emails = self.abuse_resolver.resolve(
                asn=asn_clean if asn_clean else None,
                provider_name=provider_name if provider_name != "Unknown" else None,
                whois_data=res,
                target_domain=None,  # No domain filtering at this stage
            )

            # For backward compatibility, extract first email for legacy fields
            asn_abuse_email = all_abuse_emails[0] if all_abuse_emails else None
            provider_abuse_email = all_abuse_emails[0] if all_abuse_emails else None

            logger.info(
                f"📊 IP {ip} analysis complete: Provider={provider_name}, ASN={asn}, "
                f"Resolved {len(all_abuse_emails)} abuse contact(s): {all_abuse_emails[:3]}{'...' if len(all_abuse_emails) > 3 else ''}"
            )

            # Return: provider_name, provider_abuse_email, asn, all_abuse_emails
            return provider_name, provider_abuse_email, asn, all_abuse_emails

        except Exception as e:
            logger.error(f"❌ Failed to get hosting provider info for IP {ip}: {e}")
            return None, None, None, None

    # EPIC-005: Removed get_abuse_email_by_asn() and get_abuse_email_by_provider()
    # These are now handled by AbuseContactResolver class in src/intelligence/

    @staticmethod
    def get_rdap_server(tld: str) -> Optional[str]:
        """
        Get RDAP server URL for a TLD from IANA bootstrap.

        Args:
            tld: Top-level domain (e.g., "shop", "com")

        Returns:
            RDAP server URL or None if not found
        """
        global _RDAP_BOOTSTRAP_CACHE

        tld = tld.lower()

        # Check cache first
        if tld in _RDAP_BOOTSTRAP_CACHE:
            return _RDAP_BOOTSTRAP_CACHE[tld]

        try:
            # Fetch IANA RDAP bootstrap file
            response = requests.get(
                "https://data.iana.org/rdap/dns.json",
                timeout=10,
                headers={"User-Agent": "Anisakys/1.0"},
            )
            if response.status_code == 200:
                data = response.json()
                for service in data.get("services", []):
                    tlds = [t.lower() for t in service[0]]
                    urls = service[1]
                    if tld in tlds and urls:
                        rdap_url = urls[0].rstrip("/")
                        # Cache all TLDs from this service
                        for t in tlds:
                            _RDAP_BOOTSTRAP_CACHE[t] = rdap_url
                        return rdap_url
        except Exception as e:
            logger.debug(f"Failed to fetch RDAP bootstrap: {e}")

        return None

    @staticmethod
    def get_rdap_info(domain: str) -> dict:
        """
        Get domain registration info via RDAP (Registration Data Access Protocol).

        RDAP is the modern replacement for WHOIS with better availability
        and structured JSON responses.

        Args:
            domain: Domain to query (e.g., "example.shop")

        Returns:
            dict with registrar, creation_date, org, or empty dict on failure
        """
        try:
            tld = domain.split(".")[-1].lower()
            rdap_server = EnhancedAbuseEmailDetector.get_rdap_server(tld)

            if not rdap_server:
                logger.debug(f"No RDAP server found for TLD: {tld}")
                return {}

            # Query RDAP
            url = f"{rdap_server}/domain/{domain}"
            response = requests.get(
                url,
                timeout=15,
                headers={"User-Agent": "Anisakys/1.0", "Accept": "application/rdap+json"},
            )

            if response.status_code != 200:
                logger.debug(f"RDAP query failed with status {response.status_code}")
                return {}

            data = response.json()
            result = {}

            # Extract registration date from events
            for event in data.get("events", []):
                if event.get("eventAction") == "registration":
                    date_str = event.get("eventDate", "")
                    if date_str:
                        try:
                            # Parse ISO format date
                            parsed = datetime.datetime.fromisoformat(
                                date_str.replace("Z", "+00:00").replace(".0Z", "+00:00")
                            )
                            result["creation_date"] = parsed
                        except ValueError:
                            result["creation_date"] = date_str

            # Extract registrar from entities
            for entity in data.get("entities", []):
                roles = entity.get("roles", [])
                if "registrar" in roles:
                    # Try to get name from vCard
                    vcard = entity.get("vcardArray", [])
                    if len(vcard) > 1:
                        for item in vcard[1]:
                            if item[0] == "fn":
                                result["registrar"] = item[3]
                                break
                            if item[0] == "org":
                                result["registrar"] = item[3]
                    # Fallback to handle
                    if "registrar" not in result:
                        result["registrar"] = entity.get("publicIds", [{}])[0].get("identifier")

                # Extract registrant org if available
                if "registrant" in roles:
                    vcard = entity.get("vcardArray", [])
                    if len(vcard) > 1:
                        for item in vcard[1]:
                            if item[0] == "org":
                                result["org"] = item[3]
                                break
                            if item[0] == "fn":
                                result["org"] = item[3]

            # Extract domain name
            result["domain_name"] = data.get("ldhName", domain)

            if result:
                logger.info(f"📋 Got RDAP data for {domain}: registrar={result.get('registrar')}")

            return result

        except requests.exceptions.Timeout:
            logger.debug(f"RDAP timeout for {domain}")
            return {}
        except Exception as e:
            logger.debug(f"RDAP query failed for {domain}: {e}")
            return {}

    @staticmethod
    def get_enhanced_whois_info(domain: str) -> dict:
        """
        Get WHOIS data using the appropriate server based on TLD with enhanced parsing.

        Args:
            domain (str): Domain to query

        Returns:
            dict: WHOIS data
        """
        # Invalid response patterns
        INVALID_RESPONSES = [
            "server is busy",
            "try again later",
            "rate limit",
            "too many queries",
            "connection refused",
            "no match for",
        ]

        def is_valid_whois_response(text: str) -> bool:
            """Check if WHOIS response is valid (not an error message)."""
            if not text or len(text.strip()) < 50:
                return False
            text_lower = text.lower()
            return not any(pattern in text_lower for pattern in INVALID_RESPONSES)

        def parse_whois_text(whois_text: str) -> dict:
            """Parse raw WHOIS text and extract key fields."""
            whois_dict = {"raw_whois": whois_text}

            # Extract registrar
            registrar_match = re.search(r"Registrar:\s*(.+)", whois_text, re.IGNORECASE)
            if registrar_match:
                whois_dict["registrar"] = registrar_match.group(1).strip()

            # Extract domain name
            domain_match = re.search(r"Domain Name:\s*(.+)", whois_text, re.IGNORECASE)
            if domain_match:
                whois_dict["domain_name"] = domain_match.group(1).strip()

            # Extract creation date (multiple patterns for different TLDs)
            creation_patterns = [
                r"Creation Date:\s*(.+)",
                r"Created Date:\s*(.+)",
                r"Created:\s*(.+)",
                r"Registration Date:\s*(.+)",
                r"Domain Registration Date:\s*(.+)",
                r"created:\s*(.+)",
            ]
            for pattern in creation_patterns:
                creation_match = re.search(pattern, whois_text, re.IGNORECASE)
                if creation_match:
                    whois_dict["creation_date"] = creation_match.group(1).strip()
                    break

            # Extract registrant organization
            org_patterns = [
                r"Registrant Organization:\s*(.+)",
                r"Registrant:\s*(.+)",
                r"org:\s*(.+)",
            ]
            for pattern in org_patterns:
                org_match = re.search(pattern, whois_text, re.IGNORECASE)
                if org_match:
                    org_value = org_match.group(1).strip()
                    # Skip if it's just an email or "REDACTED"
                    if "@" not in org_value and "REDACTED" not in org_value.upper():
                        whois_dict["org"] = org_value
                        break

            return whois_dict

        try:
            # First try with python-whois library
            data = whois.whois(domain)
            if data and (data.domain_name or data.registrar):
                logger.info(f"📋 Got WHOIS data for {domain} using python-whois")
                return data
        except Exception as e:
            logger.debug(f"Python-whois failed for {domain}: {e}")

        # If that fails, try with specific WHOIS server for TLD
        try:
            tld = domain.split(".")[-1].lower()
            whois_server = TLD_WHOIS_SERVERS.get(tld)

            if whois_server:
                logger.debug(f"🔍 Trying WHOIS server {whois_server} for {domain}")
                result = subprocess.run(
                    ["whois", "-h", whois_server, domain],
                    capture_output=True,
                    text=True,
                    timeout=15,
                )

                if result.returncode == 0 and result.stdout:
                    whois_text = result.stdout
                    if is_valid_whois_response(whois_text):
                        whois_dict = parse_whois_text(whois_text)
                        logger.info(f"📋 Got WHOIS data for {domain} using {whois_server}")
                        return whois_dict
                    else:
                        logger.warning(f"⚠️ Invalid WHOIS response from {whois_server} for {domain}")
        except Exception as e:
            logger.debug(f"Direct WHOIS query failed for {domain}: {e}")

        # Fallback 3 - try generic whois command
        try:
            logger.info(f"📋 Trying generic whois command for {domain}")
            result = subprocess.run(["whois", domain], capture_output=True, text=True, timeout=15)

            if result.returncode == 0 and result.stdout:
                whois_text = result.stdout
                if is_valid_whois_response(whois_text):
                    whois_dict = parse_whois_text(whois_text)
                    logger.info(f"📋 Got WHOIS data for {domain} using generic whois")
                    return whois_dict
                else:
                    logger.warning(f"⚠️ WHOIS server busy/rate-limited for {domain}, trying RDAP...")
        except Exception as e:
            logger.debug(f"Generic whois failed for {domain}: {e}")

        # Fallback 4 - try RDAP (Registration Data Access Protocol)
        # RDAP is the modern replacement for WHOIS with better availability
        try:
            rdap_result = EnhancedAbuseEmailDetector.get_rdap_info(domain)
            if rdap_result and (rdap_result.get("registrar") or rdap_result.get("creation_date")):
                logger.info(f"📋 Got RDAP data for {domain}")
                return rdap_result
        except Exception as e:
            logger.debug(f"RDAP query failed for {domain}: {e}")

        logger.warning(f"⚠️  All WHOIS/RDAP methods failed for {domain}")
        return {}
