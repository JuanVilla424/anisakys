"""
Enhanced Abuse Email Detector for Anisakys Phishing Detection Engine.

Finds the abuse contacts a phishing report should go to, and only those:

* Registration data contributes abuse-role contacts only (the RDAP ``abuse``
  entity, labelled ``... Abuse Contact Email`` lines, ``abuse@``-style
  addresses). Registrant, admin and tech addresses are never returned: they
  belong to whoever registered the phishing domain.
* Hosting contacts come from the IP the site resolves to. When that IP is a
  Cloudflare proxy, mail-server (MX) addresses are never taken as the real
  host: mail and web hosting are unrelated, so that sent complaints to
  Google/Microsoft for sites they do not host.
* Contacts are returned ordered by trust: RDAP abuse > curated database >
  ASN abuse-c (see ``src.reporting.recipient_policy``).
* Every address is checked against the reported site's registrable domain
  (Public Suffix List) and against the site's own content.
"""

import datetime
import re
import socket
import subprocess
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import dns.exception
import dns.resolver
import requests
import validators
import whois
from ipwhois import IPWhois

from src.data import (
    ASN_ABUSE_EMAIL_DB,
    PROVIDER_ABUSE_EMAIL_DB,
    ENHANCED_REGISTRAR_ABUSE_DB,
    TLD_WHOIS_SERVERS,
)
from sqlalchemy import text
from src.dns.network_utils import is_cloudflare_ip
from src.intelligence.abuse_contact_resolver import AbuseContactResolver
from src.logger import logger
from src.reporting.recipient_policy import (
    ContactCandidate,
    ContactTier,
    emails_in_text,
    holder_emails_in_whois,
    is_abuse_role_address,
    labelled_abuse_emails_in_whois,
    normalize_email,
    order_by_trust,
    recipient_rejection_reason,
)

# RDAP Bootstrap cache (TLD -> RDAP server URL)
_RDAP_BOOTSTRAP_CACHE: Dict[str, str] = {}


@dataclass
class AbuseContactResolution:
    """Abuse contacts for a domain plus the network facts behind them."""

    emails: List[str] = field(default_factory=list)
    candidates: List[ContactCandidate] = field(default_factory=list)
    resolved_ip: Optional[str] = None
    is_cloudflare: bool = False
    hosting_provider: Optional[str] = None
    asn: Optional[str] = None


@dataclass
class _NetworkInfo:
    """IP-level facts from an RDAP lookup of the hosting network."""

    provider_name: Optional[str]
    asn: Optional[str]
    rdap: Dict[str, Any]


class EnhancedAbuseEmailDetector:
    """Enhanced abuse email detection with multiple sources and validation."""

    def __init__(self, db_manager):
        self.db_manager = db_manager
        self.dns_resolver = dns.resolver.Resolver()
        self.abuse_resolver = AbuseContactResolver(
            asn_db=ASN_ABUSE_EMAIL_DB,
            provider_db=PROVIDER_ABUSE_EMAIL_DB,
        )
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

    @staticmethod
    def _whois_text(whois_info: Any) -> str:
        """Best raw-text view of a WHOIS/RDAP result.

        Args:
            whois_info: python-whois object, RDAP/parsed dict or raw text.

        Returns:
            The raw WHOIS text when available, else ``str(whois_info)``.
        """
        if whois_info is None:
            return ""
        if isinstance(whois_info, str):
            return whois_info
        if isinstance(whois_info, dict):
            raw = whois_info.get("raw_whois") or whois_info.get("text")
            return raw if isinstance(raw, str) else ""
        raw = getattr(whois_info, "text", None)
        return raw if isinstance(raw, str) else str(whois_info)

    def extract_emails_from_whois(self, whois_info: Any) -> List[str]:
        """Extract abuse-role contacts from WHOIS/RDAP data.

        Only the RDAP ``abuse`` entity, addresses on lines labelled as an
        abuse contact and addresses with an abuse-like local part are kept.
        There is no "take every address" fallback, and any address that
        appears on a registrant/admin/tech/billing line is dropped.

        Args:
            whois_info: python-whois object, RDAP/parsed dict or raw text.

        Returns:
            Lowercased, de-duplicated abuse contacts, RDAP entity first.
        """
        raw_text = self._whois_text(whois_info)
        holder = set(holder_emails_in_whois(raw_text))
        found: List[str] = []

        if isinstance(whois_info, dict):
            rdap_abuse = whois_info.get("abuse_contacts") or []
            found.extend(rdap_abuse if isinstance(rdap_abuse, list) else [rdap_abuse])
            listed = whois_info.get("emails") or []
        else:
            listed = getattr(whois_info, "emails", None) or []
        if isinstance(listed, str):
            listed = [listed]

        found.extend(labelled_abuse_emails_in_whois(raw_text))
        found.extend(email for email in listed if is_abuse_role_address(str(email)))
        found.extend(email for email in emails_in_text(raw_text) if is_abuse_role_address(email))

        unique: List[str] = []
        for email in found:
            address = normalize_email(str(email))
            if address and address not in holder and address not in unique:
                unique.append(address)
        if unique:
            logger.debug(f"Abuse contacts in registration data: {unique}")
        return unique

    def get_abuse_email_from_dns(self, domain: str) -> Optional[str]:
        """Try to get an abuse email from the domain's own DNS TXT records.

        Not used to pick report recipients: the TXT records of a phishing
        domain are controlled by the attacker.

        Args:
            domain: Domain to query.

        Returns:
            The first abuse-like address found, or ``None``.
        """
        try:
            txt_records = self.dns_resolver.resolve(domain, "TXT")
            for record in txt_records:
                record_str = str(record).lower()
                if "abuse" in record_str:
                    email_match = re.search(
                        r"([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})", record_str
                    )
                    if email_match and self.validate_email(email_match.group(1)):
                        return email_match.group(1)
        except dns.exception.DNSException:
            logger.debug(f"DNS TXT query failed for {domain}")
        return None

    def get_abuse_email_from_whois_servers(self, domain: str) -> Optional[str]:
        """Query multiple WHOIS servers for an abuse contact of ``domain``.

        Args:
            domain: Domain to query.

        Returns:
            The first abuse-role contact found, or ``None``.
        """
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
                        logger.info(f"Found abuse contact via WHOIS server {server}: {emails[0]}")
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

    def resolve_abuse_contacts(
        self,
        domain: str,
        whois_info: Any = None,
        registrar: Optional[str] = None,
        site_content: Optional[str] = None,
    ) -> AbuseContactResolution:
        """Find the abuse contacts for ``domain``, most trusted first.

        Tiers (lower is more trusted):

        1. RDAP abuse: the registrar's abuse entity / labelled abuse contact
           in the domain's registration data, then the hosting network's RDAP
           abuse contact.
        2. Curated database: registrar and hosting-provider abuse databases.
        3. ASN abuse-c: the ASN abuse database.

        Args:
            domain: Reported host name.
            whois_info: Registration data already fetched for ``domain``.
            registrar: Registrar name, when known.
            site_content: Content served by the site; addresses published
                there are rejected.

        Returns:
            The ordered, policy-checked contacts and the network facts.
        """
        resolution = AbuseContactResolution()
        candidates: List[ContactCandidate] = []

        def add(emails: Any, tier: ContactTier, source: str) -> None:
            values = emails if isinstance(emails, (list, tuple, set)) else [emails]
            for email in sorted(str(value) for value in values if value):
                candidates.append(ContactCandidate(email=email, tier=tier, source=source))

        registration = self.extract_emails_from_whois(whois_info) if whois_info else []
        add(registration, ContactTier.RDAP_ABUSE, "registration data")

        if registrar:
            try:
                cached = self.get_abuse_email_by_registrar(registrar)
            except Exception as e:
                logger.warning(f"Registrar abuse database lookup failed for {registrar}: {e}")
                cached = None
            if cached:
                add(
                    self.parse_stored_abuse_emails(cached),
                    ContactTier.CURATED,
                    "registrar database",
                )

        if not candidates:
            server_email = self.get_abuse_email_from_whois_servers(domain)
            if server_email:
                add([server_email], ContactTier.RDAP_ABUSE, "WHOIS server")

        try:
            resolution.resolved_ip = socket.gethostbyname(domain)
        except (socket.gaierror, UnicodeError, OSError) as e:
            logger.info(f"{domain} does not resolve ({e}); no hosting contacts")

        lookup_ip = resolution.resolved_ip
        if lookup_ip and is_cloudflare_ip(lookup_ip):
            resolution.is_cloudflare = True
            lookup_ip = self.get_real_ip_behind_cloudflare(domain)
            if not lookup_ip:
                logger.info(f"{domain} is behind Cloudflare and no origin IP is known")

        if lookup_ip:
            network = self._lookup_network(lookup_ip)
            if network:
                resolution.hosting_provider = network.provider_name
                resolution.asn = network.asn
                add(
                    self.abuse_resolver.resolve(whois_data=network.rdap),
                    ContactTier.RDAP_ABUSE,
                    "hosting network RDAP",
                )
                if network.provider_name:
                    add(
                        self.abuse_resolver.resolve(provider_name=network.provider_name),
                        ContactTier.CURATED,
                        "hosting provider database",
                    )
                if network.asn:
                    add(
                        self.abuse_resolver.resolve(asn=network.asn.replace("AS", "")),
                        ContactTier.ASN_ABUSE,
                        "ASN database",
                    )

        accepted: List[ContactCandidate] = []
        for candidate in candidates:
            reason = recipient_rejection_reason(candidate.email, domain, site_content)
            if reason:
                logger.warning(f"Rejected abuse contact {candidate.email}: {reason}")
                continue
            accepted.append(candidate)

        resolution.candidates = accepted
        resolution.emails = order_by_trust(accepted)
        if resolution.emails:
            logger.info(f"Abuse contacts for {domain} (most trusted first): {resolution.emails}")
        else:
            logger.warning(f"No usable abuse contacts found for {domain}")
        return resolution

    def get_enhanced_abuse_email(
        self,
        domain: str,
        whois_info: Any = None,
        registrar: Optional[str] = None,
        site_content: Optional[str] = None,
    ) -> List[str]:
        """Get abuse contacts for ``domain`` ordered by trust.

        Args:
            domain: Reported host name.
            whois_info: Registration data already fetched for ``domain``.
            registrar: Registrar name, when known.
            site_content: Content served by the site, when available.

        Returns:
            Policy-checked abuse contacts, most trusted first.
        """
        return self.resolve_abuse_contacts(domain, whois_info, registrar, site_content).emails

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
    def validate_abuse_email_domain(
        email: str, reported_domain: str, site_content: Optional[str] = None
    ) -> bool:
        """
        Validate that an abuse e-mail is not controlled by the reported site.

        The recipient's registrable domain (eTLD+1, Public Suffix List) must
        differ from the site's, so ``abuse@evil.com.co`` is rejected for
        ``login.evil.com.co``; addresses published in the site's own content
        are rejected too.

        Args:
            email (str): Abuse email to validate
            reported_domain (str): Domain (or URL) being reported for phishing
            site_content (Optional[str]): Content served by the site, if known

        Returns:
            bool: True if the address may receive the report
        """
        reason = recipient_rejection_reason(email, reported_domain, site_content)
        if reason:
            logger.warning(f"Cannot send abuse report to {email} for {reported_domain}: {reason}")
            return False
        return True

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
        Look for the origin IP of a Cloudflare-proxied site.

        Only origin-style sub-domains of the site itself are probed. MX records
        are deliberately not used: the mail host of a domain says nothing about
        where its website runs (it is usually Google or Microsoft), so treating
        it as the hosting provider sent complaints to uninvolved providers.

        Args:
            domain (str): Domain to investigate

        Returns:
            Optional[str]: Non-Cloudflare IP of an origin sub-domain, or None
        """
        common_subdomains = ["direct", "origin", "real", "server", "host", "main", "www-origin"]

        for subdomain in common_subdomains:
            test_domain = f"{subdomain}.{domain}"
            try:
                ip = socket.gethostbyname(test_domain)
            except (socket.gaierror, UnicodeError, OSError):
                continue
            if not is_cloudflare_ip(ip):
                logger.info(f"Potential origin IP via {test_domain}: {ip}")
                return ip
        return None

    def _lookup_network(self, ip: str) -> Optional[_NetworkInfo]:
        """RDAP lookup of the network an IP belongs to.

        Args:
            ip: IP address.

        Returns:
            Provider name, ASN (``AS123``) and the raw RDAP result, or ``None``
            when the lookup fails.
        """
        try:
            res = IPWhois(ip).lookup_rdap(depth=1)
        except Exception as e:
            logger.warning(f"Hosting lookup failed for IP {ip}: {e}")
            return None
        network_info = res.get("network") or {}
        provider_name = ""
        if isinstance(network_info, dict):
            provider_name = network_info.get("name") or ""
        provider_name = provider_name or res.get("asn_description") or ""
        asn = str(res.get("asn") or "").strip()
        if asn and not asn.upper().startswith("AS"):
            asn = f"AS{asn}"
        return _NetworkInfo(provider_name=provider_name or None, asn=asn or None, rdap=res)

    def get_hosting_provider_info(
        self, ip: str
    ) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[List[str]]]:
        """
        Get hosting provider information from an IP address.

        The legacy fourth element (``asn_abuse_email``) is the list of hosting
        abuse contacts, now ordered by trust: the network's RDAP abuse contact,
        then the curated provider database, then the ASN database.

        Args:
            ip (str): IP address to investigate

        Returns:
            (provider_name, provider_abuse_email, asn, abuse_emails); all
            ``None`` when the lookup fails.
        """
        network = self._lookup_network(ip)
        if network is None:
            return None, None, None, None
        candidates: List[ContactCandidate] = []
        asn_number = (network.asn or "").replace("AS", "") or None
        tiers = (
            (ContactTier.RDAP_ABUSE, self.abuse_resolver.resolve(whois_data=network.rdap)),
            (
                ContactTier.CURATED,
                (
                    self.abuse_resolver.resolve(provider_name=network.provider_name)
                    if network.provider_name
                    else []
                ),
            ),
            (
                ContactTier.ASN_ABUSE,
                self.abuse_resolver.resolve(asn=asn_number) if asn_number else [],
            ),
        )
        for tier, emails in tiers:
            for email in sorted(emails):
                candidates.append(ContactCandidate(email=email, tier=tier, source=tier.name))
        abuse_emails = order_by_trust(candidates)
        logger.info(
            f"IP {ip}: provider={network.provider_name or 'unknown'}, ASN={network.asn}, "
            f"{len(abuse_emails)} abuse contact(s)"
        )
        provider_abuse_email = abuse_emails[0] if abuse_emails else None
        return network.provider_name, provider_abuse_email, network.asn, abuse_emails

    # EPIC-005: Removed get_abuse_email_by_asn() and get_abuse_email_by_provider()
    # These are now handled by AbuseContactResolver class in src/intelligence/

    @staticmethod
    def _iter_rdap_entities(entities: list):
        """Yield every RDAP entity at any nesting depth. Per the standard
        ICANN RDAP profile, the "abuse" role is typically a sub-entity
        nested inside the "registrar" entity's own "entities" list rather
        than a top-level sibling -- confirmed against a real response
        (rdap.markmonitor.com/rdap/domain/google.com)."""
        for entity in entities:
            yield entity
            nested = entity.get("entities")
            if nested:
                yield from EnhancedAbuseEmailDetector._iter_rdap_entities(nested)

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

            # Extract abuse contact email(s) -- the whole point of trying
            # RDAP first for abuse reporting; AbuseContactResolver already
            # reads whois_data["abuse_contacts"] with no changes needed
            # (src/intelligence/abuse_contact_resolver.py). Confirmed live
            # against a real gTLD RDAP response (google.com via MarkMonitor)
            # that the "abuse" role is nested INSIDE the "registrar" entity's
            # own "entities" list, not a top-level sibling -- this is the
            # standard ICANN RDAP profile shape, not an edge case, so this
            # has to walk nested entities or it misses abuse contacts on
            # most real gTLD domains.
            for entity in EnhancedAbuseEmailDetector._iter_rdap_entities(data.get("entities", [])):
                if "abuse" not in entity.get("roles", []):
                    continue
                vcard = entity.get("vcardArray", [])
                if len(vcard) > 1:
                    abuse_emails = [item[3] for item in vcard[1] if item[0] == "email"]
                    if abuse_emails:
                        result.setdefault("abuse_contacts", []).extend(abuse_emails)

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

        # RDAP first: the modern, structured replacement for WHOIS, and the
        # only one of these sources get_rdap_info() extracts abuse contacts
        # from (see its "abuse" in roles branch) -- tried before the legacy
        # text-parsing fallbacks below, not after them.
        try:
            rdap_result = EnhancedAbuseEmailDetector.get_rdap_info(domain)
            if rdap_result and (
                rdap_result.get("registrar")
                or rdap_result.get("creation_date")
                or rdap_result.get("abuse_contacts")
            ):
                logger.info(f"📋 Got RDAP data for {domain}")
                return rdap_result
        except Exception as e:
            logger.debug(f"RDAP query failed for {domain}: {e}")

        # Fallback 1 - python-whois library
        try:
            data = whois.whois(domain)
            if data and (data.domain_name or data.registrar):
                logger.info(f"📋 Got WHOIS data for {domain} using python-whois")
                return data
        except Exception as e:
            logger.debug(f"Python-whois failed for {domain}: {e}")

        # Fallback 2 - specific WHOIS server for TLD
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
                        logger.warning(
                            f"⚠️ Invalid WHOIS response from {whois_server} for {domain}"
                        )
        except Exception as e:
            logger.debug(f"Direct WHOIS query failed for {domain}: {e}")

        # Fallback 3 - generic whois command
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
                    logger.warning(f"⚠️ WHOIS server busy/rate-limited for {domain}")
        except Exception as e:
            logger.debug(f"Generic whois failed for {domain}: {e}")

        logger.warning(f"⚠️  All WHOIS/RDAP methods failed for {domain}")
        return {}
