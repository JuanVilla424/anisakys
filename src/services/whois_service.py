"""WHOIS lookup service for domain investigation."""

import asyncio
import logging
from typing import Optional, Dict
from datetime import datetime
from urllib.parse import urlparse

import whois


logger = logging.getLogger(__name__)


class WHOISService:
    """WHOIS lookup service for domain registration information.

    Example:
        ```python
        service = WHOISService()
        whois_data = await service.lookup("phishing-site.com")
        if whois_data:
            print(f"Registrar: {whois_data['registrar']}")
            print(f"Created: {whois_data['creation_date']}")
        ```
    """

    def __init__(self, timeout: int = 10):
        """Initialize WHOIS service.

        Args:
            timeout: Timeout for WHOIS queries in seconds
        """
        self.timeout = timeout

    async def lookup(self, domain: str) -> Optional[Dict]:
        """Perform WHOIS lookup for domain.

        Args:
            domain: Domain name (e.g., "example.com")

        Returns:
            Dict with WHOIS data or None if lookup failed:
            {
                "domain": "example.com",
                "registrar": "Example Registrar LLC",
                "creation_date": "2020-01-15T10:30:00",
                "expiration_date": "2027-01-15T10:30:00",
                "updated_date": "2025-12-01T08:15:00",
                "name_servers": ["ns1.example.com", "ns2.example.com"],
                "registrant": "REDACTED FOR PRIVACY",
                "abuse_email": "abuse@registrar.com",
                "status": ["clientTransferProhibited"],
                "dnssec": "unsigned"
            }

        Example:
            ```python
            whois_data = await service.lookup("suspicious.com")
            if whois_data:
                age_days = (datetime.now() - whois_data['creation_date']).days
                if age_days < 30:
                    print("WARNING: Domain less than 30 days old!")
            ```
        """
        # Clean domain (remove protocol, path, etc.)
        domain = self._extract_domain(domain)
        if not domain:
            return None

        try:
            # Run WHOIS lookup in thread pool (it's blocking I/O)
            whois_data = await asyncio.get_event_loop().run_in_executor(
                None,
                self._perform_whois_lookup,
                domain
            )

            if whois_data:
                # Parse and normalize the data
                return self._normalize_whois_data(domain, whois_data)

            return None

        except Exception as e:
            logger.error(f"WHOIS lookup failed for {domain}: {e}")
            return None

    def _perform_whois_lookup(self, domain: str) -> Optional[whois.WhoisEntry]:
        """Perform synchronous WHOIS lookup.

        Args:
            domain: Domain name

        Returns:
            WhoisEntry or None
        """
        try:
            return whois.whois(domain)
        except Exception as e:
            # Catch all WHOIS errors (network, parsing, etc.)
            logger.warning(f"WHOIS lookup failed for {domain}: {e}")
            return None

    def _normalize_whois_data(self, domain: str, whois_data: whois.WhoisEntry) -> Dict:
        """Normalize WHOIS data to consistent format.

        Args:
            domain: Domain name
            whois_data: Raw WHOIS entry

        Returns:
            Normalized dictionary
        """
        # Handle dates (can be datetime, list, or None)
        def normalize_date(date_value):
            if date_value is None:
                return None
            if isinstance(date_value, list):
                date_value = date_value[0] if date_value else None
            if isinstance(date_value, datetime):
                return date_value.isoformat()
            return str(date_value) if date_value else None

        # Handle name servers (can be list or single value)
        def normalize_nameservers(ns_value):
            if ns_value is None:
                return []
            if isinstance(ns_value, list):
                return [str(ns).lower() for ns in ns_value if ns]
            return [str(ns_value).lower()] if ns_value else []

        # Handle status (can be list or single value)
        def normalize_status(status_value):
            if status_value is None:
                return []
            if isinstance(status_value, list):
                return [str(s) for s in status_value if s]
            return [str(status_value)] if status_value else []

        return {
            "domain": domain,
            "registrar": str(whois_data.registrar) if whois_data.registrar else None,
            "creation_date": normalize_date(whois_data.creation_date),
            "expiration_date": normalize_date(whois_data.expiration_date),
            "updated_date": normalize_date(whois_data.updated_date),
            "name_servers": normalize_nameservers(whois_data.name_servers),
            "registrant": str(whois_data.registrant) if whois_data.registrant else "REDACTED",
            "abuse_email": self._extract_abuse_email(whois_data),
            "status": normalize_status(whois_data.status),
            "dnssec": str(whois_data.dnssec) if whois_data.dnssec else "unsigned",
            "whois_server": str(whois_data.whois_server) if whois_data.whois_server else None,
        }

    def _extract_abuse_email(self, whois_data: whois.WhoisEntry) -> Optional[str]:
        """Extract abuse email from WHOIS data.

        Args:
            whois_data: WHOIS entry

        Returns:
            Abuse email or None
        """
        # Try common abuse email patterns
        if hasattr(whois_data, 'emails') and whois_data.emails:
            emails = whois_data.emails if isinstance(whois_data.emails, list) else [whois_data.emails]
            for email in emails:
                if 'abuse' in str(email).lower():
                    return str(email)
            # Return first email if no abuse email found
            return str(emails[0]) if emails else None

        return None

    def _extract_domain(self, url_or_domain: str) -> Optional[str]:
        """Extract domain from URL or domain string.

        Args:
            url_or_domain: URL or domain

        Returns:
            Clean domain name or None

        Example:
            ```python
            _extract_domain("https://example.com/path") -> "example.com"
            _extract_domain("example.com") -> "example.com"
            ```
        """
        try:
            # If it looks like a URL, parse it
            if '://' in url_or_domain:
                parsed = urlparse(url_or_domain)
                domain = parsed.netloc
            else:
                domain = url_or_domain

            # Remove www. prefix
            if domain.startswith('www.'):
                domain = domain[4:]

            # Remove port if present
            if ':' in domain:
                domain = domain.split(':')[0]

            # Validate domain format
            if '.' not in domain or len(domain) < 3:
                return None

            return domain.lower()

        except Exception:
            return None

    async def get_domain_age_days(self, domain: str) -> Optional[int]:
        """Get domain age in days.

        Args:
            domain: Domain name

        Returns:
            Age in days or None if unavailable

        Example:
            ```python
            age = await service.get_domain_age_days("example.com")
            if age and age < 30:
                print("Recently registered domain - suspicious!")
            ```
        """
        whois_data = await self.lookup(domain)
        if not whois_data or not whois_data.get('creation_date'):
            return None

        try:
            creation_date_str = whois_data['creation_date']
            creation_date = datetime.fromisoformat(creation_date_str)
            age = (datetime.now() - creation_date).days
            return age
        except Exception:
            return None

    async def is_recently_registered(self, domain: str, threshold_days: int = 30) -> bool:
        """Check if domain was recently registered.

        Args:
            domain: Domain name
            threshold_days: Days threshold (default 30)

        Returns:
            True if recently registered, False otherwise

        Example:
            ```python
            if await service.is_recently_registered("suspicious.com"):
                print("HIGH RISK: Newly registered domain")
            ```
        """
        age = await self.get_domain_age_days(domain)
        if age is None:
            return False  # Unknown age, can't determine

        return age < threshold_days
