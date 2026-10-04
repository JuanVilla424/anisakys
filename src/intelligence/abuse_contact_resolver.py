"""
Abuse Contact Resolver Module

Consolidates abuse contact resolution from multiple sources:
- ASN database lookups
- Provider database lookups
- WHOIS/RDAP data parsing
- Email validation and deduplication

EPIC-005: Multi-Abuse Contact Handling
"""

import logging
import re
from typing import Iterable, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class AbuseContactResolver:
    """
    Resolves and consolidates abuse contact emails from multiple sources.

    Features:
    - Multi-source resolution (ASN, Provider, WHOIS)
    - Email validation (format and domain filtering)
    - Automatic deduplication
    - Priority-based ordering: RDAP/WHOIS abuse contacts first, then the
      curated provider database, then the ASN database; first-seen order is
      kept inside each source, so the result is deterministic
    """

    def __init__(
        self,
        asn_db: dict,
        provider_db: dict,
        validate_domains: bool = True,
        max_contacts: int = 10,
    ):
        """
        Initialize AbuseContactResolver.

        Args:
            asn_db: ASN to abuse email mapping (dict[str, List[str]])
            provider_db: Provider to abuse email mapping (dict[str, List[str]])
            validate_domains: Filter out emails from same domain as target (default: True)
            max_contacts: Maximum number of contacts to return (default: 10)
        """
        self.asn_db = asn_db
        self.provider_db = provider_db
        self.validate_domains = validate_domains
        self.max_contacts = max_contacts
        self.logger = logging.getLogger(f"{__name__}.AbuseContactResolver")

    def resolve(
        self,
        asn: Optional[str] = None,
        provider_name: Optional[str] = None,
        whois_data: Optional[dict] = None,
        target_domain: Optional[str] = None,
    ) -> List[str]:
        """
        Resolve abuse contacts from all available sources.

        Args:
            asn: ASN number (with or without 'AS' prefix)
            provider_name: Hosting provider name
            whois_data: WHOIS/RDAP data dictionary
            target_domain: Target domain for validation (exclude same-domain emails)

        Returns:
            List[str]: Valid abuse addresses, de-duplicated case-insensitively
            and ordered by priority (RDAP/WHOIS abuse contacts, then the
            curated provider database, then the ASN database), truncated to
            ``max_contacts``.
        """
        ordered: List[str] = []

        # 1. WHOIS/RDAP abuse contacts (published by the responsible network)
        if whois_data:
            whois_emails = self._resolve_from_whois(whois_data)
            if whois_emails:
                ordered.extend(whois_emails)
                self.logger.info(f"📜 WHOIS lookup: {len(whois_emails)} contacts from WHOIS data")

        # 2. Curated provider database
        if provider_name:
            provider_emails = self._resolve_from_provider(provider_name)
            if provider_emails:
                ordered.extend(provider_emails)
                self.logger.info(
                    f"🏢 Provider lookup: {len(provider_emails)} contacts from {provider_name}"
                )

        # 3. ASN database
        if asn:
            asn_emails = self._resolve_from_asn(asn)
            if asn_emails:
                ordered.extend(asn_emails)
                self.logger.info(
                    f"📋 ASN lookup: {len(asn_emails)} contacts from AS{self._clean_asn(asn)}"
                )

        # 4. Validate, de-duplicate (first occurrence wins) and limit
        unique = self._dedupe(ordered)
        valid_emails = [e for e in unique if self._is_acceptable(e, target_domain)]
        final_emails = valid_emails[: self.max_contacts]

        self.logger.info(
            f"✅ Resolved {len(final_emails)} unique abuse contacts "
            f"(from {len(unique)} total found)"
        )

        return final_emails

    @staticmethod
    def _dedupe(emails: Iterable[str]) -> List[str]:
        """De-duplicate addresses case-insensitively, keeping first-seen order.

        Args:
            emails: Addresses in priority order (non-strings are dropped).

        Returns:
            Stripped addresses, each kept at its first position.
        """
        seen: Set[str] = set()
        result: List[str] = []
        for email in emails:
            if not isinstance(email, str):
                continue
            cleaned = email.strip()
            key = cleaned.lower()
            if cleaned and key not in seen:
                seen.add(key)
                result.append(cleaned)
        return result

    def _resolve_from_asn(self, asn: str) -> List[str]:
        """
        Resolve abuse emails from ASN database.

        Args:
            asn: ASN number (with or without 'AS' prefix)

        Returns:
            List[str]: List of abuse emails for this ASN
        """
        asn_clean = self._clean_asn(asn)

        # Try without AS prefix
        emails = self.asn_db.get(asn_clean)
        if emails:
            self.logger.debug(f"Found {len(emails)} ASN contacts for AS{asn_clean}")
            return emails

        # Try with AS prefix (in case database has inconsistent keys)
        emails = self.asn_db.get(f"AS{asn_clean}")
        if emails:
            self.logger.debug(f"Found {len(emails)} ASN contacts for AS{asn_clean} (with prefix)")
            return emails

        self.logger.debug(f"No ASN contacts found for AS{asn_clean}")
        return []

    def _resolve_from_provider(self, provider_name: str) -> List[str]:
        """
        Resolve abuse emails from provider database.

        Args:
            provider_name: Provider name (e.g., "HOSTINGER", "DIGITALOCEAN")

        Returns:
            List[str]: List of abuse emails for this provider
        """
        if not provider_name:
            return []

        # Normalize provider name
        provider_clean = provider_name.upper().strip()

        # Try exact match first
        emails = self.provider_db.get(provider_clean)
        if emails:
            valid_emails = self._filter_invalid_emails(emails)
            if valid_emails:
                self.logger.debug(
                    f"Found {len(valid_emails)} provider contacts for {provider_clean}"
                )
                return valid_emails

        # Try partial matching for providers with variable suffixes, most
        # specific candidate first (see _partial_match_candidates)
        for provider_key in self._partial_match_candidates(provider_clean):
            valid_emails = self._filter_invalid_emails(self.provider_db[provider_key])
            if valid_emails:
                self.logger.debug(
                    f"Found {len(valid_emails)} provider contacts via partial match "
                    f"({provider_clean} -> {provider_key})"
                )
                return valid_emails

        self.logger.debug(f"No provider contacts found for {provider_clean}")
        return []

    def _partial_match_candidates(self, provider_clean: str) -> List[str]:
        """Order partial provider matches from most to least specific.

        Keys contained in the provider name come first, longest key first
        (``"GOOGLE CLOUD"`` beats ``"GOOGLE"`` for ``"GOOGLE CLOUD EUROPE"``);
        then keys that contain the provider name, closest length first.
        Ties are broken alphabetically, so the result never depends on the
        database's iteration order.

        Args:
            provider_clean: Upper-cased, stripped provider name.

        Returns:
            Matching provider keys in priority order.
        """
        if not provider_clean:
            return []
        ranked: List[Tuple[int, int, str]] = []
        for key in self.provider_db:
            key_clean = str(key).upper().strip()
            if not key_clean or key_clean == provider_clean:
                continue
            if key_clean in provider_clean:
                ranked.append((0, -len(key_clean), key))
            elif provider_clean in key_clean:
                ranked.append((1, len(key_clean) - len(provider_clean), key))
        ranked.sort(key=lambda item: (item[0], item[1], str(item[2])))
        return [key for _, _, key in ranked]

    def _resolve_from_whois(self, whois_data: dict) -> List[str]:
        """
        Extract abuse emails from WHOIS/RDAP data.

        Args:
            whois_data: WHOIS/RDAP data dictionary

        Returns:
            List[str]: Abuse emails found in WHOIS data, in document order:
            RDAP abuse-role contacts, then ``abuse_contacts``, then raw text.
        """
        emails: List[str] = []

        # Check RDAP objects for abuse contacts
        objects = whois_data.get("objects", {})
        if objects and isinstance(objects, dict):
            for contact_id, contact_data in objects.items():
                if isinstance(contact_data, dict):
                    contact_info = contact_data.get("contact", {})
                    if contact_info and isinstance(contact_info, dict):
                        # Check if role contains "abuse"
                        role = str(contact_info.get("role", "")).lower()
                        if "abuse" in role:
                            email = contact_info.get("email")
                            if email:
                                if isinstance(email, list):
                                    emails.extend(email)
                                else:
                                    emails.append(email)

        # Check direct abuse_contacts field
        abuse_contacts = whois_data.get("abuse_contacts")
        if abuse_contacts:
            if isinstance(abuse_contacts, list):
                emails.extend(abuse_contacts)
            else:
                emails.append(abuse_contacts)

        # Parse raw WHOIS text for abuse emails
        raw_whois = whois_data.get("raw_whois", "")
        if raw_whois:
            # Look for lines with "abuse" and email patterns
            abuse_email_pattern = re.compile(
                r"(?:abuse|abuse-c|abuse-mailbox).*?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
                re.IGNORECASE,
            )
            matches = abuse_email_pattern.findall(raw_whois)
            if matches:
                emails.extend(matches)

        return self._dedupe(emails)

    def _is_acceptable(self, email: str, target_domain: Optional[str]) -> bool:
        """Check one address for format and (optionally) same-domain rejection.

        Args:
            email: Address to check.
            target_domain: Target domain to exclude (if validate_domains is True).

        Returns:
            bool: True if the address may be used.
        """
        if not self._is_valid_email_format(email):
            self.logger.debug(f"❌ Invalid email format: {email}")
            return False
        if (
            self.validate_domains
            and target_domain
            and not self._is_valid_domain(email, target_domain)
        ):
            self.logger.debug(f"❌ Same-domain email rejected: {email}")
            return False
        return True

    @staticmethod
    def _is_valid_email_format(email: str) -> bool:
        """
        Check if email has valid format.

        Args:
            email: Email address to validate

        Returns:
            bool: True if valid format
        """
        if not email or not isinstance(email, str):
            return False

        # Must contain @ but not end with it
        if "@" not in email or email.endswith("@"):
            return False

        # Basic regex pattern
        pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        return bool(re.match(pattern, email))

    @staticmethod
    def _is_valid_domain(email: str, target_domain: str) -> bool:
        """
        Check if email domain is different from target domain.

        Args:
            email: Email address to check
            target_domain: Target domain to compare against

        Returns:
            bool: True if email domain is different from target domain
        """
        try:
            email_domain = email.split("@")[1].lower()
            target_clean = target_domain.lower().replace("www.", "")

            # Reject if email domain matches target domain
            if email_domain == target_clean:
                return False

            # Reject if email domain is subdomain of target
            if email_domain.endswith(f".{target_clean}"):
                return False

            return True
        except (IndexError, AttributeError):
            return False

    @staticmethod
    def _filter_invalid_emails(emails: List[str]) -> List[str]:
        """
        Filter out obviously invalid email entries.

        Args:
            emails: List of email addresses

        Returns:
            List[str]: Filtered list of potentially valid emails
        """
        return [email for email in emails if email and "@" in email and not email.endswith("@")]

    @staticmethod
    def _clean_asn(asn: str) -> str:
        """
        Normalize ASN format (remove AS prefix).

        Args:
            asn: ASN string (with or without AS prefix)

        Returns:
            str: Cleaned ASN number
        """
        return asn.replace("AS", "").strip()
