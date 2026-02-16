"""Typosquatting Detection Service - Domain Variant Generation & Monitoring."""

import asyncio
import logging
from datetime import datetime
from typing import List, Dict, Optional, Set
from urllib.parse import urlparse

import dns.resolver
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.domain_variant import DomainVariant
from src.models.scan import Scan

logger = logging.getLogger(__name__)


class TyposquattingService:
    """Service for detecting typosquatting domain variants.

    Generates domain permutations using various techniques:
    - Homoglyphs (visual similarity)
    - Keyboard typos (QWERTY layout)
    - TLD variations
    - Subdomain tricks
    - Combo squatting

    Example:
        ```python
        service = TyposquattingService(db)
        variants = await service.generate_variants("paypal.com")
        active_variants = await service.check_dns_resolution(variants)
        await service.save_variants("paypal.com", active_variants)
        ```
    """

    # Homoglyph mappings (visual similarity)
    HOMOGLYPHS = {
        'a': ['à', 'á', 'â', 'ã', 'ä', 'å', 'ą'],
        'e': ['è', 'é', 'ê', 'ë', 'ę'],
        'i': ['ì', 'í', 'î', 'ï', 'ı', '1', 'l'],
        'o': ['ò', 'ó', 'ô', 'õ', 'ö', 'ø', '0'],
        'u': ['ù', 'ú', 'û', 'ü'],
        'l': ['1', 'i', '|'],
        '0': ['o', 'O'],
        '1': ['l', 'i', 'I'],
        's': ['$', '5'],
        'g': ['9', 'q'],
    }

    # Keyboard typo mappings (QWERTY layout - adjacent keys)
    QWERTY_TYPOS = {
        'a': ['q', 's', 'w', 'z'],
        'b': ['v', 'g', 'h', 'n'],
        'c': ['x', 'd', 'f', 'v'],
        'd': ['s', 'e', 'r', 'f', 'c', 'x'],
        'e': ['w', 'r', 'd', 's'],
        'f': ['d', 'r', 't', 'g', 'v', 'c'],
        'g': ['f', 't', 'y', 'h', 'b', 'v'],
        'h': ['g', 'y', 'u', 'j', 'n', 'b'],
        'i': ['u', 'o', 'k', 'j'],
        'j': ['h', 'u', 'i', 'k', 'n', 'm'],
        'k': ['j', 'i', 'o', 'l', 'm'],
        'l': ['k', 'o', 'p'],
        'm': ['n', 'j', 'k'],
        'n': ['b', 'h', 'j', 'm'],
        'o': ['i', 'p', 'l', 'k'],
        'p': ['o', 'l'],
        'q': ['w', 'a'],
        'r': ['e', 't', 'f', 'd'],
        's': ['a', 'w', 'e', 'd', 'x', 'z'],
        't': ['r', 'y', 'g', 'f'],
        'u': ['y', 'i', 'j', 'h'],
        'v': ['c', 'f', 'g', 'b'],
        'w': ['q', 'e', 's', 'a'],
        'x': ['z', 's', 'd', 'c'],
        'y': ['t', 'u', 'h', 'g'],
        'z': ['a', 's', 'x'],
    }

    # Common TLD variations
    COMMON_TLDS = [
        'com', 'net', 'org', 'info', 'biz', 'co', 'io',
        'me', 'app', 'dev', 'online', 'store', 'site',
        'xyz', 'tech', 'cloud', 'pro', 'us', 'uk', 'de'
    ]

    # Common subdomain tricks
    SUBDOMAIN_TRICKS = [
        'www', 'secure', 'login', 'account', 'verify',
        'update', 'support', 'help', 'service', 'portal'
    ]

    def __init__(self, db: AsyncSession):
        """Initialize typosquatting service.

        Args:
            db: Database session
        """
        self.db = db

    async def generate_variants(
        self,
        target_domain: str,
        max_variants: int = 200,
        techniques: Optional[List[str]] = None
    ) -> List[Dict[str, str]]:
        """Generate domain variants using multiple techniques.

        Args:
            target_domain: Legitimate domain to generate variants for
            max_variants: Maximum variants to generate
            techniques: List of techniques to use (default: all)
                       Options: homoglyph, typo, tld, subdomain, combo

        Returns:
            List of variant dictionaries with 'domain' and 'type' keys

        Example:
            ```python
            variants = await service.generate_variants("paypal.com", max_variants=50)
            # [
            #   {'domain': 'paypa1.com', 'type': 'homoglyph'},
            #   {'domain': 'paypsl.com', 'type': 'typo'},
            #   ...
            # ]
            ```
        """
        if techniques is None:
            techniques = ['homoglyph', 'typo', 'tld', 'subdomain', 'combo']

        # Parse domain
        domain_parts = target_domain.lower().replace('www.', '').split('.')
        if len(domain_parts) < 2:
            raise ValueError(f"Invalid domain format: {target_domain}")

        domain_name = domain_parts[0]
        original_tld = '.'.join(domain_parts[1:])

        variants: Set[str] = set()
        variant_list: List[Dict[str, str]] = []

        # 1. Homoglyph variants
        if 'homoglyph' in techniques:
            homoglyph_variants = self._generate_homoglyphs(domain_name, original_tld)
            for variant in homoglyph_variants:
                if variant not in variants and len(variant_list) < max_variants:
                    variants.add(variant)
                    variant_list.append({'domain': variant, 'type': 'homoglyph'})

        # 2. Keyboard typo variants
        if 'typo' in techniques:
            typo_variants = self._generate_typos(domain_name, original_tld)
            for variant in typo_variants:
                if variant not in variants and len(variant_list) < max_variants:
                    variants.add(variant)
                    variant_list.append({'domain': variant, 'type': 'keyboard_typo'})

        # 3. TLD variation variants
        if 'tld' in techniques:
            tld_variants = self._generate_tld_variations(domain_name, original_tld)
            for variant in tld_variants:
                if variant not in variants and len(variant_list) < max_variants:
                    variants.add(variant)
                    variant_list.append({'domain': variant, 'type': 'tld_variation'})

        # 4. Subdomain trick variants
        if 'subdomain' in techniques:
            subdomain_variants = self._generate_subdomain_tricks(domain_name, original_tld)
            for variant in subdomain_variants:
                if variant not in variants and len(variant_list) < max_variants:
                    variants.add(variant)
                    variant_list.append({'domain': variant, 'type': 'subdomain_trick'})

        # 5. Combo squatting variants
        if 'combo' in techniques:
            combo_variants = self._generate_combo_squatting(domain_name, original_tld)
            for variant in combo_variants:
                if variant not in variants and len(variant_list) < max_variants:
                    variants.add(variant)
                    variant_list.append({'domain': variant, 'type': 'combo_squatting'})

        logger.info(f"Generated {len(variant_list)} variants for {target_domain}")
        return variant_list[:max_variants]

    def _generate_homoglyphs(self, domain: str, tld: str) -> List[str]:
        """Generate homoglyph variants (character substitution)."""
        variants = []
        for i, char in enumerate(domain):
            if char in self.HOMOGLYPHS:
                for replacement in self.HOMOGLYPHS[char]:
                    variant = domain[:i] + replacement + domain[i+1:]
                    variants.append(f"{variant}.{tld}")
        return variants

    def _generate_typos(self, domain: str, tld: str) -> List[str]:
        """Generate keyboard typo variants."""
        variants = []
        for i, char in enumerate(domain):
            if char in self.QWERTY_TYPOS:
                for typo in self.QWERTY_TYPOS[char]:
                    variant = domain[:i] + typo + domain[i+1:]
                    variants.append(f"{variant}.{tld}")
        return variants

    def _generate_tld_variations(self, domain: str, original_tld: str) -> List[str]:
        """Generate TLD variation variants."""
        variants = []
        for tld in self.COMMON_TLDS:
            if tld != original_tld:
                variants.append(f"{domain}.{tld}")
        return variants

    def _generate_subdomain_tricks(self, domain: str, tld: str) -> List[str]:
        """Generate subdomain trick variants."""
        variants = []
        for trick in self.SUBDOMAIN_TRICKS:
            variants.append(f"{domain}-{trick}.{tld}")
            variants.append(f"{trick}-{domain}.{tld}")
            variants.append(f"{trick}{domain}.{tld}")
        return variants

    def _generate_combo_squatting(self, domain: str, tld: str) -> List[str]:
        """Generate combo squatting variants (brand + keyword)."""
        keywords = ['login', 'secure', 'account', 'verify', 'update', 'support']
        variants = []
        for keyword in keywords:
            variants.append(f"{domain}{keyword}.{tld}")
            variants.append(f"{domain}-{keyword}.{tld}")
            variants.append(f"{keyword}{domain}.{tld}")
        return variants

    async def check_dns_resolution(
        self,
        variants: List[Dict[str, str]],
        timeout: int = 3
    ) -> List[Dict[str, str]]:
        """Check which variants resolve (are active).

        Args:
            variants: List of variant dicts from generate_variants()
            timeout: DNS query timeout in seconds

        Returns:
            List of active variants (DNS resolves)
        """
        active_variants = []
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout

        for variant in variants:
            domain = variant['domain']
            try:
                # Try to resolve A record
                answers = resolver.resolve(domain, 'A')
                if answers:
                    active_variants.append(variant)
                    logger.info(f"Active variant found: {domain}")
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                # Domain doesn't resolve, skip
                pass
            except Exception as e:
                logger.warning(f"DNS error for {domain}: {e}")

        logger.info(f"Found {len(active_variants)} active variants out of {len(variants)}")
        return active_variants

    async def save_variants(
        self,
        target_domain: str,
        variants: List[Dict[str, str]],
        detection_method: str = "automated"
    ) -> List[DomainVariant]:
        """Save detected variants to database.

        Args:
            target_domain: Original legitimate domain
            variants: List of variant dicts
            detection_method: How variants were detected

        Returns:
            List of saved DomainVariant objects
        """
        saved_variants = []

        for variant_data in variants:
            # Check if variant already exists
            stmt = select(DomainVariant).where(
                DomainVariant.variant_domain == variant_data['domain']
            )
            result = await self.db.execute(stmt)
            existing = result.scalar_one_or_none()

            if existing:
                # Update last_checked timestamp
                existing.last_checked = datetime.utcnow()
                existing.is_active = True
                saved_variants.append(existing)
            else:
                # Create new variant
                variant = DomainVariant(
                    target_domain=target_domain,
                    variant_domain=variant_data['domain'],
                    variant_type=variant_data['type'],
                    is_active=True,
                    detection_method=detection_method,
                    first_seen=datetime.utcnow(),
                    last_checked=datetime.utcnow()
                )
                self.db.add(variant)
                saved_variants.append(variant)

        await self.db.commit()
        logger.info(f"Saved {len(saved_variants)} variants for {target_domain}")
        return saved_variants

    async def analyze_domain(
        self,
        target_domain: str,
        max_variants: int = 100,
        check_active_only: bool = True
    ) -> Dict:
        """Complete typosquatting analysis workflow.

        Args:
            target_domain: Domain to analyze
            max_variants: Max variants to generate
            check_active_only: Only save active variants

        Returns:
            Analysis results dictionary

        Example:
            ```python
            results = await service.analyze_domain("paypal.com")
            # {
            #     'target_domain': 'paypal.com',
            #     'total_generated': 150,
            #     'active_variants': 8,
            #     'saved_variants': 8,
            #     'variants': [...]
            # }
            ```
        """
        # Generate variants
        all_variants = await self.generate_variants(target_domain, max_variants=max_variants)

        # Check DNS resolution
        active_variants = await self.check_dns_resolution(all_variants)

        # Save to database
        if check_active_only:
            saved = await self.save_variants(target_domain, active_variants)
        else:
            saved = await self.save_variants(target_domain, all_variants)

        return {
            'target_domain': target_domain,
            'total_generated': len(all_variants),
            'active_variants': len(active_variants),
            'saved_variants': len(saved),
            'variants': [
                {
                    'domain': v.variant_domain,
                    'type': v.variant_type,
                    'is_active': v.is_active
                }
                for v in saved
            ]
        }

    async def get_variants_for_domain(
        self,
        target_domain: str,
        active_only: bool = True
    ) -> List[DomainVariant]:
        """Get all saved variants for a target domain.

        Args:
            target_domain: Target domain to query
            active_only: Only return active variants

        Returns:
            List of DomainVariant objects
        """
        stmt = select(DomainVariant).where(
            DomainVariant.target_domain == target_domain
        )

        if active_only:
            stmt = stmt.where(DomainVariant.is_active == True)

        stmt = stmt.order_by(DomainVariant.confidence_score.desc().nulls_last())

        result = await self.db.execute(stmt)
        return list(result.scalars().all())
