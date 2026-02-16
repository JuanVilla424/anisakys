"""Certificate Transparency Log Monitoring Service.

Monitors CT logs for suspicious domain certificates that may indicate
phishing campaigns or brand impersonation.
"""

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Optional, Set
import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.ct_certificate import CTCertificate
from src.models.scan import Scan

logger = logging.getLogger(__name__)


class CTMonitorService:
    """Service for monitoring Certificate Transparency logs.

    Integrates with crt.sh and other CT log sources to detect
    suspicious certificate issuance for domain monitoring.

    Features:
    - CT log polling (crt.sh API)
    - Keyword-based detection
    - Automatic scan triggering
    - Duplicate prevention

    Example:
        ```python
        service = CTMonitorService(db)
        results = await service.monitor_keywords(["paypal", "banking"])
        suspicious = await service.get_suspicious_certificates(days=7)
        ```
    """

    # CT Log sources
    CRT_SH_API = "https://crt.sh/"

    # Suspicious patterns (phishing indicators)
    SUSPICIOUS_KEYWORDS = [
        'login', 'secure', 'verify', 'account', 'update', 'banking',
        'paypal', 'amazon', 'apple', 'microsoft', 'google', 'facebook',
        'signin', 'validation', 'confirm', 'suspended', 'locked'
    ]

    # Common certificate issuers (legitimate)
    LEGITIMATE_ISSUERS = [
        "Let's Encrypt",
        "DigiCert",
        "Sectigo",
        "GoDaddy",
        "GlobalSign",
        "Comodo",
        "Thawte",
        "GeoTrust"
    ]

    def __init__(self, db: AsyncSession):
        """Initialize CT monitoring service.

        Args:
            db: Database session
        """
        self.db = db
        self.client = httpx.AsyncClient(timeout=30.0)

    async def search_crt_sh(
        self,
        query: str,
        match_type: str = "ILIKE"
    ) -> List[Dict]:
        """Search crt.sh for certificates matching query.

        Args:
            query: Search query (domain or keyword)
            match_type: Match type (ILIKE, =, LIKE)

        Returns:
            List of certificate dictionaries from crt.sh

        Example:
            ```python
            certs = await service.search_crt_sh("paypal")
            # Returns raw crt.sh results
            ```
        """
        try:
            params = {
                'q': query,
                'output': 'json'
            }

            response = await self.client.get(
                f"{self.CRT_SH_API}",
                params=params
            )
            response.raise_for_status()

            results = response.json()
            logger.info(f"Found {len(results)} certificates for query: {query}")
            return results

        except httpx.HTTPError as e:
            logger.error(f"crt.sh API error for query '{query}': {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error querying crt.sh: {e}")
            return []

    async def parse_certificate(
        self,
        cert_data: Dict,
        matched_keywords: Optional[List[str]] = None
    ) -> Optional[Dict]:
        """Parse crt.sh certificate data into our format.

        Args:
            cert_data: Raw certificate data from crt.sh
            matched_keywords: Keywords that triggered detection

        Returns:
            Parsed certificate dictionary or None if invalid
        """
        try:
            # Extract Subject Alternative Names (SANs)
            name_value = cert_data.get('name_value', '')
            san_domains = [d.strip() for d in name_value.split('\n') if d.strip()]

            # Use first domain as subject_cn if not provided
            subject_cn = cert_data.get('common_name') or (san_domains[0] if san_domains else 'unknown')

            # Parse dates
            not_before = datetime.fromisoformat(
                cert_data['entry_timestamp'].replace('Z', '+00:00')
            ) if 'entry_timestamp' in cert_data else datetime.now(timezone.utc)

            # Estimate not_after (typically 90 days for Let's Encrypt)
            not_after = not_before + timedelta(days=90)

            return {
                'cert_id': str(cert_data.get('id', cert_data.get('min_cert_id', 'unknown'))),
                'fingerprint': cert_data.get('fingerprint', f"crt_sh_{cert_data.get('id', 'unknown')}"),
                'issuer': cert_data.get('issuer_name', 'Unknown'),
                'subject_cn': subject_cn,
                'san_domains': san_domains,
                'not_before': not_before,
                'not_after': not_after,
                'log_source': 'crt.sh',
                'matched_keywords': matched_keywords or [],
                'raw_data': cert_data
            }

        except Exception as e:
            logger.warning(f"Failed to parse certificate: {e}")
            return None

    def calculate_threat_score(
        self,
        cert_data: Dict,
        matched_keywords: List[str]
    ) -> tuple[int, str]:
        """Calculate threat confidence score and level.

        Args:
            cert_data: Parsed certificate data
            matched_keywords: Keywords that matched

        Returns:
            Tuple of (confidence_score, threat_level)

        Scoring Logic:
        - Multiple suspicious keywords: +30
        - Recently issued (< 7 days): +20
        - Free/automated issuer: +15
        - Long domain name (> 20 chars): +10
        - Multiple subdomains: +10
        - Hyphenated domain: +5
        """
        score = 0

        subject_cn = cert_data['subject_cn'].lower()
        issuer = cert_data['issuer']

        # Multiple suspicious keywords
        if len(matched_keywords) > 1:
            score += 30
        elif len(matched_keywords) == 1:
            score += 15

        # Recently issued certificate
        days_old = (datetime.now(timezone.utc) - cert_data['not_before']).days
        if days_old < 7:
            score += 20
        elif days_old < 30:
            score += 10

        # Free/automated certificate issuer (common in phishing)
        if "Let's Encrypt" in issuer or "ZeroSSL" in issuer:
            score += 15

        # Long domain name (typosquatting indicator)
        if len(subject_cn) > 20:
            score += 10

        # Multiple subdomains (e.g., login.secure.paypal-verify.com)
        subdomain_count = subject_cn.count('.')
        if subdomain_count > 2:
            score += 10

        # Hyphenated domains (common in phishing)
        if '-' in subject_cn:
            score += 5

        # Determine threat level
        if score >= 70:
            threat_level = 'critical'
        elif score >= 50:
            threat_level = 'high'
        elif score >= 30:
            threat_level = 'medium'
        elif score >= 10:
            threat_level = 'low'
        else:
            threat_level = 'safe'

        return min(score, 100), threat_level

    async def save_certificate(
        self,
        cert_data: Dict,
        is_suspicious: bool = False
    ) -> Optional[CTCertificate]:
        """Save certificate to database.

        Args:
            cert_data: Parsed certificate data
            is_suspicious: Whether certificate is flagged as suspicious

        Returns:
            Saved CTCertificate object or None if duplicate
        """
        # Check if certificate already exists
        stmt = select(CTCertificate).where(
            CTCertificate.cert_id == cert_data['cert_id']
        )
        result = await self.db.execute(stmt)
        existing = result.scalar_one_or_none()

        if existing:
            logger.debug(f"Certificate {cert_data['cert_id']} already exists, skipping")
            return None

        # Calculate threat score
        confidence_score, threat_level = self.calculate_threat_score(
            cert_data,
            cert_data.get('matched_keywords', [])
        )

        # Create new certificate record
        certificate = CTCertificate(
            cert_id=cert_data['cert_id'],
            fingerprint=cert_data['fingerprint'],
            issuer=cert_data['issuer'],
            subject_cn=cert_data['subject_cn'],
            san_domains=cert_data['san_domains'],
            not_before=cert_data['not_before'],
            not_after=cert_data['not_after'],
            log_source=cert_data['log_source'],
            discovered_at=datetime.now(timezone.utc),
            is_suspicious=is_suspicious or confidence_score >= 30,
            matched_keywords=cert_data.get('matched_keywords', []),
            confidence_score=confidence_score,
            threat_level=threat_level,
            scan_triggered=False,
            raw_data=cert_data.get('raw_data', {}),
            notes=None
        )

        self.db.add(certificate)
        await self.db.commit()
        await self.db.refresh(certificate)

        logger.info(
            f"Saved certificate: {cert_data['subject_cn']} "
            f"(threat: {threat_level}, score: {confidence_score})"
        )

        return certificate

    async def monitor_keywords(
        self,
        keywords: List[str],
        min_threat_level: str = 'medium',
        auto_save: bool = True
    ) -> Dict:
        """Monitor CT logs for certificates matching keywords.

        Args:
            keywords: List of keywords to monitor
            min_threat_level: Minimum threat level to flag (low, medium, high, critical)
            auto_save: Automatically save suspicious certificates

        Returns:
            Monitoring results dictionary

        Example:
            ```python
            results = await service.monitor_keywords(
                ["paypal", "banking"],
                min_threat_level="medium"
            )
            # {
            #     'keywords_searched': ['paypal', 'banking'],
            #     'certificates_found': 45,
            #     'suspicious_certificates': 12,
            #     'saved_certificates': 12
            # }
            ```
        """
        all_certificates = []
        suspicious_count = 0
        saved_count = 0

        for keyword in keywords:
            logger.info(f"Searching CT logs for keyword: {keyword}")

            # Search crt.sh
            raw_results = await self.search_crt_sh(f"%{keyword}%")

            for raw_cert in raw_results:
                # Parse certificate
                parsed = await self.parse_certificate(raw_cert, matched_keywords=[keyword])
                if not parsed:
                    continue

                # Calculate threat
                confidence_score, threat_level = self.calculate_threat_score(
                    parsed,
                    [keyword]
                )

                parsed['confidence_score'] = confidence_score
                parsed['threat_level'] = threat_level

                all_certificates.append(parsed)

                # Check if suspicious
                threat_levels = ['safe', 'low', 'medium', 'high', 'critical']
                min_level_index = threat_levels.index(min_threat_level)
                cert_level_index = threat_levels.index(threat_level)

                is_suspicious = cert_level_index >= min_level_index

                if is_suspicious:
                    suspicious_count += 1

                    # Auto-save if enabled
                    if auto_save:
                        saved = await self.save_certificate(parsed, is_suspicious=True)
                        if saved:
                            saved_count += 1

            # Small delay between keyword searches to avoid rate limiting
            await asyncio.sleep(0.5)

        return {
            'keywords_searched': keywords,
            'certificates_found': len(all_certificates),
            'suspicious_certificates': suspicious_count,
            'saved_certificates': saved_count,
            'certificates': all_certificates
        }

    async def monitor_domain(
        self,
        domain: str,
        include_subdomains: bool = True,
        auto_save: bool = True
    ) -> Dict:
        """Monitor CT logs for specific domain.

        Args:
            domain: Domain to monitor
            include_subdomains: Include subdomain certificates
            auto_save: Automatically save found certificates

        Returns:
            Monitoring results dictionary
        """
        query = f"%.{domain}" if include_subdomains else domain

        logger.info(f"Monitoring CT logs for domain: {domain}")

        raw_results = await self.search_crt_sh(query)

        certificates = []
        saved_count = 0

        for raw_cert in raw_results:
            parsed = await self.parse_certificate(raw_cert)
            if not parsed:
                continue

            # Calculate threat (lower for exact domain matches)
            confidence_score, threat_level = self.calculate_threat_score(parsed, [])
            parsed['confidence_score'] = confidence_score
            parsed['threat_level'] = threat_level

            certificates.append(parsed)

            if auto_save:
                saved = await self.save_certificate(parsed, is_suspicious=False)
                if saved:
                    saved_count += 1

        return {
            'domain': domain,
            'certificates_found': len(certificates),
            'saved_certificates': saved_count,
            'certificates': certificates
        }

    async def get_suspicious_certificates(
        self,
        days: int = 7,
        min_threat_level: str = 'medium'
    ) -> List[CTCertificate]:
        """Get suspicious certificates from recent days.

        Args:
            days: Number of days to look back
            min_threat_level: Minimum threat level filter

        Returns:
            List of CTCertificate objects
        """
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)

        stmt = select(CTCertificate).where(
            CTCertificate.is_suspicious == True,
            CTCertificate.discovered_at >= cutoff_date
        )

        # Filter by threat level if specified
        if min_threat_level != 'low':
            threat_levels = ['medium', 'high', 'critical']
            if min_threat_level in threat_levels:
                stmt = stmt.where(CTCertificate.threat_level.in_(
                    threat_levels[threat_levels.index(min_threat_level):]
                ))

        stmt = stmt.order_by(CTCertificate.confidence_score.desc())

        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    async def trigger_scan_for_certificate(
        self,
        certificate_id: int,
        user_id: int
    ) -> Optional[Scan]:
        """Trigger automatic scan for suspicious certificate.

        Args:
            certificate_id: CTCertificate ID to scan
            user_id: User ID to attribute scan to

        Returns:
            Created Scan object or None if failed
        """
        # Get certificate
        stmt = select(CTCertificate).where(CTCertificate.id == certificate_id)
        result = await self.db.execute(stmt)
        certificate = result.scalar_one_or_none()

        if not certificate:
            logger.error(f"Certificate {certificate_id} not found")
            return None

        # Create scan for primary domain
        scan = Scan(
            user_id=user_id,
            url=f"https://{certificate.subject_cn}",
            status="pending",
            threat_level="unknown",
            created_at=datetime.now(timezone.utc)
        )

        self.db.add(scan)

        # Mark certificate as having triggered scan
        certificate.scan_triggered = True
        certificate.updated_at = datetime.now(timezone.utc)

        await self.db.commit()
        await self.db.refresh(scan)

        logger.info(f"Triggered scan {scan.id} for certificate {certificate_id}")

        return scan

    async def close(self):
        """Close HTTP client."""
        await self.client.aclose()
