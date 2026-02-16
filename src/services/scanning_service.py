"""URL scanning service with multi-API orchestration."""

import asyncio
import hashlib
from datetime import datetime
from decimal import Decimal
from typing import Optional, Dict
from urllib.parse import urlparse
from sqlalchemy.ext.asyncio import AsyncSession

from src.integrations import VirusTotalClient, URLVoidClient, PhishTankClient
from src.services.confidence_calculator import ConfidenceCalculator, ThreatLevel
from src.services.screenshot_service import ScreenshotService
from src.services.whois_service import WHOISService
from src.models.scan import Scan
from src.models.user import User


class ScanningService:
    """Orchestrates multi-API URL scanning with confidence scoring.

    Example:
        ```python
        async with get_db_session() as db:
            scanner = ScanningService(db)
            scan = await scanner.scan_url(
                url="https://suspicious-site.com",
                user_id=user.id
            )
            print(f"Threat: {scan.threat_level} ({scan.confidence_score}%)")
        ```
    """

    def __init__(
        self,
        db: AsyncSession,
        vt_client: Optional[VirusTotalClient] = None,
        urlvoid_client: Optional[URLVoidClient] = None,
        phishtank_client: Optional[PhishTankClient] = None,
        screenshot_service: Optional[ScreenshotService] = None,
        whois_service: Optional[WHOISService] = None,
    ):
        """Initialize scanning service.

        Args:
            db: Database session
            vt_client: Optional VirusTotal client (defaults to new instance)
            urlvoid_client: Optional URLVoid client (defaults to new instance)
            phishtank_client: Optional PhishTank client (defaults to new instance)
            screenshot_service: Optional Screenshot service (defaults to new instance)
            whois_service: Optional WHOIS service (defaults to new instance)
        """
        self.db = db
        self.vt_client = vt_client or VirusTotalClient()
        self.urlvoid_client = urlvoid_client or URLVoidClient()
        self.phishtank_client = phishtank_client or PhishTankClient()
        self.screenshot_service = screenshot_service or ScreenshotService()
        self.whois_service = whois_service or WHOISService()
        self.calculator = ConfidenceCalculator()

    async def scan_url(
        self,
        url: str,
        user_id: int,
        force_rescan: bool = False
    ) -> Scan:
        """Scan URL using all available threat intelligence APIs.

        Args:
            url: URL to scan
            user_id: ID of user requesting scan
            force_rescan: If True, bypass cache and force new scan

        Returns:
            Scan object with results and confidence analysis

        Raises:
            ValueError: If URL is invalid

        Example:
            ```python
            scan = await scanner.scan_url(
                url="https://malicious.com",
                user_id=123,
                force_rescan=True
            )
            ```
        """
        # Validate URL
        parsed = self._validate_url(url)
        if not parsed:
            raise ValueError(f"Invalid URL: {url}")

        # Check for recent scan (unless force_rescan)
        if not force_rescan:
            recent_scan = await self._get_recent_scan(url, user_id)
            if recent_scan:
                return recent_scan

        # Extract host for URLVoid
        host = parsed.netloc

        # Execute all API scans + screenshot + WHOIS in parallel
        vt_result, urlvoid_result, phishtank_result, screenshot_path, whois_data = await asyncio.gather(
            self._safe_scan(self.vt_client.scan_url, url),
            self._safe_scan(self.urlvoid_client.check_reputation, host),
            self._safe_scan(self.phishtank_client.check_url, url),
            self._safe_scan(self.screenshot_service.capture, url),
            self._safe_scan(self.whois_service.lookup, host),
            return_exceptions=True
        )

        # Handle exceptions from parallel execution
        vt_result = None if isinstance(vt_result, Exception) else vt_result
        urlvoid_result = None if isinstance(urlvoid_result, Exception) else urlvoid_result
        phishtank_result = None if isinstance(phishtank_result, Exception) else phishtank_result
        screenshot_path = None if isinstance(screenshot_path, Exception) else screenshot_path
        whois_data = None if isinstance(whois_data, Exception) else whois_data

        # Aggregate results
        api_results = {
            "virustotal": vt_result,
            "urlvoid": urlvoid_result,
            "phishtank": phishtank_result
        }

        # Calculate confidence score
        confidence_analysis = self.calculator.calculate(api_results)

        # Calculate URL hash for deduplication
        url_hash = hashlib.sha256(url.encode()).hexdigest()

        # Create scan record
        scan = Scan(
            user_id=user_id,
            url=url,
            url_hash=url_hash,
            scan_type="manual",
            status="completed",
            domain=host,
            confidence_score=Decimal(str(confidence_analysis["confidence_score"])),
            threat_level=confidence_analysis["threat_level"].value,
            is_phishing=phishtank_result.get("is_phishing") if phishtank_result else None,
            virustotal_result=vt_result,
            urlvoid_result=urlvoid_result,
            phishtank_result=phishtank_result,
            grinder_result={"confidence_analysis": confidence_analysis},
            screenshot_url=screenshot_path,
            whois_data=whois_data
        )

        # Save to database
        self.db.add(scan)
        await self.db.commit()
        await self.db.refresh(scan)

        return scan

    async def get_scan_by_id(self, scan_id: int, user_id: int) -> Optional[Scan]:
        """Retrieve scan by ID (user must own the scan).

        Args:
            scan_id: Scan ID
            user_id: User ID (for authorization)

        Returns:
            Scan if found and owned by user, None otherwise
        """
        from sqlalchemy import select

        stmt = select(Scan).where(
            Scan.id == scan_id,
            Scan.user_id == user_id
        )
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    async def get_user_scans(
        self,
        user_id: int,
        limit: int = 50,
        offset: int = 0
    ) -> list[Scan]:
        """Get user's scan history.

        Args:
            user_id: User ID
            limit: Maximum number of scans to return
            offset: Pagination offset

        Returns:
            List of Scan objects
        """
        from sqlalchemy import select

        stmt = (
            select(Scan)
            .where(Scan.user_id == user_id)
            .order_by(Scan.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    def _validate_url(self, url: str) -> Optional[urlparse]:
        """Validate URL format.

        Args:
            url: URL string

        Returns:
            Parsed URL object if valid, None otherwise
        """
        try:
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                return None
            if parsed.scheme not in ("http", "https"):
                return None
            return parsed
        except Exception:
            return None

    async def _safe_scan(self, scan_func, *args, **kwargs):
        """Execute scan function safely with exception handling.

        Args:
            scan_func: Async function to call
            *args: Positional arguments
            **kwargs: Keyword arguments

        Returns:
            Scan result or None if error
        """
        try:
            return await scan_func(*args, **kwargs)
        except Exception:
            return None

    async def _get_recent_scan(
        self,
        url: str,
        user_id: int,
        max_age_hours: int = 24
    ) -> Optional[Scan]:
        """Check for recent scan of same URL by user.

        Args:
            url: URL to check
            user_id: User ID
            max_age_hours: Maximum age of cached scan in hours

        Returns:
            Recent Scan if found, None otherwise
        """
        from sqlalchemy import select
        from datetime import datetime, timedelta

        cutoff_time = datetime.utcnow() - timedelta(hours=max_age_hours)

        stmt = (
            select(Scan)
            .where(
                Scan.user_id == user_id,
                Scan.url == url,
                Scan.created_at >= cutoff_time
            )
            .order_by(Scan.created_at.desc())
            .limit(1)
        )
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()
