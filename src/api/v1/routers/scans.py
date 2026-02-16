"""URL scanning endpoints."""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from pydantic import BaseModel, HttpUrl, Field
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.dependencies import get_db, get_current_user, get_scanning_service
from src.services import ScanningService
from src.models.user import User
from src.models.scan import Scan


router = APIRouter(prefix="/scans", tags=["Scanning"])


class ScanRequest(BaseModel):
    """URL scan request."""
    url: HttpUrl
    force_rescan: bool = Field(False, description="Force new scan even if recent scan exists")


class ScanResponse(BaseModel):
    """Scan result response."""
    id: int
    url: str
    host: str
    confidence_score: float
    threat_level: str
    virustotal_positives: Optional[int]
    virustotal_total: Optional[int]
    urlvoid_blacklists: Optional[int]
    urlvoid_engines: Optional[int]
    phishtank_is_phishing: Optional[bool]
    phishtank_verified: Optional[bool]
    screenshot_url: Optional[str]
    whois_data: Optional[dict]
    scanned_at: str

    class Config:
        from_attributes = True

    @classmethod
    def from_scan(cls, scan: Scan) -> "ScanResponse":
        """Create response from Scan model."""
        return cls(
            id=scan.id,
            url=scan.url,
            host=scan.host,
            confidence_score=scan.confidence_score,
            threat_level=scan.threat_level,
            virustotal_positives=scan.virustotal_positives,
            virustotal_total=scan.virustotal_total,
            urlvoid_blacklists=scan.urlvoid_blacklists,
            urlvoid_engines=scan.urlvoid_engines,
            phishtank_is_phishing=scan.phishtank_is_phishing,
            phishtank_verified=scan.phishtank_verified,
            screenshot_url=scan.screenshot_url,
            whois_data=scan.whois_data,
            scanned_at=scan.scanned_at.isoformat() if scan.scanned_at else ""
        )


class ScanListResponse(BaseModel):
    """List of scans response."""
    scans: List[ScanResponse]
    total: int
    limit: int
    offset: int


@router.post("/", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def create_scan(
    request: ScanRequest,
    current_user: User = Depends(get_current_user),
    scanner: ScanningService = Depends(get_scanning_service)
):
    """Scan a URL for threats.

    Performs multi-API threat intelligence scan:
    - VirusTotal: Malware detection
    - URLVoid: Blacklist reputation
    - PhishTank: Phishing database check

    Returns confidence score (0-100) and threat level.

    Args:
        request: Scan request with URL
        current_user: Authenticated user
        scanner: Scanning service

    Returns:
        Scan results with threat analysis

    Raises:
        HTTPException: If URL invalid
    """
    try:
        scan = await scanner.scan_url(
            url=str(request.url),
            user_id=current_user.id,
            force_rescan=request.force_rescan
        )
        return ScanResponse.from_scan(scan)

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: int,
    current_user: User = Depends(get_current_user),
    scanner: ScanningService = Depends(get_scanning_service)
):
    """Get scan by ID.

    Args:
        scan_id: Scan ID
        current_user: Authenticated user
        scanner: Scanning service

    Returns:
        Scan result

    Raises:
        HTTPException: If scan not found or not owned by user
    """
    scan = await scanner.get_scan_by_id(scan_id, current_user.id)

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )

    return ScanResponse.from_scan(scan)


@router.get("/", response_model=ScanListResponse)
async def list_scans(
    limit: int = Query(50, ge=1, le=100, description="Maximum number of results"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    current_user: User = Depends(get_current_user),
    scanner: ScanningService = Depends(get_scanning_service)
):
    """List user's scan history.

    Args:
        limit: Maximum results (1-100)
        offset: Pagination offset
        current_user: Authenticated user
        scanner: Scanning service

    Returns:
        List of scans
    """
    scans = await scanner.get_user_scans(
        user_id=current_user.id,
        limit=limit,
        offset=offset
    )

    return ScanListResponse(
        scans=[ScanResponse.from_scan(scan) for scan in scans],
        total=len(scans),
        limit=limit,
        offset=offset
    )
