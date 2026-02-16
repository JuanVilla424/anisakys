"""Research endpoints - Typosquatting & Certificate Transparency monitoring."""

from typing import List, Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.dependencies import get_db, get_current_user
from src.services.typosquatting_service import TyposquattingService
from src.services.ct_monitor_service import CTMonitorService
from src.models.user import User
from src.models.domain_variant import DomainVariant
from src.models.ct_certificate import CTCertificate


router = APIRouter(prefix="/research", tags=["Research"])


# ========== SCHEMAS ==========

class TyposquattingRequest(BaseModel):
    """Typosquatting analysis request."""
    target_domain: str = Field(..., description="Domain to analyze for variants")
    max_variants: int = Field(100, ge=10, le=500, description="Maximum variants to generate")
    check_active_only: bool = Field(True, description="Only save active (resolving) variants")
    techniques: Optional[List[str]] = Field(
        None,
        description="Techniques to use: homoglyph, typo, tld, subdomain, combo"
    )


class DomainVariantResponse(BaseModel):
    """Domain variant response."""
    id: int
    target_domain: str
    variant_domain: str
    variant_type: str
    is_active: bool
    confidence_score: Optional[int]
    threat_level: Optional[str]
    detection_method: str
    first_seen: str
    last_checked: str
    whois_data: Optional[dict]

    class Config:
        from_attributes = True

    @classmethod
    def from_variant(cls, variant: DomainVariant) -> "DomainVariantResponse":
        """Create response from DomainVariant model."""
        return cls(
            id=variant.id,
            target_domain=variant.target_domain,
            variant_domain=variant.variant_domain,
            variant_type=variant.variant_type,
            is_active=variant.is_active,
            confidence_score=variant.confidence_score,
            threat_level=variant.threat_level,
            detection_method=variant.detection_method,
            first_seen=variant.first_seen.isoformat(),
            last_checked=variant.last_checked.isoformat(),
            whois_data=variant.whois_data
        )


class TyposquattingAnalysisResponse(BaseModel):
    """Typosquatting analysis results."""
    target_domain: str
    total_generated: int
    active_variants: int
    saved_variants: int
    variants: List[DomainVariantResponse]


class CTMonitorRequest(BaseModel):
    """CT monitoring request."""
    keywords: List[str] = Field(..., min_items=1, max_items=10, description="Keywords to monitor")
    min_threat_level: str = Field("medium", description="Minimum threat level: low, medium, high, critical")
    auto_save: bool = Field(True, description="Auto-save suspicious certificates")


class CTCertificateResponse(BaseModel):
    """CT certificate response."""
    id: int
    cert_id: str
    fingerprint: str
    issuer: str
    subject_cn: str
    san_domains: List[str]
    not_before: str
    not_after: str
    log_source: str
    discovered_at: str
    is_suspicious: bool
    matched_keywords: Optional[List[str]]
    confidence_score: Optional[int]
    threat_level: Optional[str]
    scan_triggered: bool

    class Config:
        from_attributes = True

    @classmethod
    def from_certificate(cls, cert: CTCertificate) -> "CTCertificateResponse":
        """Create response from CTCertificate model."""
        return cls(
            id=cert.id,
            cert_id=cert.cert_id,
            fingerprint=cert.fingerprint,
            issuer=cert.issuer,
            subject_cn=cert.subject_cn,
            san_domains=cert.san_domains,
            not_before=cert.not_before.isoformat(),
            not_after=cert.not_after.isoformat(),
            log_source=cert.log_source,
            discovered_at=cert.discovered_at.isoformat(),
            is_suspicious=cert.is_suspicious,
            matched_keywords=cert.matched_keywords,
            confidence_score=cert.confidence_score,
            threat_level=cert.threat_level,
            scan_triggered=cert.scan_triggered
        )


class CTMonitorResponse(BaseModel):
    """CT monitoring results."""
    keywords_searched: List[str]
    certificates_found: int
    suspicious_certificates: int
    saved_certificates: int


# ========== TYPOSQUATTING ENDPOINTS ==========

@router.post("/typosquatting/analyze", response_model=TyposquattingAnalysisResponse)
async def analyze_typosquatting(
    request: TyposquattingRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Analyze domain for typosquatting variants.

    Generates domain variants using multiple techniques:
    - Homoglyphs (visual similarity)
    - Keyboard typos (QWERTY layout)
    - TLD variations
    - Subdomain tricks
    - Combo squatting

    Then checks which variants resolve (are active) and saves them.

    Args:
        request: Analysis request with target domain
        current_user: Authenticated user
        db: Database session

    Returns:
        Analysis results with detected variants

    Example:
        POST /api/v1/research/typosquatting/analyze
        {
            "target_domain": "paypal.com",
            "max_variants": 100,
            "check_active_only": true
        }
    """
    service = TyposquattingService(db)

    try:
        results = await service.analyze_domain(
            target_domain=request.target_domain,
            max_variants=request.max_variants,
            check_active_only=request.check_active_only
        )

        # Convert variant objects to response models
        variant_responses = [
            DomainVariantResponse.from_variant(v)
            for v in results['variants']
        ]

        return TyposquattingAnalysisResponse(
            target_domain=results['target_domain'],
            total_generated=results['total_generated'],
            active_variants=results['active_variants'],
            saved_variants=results['saved_variants'],
            variants=variant_responses
        )

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Typosquatting analysis failed: {str(e)}"
        )


@router.get("/typosquatting/variants/{target_domain}", response_model=List[DomainVariantResponse])
async def get_domain_variants(
    target_domain: str,
    active_only: bool = Query(True, description="Only return active variants"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get saved variants for a target domain.

    Args:
        target_domain: Domain to get variants for
        active_only: Only return active (resolving) variants
        current_user: Authenticated user
        db: Database session

    Returns:
        List of domain variants

    Example:
        GET /api/v1/research/typosquatting/variants/paypal.com?active_only=true
    """
    service = TyposquattingService(db)

    try:
        variants = await service.get_variants_for_domain(
            target_domain=target_domain,
            active_only=active_only
        )

        return [DomainVariantResponse.from_variant(v) for v in variants]

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve variants: {str(e)}"
        )


# ========== CT MONITORING ENDPOINTS ==========

@router.post("/ct-monitoring/monitor", response_model=CTMonitorResponse)
async def monitor_ct_logs(
    request: CTMonitorRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Monitor Certificate Transparency logs for keywords.

    Searches CT logs (crt.sh) for certificates matching keywords.
    Useful for detecting phishing campaigns targeting specific brands.

    Args:
        request: Monitoring request with keywords
        current_user: Authenticated user
        db: Database session

    Returns:
        Monitoring results with suspicious certificates found

    Example:
        POST /api/v1/research/ct-monitoring/monitor
        {
            "keywords": ["paypal", "banking"],
            "min_threat_level": "medium",
            "auto_save": true
        }
    """
    service = CTMonitorService(db)

    try:
        # Validate threat level
        valid_levels = ['low', 'medium', 'high', 'critical']
        if request.min_threat_level not in valid_levels:
            raise ValueError(f"Invalid threat level. Must be one of: {valid_levels}")

        results = await service.monitor_keywords(
            keywords=request.keywords,
            min_threat_level=request.min_threat_level,
            auto_save=request.auto_save
        )

        return CTMonitorResponse(
            keywords_searched=results['keywords_searched'],
            certificates_found=results['certificates_found'],
            suspicious_certificates=results['suspicious_certificates'],
            saved_certificates=results['saved_certificates']
        )

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"CT monitoring failed: {str(e)}"
        )
    finally:
        await service.close()


@router.get("/ct-monitoring/suspicious", response_model=List[CTCertificateResponse])
async def get_suspicious_certificates(
    days: int = Query(7, ge=1, le=90, description="Number of days to look back"),
    min_threat_level: str = Query("medium", description="Minimum threat level filter"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get suspicious certificates from recent days.

    Args:
        days: Number of days to look back (1-90)
        min_threat_level: Minimum threat level (low, medium, high, critical)
        current_user: Authenticated user
        db: Database session

    Returns:
        List of suspicious certificates

    Example:
        GET /api/v1/research/ct-monitoring/suspicious?days=7&min_threat_level=high
    """
    service = CTMonitorService(db)

    try:
        # Validate threat level
        valid_levels = ['low', 'medium', 'high', 'critical']
        if min_threat_level not in valid_levels:
            raise ValueError(f"Invalid threat level. Must be one of: {valid_levels}")

        certificates = await service.get_suspicious_certificates(
            days=days,
            min_threat_level=min_threat_level
        )

        return [CTCertificateResponse.from_certificate(cert) for cert in certificates]

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve certificates: {str(e)}"
        )
    finally:
        await service.close()


@router.post("/ct-monitoring/trigger-scan/{certificate_id}", status_code=status.HTTP_201_CREATED)
async def trigger_certificate_scan(
    certificate_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Trigger automatic scan for suspicious certificate.

    Args:
        certificate_id: CT certificate ID to scan
        current_user: Authenticated user
        db: Database session

    Returns:
        Created scan information

    Example:
        POST /api/v1/research/ct-monitoring/trigger-scan/123
    """
    service = CTMonitorService(db)

    try:
        scan = await service.trigger_scan_for_certificate(
            certificate_id=certificate_id,
            user_id=current_user.id
        )

        if not scan:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Certificate {certificate_id} not found"
            )

        return {
            "scan_id": scan.id,
            "url": scan.url,
            "status": scan.status,
            "message": f"Scan triggered for certificate {certificate_id}"
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to trigger scan: {str(e)}"
        )
    finally:
        await service.close()
