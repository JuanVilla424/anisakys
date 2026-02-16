"""Abuse Reports API Router."""

import logging
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.v1.dependencies.database import get_db
from src.api.v1.schemas.abuse_report import (
    AbuseReportCreate,
    AbuseReportSubmit,
    AbuseReportAcknowledge,
    AbuseReportResolve,
    AbuseReportResponse,
    SLAStatisticsResponse,
)
from src.services.abuse_report_service import AbuseReportService
from src.services.email_service import EmailService
from src.services.report_template_engine import ReportTemplateEngine
from src.services.sla_manager import SLAManager

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/abuse-reports",
    tags=["Abuse Reports"],
)


@router.post(
    "/",
    response_model=AbuseReportResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create abuse report",
    description="Create a new abuse report draft from scan or manual URL",
)
async def create_abuse_report(
    report_data: AbuseReportCreate,
    db: AsyncSession = Depends(get_db),
    # TODO: Add authentication dependency
    # current_user: User = Depends(get_current_user),
) -> AbuseReportResponse:
    """Create a new abuse report.

    Args:
        report_data: Report creation data
        db: Database session
        # current_user: Current authenticated user

    Returns:
        Created AbuseReport

    Example:
        ```bash
        curl -X POST "http://localhost:8000/api/v1/abuse-reports/" \\
          -H "Content-Type: application/json" \\
          -d '{
            "url": "https://evil-site.com",
            "report_type": "phishing",
            "recipient_emails": ["abuse@registrar.com"],
            "cc_emails": ["team@company.com"]
          }'
        ```
    """
    try:
        # TODO: Replace with actual user from auth
        user_id = 1  # Temporary hardcoded user_id

        service = AbuseReportService(db)

        report = await service.create_from_scan(
            scan_id=report_data.scan_id,
            user_id=user_id,
            report_type=report_data.report_type,
            recipient_emails=report_data.recipient_emails,
            cc_emails=report_data.cc_emails,
            attachments=report_data.attachments,
            manual_submission=report_data.manual_submission,
        )

        logger.info(f"Created abuse report {report.id} for URL {report.url}")
        return AbuseReportResponse.model_validate(report)

    except ValueError as e:
        logger.warning(f"Invalid abuse report creation: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except Exception as e:
        logger.error(f"Error creating abuse report: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create abuse report",
        )


@router.post(
    "/{report_id}/submit",
    response_model=AbuseReportResponse,
    summary="Submit abuse report",
    description="Submit abuse report and start ICANN SLA clock",
)
async def submit_abuse_report(
    report_id: int,
    submit_data: AbuseReportSubmit,
    db: AsyncSession = Depends(get_db),
) -> AbuseReportResponse:
    """Submit an abuse report (starts SLA deadline).

    Args:
        report_id: Report ID to submit
        submit_data: Submission data (template choice or custom text)
        db: Database session

    Returns:
        Updated AbuseReport with SLA deadline set

    Example:
        ```bash
        curl -X POST "http://localhost:8000/api/v1/abuse-reports/123/submit" \\
          -H "Content-Type: application/json" \\
          -d '{"use_template": true}'
        ```
    """
    try:
        service = AbuseReportService(db)

        # Get report
        report = await service._get_report(report_id)
        if not report:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Report {report_id} not found",
            )

        # Generate email content
        if submit_data.use_template:
            # Use professional template
            template_engine = ReportTemplateEngine()

            # Get scan data if available
            scan = None
            if report.scan_id:
                scan = await service._get_scan(report.scan_id)

            email_content = template_engine.generate_phishing_report(
                url=report.url,
                virustotal_positives=scan.virustotal_result.get("positives") if scan and scan.virustotal_result else None,
                virustotal_total=scan.virustotal_result.get("total") if scan and scan.virustotal_result else None,
                urlvoid_blacklists=scan.urlvoid_result.get("blacklists") if scan and scan.urlvoid_result else None,
                urlvoid_engines=scan.urlvoid_result.get("engines") if scan and scan.urlvoid_result else None,
                confidence_score=float(scan.confidence_score) if scan and scan.confidence_score else None,
                threat_level=scan.threat_level if scan else None,
                screenshot_url=scan.screenshot_url if scan else None,
                whois_data=scan.whois_data if scan else None,
            )

            subject = email_content["subject"]
            body = email_content["body"]
        else:
            # Use custom subject/body
            subject = submit_data.custom_subject or f"Abuse Report - {report.url}"
            body = submit_data.custom_body or f"We are reporting abuse for {report.url}"

        # Submit report
        updated_report = await service.submit_report(
            report_id=report_id,
            subject=subject,
            body=body,
        )

        # Send email
        email_service = EmailService()
        email_success = await email_service.send_abuse_report(
            to_emails=report.recipient_email,
            subject=subject,
            body=body,
            cc_emails=None,  # TODO: Add from report_data
            attachments=report.attachments,
        )

        if not email_success:
            logger.warning(f"Email sending failed for report {report_id}")

        logger.info(
            f"Submitted abuse report {report_id} with SLA deadline "
            f"{updated_report.icann_sla_deadline.isoformat()}"
        )

        return AbuseReportResponse.model_validate(updated_report)

    except ValueError as e:
        logger.warning(f"Invalid report submission: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except Exception as e:
        logger.error(f"Error submitting abuse report: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to submit abuse report",
        )


@router.post(
    "/{report_id}/acknowledge",
    response_model=AbuseReportResponse,
    summary="Acknowledge abuse report",
    description="Mark report as acknowledged by recipient",
)
async def acknowledge_abuse_report(
    report_id: int,
    ack_data: AbuseReportAcknowledge,
    db: AsyncSession = Depends(get_db),
) -> AbuseReportResponse:
    """Acknowledge abuse report.

    Args:
        report_id: Report ID to acknowledge
        ack_data: Acknowledgement data
        db: Database session

    Returns:
        Updated AbuseReport

    Example:
        ```bash
        curl -X POST "http://localhost:8000/api/v1/abuse-reports/123/acknowledge" \\
          -H "Content-Type: application/json" \\
          -d '{"response_text": "We are investigating this issue"}'
        ```
    """
    try:
        service = AbuseReportService(db)

        updated_report = await service.acknowledge_report(
            report_id=report_id,
            response_text=ack_data.response_text,
        )

        logger.info(f"Acknowledged abuse report {report_id}")
        return AbuseReportResponse.model_validate(updated_report)

    except ValueError as e:
        logger.warning(f"Invalid report acknowledgement: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except Exception as e:
        logger.error(f"Error acknowledging abuse report: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to acknowledge abuse report",
        )


@router.post(
    "/{report_id}/resolve",
    response_model=AbuseReportResponse,
    summary="Resolve abuse report",
    description="Mark report as resolved",
)
async def resolve_abuse_report(
    report_id: int,
    resolve_data: AbuseReportResolve,
    db: AsyncSession = Depends(get_db),
) -> AbuseReportResponse:
    """Resolve abuse report.

    Args:
        report_id: Report ID to resolve
        resolve_data: Resolution data
        db: Database session

    Returns:
        Updated AbuseReport

    Example:
        ```bash
        curl -X POST "http://localhost:8000/api/v1/abuse-reports/123/resolve" \\
          -H "Content-Type: application/json" \\
          -d '{"response_text": "Site has been taken down"}'
        ```
    """
    try:
        service = AbuseReportService(db)

        updated_report = await service.resolve_report(
            report_id=report_id,
            response_text=resolve_data.response_text,
        )

        logger.info(f"Resolved abuse report {report_id}")
        return AbuseReportResponse.model_validate(updated_report)

    except ValueError as e:
        logger.warning(f"Invalid report resolution: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except Exception as e:
        logger.error(f"Error resolving abuse report: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to resolve abuse report",
        )


@router.get(
    "/{report_id}",
    response_model=AbuseReportResponse,
    summary="Get abuse report",
    description="Get abuse report by ID",
)
async def get_abuse_report(
    report_id: int,
    db: AsyncSession = Depends(get_db),
) -> AbuseReportResponse:
    """Get abuse report by ID.

    Args:
        report_id: Report ID
        db: Database session

    Returns:
        AbuseReport

    Example:
        ```bash
        curl "http://localhost:8000/api/v1/abuse-reports/123"
        ```
    """
    service = AbuseReportService(db)

    report = await service._get_report(report_id)
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report {report_id} not found",
        )

    return AbuseReportResponse.model_validate(report)


@router.get(
    "/",
    response_model=List[AbuseReportResponse],
    summary="Get user's abuse reports",
    description="Get all abuse reports for current user",
)
async def get_user_abuse_reports(
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
) -> List[AbuseReportResponse]:
    """Get user's abuse reports.

    Args:
        limit: Maximum reports to return
        offset: Pagination offset
        db: Database session

    Returns:
        List of AbuseReports

    Example:
        ```bash
        curl "http://localhost:8000/api/v1/abuse-reports/?limit=20&offset=0"
        ```
    """
    # TODO: Replace with actual user from auth
    user_id = 1

    service = AbuseReportService(db)
    reports = await service.get_user_reports(
        user_id=user_id,
        limit=limit,
        offset=offset,
    )

    return [AbuseReportResponse.model_validate(r) for r in reports]


@router.get(
    "/sla/statistics",
    response_model=SLAStatisticsResponse,
    summary="Get SLA statistics",
    description="Get ICANN SLA compliance statistics",
)
async def get_sla_statistics(
    db: AsyncSession = Depends(get_db),
) -> SLAStatisticsResponse:
    """Get SLA compliance statistics.

    Args:
        db: Database session

    Returns:
        SLA statistics

    Example:
        ```bash
        curl "http://localhost:8000/api/v1/abuse-reports/sla/statistics"
        ```
    """
    sla_manager = SLAManager(db)
    stats = await sla_manager.get_sla_statistics()

    return SLAStatisticsResponse(**stats)


@router.get(
    "/sla/overdue",
    response_model=List[AbuseReportResponse],
    summary="Get overdue reports",
    description="Get all overdue abuse reports",
)
async def get_overdue_reports(
    db: AsyncSession = Depends(get_db),
) -> List[AbuseReportResponse]:
    """Get overdue abuse reports.

    Args:
        db: Database session

    Returns:
        List of overdue AbuseReports

    Example:
        ```bash
        curl "http://localhost:8000/api/v1/abuse-reports/sla/overdue"
        ```
    """
    service = AbuseReportService(db)
    overdue_reports = await service.get_overdue_reports()

    return [AbuseReportResponse.model_validate(r) for r in overdue_reports]
