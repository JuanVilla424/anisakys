"""Abuse Report Service for ICANN-compliant phishing reporting."""

import logging
from datetime import datetime, timedelta
from typing import Optional, List, Dict
from decimal import Decimal
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_

from src.models.abuse_report import AbuseReport
from src.models.scan import Scan
from src.models.user import User

logger = logging.getLogger(__name__)


class AbuseReportService:
    """Service for creating and managing ICANN-compliant abuse reports.

    Features:
    - Automatic ICANN SLA deadline calculation (48 hours)
    - Report generation from scan results
    - Status tracking (draft → submitted → acknowledged → resolved)
    - Response management
    - SLA compliance monitoring

    Example:
        ```python
        async with get_db_session() as db:
            service = AbuseReportService(db)
            report = await service.create_from_scan(
                scan_id=123,
                user_id=1,
                report_type="phishing",
                recipient_emails=["abuse@registrar.com"],
                cc_emails=["soc@company.com"]
            )
            print(f"Report created with SLA deadline: {report.icann_sla_deadline}")
        ```
    """

    # ICANN SLA: 48 hours from submission
    ICANN_SLA_HOURS = 48

    # SLA warning threshold (hours before deadline)
    SLA_WARNING_HOURS = 12

    def __init__(self, db: AsyncSession):
        """Initialize abuse report service.

        Args:
            db: Database session
        """
        self.db = db

    async def create_from_scan(
        self,
        scan_id: int,
        user_id: int,
        report_type: str,
        recipient_emails: List[str],
        cc_emails: Optional[List[str]] = None,
        attachments: Optional[List[str]] = None,
        manual_submission: bool = False,
    ) -> AbuseReport:
        """Create abuse report from a scan result.

        Args:
            scan_id: ID of the scan to report
            user_id: ID of user creating the report
            report_type: Type of report (phishing, malware, spam, copyright, other)
            recipient_emails: List of abuse contact emails
            cc_emails: Optional CC recipients
            attachments: Optional paths to attachments
            manual_submission: Whether this is manual (vs automatic)

        Returns:
            Created AbuseReport object

        Raises:
            ValueError: If scan not found or invalid data

        Example:
            ```python
            report = await service.create_from_scan(
                scan_id=456,
                user_id=10,
                report_type="phishing",
                recipient_emails=["abuse@evil-domain.com"],
                cc_emails=["team@company.com"],
                manual_submission=True
            )
            ```
        """
        # Validate scan exists
        scan = await self._get_scan(scan_id)
        if not scan:
            raise ValueError(f"Scan {scan_id} not found")

        # Create report
        report = AbuseReport(
            scan_id=scan_id,
            user_id=user_id,
            url=scan.url,
            report_type=report_type,
            recipient_email=recipient_emails,
            attachments=attachments or [],
            manual_submission=manual_submission,
            status="draft",
            created_by=user_id,
        )

        # Save draft
        self.db.add(report)
        await self.db.commit()
        await self.db.refresh(report)

        logger.info(f"Created abuse report {report.id} for scan {scan_id}")
        return report

    async def submit_report(
        self,
        report_id: int,
        subject: str,
        body: str,
    ) -> AbuseReport:
        """Submit an abuse report (sets SLA deadline).

        Args:
            report_id: ID of report to submit
            subject: Email subject line
            body: Email body content

        Returns:
            Updated AbuseReport

        Raises:
            ValueError: If report not found or already submitted

        Example:
            ```python
            report = await service.submit_report(
                report_id=789,
                subject="Phishing Site Report - urgent-bank-login.com",
                body="We detected a phishing site impersonating..."
            )
            print(f"SLA deadline: {report.icann_sla_deadline}")
            ```
        """
        # Get report
        report = await self._get_report(report_id)
        if not report:
            raise ValueError(f"Report {report_id} not found")

        if report.status != "draft":
            raise ValueError(f"Report {report_id} already submitted (status: {report.status})")

        # Calculate ICANN SLA deadline (48 hours from now)
        now = datetime.utcnow()
        sla_deadline = now + timedelta(hours=self.ICANN_SLA_HOURS)

        # Update report
        report.subject = subject
        report.body = body
        report.status = "submitted"
        report.submitted_at = now
        report.icann_sla_deadline = sla_deadline
        report.icann_sla_status = "compliant"  # Initially compliant
        report.sla_alert_sent = False

        await self.db.commit()
        await self.db.refresh(report)

        logger.info(
            f"Submitted report {report_id} with SLA deadline {sla_deadline.isoformat()}"
        )
        return report

    async def acknowledge_report(
        self,
        report_id: int,
        response_text: Optional[str] = None,
    ) -> AbuseReport:
        """Mark report as acknowledged by recipient.

        Args:
            report_id: ID of report to acknowledge
            response_text: Optional response from recipient

        Returns:
            Updated AbuseReport

        Example:
            ```python
            report = await service.acknowledge_report(
                report_id=789,
                response_text="Thank you for your report. We are investigating."
            )
            ```
        """
        report = await self._get_report(report_id)
        if not report:
            raise ValueError(f"Report {report_id} not found")

        report.status = "acknowledged"
        report.acknowledged_at = datetime.utcnow()

        if response_text:
            report.response_received = True
            report.response_text = response_text
            report.response_received_at = datetime.utcnow()

        await self.db.commit()
        await self.db.refresh(report)

        logger.info(f"Acknowledged report {report_id}")
        return report

    async def resolve_report(
        self,
        report_id: int,
        response_text: Optional[str] = None,
    ) -> AbuseReport:
        """Mark report as resolved.

        Args:
            report_id: ID of report to resolve
            response_text: Optional final response

        Returns:
            Updated AbuseReport

        Example:
            ```python
            report = await service.resolve_report(
                report_id=789,
                response_text="Site has been taken down. Thank you."
            )
            ```
        """
        report = await self._get_report(report_id)
        if not report:
            raise ValueError(f"Report {report_id} not found")

        report.status = "resolved"
        report.resolved_at = datetime.utcnow()

        if response_text:
            report.response_received = True
            report.response_text = response_text
            report.response_received_at = datetime.utcnow()

        await self.db.commit()
        await self.db.refresh(report)

        logger.info(f"Resolved report {report_id}")
        return report

    async def update_sla_status(self, report_id: int) -> AbuseReport:
        """Update SLA status based on current time.

        Args:
            report_id: ID of report to update

        Returns:
            Updated AbuseReport

        Example:
            ```python
            report = await service.update_sla_status(789)
            if report.icann_sla_status == "overdue":
                # Trigger escalation
                await escalation_manager.escalate(report)
            ```
        """
        report = await self._get_report(report_id)
        if not report:
            raise ValueError(f"Report {report_id} not found")

        # Only update if not resolved/rejected
        if report.status in ["resolved", "rejected"]:
            return report

        if not report.icann_sla_deadline:
            # Not submitted yet
            return report

        now = datetime.utcnow()
        deadline = report.icann_sla_deadline
        time_remaining = (deadline - now).total_seconds() / 3600  # hours

        # Update SLA status
        if now > deadline:
            report.icann_sla_status = "overdue"
        elif time_remaining <= self.SLA_WARNING_HOURS:
            report.icann_sla_status = "approaching"
        else:
            report.icann_sla_status = "compliant"

        await self.db.commit()
        await self.db.refresh(report)

        return report

    async def get_overdue_reports(self) -> List[AbuseReport]:
        """Get all overdue reports.

        Returns:
            List of overdue AbuseReport objects

        Example:
            ```python
            overdue = await service.get_overdue_reports()
            for report in overdue:
                print(f"Report {report.id} overdue by {hours} hours")
            ```
        """
        now = datetime.utcnow()

        stmt = (
            select(AbuseReport)
            .where(
                and_(
                    AbuseReport.status.in_(["submitted", "acknowledged"]),
                    AbuseReport.icann_sla_deadline < now,
                )
            )
            .order_by(AbuseReport.icann_sla_deadline.asc())
        )

        result = await self.db.execute(stmt)
        reports = list(result.scalars().all())

        logger.info(f"Found {len(reports)} overdue reports")
        return reports

    async def get_approaching_deadline_reports(self) -> List[AbuseReport]:
        """Get reports approaching deadline (within warning threshold).

        Returns:
            List of AbuseReport objects approaching deadline

        Example:
            ```python
            approaching = await service.get_approaching_deadline_reports()
            for report in approaching:
                # Send warning notification
                await notification_service.send_sla_warning(report)
            ```
        """
        now = datetime.utcnow()
        warning_threshold = now + timedelta(hours=self.SLA_WARNING_HOURS)

        stmt = (
            select(AbuseReport)
            .where(
                and_(
                    AbuseReport.status.in_(["submitted", "acknowledged"]),
                    AbuseReport.icann_sla_deadline <= warning_threshold,
                    AbuseReport.icann_sla_deadline > now,
                    AbuseReport.sla_alert_sent == False,
                )
            )
            .order_by(AbuseReport.icann_sla_deadline.asc())
        )

        result = await self.db.execute(stmt)
        reports = list(result.scalars().all())

        logger.info(f"Found {len(reports)} reports approaching deadline")
        return reports

    async def get_user_reports(
        self,
        user_id: int,
        limit: int = 50,
        offset: int = 0,
    ) -> List[AbuseReport]:
        """Get user's abuse reports.

        Args:
            user_id: User ID
            limit: Maximum reports to return
            offset: Pagination offset

        Returns:
            List of AbuseReport objects

        Example:
            ```python
            reports = await service.get_user_reports(user_id=10, limit=20)
            for report in reports:
                print(f"{report.url} - Status: {report.status}")
            ```
        """
        stmt = (
            select(AbuseReport)
            .where(AbuseReport.user_id == user_id)
            .order_by(AbuseReport.created_at.desc())
            .limit(limit)
            .offset(offset)
        )

        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    async def _get_report(self, report_id: int) -> Optional[AbuseReport]:
        """Get report by ID.

        Args:
            report_id: Report ID

        Returns:
            AbuseReport or None
        """
        stmt = select(AbuseReport).where(AbuseReport.id == report_id)
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    async def _get_scan(self, scan_id: int) -> Optional[Scan]:
        """Get scan by ID.

        Args:
            scan_id: Scan ID

        Returns:
            Scan or None
        """
        stmt = select(Scan).where(Scan.id == scan_id)
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()
