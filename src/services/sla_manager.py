"""SLA Tracker and Escalation Manager for ICANN compliance."""

import logging
import asyncio
from datetime import datetime, timedelta
from typing import List, Optional, Dict
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_

from src.models.abuse_report import AbuseReport
from src.services.abuse_report_service import AbuseReportService
from src.services.email_service import EmailService

logger = logging.getLogger(__name__)


class SLAManager:
    """Manages ICANN SLA compliance and automatic escalations.

    Features:
    - Continuous SLA monitoring (48-hour deadline)
    - Automatic escalation for overdue reports
    - Warning notifications (12 hours before deadline)
    - Multi-level escalation (Team → Manager → Executive)
    - Background daemon mode
    - Comprehensive logging

    Example:
        ```python
        async with get_db_session() as db:
            sla_manager = SLAManager(
                db=db,
                warning_hours=12,
                escalation_levels=[
                    ["team@company.com"],
                    ["manager@company.com"],
                    ["executive@company.com", "legal@company.com"]
                ]
            )

            # Run continuous monitoring
            await sla_manager.run_monitoring_loop(interval_minutes=15)
        ```
    """

    def __init__(
        self,
        db: AsyncSession,
        email_service: Optional[EmailService] = None,
        warning_hours: int = 12,
        escalation_levels: Optional[List[List[str]]] = None,
    ):
        """Initialize SLA manager.

        Args:
            db: Database session
            email_service: Email service instance (creates new if not provided)
            warning_hours: Hours before deadline to send warning
            escalation_levels: List of escalation email groups
                              [[level1], [level2], [level3]]
        """
        self.db = db
        self.report_service = AbuseReportService(db)
        self.email_service = email_service or EmailService()
        self.warning_hours = warning_hours
        self.escalation_levels = escalation_levels or [
            [],  # Level 1: No escalation
            [],  # Level 2: First escalation
            [],  # Level 3: Final escalation
        ]

    async def check_sla_compliance(self) -> Dict[str, List[AbuseReport]]:
        """Check SLA compliance for all active reports.

        Returns:
            Dict with categories:
            - "compliant": Reports within SLA
            - "approaching": Reports approaching deadline
            - "overdue": Reports past deadline

        Example:
            ```python
            status = await sla_manager.check_sla_compliance()
            print(f"Overdue: {len(status['overdue'])}")
            print(f"Approaching: {len(status['approaching'])}")
            ```
        """
        now = datetime.utcnow()
        warning_threshold = now + timedelta(hours=self.warning_hours)

        # Get all active reports
        stmt = select(AbuseReport).where(
            and_(
                AbuseReport.status.in_(["submitted", "acknowledged"]),
                AbuseReport.icann_sla_deadline.isnot(None),
            )
        )

        result = await self.db.execute(stmt)
        reports = list(result.scalars().all())

        # Categorize reports
        compliant = []
        approaching = []
        overdue = []

        for report in reports:
            if report.icann_sla_deadline < now:
                overdue.append(report)
            elif report.icann_sla_deadline <= warning_threshold:
                approaching.append(report)
            else:
                compliant.append(report)

        logger.info(
            f"SLA Check: {len(compliant)} compliant, "
            f"{len(approaching)} approaching, {len(overdue)} overdue"
        )

        return {
            "compliant": compliant,
            "approaching": approaching,
            "overdue": overdue,
        }

    async def send_sla_warnings(self) -> int:
        """Send warnings for reports approaching deadline.

        Returns:
            Number of warnings sent

        Example:
            ```python
            warnings_sent = await sla_manager.send_sla_warnings()
            print(f"Sent {warnings_sent} SLA warnings")
            ```
        """
        approaching = await self.report_service.get_approaching_deadline_reports()
        sent_count = 0

        for report in approaching:
            if report.sla_alert_sent:
                continue  # Already sent warning

            # Calculate hours remaining
            now = datetime.utcnow()
            time_remaining = (report.icann_sla_deadline - now).total_seconds() / 3600

            # Send warning email
            success = await self.email_service.send_sla_warning(
                to_emails=self.escalation_levels[0] if self.escalation_levels[0] else ["team@localhost"],
                report_id=report.id,
                url=report.url,
                deadline=report.icann_sla_deadline.isoformat(),
                hours_remaining=time_remaining,
            )

            if success:
                # Mark warning as sent
                report.sla_alert_sent = True
                await self.db.commit()
                sent_count += 1

                logger.info(
                    f"Sent SLA warning for report {report.id} "
                    f"({time_remaining:.1f}h remaining)"
                )

        return sent_count

    async def escalate_overdue_reports(self) -> int:
        """Escalate overdue reports through escalation levels.

        Returns:
            Number of reports escalated

        Example:
            ```python
            escalated = await sla_manager.escalate_overdue_reports()
            print(f"Escalated {escalated} overdue reports")
            ```
        """
        overdue = await self.report_service.get_overdue_reports()
        escalated_count = 0

        for report in overdue:
            # Calculate hours overdue
            now = datetime.utcnow()
            hours_overdue = (now - report.icann_sla_deadline).total_seconds() / 3600

            # Determine escalation level based on how overdue
            escalation_level = self._determine_escalation_level(hours_overdue)

            # Get escalation recipients
            recipients = self._get_escalation_recipients(escalation_level)
            if not recipients:
                logger.warning(f"No escalation recipients configured for level {escalation_level}")
                recipients = ["noreply@localhost"]  # Fallback

            # Send escalation alert
            success = await self.email_service.send_sla_overdue_alert(
                to_emails=recipients,
                report_id=report.id,
                url=report.url,
                hours_overdue=hours_overdue,
            )

            if success:
                escalated_count += 1
                logger.warning(
                    f"Escalated report {report.id} (level {escalation_level}, "
                    f"{hours_overdue:.1f}h overdue)"
                )

        return escalated_count

    async def run_monitoring_loop(
        self,
        interval_minutes: int = 15,
        max_iterations: Optional[int] = None,
    ) -> None:
        """Run continuous SLA monitoring loop.

        Args:
            interval_minutes: Check interval in minutes
            max_iterations: Optional max iterations (None = infinite)

        Example:
            ```python
            # Run forever (daemon mode)
            await sla_manager.run_monitoring_loop(interval_minutes=10)

            # Run for 24 hours (96 iterations at 15min intervals)
            await sla_manager.run_monitoring_loop(interval_minutes=15, max_iterations=96)
            ```
        """
        logger.info(
            f"Starting SLA monitoring loop (interval: {interval_minutes} minutes)"
        )

        iteration = 0
        while True:
            try:
                # Check SLA compliance
                status = await self.check_sla_compliance()

                # Send warnings for approaching deadlines
                warnings_sent = await self.send_sla_warnings()

                # Escalate overdue reports
                escalated = await self.escalate_overdue_reports()

                logger.info(
                    f"SLA Monitor Iteration {iteration + 1}: "
                    f"Warnings={warnings_sent}, Escalated={escalated}"
                )

                iteration += 1

                # Check if max iterations reached
                if max_iterations and iteration >= max_iterations:
                    logger.info(f"Reached max iterations ({max_iterations}), stopping")
                    break

                # Wait for next iteration
                await asyncio.sleep(interval_minutes * 60)

            except asyncio.CancelledError:
                logger.info("SLA monitoring loop cancelled")
                break
            except Exception as e:
                logger.error(f"Error in SLA monitoring loop: {e}")
                # Continue running despite errors
                await asyncio.sleep(interval_minutes * 60)

    def _determine_escalation_level(self, hours_overdue: float) -> int:
        """Determine escalation level based on hours overdue.

        Args:
            hours_overdue: Hours past deadline

        Returns:
            Escalation level (0, 1, 2)
        """
        if hours_overdue < 24:
            return 0  # Within first day overdue
        elif hours_overdue < 48:
            return 1  # 1-2 days overdue
        else:
            return 2  # 2+ days overdue (critical)

    def _get_escalation_recipients(self, level: int) -> List[str]:
        """Get email recipients for escalation level.

        Args:
            level: Escalation level (0, 1, 2)

        Returns:
            List of email addresses
        """
        if level >= len(self.escalation_levels):
            # Return highest level if exceeded
            return self.escalation_levels[-1]

        return self.escalation_levels[level]

    async def get_sla_statistics(self) -> Dict[str, any]:
        """Get SLA compliance statistics.

        Returns:
            Dict with statistics

        Example:
            ```python
            stats = await sla_manager.get_sla_statistics()
            print(f"Compliance rate: {stats['compliance_rate']}%")
            print(f"Average response time: {stats['avg_response_hours']}h")
            ```
        """
        status = await self.check_sla_compliance()

        total = len(status["compliant"]) + len(status["approaching"]) + len(status["overdue"])

        if total == 0:
            compliance_rate = 100.0
        else:
            compliant_count = len(status["compliant"]) + len(status["approaching"])
            compliance_rate = (compliant_count / total) * 100

        # Calculate average response time for resolved reports
        stmt = (
            select(AbuseReport)
            .where(AbuseReport.status == "resolved")
            .order_by(AbuseReport.resolved_at.desc())
            .limit(100)
        )

        result = await self.db.execute(stmt)
        resolved_reports = list(result.scalars().all())

        avg_response_hours = 0
        if resolved_reports:
            total_hours = 0
            count = 0
            for report in resolved_reports:
                if report.submitted_at and report.resolved_at:
                    hours = (report.resolved_at - report.submitted_at).total_seconds() / 3600
                    total_hours += hours
                    count += 1

            if count > 0:
                avg_response_hours = total_hours / count

        return {
            "total_active_reports": total,
            "compliant": len(status["compliant"]),
            "approaching_deadline": len(status["approaching"]),
            "overdue": len(status["overdue"]),
            "compliance_rate": round(compliance_rate, 2),
            "avg_response_hours": round(avg_response_hours, 2),
        }
