"""
Report tracking system for ICANN compliance
Tracks sent abuse reports and their responses
"""

import uuid
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from sqlalchemy import create_engine, text
from dataclasses import dataclass, asdict
from enum import Enum

logger = logging.getLogger(__name__)


class ReportStatus(Enum):
    """Status of abuse reports"""

    SENT = "sent"
    ACKNOWLEDGED = "acknowledged"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    REJECTED = "rejected"
    TIMEOUT = "timeout"
    BOUNCED = "bounced"


@dataclass
class AbuseReportRecord:
    """Data class for abuse report records"""

    site_url: str
    recipients: List[str]
    subject: str
    report_id: str
    status: str = ReportStatus.SENT.value
    cc_recipients: Optional[List[str]] = None
    response_received: bool = False
    response_date: Optional[datetime] = None
    response_content: Optional[str] = None
    sla_deadline: Optional[datetime] = None
    icann_compliant: bool = True
    screenshot_included: bool = False
    multi_api_results: Optional[Dict[str, Any]] = None
    confidence_score: Optional[int] = None
    threat_level: Optional[str] = None
    follow_up_required: bool = False
    report_date: datetime = None
    created_at: datetime = None
    updated_at: datetime = None

    def __post_init__(self):
        if self.report_date is None:
            self.report_date = datetime.now()
        if self.created_at is None:
            self.created_at = datetime.now()
        if self.updated_at is None:
            self.updated_at = datetime.now()
        if self.sla_deadline is None:
            # ICANN requires 2 business day response time
            self.sla_deadline = self._calculate_sla_deadline()

    def _calculate_sla_deadline(self) -> datetime:
        """Calculate SLA deadline (2 business days from report date)"""
        current = self.report_date or datetime.now()
        days_added = 0

        while days_added < 2:
            current += timedelta(days=1)
            # Skip weekends (Monday = 0, Sunday = 6)
            if current.weekday() < 5:  # Monday to Friday
                days_added += 1

        # Set deadline to end of business day (5 PM)
        return current.replace(hour=17, minute=0, second=0, microsecond=0)


class ReportTracker:
    """Tracks abuse reports for ICANN compliance - integrates with existing phishing_sites fields"""

    def __init__(self, db_engine):
        """
        Initialize report tracker

        Args:
            db_engine: SQLAlchemy database engine
        """
        self.db_engine = db_engine
        if db_engine is not None:  # Only ensure table exists if we have a valid engine
            self._ensure_table_exists()

    def _ensure_table_exists(self):
        """Ensure the abuse_reports table exists"""
        if self.db_engine is None:
            logger.warning("Database engine not initialized, skipping table creation")
            return
        try:
            with self.db_engine.begin() as conn:
                conn.execute(
                    text(
                        """
                        CREATE TABLE IF NOT EXISTS abuse_reports (
                            id SERIAL PRIMARY KEY,
                            site_url TEXT NOT NULL,
                            report_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            recipients TEXT NOT NULL,
                            cc_recipients TEXT,
                            subject TEXT,
                            report_id TEXT UNIQUE,
                            status TEXT DEFAULT 'sent',
                            response_received INTEGER DEFAULT 0,
                            response_date TIMESTAMP,
                            response_content TEXT,
                            sla_deadline TIMESTAMP,
                            icann_compliant INTEGER DEFAULT 1,
                            screenshot_included INTEGER DEFAULT 0,
                            multi_api_results TEXT,
                            confidence_score INTEGER,
                            threat_level TEXT,
                            follow_up_required INTEGER DEFAULT 0,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        )
                    """
                    )
                )
                logger.debug("Verified abuse_reports table exists")
        except Exception as e:
            logger.error(f"Error ensuring abuse_reports table exists: {e}")

    def generate_report_id(self) -> str:
        """Generate unique report ID"""
        return f"ANISAKYS-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:8].upper()}"

    def track_report(self, report: AbuseReportRecord) -> bool:
        """
        Track a new abuse report and update phishing_sites table

        Args:
            report: AbuseReportRecord to track

        Returns:
            True if successfully tracked
        """
        try:
            with self.db_engine.begin() as conn:
                # Insert into abuse_reports table
                conn.execute(
                    text(
                        """
                        INSERT INTO abuse_reports (
                            site_url, report_date, recipients, cc_recipients, subject,
                            report_id, status, sla_deadline, icann_compliant,
                            screenshot_included, multi_api_results, confidence_score,
                            threat_level, follow_up_required, created_at, updated_at
                        ) VALUES (
                            :site_url, :report_date, :recipients, :cc_recipients, :subject,
                            :report_id, :status, :sla_deadline, :icann_compliant,
                            :screenshot_included, :multi_api_results, :confidence_score,
                            :threat_level, :follow_up_required, :created_at, :updated_at
                        )
                    """
                    ),
                    {
                        "site_url": report.site_url,
                        "report_date": report.report_date,
                        "recipients": (
                            json.dumps(report.recipients)
                            if isinstance(report.recipients, list)
                            else report.recipients
                        ),
                        "cc_recipients": (
                            json.dumps(report.cc_recipients) if report.cc_recipients else None
                        ),
                        "subject": report.subject,
                        "report_id": report.report_id,
                        "status": report.status,
                        "sla_deadline": report.sla_deadline,
                        "icann_compliant": 1 if report.icann_compliant else 0,
                        "screenshot_included": 1 if report.screenshot_included else 0,
                        "multi_api_results": (
                            json.dumps(report.multi_api_results)
                            if report.multi_api_results
                            else None
                        ),
                        "confidence_score": report.confidence_score,
                        "threat_level": report.threat_level,
                        "follow_up_required": 1 if report.follow_up_required else 0,
                        "created_at": report.created_at,
                        "updated_at": report.updated_at,
                    },
                )

                # Update existing phishing_sites table fields
                conn.execute(
                    text(
                        """
                        UPDATE phishing_sites
                        SET abuse_report_sent = 1,
                            reported = 1,
                            last_report_sent = :report_date,
                            abuse_email = :abuse_email
                        WHERE url = :site_url
                    """
                    ),
                    {
                        "site_url": report.site_url,
                        "report_date": report.report_date,
                        "abuse_email": report.recipients[0] if report.recipients else None,
                    },
                )

                logger.info(f"✅ Tracked abuse report: {report.report_id} for {report.site_url}")
                return True

        except Exception as e:
            logger.error(f"❌ Failed to track abuse report: {e}")
            return False

    def update_report_status(
        self,
        report_id: str,
        status: ReportStatus,
        response_content: str = None,
        follow_up_required: bool = False,
    ) -> bool:
        """
        Update status of an existing report

        Args:
            report_id: Report ID to update
            status: New status
            response_content: Response content if any
            follow_up_required: Whether follow-up is needed

        Returns:
            True if successfully updated
        """
        try:
            with self.db_engine.begin() as conn:
                update_data = {
                    "report_id": report_id,
                    "status": status.value,
                    "updated_at": datetime.now(),
                    "follow_up_required": 1 if follow_up_required else 0,
                }

                # Add response data if provided
                if response_content:
                    update_data.update(
                        {
                            "response_received": 1,
                            "response_date": datetime.now(),
                            "response_content": response_content,
                        }
                    )

                query = """
                    UPDATE abuse_reports
                    SET status = :status, updated_at = :updated_at,
                        follow_up_required = :follow_up_required
                """

                if response_content:
                    query += """
                        , response_received = :response_received,
                          response_date = :response_date,
                          response_content = :response_content
                    """

                query += " WHERE report_id = :report_id"

                result = conn.execute(text(query), update_data)

                if result.rowcount > 0:
                    logger.info(f"✅ Updated report {report_id} status to {status.value}")
                    return True
                else:
                    logger.warning(f"⚠️  Report {report_id} not found for status update")
                    return False

        except Exception as e:
            logger.error(f"❌ Failed to update report status: {e}")
            return False

    def get_report(self, report_id: str) -> Optional[Dict[str, Any]]:
        """
        Get report by ID

        Args:
            report_id: Report ID to retrieve

        Returns:
            Report data dict or None if not found
        """
        try:
            with self.db_engine.connect() as conn:
                result = conn.execute(
                    text("SELECT * FROM abuse_reports WHERE report_id = :report_id"),
                    {"report_id": report_id},
                ).fetchone()

                if result:
                    # Convert to dict and parse JSON fields
                    report_dict = dict(result._mapping)

                    # Parse JSON fields
                    if report_dict.get("recipients"):
                        try:
                            report_dict["recipients"] = json.loads(report_dict["recipients"])
                        except (json.JSONDecodeError, TypeError):
                            pass  # Keep as string if not valid JSON

                    if report_dict.get("cc_recipients"):
                        try:
                            report_dict["cc_recipients"] = json.loads(report_dict["cc_recipients"])
                        except (json.JSONDecodeError, TypeError):
                            pass

                    if report_dict.get("multi_api_results"):
                        try:
                            report_dict["multi_api_results"] = json.loads(
                                report_dict["multi_api_results"]
                            )
                        except (json.JSONDecodeError, TypeError):
                            pass

                    # Convert integer flags to boolean
                    for bool_field in [
                        "response_received",
                        "icann_compliant",
                        "screenshot_included",
                        "follow_up_required",
                    ]:
                        if bool_field in report_dict:
                            report_dict[bool_field] = bool(report_dict[bool_field])

                    return report_dict

                return None

        except Exception as e:
            logger.error(f"❌ Failed to get report {report_id}: {e}")
            return None

    def get_reports_by_site(self, site_url: str) -> List[Dict[str, Any]]:
        """
        Get all reports for a specific site

        Args:
            site_url: Site URL to search for

        Returns:
            List of report dicts
        """
        try:
            with self.db_engine.connect() as conn:
                result = conn.execute(
                    text(
                        "SELECT * FROM abuse_reports WHERE site_url = :site_url ORDER BY report_date DESC"
                    ),
                    {"site_url": site_url},
                ).fetchall()

                reports = []
                for row in result:
                    report_dict = dict(row._mapping)

                    # Parse JSON fields (same as get_report)
                    if report_dict.get("recipients"):
                        try:
                            report_dict["recipients"] = json.loads(report_dict["recipients"])
                        except (json.JSONDecodeError, TypeError):
                            pass

                    if report_dict.get("cc_recipients"):
                        try:
                            report_dict["cc_recipients"] = json.loads(report_dict["cc_recipients"])
                        except (json.JSONDecodeError, TypeError):
                            pass

                    if report_dict.get("multi_api_results"):
                        try:
                            report_dict["multi_api_results"] = json.loads(
                                report_dict["multi_api_results"]
                            )
                        except (json.JSONDecodeError, TypeError):
                            pass

                    # Convert integer flags to boolean
                    for bool_field in [
                        "response_received",
                        "icann_compliant",
                        "screenshot_included",
                        "follow_up_required",
                    ]:
                        if bool_field in report_dict:
                            report_dict[bool_field] = bool(report_dict[bool_field])

                    reports.append(report_dict)

                return reports

        except Exception as e:
            logger.error(f"❌ Failed to get reports for site {site_url}: {e}")
            return []

    def get_overdue_reports(self) -> List[Dict[str, Any]]:
        """
        Get reports that are past their SLA deadline

        Returns:
            List of overdue report dicts
        """
        try:
            with self.db_engine.connect() as conn:
                result = conn.execute(
                    text(
                        """
                        SELECT * FROM abuse_reports
                        WHERE sla_deadline < CURRENT_TIMESTAMP
                        AND status NOT IN ('resolved', 'rejected', 'timeout')
                        AND response_received = 0
                        ORDER BY sla_deadline ASC
                    """
                    )
                ).fetchall()

                overdue_reports = []
                for row in result:
                    report_dict = dict(row._mapping)

                    # Calculate how overdue
                    if report_dict.get("sla_deadline"):
                        overdue_hours = (
                            datetime.now() - report_dict["sla_deadline"]
                        ).total_seconds() / 3600
                        report_dict["overdue_hours"] = round(overdue_hours, 2)

                    overdue_reports.append(report_dict)

                return overdue_reports

        except Exception as e:
            logger.error(f"❌ Failed to get overdue reports: {e}")
            return []

    def get_reports_needing_followup(self) -> List[Dict[str, Any]]:
        """
        Get reports that need follow-up

        Returns:
            List of reports needing follow-up
        """
        try:
            with self.db_engine.connect() as conn:
                result = conn.execute(
                    text(
                        """
                        SELECT * FROM abuse_reports
                        WHERE follow_up_required = 1
                        AND status NOT IN ('resolved', 'rejected')
                        ORDER BY updated_at ASC
                    """
                    )
                ).fetchall()

                return [dict(row._mapping) for row in result]

        except Exception as e:
            logger.error(f"❌ Failed to get reports needing follow-up: {e}")
            return []

    def mark_report_for_followup(self, report_id: str, reason: str = None) -> bool:
        """
        Mark a report as needing follow-up

        Args:
            report_id: Report ID to mark
            reason: Optional reason for follow-up

        Returns:
            True if successfully marked
        """
        try:
            with self.db_engine.begin() as conn:
                update_data = {
                    "report_id": report_id,
                    "follow_up_required": 1,
                    "updated_at": datetime.now(),
                }

                # Add reason to response_content if provided
                if reason:
                    update_data["response_content"] = f"Follow-up required: {reason}"

                query = """
                    UPDATE abuse_reports
                    SET follow_up_required = :follow_up_required, updated_at = :updated_at
                """

                if reason:
                    query += ", response_content = :response_content"

                query += " WHERE report_id = :report_id"

                result = conn.execute(text(query), update_data)

                if result.rowcount > 0:
                    logger.info(f"✅ Marked report {report_id} for follow-up")
                    return True
                else:
                    logger.warning(f"⚠️  Report {report_id} not found for follow-up marking")
                    return False

        except Exception as e:
            logger.error(f"❌ Failed to mark report for follow-up: {e}")
            return False

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get report statistics

        Returns:
            Dict with various statistics
        """
        try:
            with self.db_engine.connect() as conn:
                # Total reports
                total_reports = conn.execute(text("SELECT COUNT(*) FROM abuse_reports")).scalar()

                # Reports by status
                status_counts = conn.execute(
                    text("SELECT status, COUNT(*) FROM abuse_reports GROUP BY status")
                ).fetchall()

                # Response rate
                responded_reports = conn.execute(
                    text("SELECT COUNT(*) FROM abuse_reports WHERE response_received = 1")
                ).scalar()

                # Overdue reports
                overdue_count = conn.execute(
                    text(
                        """
                        SELECT COUNT(*) FROM abuse_reports
                        WHERE sla_deadline < CURRENT_TIMESTAMP
                        AND status NOT IN ('resolved', 'rejected', 'timeout')
                        AND response_received = 0
                    """
                    )
                ).scalar()

                # Average response time (for reports that got responses)
                avg_response_time = conn.execute(
                    text(
                        """
                        SELECT AVG(EXTRACT(EPOCH FROM (response_date - report_date))/3600) as avg_hours
                        FROM abuse_reports
                        WHERE response_received = 1 AND response_date IS NOT NULL
                    """
                    )
                ).scalar()

                return {
                    "total_reports": total_reports or 0,
                    "status_breakdown": {status: count for status, count in status_counts},
                    "response_rate": (
                        round((responded_reports / total_reports * 100), 2)
                        if total_reports > 0
                        else 0
                    ),
                    "overdue_reports": overdue_count or 0,
                    "avg_response_time_hours": (
                        round(avg_response_time, 2) if avg_response_time else None
                    ),
                    "generated_at": datetime.now().isoformat(),
                }

        except Exception as e:
            logger.error(f"❌ Failed to get statistics: {e}")
            return {"error": str(e)}


# Convenience functions
def create_report_record(
    site_url: str,
    recipients: List[str],
    subject: str,
    cc_recipients: List[str] = None,
    multi_api_results: Dict = None,
    screenshot_included: bool = False,
) -> AbuseReportRecord:
    """
    Create a new AbuseReportRecord

    Args:
        site_url: URL being reported
        recipients: List of abuse email recipients
        subject: Email subject
        cc_recipients: Optional CC recipients
        multi_api_results: Optional API scan results
        screenshot_included: Whether screenshot was included

    Returns:
        AbuseReportRecord instance
    """
    tracker = ReportTracker(None)  # We'll set engine when tracking
    report_id = tracker.generate_report_id()

    confidence_score = None
    threat_level = None

    if multi_api_results:
        confidence_score = multi_api_results.get("confidence_score")
        threat_level = multi_api_results.get("threat_level")

    return AbuseReportRecord(
        site_url=site_url,
        recipients=recipients,
        subject=subject,
        report_id=report_id,
        cc_recipients=cc_recipients,
        multi_api_results=multi_api_results,
        confidence_score=confidence_score,
        threat_level=threat_level,
        screenshot_included=screenshot_included,
        icann_compliant=True,  # Assume compliant by default
    )


if __name__ == "__main__":
    # Test the report tracker
    from sqlalchemy import create_engine

    # Create test database engine (you'd use your actual DATABASE_URL)
    engine = create_engine("sqlite:///test_reports.db")
    tracker = ReportTracker(engine)

    # Create test report
    report = create_report_record(
        site_url="https://phishing-test.com",
        recipients=["abuse@registrar.com"],
        subject="Phishing Report: phishing-test.com",
        cc_recipients=["security@test.com"],
        screenshot_included=True,
    )

    # Track the report
    if tracker.track_report(report):
        print(f"✅ Tracked report: {report.report_id}")

        # Test retrieving the report
        retrieved = tracker.get_report(report.report_id)
        if retrieved:
            print(f"✅ Retrieved report: {retrieved['report_id']}")

        # Test statistics
        stats = tracker.get_statistics()
        print(f"📊 Statistics: {json.dumps(stats, indent=2)}")
    else:
        print("❌ Failed to track report")
