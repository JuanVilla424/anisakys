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
        """Ensure the abuse_reports table exists and is up to date"""
        if self.db_engine is None:
            logger.warning("Database engine not initialized, skipping table creation")
            return
        try:
            with self.db_engine.begin() as conn:
                # Check if table exists and verify schema
                table_exists = conn.execute(
                    text(
                        "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'abuse_reports')"
                    )
                ).scalar()

                if table_exists:
                    # Verify schema matches expected structure
                    if not self._verify_table_schema(conn):
                        logger.warning("Table schema mismatch detected, attempting to migrate...")
                        self._migrate_table_schema(conn)
                    else:
                        # Add missing columns if they don't exist
                        self._add_missing_columns(conn)
                else:
                    # Create table from scratch
                    conn.execute(
                        text(
                            """
                            CREATE TABLE abuse_reports (
                                id SERIAL PRIMARY KEY,
                                site_url TEXT NOT NULL,
                                site_id INTEGER,
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
                                screenshot_path TEXT,
                                attachment_count INTEGER DEFAULT 0,
                                follow_up_required INTEGER DEFAULT 0,
                                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                FOREIGN KEY (site_id) REFERENCES phishing_sites(id)
                            )
                        """
                        )
                    )
                    logger.info("Created abuse_reports table")
        except Exception as e:
            logger.error(f"Error ensuring abuse_reports table exists: {e}")
            # Try to create a minimal working table
            try:
                self._create_minimal_table()
            except Exception as e2:
                logger.error(f"Failed to create minimal table: {e2}")

    def _verify_table_schema(self, conn) -> bool:
        """Verify if the table schema matches expected structure"""
        try:
            # Get current table columns and their types
            result = conn.execute(
                text(
                    """
                    SELECT column_name, data_type, is_nullable, column_default
                    FROM information_schema.columns
                    WHERE table_name = 'abuse_reports'
                    ORDER BY ordinal_position
                    """
                )
            ).fetchall()

            current_columns = {
                row[0]: {"type": row[1], "nullable": row[2], "default": row[3]} for row in result
            }

            # Define expected schema
            expected_columns = {
                "id": {"type": "integer", "nullable": "NO"},
                "site_url": {"type": "text", "nullable": "NO"},
                "recipients": {"type": "text", "nullable": "NO"},
                "status": {"type": "text", "nullable": "YES"},
                "report_id": {"type": "text", "nullable": "YES"},
            }

            # Check if critical columns exist with correct types
            for col, props in expected_columns.items():
                if col not in current_columns:
                    logger.warning(f"Missing critical column: {col}")
                    return False
                if current_columns[col]["type"] != props["type"]:
                    logger.warning(
                        f"Column {col} has wrong type: {current_columns[col]['type']} != {props['type']}"
                    )
                    return False

            return True
        except Exception as e:
            logger.error(f"Error verifying table schema: {e}")
            return False

    def _migrate_table_schema(self, conn):
        """Migrate table to correct schema preserving data"""
        try:
            logger.info("Starting table migration...")

            # Create backup
            conn.execute(text("ALTER TABLE abuse_reports RENAME TO abuse_reports_backup"))

            # Create new table with correct schema
            conn.execute(
                text(
                    """
                    CREATE TABLE abuse_reports (
                        id SERIAL PRIMARY KEY,
                        site_url TEXT NOT NULL,
                        site_id INTEGER,
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
                        screenshot_path TEXT,
                        attachment_count INTEGER DEFAULT 0,
                        follow_up_required INTEGER DEFAULT 0,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (site_id) REFERENCES phishing_sites(id)
                    )
                """
                )
            )

            # Copy data from backup
            conn.execute(
                text(
                    """
                    INSERT INTO abuse_reports (site_url, recipients, status, report_id)
                    SELECT site_url, recipients, COALESCE(status, 'sent'), report_id
                    FROM abuse_reports_backup
                    WHERE site_url IS NOT NULL AND recipients IS NOT NULL
                    """
                )
            )

            # Drop backup
            conn.execute(text("DROP TABLE abuse_reports_backup"))
            logger.info("Table migration completed successfully")

        except Exception as e:
            logger.error(f"Error during table migration: {e}")
            # Try to restore backup if exists
            try:
                conn.execute(text("DROP TABLE IF EXISTS abuse_reports"))
                conn.execute(text("ALTER TABLE abuse_reports_backup RENAME TO abuse_reports"))
                logger.info("Restored backup table")
            except:
                pass
            raise

    def _create_minimal_table(self):
        """Create a minimal working table as fallback"""
        try:
            with self.db_engine.begin() as conn:
                # Drop existing table if corrupted
                conn.execute(text("DROP TABLE IF EXISTS abuse_reports CASCADE"))

                # Create minimal table
                conn.execute(
                    text(
                        """
                        CREATE TABLE abuse_reports (
                            id SERIAL PRIMARY KEY,
                            site_url TEXT NOT NULL,
                            recipients TEXT NOT NULL,
                            report_id TEXT,
                            status TEXT DEFAULT 'sent',
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        )
                    """
                    )
                )
                logger.info("Created minimal abuse_reports table")
        except Exception as e:
            logger.error(f"Failed to create minimal table: {e}")

    def _add_missing_columns(self, conn):
        """Add missing columns to existing abuse_reports table"""
        try:
            # Get current columns
            result = conn.execute(
                text(
                    "SELECT column_name FROM information_schema.columns WHERE table_name = 'abuse_reports'"
                )
            ).fetchall()
            current_columns = {row[0] for row in result}

            # Define columns to add if missing
            columns_to_add = [
                ("site_id", "INTEGER"),
                ("report_date", "TIMESTAMP DEFAULT CURRENT_TIMESTAMP"),
                ("cc_recipients", "TEXT"),
                ("subject", "TEXT"),
                ("response_received", "INTEGER DEFAULT 0"),
                ("response_date", "TIMESTAMP"),
                ("response_content", "TEXT"),
                ("sla_deadline", "TIMESTAMP"),
                ("icann_compliant", "INTEGER DEFAULT 1"),
                ("screenshot_included", "INTEGER DEFAULT 0"),
                ("screenshot_path", "TEXT"),
                ("attachment_count", "INTEGER DEFAULT 0"),
                ("follow_up_required", "INTEGER DEFAULT 0"),
                ("created_at", "TIMESTAMP DEFAULT CURRENT_TIMESTAMP"),
                ("updated_at", "TIMESTAMP DEFAULT CURRENT_TIMESTAMP"),
            ]

            for col_name, col_type in columns_to_add:
                if col_name not in current_columns:
                    try:
                        logger.info(f"Adding column {col_name} to abuse_reports table...")
                        conn.execute(
                            text(f"ALTER TABLE abuse_reports ADD COLUMN {col_name} {col_type}")
                        )
                    except Exception as e:
                        logger.warning(f"Could not add column {col_name}: {e}")

        except Exception as e:
            logger.warning(f"Error adding missing columns: {e}")

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
            # Use separate transactions to avoid blocking
            with self.db_engine.connect() as conn:
                # Get site_id from phishing_sites table
                site_result = conn.execute(
                    text("SELECT id FROM phishing_sites WHERE url = :site_url"),
                    {"site_url": report.site_url},
                ).fetchone()

                site_id = site_result[0] if site_result else None

                # Insert into abuse_reports table
                conn.execute(
                    text(
                        """
                        INSERT INTO abuse_reports (
                            site_url, site_id, report_date, recipients, cc_recipients, subject,
                            report_id, status, sla_deadline, icann_compliant,
                            screenshot_included, screenshot_path, attachment_count,
                            follow_up_required, created_at, updated_at
                        ) VALUES (
                            :site_url, :site_id, :report_date, :recipients, :cc_recipients, :subject,
                            :report_id, :status, :sla_deadline, :icann_compliant,
                            :screenshot_included, :screenshot_path, :attachment_count,
                            :follow_up_required, :created_at, :updated_at
                        )
                    """
                    ),
                    {
                        "site_url": report.site_url,
                        "site_id": site_id,
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
                        "screenshot_path": getattr(report, "screenshot_path", None),
                        "attachment_count": getattr(report, "attachment_count", 0),
                        "follow_up_required": 1 if report.follow_up_required else 0,
                        "created_at": report.created_at,
                        "updated_at": report.updated_at,
                    },
                )
                conn.commit()

                # Update phishing_sites in a separate transaction
                conn.execute(
                    text(
                        """
                        UPDATE phishing_sites
                        SET abuse_report_sent = 1,
                            reported = 1,
                            last_report_sent = :report_date
                        WHERE url = :site_url
                    """
                    ),
                    {
                        "site_url": report.site_url,
                        "report_date": report.report_date,
                    },
                )
                conn.commit()

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
                        SELECT ar.* FROM abuse_reports ar
                        LEFT JOIN phishing_sites ps ON ar.site_url = ps.url
                        WHERE ar.sla_deadline < CURRENT_TIMESTAMP
                        AND ar.status NOT IN ('resolved', 'rejected', 'timeout')
                        AND ar.response_received = 0
                        AND (ps.site_status IS NULL OR ps.site_status NOT IN ('down', 'timeout', 'resolved'))
                        ORDER BY ar.sla_deadline ASC
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
