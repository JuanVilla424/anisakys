"""
Report tracking for abuse reports (SLA and follow-ups).

Every report is one row in ``abuse_reports`` keyed by its stable report id
(``ANISAKYS-YYYYMMDD-XXXXXXXX``), the same id the e-mail subject carries.
Tracking is append-only: a new report for a site creates a new row, and a
follow-up only updates the counters, timestamps and SLA deadline of its own
report's row.

The ``abuse_reports`` schema is owned by Alembic (revisions 001 and 004); this
module never creates, alters or drops tables.

Timestamps are written as timezone-aware UTC values and SLA checks compare
against an explicit ``now``, so callers (and tests) control the clock.
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from sqlalchemy import text
from sqlalchemy.engine import Connection, Engine

from src.config import settings
from src.reporting.db import short_transaction, utc_now

logger = logging.getLogger(__name__)

# Statuses for which no follow-up is ever sent.
CLOSED_STATUSES = (
    "resolved",
    "rejected",
    "timeout",
    "queued",
    "failed",
    "pending_manual",
    "bounced",
)
_CLOSED_SQL = ", ".join(f"'{status}'" for status in CLOSED_STATUSES)


def generate_report_id() -> str:
    """Generate a unique, stable report id.

    The same id is tracked in ``abuse_reports`` and carried in the e-mail
    subject and body, so replies and follow-ups can be matched to it.

    Returns:
        ``ANISAKYS-YYYYMMDD-XXXXXXXX`` (UTC date).
    """
    return f"ANISAKYS-{utc_now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:8].upper()}"


def calculate_sla_deadline(start: datetime, business_days: int = 2) -> datetime:
    """Anisakys' follow-up deadline: ``business_days`` working days after ``start``.

    This is our own follow-up schedule, not a contractual obligation of the
    recipient.

    Args:
        start: When the report was sent (naive values are taken as UTC).
        business_days: Working days to add (Saturday and Sunday are skipped).

    Returns:
        17:00 UTC on the resulting day, timezone-aware.
    """
    current = start if start.tzinfo else start.replace(tzinfo=timezone.utc)
    current = current.astimezone(timezone.utc)
    added = 0
    while added < business_days:
        current += timedelta(days=1)
        if current.weekday() < 5:
            added += 1
    return current.replace(hour=17, minute=0, second=0, microsecond=0)


class ReportStatus(Enum):
    """Status of abuse reports"""

    QUEUED = "queued"
    SENT = "sent"
    ACKNOWLEDGED = "acknowledged"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    REJECTED = "rejected"
    TIMEOUT = "timeout"
    BOUNCED = "bounced"
    FAILED = "failed"
    PENDING_MANUAL = "pending_manual"


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
    screenshot_path: Optional[str] = None
    attachment_count: int = 0
    multi_api_results: Optional[Dict[str, Any]] = None
    confidence_score: Optional[int] = None
    threat_level: Optional[str] = None
    follow_up_required: bool = False
    evidence: Optional[Dict[str, Any]] = None
    report_date: Optional[datetime] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    def __post_init__(self) -> None:
        """Fill UTC timestamps and, for sent reports, the SLA deadline."""
        now = utc_now()
        if self.report_date is None:
            self.report_date = now
        if self.created_at is None:
            self.created_at = now
        if self.updated_at is None:
            self.updated_at = now
        if self.sla_deadline is None and self.status == ReportStatus.SENT.value:
            self.sla_deadline = self._calculate_sla_deadline()

    def _calculate_sla_deadline(self) -> datetime:
        """Calculate the follow-up deadline (2 business days after the report).

        Returns:
            Timezone-aware UTC deadline.
        """
        return calculate_sla_deadline(self.report_date or utc_now())


@dataclass(frozen=True)
class FollowupClaim:
    """A follow-up slot reserved for one overdue report."""

    report_id: str
    site_url: str
    followup_seq: int
    recipients: List[str]
    report_date: Optional[datetime]
    evidence: Optional[Dict[str, Any]]


def _json_list(value: Any) -> List[str]:
    """Decode a JSON (or comma separated) recipient list column.

    Args:
        value: Stored value.

    Returns:
        The list of addresses.
    """
    if not value:
        return []
    if isinstance(value, list):
        return [str(item) for item in value if item]
    try:
        decoded = json.loads(value)
    except (TypeError, ValueError):
        return [part.strip() for part in str(value).split(",") if part.strip()]
    if isinstance(decoded, list):
        return [str(item) for item in decoded if item]
    return [str(decoded)] if decoded else []


class ReportTracker:
    """Tracks abuse reports and their follow-up SLA in ``abuse_reports``."""

    def __init__(self, db_engine: Optional[Engine]):
        """
        Initialize report tracker

        The ``abuse_reports`` schema is owned by Alembic (revisions 001 and
        004); the tracker never creates, alters or drops tables.

        Args:
            db_engine: SQLAlchemy database engine
        """
        self.db_engine = db_engine

    def generate_report_id(self) -> str:
        """Generate unique report ID.

        Returns:
            ``ANISAKYS-YYYYMMDD-XXXXXXXX``.
        """
        return generate_report_id()

    # ------------------------------------------------------------------
    # Writes used by the reporting pipeline (inside the caller's transaction)
    # ------------------------------------------------------------------

    def insert_report(self, conn: Connection, report: AbuseReportRecord) -> None:
        """Insert a new report row (append-only) inside the caller's transaction.

        Args:
            conn: Connection inside an open transaction.
            report: The report to record.

        Raises:
            sqlalchemy.exc.IntegrityError: If the report id already exists.
        """
        recipients = report.recipients
        conn.execute(
            text("""
                INSERT INTO abuse_reports (
                    site_url, site_id, report_date, recipients, cc_recipients, subject,
                    report_id, status, sla_deadline, icann_compliant, screenshot_included,
                    screenshot_path, attachment_count, follow_up_required, evidence,
                    created_at, updated_at
                ) VALUES (
                    :site_url,
                    (SELECT id FROM phishing_sites WHERE url = :site_url ORDER BY id LIMIT 1),
                    :report_date, :recipients, :cc_recipients, :subject,
                    :report_id, :status, :sla_deadline, :icann_compliant, :screenshot_included,
                    :screenshot_path, :attachment_count, :follow_up_required,
                    CAST(:evidence AS JSONB), :created_at, :updated_at
                )
                """),
            {
                "site_url": report.site_url,
                "report_date": report.report_date,
                "recipients": json.dumps(
                    recipients if isinstance(recipients, list) else [recipients]
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
                "screenshot_path": report.screenshot_path,
                "attachment_count": report.attachment_count,
                "follow_up_required": 1 if report.follow_up_required else 0,
                "evidence": json.dumps(report.evidence) if report.evidence is not None else None,
                "created_at": report.created_at,
                "updated_at": report.updated_at,
            },
        )

    def mark_report_sent(self, conn: Connection, report_id: str, sent_at: datetime) -> bool:
        """Move a queued report to ``sent`` and start its SLA clock.

        Only the first primary delivery counts; later ones leave the row alone.

        Args:
            conn: Connection inside an open transaction.
            report_id: Tracked report id.
            sent_at: When the first abuse desk accepted the report.

        Returns:
            ``True`` if the row changed.
        """
        result = conn.execute(
            text("""
                UPDATE abuse_reports
                SET status = 'sent', report_date = :sent_at, sla_deadline = :deadline,
                    updated_at = :sent_at
                WHERE report_id = :report_id AND status = 'queued'
                """),
            {
                "report_id": report_id,
                "sent_at": sent_at,
                "deadline": calculate_sla_deadline(sent_at),
            },
        )
        return bool(result.rowcount)

    def mark_report_failed_if_undeliverable(self, conn: Connection, report_id: str) -> bool:
        """Mark a queued report ``failed`` once none of its primary e-mails can succeed.

        Args:
            conn: Connection inside an open transaction.
            report_id: Tracked report id.

        Returns:
            ``True`` if the report was marked failed.
        """
        result = conn.execute(
            text("""
                UPDATE abuse_reports
                SET status = 'failed', updated_at = now()
                WHERE report_id = :report_id AND status = 'queued'
                  AND NOT EXISTS (
                      SELECT 1 FROM abuse_report_outbox AS o
                      WHERE o.report_id = :report_id AND o.channel = 'email'
                        AND o.audience = 'primary' AND o.followup_seq = 0
                        AND o.status IN ('pending', 'sending', 'sent')
                  )
                """),
            {"report_id": report_id},
        )
        return bool(result.rowcount)

    def claim_followup(
        self,
        conn: Connection,
        report_id: str,
        now: datetime,
        interval_hours: Optional[int] = None,
        max_followups: Optional[int] = None,
    ) -> Optional[FollowupClaim]:
        """Reserve the next follow-up of an overdue report.

        Locks the report row (``FOR UPDATE SKIP LOCKED``), re-checks that it is
        still overdue, increments ``follow_up_count`` and advances
        ``sla_deadline`` by one interval, so the same report cannot be followed
        up again before the next deadline even if delivery is delayed. Once
        ``max_followups`` is spent the report is closed as ``timeout``.

        Args:
            conn: Connection inside an open transaction.
            report_id: Tracked report id.
            now: Current time (UTC, aware).
            interval_hours: Hours between follow-ups.
            max_followups: Maximum number of follow-ups per report.

        Returns:
            The reserved follow-up, or ``None`` when another worker holds the
            row, it is no longer overdue, or the follow-up budget is spent.
        """
        interval = interval_hours or settings.FOLLOWUP_INTERVAL_HOURS
        budget = settings.FOLLOWUP_MAX_COUNT if max_followups is None else max_followups
        row = (
            conn.execute(
                text(f"""
                    SELECT report_id, site_url, recipients, evidence,
                           CAST(report_date AS timestamptz) AS report_date,
                           COALESCE(follow_up_count, 0) AS follow_up_count
                    FROM abuse_reports
                    WHERE report_id = :report_id
                      AND sla_deadline < :now
                      AND COALESCE(response_received, 0) = 0
                      AND status NOT IN ({_CLOSED_SQL})
                    FOR UPDATE SKIP LOCKED
                    """),
                {"report_id": report_id, "now": now},
            )
            .mappings()
            .first()
        )
        if row is None:
            return None
        sequence = int(row["follow_up_count"]) + 1
        if sequence > budget:
            conn.execute(
                text("""
                    UPDATE abuse_reports
                    SET status = 'timeout', follow_up_required = 0, updated_at = :now
                    WHERE report_id = :report_id
                    """),
                {"report_id": report_id, "now": now},
            )
            logger.warning(
                f"Report {report_id} unanswered after {budget} follow-up(s); closed as timeout"
            )
            return None
        conn.execute(
            text("""
                UPDATE abuse_reports
                SET follow_up_count = :sequence, follow_up_required = 1,
                    sla_deadline = :next_deadline, updated_at = :now
                WHERE report_id = :report_id
                """),
            {
                "report_id": report_id,
                "sequence": sequence,
                "next_deadline": now + timedelta(hours=interval),
                "now": now,
            },
        )
        evidence = row["evidence"]
        if isinstance(evidence, str):
            evidence = json.loads(evidence)
        return FollowupClaim(
            report_id=row["report_id"],
            site_url=row["site_url"],
            followup_seq=sequence,
            recipients=_json_list(row["recipients"]),
            report_date=row["report_date"],
            evidence=evidence,
        )

    def record_followup_sent(
        self,
        conn: Connection,
        report_id: str,
        sent_at: datetime,
        interval_hours: Optional[int] = None,
    ) -> None:
        """Record a delivered follow-up and restart the SLA clock from it.

        Args:
            conn: Connection inside an open transaction.
            report_id: Tracked report id.
            sent_at: When the follow-up was accepted.
            interval_hours: Hours until the next follow-up is due.
        """
        interval = interval_hours or settings.FOLLOWUP_INTERVAL_HOURS
        conn.execute(
            text("""
                UPDATE abuse_reports
                SET last_follow_up_at = :sent_at,
                    sla_deadline = GREATEST(CAST(sla_deadline AS timestamptz), :next_deadline),
                    updated_at = :sent_at
                WHERE report_id = :report_id
                """),
            {
                "report_id": report_id,
                "sent_at": sent_at,
                "next_deadline": sent_at + timedelta(hours=interval),
            },
        )

    # ------------------------------------------------------------------
    # Public API (each call is its own short transaction)
    # ------------------------------------------------------------------

    def track_report(self, report: AbuseReportRecord) -> bool:
        """
        Track a new abuse report and update the phishing_sites table.

        Append-only: every report id gets its own row; an earlier report of
        the same site is never overwritten.

        Args:
            report: AbuseReportRecord to track

        Returns:
            True if successfully tracked
        """
        try:
            with short_transaction(self.db_engine) as conn:
                self.insert_report(conn, report)
                conn.execute(
                    text("""
                        UPDATE phishing_sites
                        SET abuse_report_sent = 1, reported = 1, last_report_sent = :report_date
                        WHERE url = :site_url
                        """),
                    {"site_url": report.site_url, "report_date": report.report_date},
                )
            logger.info(f"Tracked abuse report {report.report_id} for {report.site_url}")
            return True
        except Exception as e:
            logger.error(f"Failed to track abuse report {report.report_id}: {e}")
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
                now = utc_now()
                update_data = {
                    "report_id": report_id,
                    "status": status.value,
                    "updated_at": now,
                    "follow_up_required": 1 if follow_up_required else 0,
                }

                if response_content:
                    update_data.update(
                        {
                            "response_received": 1,
                            "response_date": now,
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
                    logger.info(f"Updated report {report_id} status to {status.value}")
                    return True
                logger.warning(f"Report {report_id} not found for status update")
                return False

        except Exception as e:
            logger.error(f"Failed to update report status: {e}")
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
                return self._decode_row(result) if result else None
        except Exception as e:
            logger.error(f"Failed to get report {report_id}: {e}")
            return None

    def get_reports_by_site(self, site_url: str) -> List[Dict[str, Any]]:
        """
        Get all reports for a specific site

        Args:
            site_url: Site URL to search for

        Returns:
            List of report dicts, newest first
        """
        try:
            with self.db_engine.connect() as conn:
                result = conn.execute(
                    text(
                        "SELECT * FROM abuse_reports WHERE site_url = :site_url "
                        "ORDER BY report_date DESC, id DESC"
                    ),
                    {"site_url": site_url},
                ).fetchall()
                return [self._decode_row(row) for row in result]
        except Exception as e:
            logger.error(f"Failed to get reports for site {site_url}: {e}")
            return []

    @staticmethod
    def _decode_row(row: Any) -> Dict[str, Any]:
        """Turn a row into a dict with JSON columns decoded and flags as bools.

        Args:
            row: Result row.

        Returns:
            The decoded dict.
        """
        report_dict = dict(row._mapping)
        for json_field in ("recipients", "cc_recipients", "multi_api_results", "evidence"):
            value = report_dict.get(json_field)
            if isinstance(value, str) and value:
                try:
                    report_dict[json_field] = json.loads(value)
                except (json.JSONDecodeError, TypeError):
                    pass
        for bool_field in (
            "response_received",
            "icann_compliant",
            "screenshot_included",
            "follow_up_required",
        ):
            if bool_field in report_dict:
                report_dict[bool_field] = bool(report_dict[bool_field])
        return report_dict

    def get_overdue_reports(self, now: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """
        Get reports that are past their SLA deadline.

        Only the newest open report of each site is considered, so a site that
        was reported again never gets parallel follow-ups.

        Args:
            now: Reference time (UTC); defaults to the current time.

        Returns:
            List of overdue report dicts with ``overdue_hours``
        """
        reference = now or utc_now()
        try:
            with short_transaction(self.db_engine) as conn:
                result = conn.execute(
                    text(f"""
                        SELECT latest.*,
                               ROUND(CAST(EXTRACT(EPOCH FROM (CAST(:now AS timestamptz)
                                    - latest.sla_deadline)) / 3600 AS numeric), 2)
                                   AS overdue_hours
                        FROM (
                            SELECT DISTINCT ON (ar.site_url) ar.*
                            FROM abuse_reports AS ar
                            INNER JOIN phishing_sites AS ps ON ar.site_url = ps.url
                            WHERE ar.status NOT IN ({_CLOSED_SQL})
                              AND ps.site_status NOT IN ('down', 'timeout', 'resolved')
                            ORDER BY ar.site_url, ar.id DESC
                        ) AS latest
                        WHERE latest.sla_deadline < :now
                          AND COALESCE(latest.response_received, 0) = 0
                        ORDER BY latest.sla_deadline ASC
                        """),
                    {"now": reference},
                ).fetchall()

                overdue_reports = []
                for row in result:
                    report_dict = dict(row._mapping)
                    if report_dict.get("overdue_hours") is not None:
                        report_dict["overdue_hours"] = float(report_dict["overdue_hours"])
                    elif report_dict.get("sla_deadline"):
                        deadline = report_dict["sla_deadline"]
                        if deadline.tzinfo is None:
                            deadline = deadline.replace(tzinfo=timezone.utc)
                        report_dict["overdue_hours"] = round(
                            (reference - deadline).total_seconds() / 3600, 2
                        )
                    overdue_reports.append(report_dict)

                return overdue_reports

        except Exception as e:
            logger.error(f"Failed to get overdue reports: {e}")
            return []

    def get_reports_needing_followup(self) -> List[Dict[str, Any]]:
        """
        Get reports that need follow-up

        Returns:
            List of reports needing follow-up
        """
        try:
            with self.db_engine.connect() as conn:
                result = conn.execute(text("""
                        SELECT * FROM abuse_reports
                        WHERE follow_up_required = 1
                        AND status NOT IN ('resolved', 'rejected')
                        ORDER BY updated_at ASC
                    """)).fetchall()

                return [dict(row._mapping) for row in result]

        except Exception as e:
            logger.error(f"Failed to get reports needing follow-up: {e}")
            return []

    def mark_report_for_followup(
        self,
        report_id: str,
        reason: str = None,
        now: Optional[datetime] = None,
        interval_hours: Optional[int] = None,
    ) -> bool:
        """
        Mark a report as needing follow-up and push its SLA deadline forward.

        Advancing ``sla_deadline`` by one follow-up interval is what keeps the
        next overdue check from sending the same follow-up again.

        Args:
            report_id: Report ID to mark
            reason: Optional reason for follow-up
            now: Reference time (UTC); defaults to the current time.
            interval_hours: Hours until the report is overdue again.

        Returns:
            True if successfully marked
        """
        reference = now or utc_now()
        interval = interval_hours or settings.FOLLOWUP_INTERVAL_HOURS
        try:
            with self.db_engine.begin() as conn:
                update_data = {
                    "report_id": report_id,
                    "follow_up_required": 1,
                    "updated_at": reference,
                    "next_deadline": reference + timedelta(hours=interval),
                }

                query = """
                    UPDATE abuse_reports
                    SET follow_up_required = :follow_up_required, updated_at = :updated_at,
                        sla_deadline = :next_deadline
                """

                if reason:
                    update_data["response_content"] = f"Follow-up required: {reason}"
                    query += ", response_content = :response_content"

                query += " WHERE report_id = :report_id"

                result = conn.execute(text(query), update_data)

                if result.rowcount > 0:
                    logger.info(f"Marked report {report_id} for follow-up")
                    return True
                logger.warning(f"Report {report_id} not found for follow-up marking")
                return False

        except Exception as e:
            logger.error(f"Failed to mark report for follow-up: {e}")
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
                overdue_count = conn.execute(text("""
                        SELECT COUNT(*) FROM abuse_reports
                        WHERE sla_deadline < CURRENT_TIMESTAMP
                        AND status NOT IN ('resolved', 'rejected', 'timeout')
                        AND response_received = 0
                    """)).scalar()

                # Average response time (for reports that got responses)
                avg_response_time = conn.execute(text("""
                        SELECT AVG(EXTRACT(EPOCH FROM (response_date - report_date))/3600) as avg_hours
                        FROM abuse_reports
                        WHERE response_received = 1 AND response_date IS NOT NULL
                    """)).scalar()

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
                    "generated_at": utc_now().isoformat(),
                }

        except Exception as e:
            logger.error(f"Failed to get statistics: {e}")
            return {"error": str(e)}


# Convenience functions
def create_report_record(
    site_url: str,
    recipients: List[str],
    subject: str,
    cc_recipients: List[str] = None,
    multi_api_results: Dict = None,
    screenshot_included: bool = False,
    report_id: Optional[str] = None,
    status: str = ReportStatus.SENT.value,
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
        report_id: Id already used in the e-mail; generated when omitted
        status: Initial status (``queued`` until the first delivery)

    Returns:
        AbuseReportRecord instance
    """
    confidence_score = None
    threat_level = None

    if multi_api_results:
        confidence_score = multi_api_results.get("confidence_score")
        threat_level = multi_api_results.get("aggregated_threat_level") or multi_api_results.get(
            "threat_level"
        )

    return AbuseReportRecord(
        site_url=site_url,
        recipients=recipients,
        subject=subject,
        report_id=report_id or generate_report_id(),
        status=status,
        cc_recipients=cc_recipients,
        multi_api_results=multi_api_results,
        confidence_score=confidence_score,
        threat_level=threat_level,
        screenshot_included=screenshot_included,
        icann_compliant=True,
    )
