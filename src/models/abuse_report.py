"""Abuse Report model for ICANN compliance tracking."""

from datetime import datetime
from typing import List, Optional

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    ForeignKey,
    Index,
    String,
    Text,
    ARRAY,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.models.base import Base


class AbuseReport(Base):
    """Abuse Report model for ICANN abuse report tracking.

    Attributes:
        id: Primary key
        scan_id: Optional foreign key to scans table
        user_id: Foreign key to users table
        url: URL being reported
        report_type: Type of report (phishing, malware, spam, copyright, other)
        recipient_email: Array of recipient emails
        subject: Email subject line
        body: Email body content
        attachments: Array of S3/MinIO paths to attachments
        icann_sla_deadline: ICANN SLA deadline (submission + 48 hours)
        icann_sla_status: SLA status (compliant, approaching, overdue, waived)
        sla_alert_sent: Whether SLA alert was sent
        status: Report status (draft, submitted, acknowledged, resolved, rejected)
        submitted_at: Submission timestamp
        acknowledged_at: Acknowledgment timestamp
        resolved_at: Resolution timestamp
        response_received: Whether response was received
        response_text: Response text content
        response_received_at: Response received timestamp
        manual_submission: Whether report was manually submitted
        created_by: User who created the report
        created_at: Record creation timestamp
        updated_at: Last update timestamp
    """

    __tablename__ = "abuse_reports"

    # Primary Key
    id: Mapped[int] = mapped_column(primary_key=True, index=True)

    # Foreign Keys
    scan_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("scans.id", ondelete="SET NULL"), index=True
    )
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # Report Data
    url: Mapped[str] = mapped_column(Text, nullable=False)
    report_type: Mapped[str] = mapped_column(String(50), nullable=False)
    recipient_email: Mapped[List[str]] = mapped_column(ARRAY(Text), nullable=False)
    subject: Mapped[Optional[str]] = mapped_column(String(500))
    body: Mapped[Optional[str]] = mapped_column(Text)
    attachments: Mapped[Optional[List[str]]] = mapped_column(ARRAY(Text))

    # ICANN SLA Tracking
    icann_sla_deadline: Mapped[Optional[datetime]] = mapped_column(index=True)
    icann_sla_status: Mapped[Optional[str]] = mapped_column(String(20))
    sla_alert_sent: Mapped[bool] = mapped_column(Boolean, default=False)

    # Status Tracking
    status: Mapped[str] = mapped_column(
        String(20), default="draft", nullable=False, index=True
    )
    submitted_at: Mapped[Optional[datetime]] = mapped_column(index=True)
    acknowledged_at: Mapped[Optional[datetime]]
    resolved_at: Mapped[Optional[datetime]]

    # Response Tracking
    response_received: Mapped[bool] = mapped_column(Boolean, default=False)
    response_text: Mapped[Optional[str]] = mapped_column(Text)
    response_received_at: Mapped[Optional[datetime]]

    # Metadata
    manual_submission: Mapped[bool] = mapped_column(Boolean, default=False)
    created_by: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(default=datetime.utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    # Relationships
    scan: Mapped[Optional["Scan"]] = relationship("Scan", back_populates="abuse_reports")
    user: Mapped["User"] = relationship(
        "User", back_populates="abuse_reports", foreign_keys=[user_id]
    )
    case_assignments: Mapped[List["CaseAssignment"]] = relationship(
        "CaseAssignment", back_populates="abuse_report", foreign_keys="[CaseAssignment.abuse_report_id]"
    )
    notes: Mapped[List["Note"]] = relationship(
        "Note", back_populates="abuse_report", foreign_keys="[Note.abuse_report_id]"
    )

    # Constraints & Indexes
    __table_args__ = (
        CheckConstraint(
            "report_type IN ('phishing', 'malware', 'spam', 'copyright', 'other')",
            name="check_report_type",
        ),
        CheckConstraint(
            "status IN ('draft', 'submitted', 'acknowledged', 'resolved', 'rejected')",
            name="check_report_status",
        ),
        CheckConstraint(
            "icann_sla_status IN ('compliant', 'approaching', 'overdue', 'waived')",
            name="check_icann_sla_status",
        ),
        Index("idx_abuse_reports_scan_id", "scan_id"),
        Index("idx_abuse_reports_user_id", "user_id"),
        Index("idx_abuse_reports_status", "status"),
        Index("idx_abuse_reports_icann_sla_deadline", "icann_sla_deadline"),
        Index("idx_abuse_reports_submitted_at", "submitted_at"),
    )

    def __repr__(self) -> str:
        """String representation of AbuseReport."""
        return (
            f"<AbuseReport(id={self.id}, url='{self.url[:50]}...', "
            f"type='{self.report_type}', status='{self.status}')>"
        )
