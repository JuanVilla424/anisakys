"""Case Assignment Model - Team Collaboration."""

from datetime import datetime
from typing import Optional, List
from sqlalchemy import String, Integer, DateTime, ForeignKey, Text, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.models.base import Base


class CaseAssignment(Base):
    """Case assignment model for team collaboration.

    Tracks assignment of abuse reports/scans to team members
    for investigation and response.

    Attributes:
        id: Primary key
        scan_id: Link to scan being investigated
        abuse_report_id: Link to abuse report (optional)
        assigned_to_user_id: Analyst assigned to case
        assigned_by_user_id: Manager who assigned case
        status: Assignment status (pending, in_progress, completed)
        priority: Case priority (low, medium, high, critical)
        due_date: Optional deadline
        assigned_at: Assignment timestamp
        accepted_at: When analyst accepted assignment
        completed_at: When case was completed
        notes: Assignment notes from manager

    Example:
        ```python
        assignment = CaseAssignment(
            scan_id=123,
            assigned_to_user_id=5,
            assigned_by_user_id=1,
            status="pending",
            priority="high",
            notes="Suspected phishing campaign targeting banking customers"
        )
        ```
    """

    __tablename__ = "case_assignments"

    # Primary Key
    id: Mapped[int] = mapped_column(primary_key=True)

    # Case References
    scan_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
        comment="Link to scan being investigated"
    )

    abuse_report_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("abuse_reports.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
        comment="Link to abuse report (if applicable)"
    )

    # Assignment
    assigned_to_user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="Analyst assigned to investigate"
    )

    assigned_by_user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        comment="Manager who assigned case"
    )

    # Status
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="pending",
        index=True,
        comment="Status: pending, in_progress, completed, reassigned"
    )

    priority: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="medium",
        index=True,
        comment="Priority: low, medium, high, critical"
    )

    # Deadlines
    due_date: Mapped[Optional[datetime]] = mapped_column(
        DateTime,
        nullable=True,
        index=True,
        comment="Optional deadline for completion"
    )

    # Timestamps
    assigned_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=datetime.utcnow,
        index=True,
        comment="When case was assigned"
    )

    accepted_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime,
        nullable=True,
        comment="When analyst accepted assignment"
    )

    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime,
        nullable=True,
        index=True,
        comment="When case was completed"
    )

    # Notes (Text column for assignment notes from manager)
    assignment_notes: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        comment="Assignment notes from manager"
    )

    completion_summary: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        comment="Summary provided by analyst on completion"
    )

    # Relationships
    scan: Mapped[Optional["Scan"]] = relationship(
        "Scan",
        back_populates="case_assignments",
        foreign_keys=[scan_id]
    )

    abuse_report: Mapped[Optional["AbuseReport"]] = relationship(
        "AbuseReport",
        back_populates="case_assignments",
        foreign_keys=[abuse_report_id]
    )

    assigned_to: Mapped["User"] = relationship(
        "User",
        back_populates="assigned_cases",
        foreign_keys=[assigned_to_user_id]
    )

    assigned_by: Mapped["User"] = relationship(
        "User",
        back_populates="cases_assigned_by_me",
        foreign_keys=[assigned_by_user_id]
    )

    # Relationship to Note objects (list of notes/comments on this assignment)
    notes: Mapped[List["Note"]] = relationship(
        "Note",
        back_populates="case_assignment",
        foreign_keys="[Note.case_assignment_id]"
    )

    # Composite Indexes
    __table_args__ = (
        Index('idx_assignment_user_status', 'assigned_to_user_id', 'status'),
        Index('idx_assignment_priority_status', 'priority', 'status'),
        Index('idx_assignment_due_date', 'due_date', 'status'),
    )

    def __repr__(self) -> str:
        return (
            f"<CaseAssignment(id={self.id}, "
            f"assigned_to={self.assigned_to_user_id}, "
            f"status='{self.status}', "
            f"priority='{self.priority}')>"
        )
