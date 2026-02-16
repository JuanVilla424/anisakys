"""Note Model - Team Collaboration."""

from datetime import datetime
from typing import Optional, List
from sqlalchemy import String, Integer, DateTime, ForeignKey, Text, Boolean, Index
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.models.base import Base


class Note(Base):
    """Note/Comment model for team collaboration.

    Stores notes and comments added by team members to scans,
    abuse reports, or other entities for knowledge sharing.

    Attributes:
        id: Primary key
        scan_id: Link to scan (if note is on scan)
        abuse_report_id: Link to abuse report (if note is on report)
        author_user_id: User who created note
        content: Note content (supports markdown)
        is_important: Whether note is marked important
        mentions: List of @mentioned user IDs
        attachments: List of attachment file paths
        created_at: Note creation timestamp
        updated_at: Note update timestamp
        is_archived: Soft delete flag

    Example:
        ```python
        note = Note(
            scan_id=123,
            author_user_id=5,
            content="This looks like a **phishing campaign** targeting PayPal. @john please review.",
            is_important=True,
            mentions=[3],  # john's user_id
        )
        ```
    """

    __tablename__ = "notes"

    # Primary Key
    id: Mapped[int] = mapped_column(primary_key=True)

    # Entity References (at least one must be set)
    scan_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
        comment="Link to scan (if note is on scan)"
    )

    abuse_report_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("abuse_reports.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
        comment="Link to abuse report (if note is on report)"
    )

    case_assignment_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("case_assignments.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
        comment="Link to case assignment (if note is on assignment)"
    )

    # Author
    author_user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="User who created note"
    )

    # Content
    content: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="Note content (markdown supported)"
    )

    is_important: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        index=True,
        comment="Whether note is flagged as important"
    )

    # Mentions & Attachments
    mentions: Mapped[Optional[List[int]]] = mapped_column(
        ARRAY(Integer),
        nullable=True,
        comment="User IDs mentioned in note (@user)"
    )

    attachments: Mapped[Optional[List[str]]] = mapped_column(
        ARRAY(String),
        nullable=True,
        comment="Attachment file paths (max 10MB each)"
    )

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=datetime.utcnow,
        index=True,
        comment="Note creation timestamp"
    )

    updated_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime,
        nullable=True,
        onupdate=datetime.utcnow,
        comment="Note last update timestamp"
    )

    # Soft Delete
    is_archived: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        index=True,
        comment="Soft delete flag (notes never hard deleted)"
    )

    # Relationships
    scan: Mapped[Optional["Scan"]] = relationship(
        "Scan",
        back_populates="notes",
        foreign_keys=[scan_id]
    )

    abuse_report: Mapped[Optional["AbuseReport"]] = relationship(
        "AbuseReport",
        back_populates="notes",
        foreign_keys=[abuse_report_id]
    )

    case_assignment: Mapped[Optional["CaseAssignment"]] = relationship(
        "CaseAssignment",
        back_populates="notes",
        foreign_keys=[case_assignment_id]
    )

    author: Mapped["User"] = relationship(
        "User",
        back_populates="notes",
        foreign_keys=[author_user_id]
    )

    # Composite Indexes
    __table_args__ = (
        Index('idx_note_scan_created', 'scan_id', 'created_at'),
        Index('idx_note_report_created', 'abuse_report_id', 'created_at'),
        Index('idx_note_important', 'is_important', 'created_at'),
        Index('idx_note_archived', 'is_archived', 'created_at'),
    )

    def __repr__(self) -> str:
        entity = "scan" if self.scan_id else "report" if self.abuse_report_id else "assignment"
        return (
            f"<Note(id={self.id}, "
            f"author={self.author_user_id}, "
            f"entity='{entity}', "
            f"important={self.is_important})>"
        )
