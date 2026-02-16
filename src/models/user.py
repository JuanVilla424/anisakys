"""User model for authentication and authorization."""

from datetime import datetime
from typing import List, Optional

from sqlalchemy import Boolean, CheckConstraint, Index, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.models.base import Base


class User(Base):
    """User model for authentication and profile management.

    Attributes:
        id: Primary key
        email: Unique email address (validated format)
        password_hash: Bcrypt hashed password
        full_name: Optional full name
        tier: Subscription tier (community, professional, business, enterprise)
        status: Account status (active, suspended, cancelled)
        email_verified: Email verification status
        created_at: Account creation timestamp
        updated_at: Last update timestamp
        last_login_at: Last login timestamp
    """

    __tablename__ = "users"

    # Primary Key
    id: Mapped[int] = mapped_column(primary_key=True, index=True)

    # Authentication
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)

    # Profile
    full_name: Mapped[Optional[str]] = mapped_column(String(255))

    # Subscription & Status
    tier: Mapped[str] = mapped_column(
        String(20), default="community", nullable=False, index=True
    )
    status: Mapped[str] = mapped_column(
        String(20), default="active", nullable=False, index=True
    )

    # Verification
    email_verified: Mapped[bool] = mapped_column(Boolean, default=False)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(default=datetime.utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )
    last_login_at: Mapped[Optional[datetime]]

    # Relationships
    api_keys: Mapped[List["APIKey"]] = relationship(
        "APIKey", back_populates="user", cascade="all, delete-orphan"
    )
    scans: Mapped[List["Scan"]] = relationship(
        "Scan", back_populates="user", cascade="all, delete-orphan"
    )
    batch_scans: Mapped[List["BatchScan"]] = relationship(
        "BatchScan", back_populates="user", cascade="all, delete-orphan"
    )
    abuse_reports: Mapped[List["AbuseReport"]] = relationship(
        "AbuseReport",
        back_populates="user",
        foreign_keys="[AbuseReport.user_id]",
        cascade="all, delete-orphan"
    )
    domain_watchlist: Mapped[List["DomainWatchlist"]] = relationship(
        "DomainWatchlist", back_populates="user", cascade="all, delete-orphan"
    )
    audit_logs: Mapped[List["AuditLog"]] = relationship("AuditLog", back_populates="user")
    usage_tracking: Mapped[List["UsageTracking"]] = relationship(
        "UsageTracking", back_populates="user", cascade="all, delete-orphan"
    )
    # Sprint 4: Team Collaboration
    assigned_cases: Mapped[List["CaseAssignment"]] = relationship(
        "CaseAssignment", back_populates="assigned_to", foreign_keys="[CaseAssignment.assigned_to_user_id]"
    )
    cases_assigned_by_me: Mapped[List["CaseAssignment"]] = relationship(
        "CaseAssignment", back_populates="assigned_by", foreign_keys="[CaseAssignment.assigned_by_user_id]"
    )
    notes: Mapped[List["Note"]] = relationship(
        "Note", back_populates="author", foreign_keys="[Note.author_user_id]"
    )

    # Constraints
    __table_args__ = (
        CheckConstraint(
            "tier IN ('community', 'professional', 'business', 'enterprise')",
            name="check_tier",
        ),
        CheckConstraint(
            "status IN ('active', 'suspended', 'cancelled')", name="check_status"
        ),
        CheckConstraint(
            "email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}$'",
            name="check_email_format",
        ),
    )

    def __repr__(self) -> str:
        """String representation of User."""
        return f"<User(id={self.id}, email='{self.email}', tier='{self.tier}')>"
