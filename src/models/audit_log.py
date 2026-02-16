"""Audit Log model for security audit trail."""

from datetime import datetime
from typing import Optional

from sqlalchemy import CheckConstraint, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import INET, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.models.base import Base


class AuditLog(Base):
    """Audit Log model for security audit trail and compliance.

    Attributes:
        id: Primary key (BIGINT for high volume)
        user_id: Optional foreign key to users table (NULL if user deleted)
        action: Action performed (e.g., 'user.login', 'scan.create')
        resource_type: Type of resource affected (scan, user, api_key, report)
        resource_id: ID of the resource
        ip_address: Client IP address
        user_agent: Client user agent
        request_method: HTTP method (GET, POST, PUT, DELETE)
        request_path: Request path
        old_values: Previous values (for UPDATE operations) - JSONB
        new_values: New values (for UPDATE operations) - JSONB
        status: Operation status (success, failure, error)
        error_message: Error message if status is failure/error
        timestamp: Log entry timestamp
    """

    __tablename__ = "audit_logs"

    # Primary Key (BIGSERIAL for high volume)
    id: Mapped[int] = mapped_column(primary_key=True, index=True)

    # Foreign Key (nullable - user may be deleted)
    user_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True
    )

    # Action Details
    action: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    resource_type: Mapped[Optional[str]] = mapped_column(String(50))
    resource_id: Mapped[Optional[int]] = mapped_column(Integer)

    # Request Context
    ip_address: Mapped[Optional[str]] = mapped_column(INET)
    user_agent: Mapped[Optional[str]] = mapped_column(Text)
    request_method: Mapped[Optional[str]] = mapped_column(String(10))
    request_path: Mapped[Optional[str]] = mapped_column(Text)

    # Changes (for UPDATE operations)
    old_values: Mapped[Optional[dict]] = mapped_column(JSON)
    new_values: Mapped[Optional[dict]] = mapped_column(JSON)

    # Result
    status: Mapped[Optional[str]] = mapped_column(String(20))
    error_message: Mapped[Optional[str]] = mapped_column(Text)

    # Timestamp
    timestamp: Mapped[datetime] = mapped_column(
        default=datetime.utcnow, nullable=False, index=True
    )

    # Relationships
    user: Mapped[Optional["User"]] = relationship("User", back_populates="audit_logs")

    # Constraints & Indexes
    __table_args__ = (
        CheckConstraint(
            "status IN ('success', 'failure', 'error')", name="check_status"
        ),
        Index("idx_audit_logs_user_id", "user_id"),
        Index("idx_audit_logs_timestamp", "timestamp", postgresql_using="btree"),
        Index("idx_audit_logs_action", "action"),
        Index("idx_audit_logs_resource", "resource_type", "resource_id"),
    )

    def __repr__(self) -> str:
        """String representation of AuditLog."""
        return (
            f"<AuditLog(id={self.id}, action='{self.action}', "
            f"user_id={self.user_id}, status='{self.status}')>"
        )
