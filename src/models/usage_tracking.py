"""Usage Tracking model for billing and resource monitoring."""

from datetime import date, datetime
from typing import Optional

from sqlalchemy import Date, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.models.base import Base


class UsageTracking(Base):
    """Usage Tracking model for resource usage and billing.

    Attributes:
        id: Primary key (BIGINT for high volume)
        user_id: Foreign key to users table
        tier: User's subscription tier at time of usage
        resource_type: Type of resource used (url_scan, api_request, storage_gb)
        quantity: Quantity of resource used
        scan_id: Optional foreign key to scans table
        api_endpoint: API endpoint accessed (if applicable)
        timestamp: Usage timestamp
        billing_period: Billing period in YYYY-MM-01 format
    """

    __tablename__ = "usage_tracking"

    # Primary Key (BIGINT for high volume)
    id: Mapped[int] = mapped_column(primary_key=True, index=True)

    # Foreign Key
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # Usage Details
    tier: Mapped[str] = mapped_column(String(20), nullable=False)
    resource_type: Mapped[str] = mapped_column(
        String(50), nullable=False, index=True
    )
    quantity: Mapped[int] = mapped_column(Integer, default=1, nullable=False)

    # Metadata
    scan_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("scans.id", ondelete="SET NULL")
    )
    api_endpoint: Mapped[Optional[str]] = mapped_column(Text)

    # Timestamps
    timestamp: Mapped[datetime] = mapped_column(
        default=datetime.utcnow, nullable=False, index=True
    )
    billing_period: Mapped[date] = mapped_column(Date, nullable=False)

    # Relationships
    user: Mapped["User"] = relationship("User", back_populates="usage_tracking")

    # Indexes
    __table_args__ = (
        Index("idx_usage_user_period", "user_id", "billing_period"),
        Index("idx_usage_resource_type", "resource_type"),
        Index("idx_usage_timestamp", "timestamp"),
    )

    def __repr__(self) -> str:
        """String representation of UsageTracking."""
        return (
            f"<UsageTracking(id={self.id}, user_id={self.user_id}, "
            f"resource='{self.resource_type}', quantity={self.quantity})>"
        )
