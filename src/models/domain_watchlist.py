"""Domain Watchlist model for brand protection monitoring."""

from datetime import datetime
from typing import Optional

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.models.base import Base


class DomainWatchlist(Base):
    """Domain Watchlist model for monitored domains.

    Attributes:
        id: Primary key
        user_id: Foreign key to users table
        domain: Domain name to monitor
        brand_name: Associated brand name
        monitoring_enabled: Whether monitoring is active
        alert_threshold: Alert threshold (low, medium, high, critical)
        check_typosquatting: Enable typosquatting detection
        check_certificate_transparency: Enable CT monitoring
        check_social_media: Enable social media monitoring
        notify_email: Enable email notifications
        notify_webhook: Enable webhook notifications
        webhook_url: Webhook URL for notifications
        created_at: Record creation timestamp
        last_checked_at: Last monitoring check timestamp
    """

    __tablename__ = "domain_watchlist"

    # Primary Key
    id: Mapped[int] = mapped_column(primary_key=True, index=True)

    # Foreign Key
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # Domain Data
    domain: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    brand_name: Mapped[Optional[str]] = mapped_column(String(255))

    # Monitoring Configuration
    monitoring_enabled: Mapped[bool] = mapped_column(
        Boolean, default=True, index=True
    )
    alert_threshold: Mapped[str] = mapped_column(String(20), default="medium")

    # Monitoring Features
    check_typosquatting: Mapped[bool] = mapped_column(Boolean, default=True)
    check_certificate_transparency: Mapped[bool] = mapped_column(Boolean, default=True)
    check_social_media: Mapped[bool] = mapped_column(Boolean, default=False)

    # Notifications
    notify_email: Mapped[bool] = mapped_column(Boolean, default=True)
    notify_webhook: Mapped[bool] = mapped_column(Boolean, default=False)
    webhook_url: Mapped[Optional[str]] = mapped_column(Text)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(default=datetime.utcnow, nullable=False)
    last_checked_at: Mapped[Optional[datetime]]

    # Relationships
    user: Mapped["User"] = relationship("User", back_populates="domain_watchlist")

    # Constraints & Indexes
    __table_args__ = (
        UniqueConstraint("user_id", "domain", name="unique_user_domain"),
        CheckConstraint(
            "alert_threshold IN ('low', 'medium', 'high', 'critical')",
            name="check_alert_threshold",
        ),
        Index("idx_watchlist_user_id", "user_id"),
        Index("idx_watchlist_domain", "domain"),
        Index("idx_watchlist_monitoring_enabled", "monitoring_enabled"),
    )

    def __repr__(self) -> str:
        """String representation of DomainWatchlist."""
        return (
            f"<DomainWatchlist(id={self.id}, domain='{self.domain}', "
            f"enabled={self.monitoring_enabled})>"
        )
