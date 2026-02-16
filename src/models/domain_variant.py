"""Domain Variant Model - Typosquatting Detection."""

from datetime import datetime
from typing import Optional
from sqlalchemy import String, Integer, DateTime, Boolean, Float, ForeignKey, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.models.base import Base


class DomainVariant(Base):
    """Domain variant model for typosquatting detection.

    Stores detected domain variants (typosquatting, homoglyphs, etc.)
    and their threat assessment.

    Attributes:
        id: Primary key
        target_domain: Original/legitimate domain being monitored
        variant_domain: Detected variant (potentially malicious)
        variant_type: Type of variant (homoglyph, typo, tld_variation, etc.)
        is_active: Whether domain is currently active (DNS resolves)
        confidence_score: Threat confidence score (0-100)
        threat_level: Classified threat level
        first_seen: When variant was first detected
        last_checked: Last verification timestamp
        scan_id: Optional link to full scan if performed
        whois_data: WHOIS information
        detection_method: How variant was discovered
        notes: Additional analyst notes

    Example:
        ```python
        variant = DomainVariant(
            target_domain="paypal.com",
            variant_domain="paypa1.com",  # l → 1
            variant_type="homoglyph",
            is_active=True,
            confidence_score=85,
            threat_level="high"
        )
        ```
    """

    __tablename__ = "domain_variants"

    # Primary Key
    id: Mapped[int] = mapped_column(primary_key=True)

    # Domain Information
    target_domain: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
        comment="Legitimate domain being monitored"
    )

    variant_domain: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        unique=True,
        index=True,
        comment="Detected variant domain"
    )

    variant_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
        comment="Type: homoglyph, typo, tld_variation, combo_squatting, etc."
    )

    # Status
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
        index=True,
        comment="Whether domain currently resolves"
    )

    # Threat Assessment
    confidence_score: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
        comment="Threat confidence score (0-100)"
    )

    threat_level: Mapped[Optional[str]] = mapped_column(
        String(20),
        nullable=True,
        index=True,
        comment="Threat level: safe, low, medium, high, critical"
    )

    # Relationships
    scan_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("scans.id", ondelete="SET NULL"),
        nullable=True,
        comment="Link to full scan if performed"
    )

    # Metadata
    whois_data: Mapped[Optional[dict]] = mapped_column(
        JSONB,
        nullable=True,
        comment="WHOIS lookup results"
    )

    detection_method: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="automated",
        comment="Detection method: automated, manual, ct_logs, etc."
    )

    notes: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        comment="Analyst notes and observations"
    )

    # Timestamps
    first_seen: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=datetime.utcnow,
        index=True,
        comment="First detection timestamp"
    )

    last_checked: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        comment="Last verification timestamp"
    )

    # Relationships
    scan: Mapped[Optional["Scan"]] = relationship(
        "Scan",
        back_populates="domain_variants",
        foreign_keys=[scan_id]
    )

    def __repr__(self) -> str:
        return (
            f"<DomainVariant(id={self.id}, "
            f"variant='{self.variant_domain}', "
            f"type='{self.variant_type}', "
            f"threat='{self.threat_level}')>"
        )
