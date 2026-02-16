"""Certificate Transparency Certificate Model."""

from datetime import datetime
from typing import Optional, List
from sqlalchemy import String, Integer, DateTime, Boolean, Text, Index
from sqlalchemy.dialects.postgresql import JSONB, ARRAY
from sqlalchemy.orm import Mapped, mapped_column

from src.models.base import Base


class CTCertificate(Base):
    """Certificate Transparency certificate model.

    Stores certificates discovered through CT log monitoring for
    suspicious domain detection.

    Attributes:
        id: Primary key
        cert_id: Certificate ID from CT log
        issuer: Certificate issuer
        subject_cn: Subject Common Name
        san_domains: Subject Alternative Names (all domains)
        not_before: Certificate validity start
        not_after: Certificate validity end
        fingerprint: Certificate fingerprint (SHA256)
        log_source: CT log source (crt.sh, google, cloudflare)
        is_suspicious: Whether cert is flagged as suspicious
        matched_keywords: Keywords that triggered detection
        confidence_score: Threat confidence (0-100)
        threat_level: Assessed threat level
        scan_triggered: Whether automatic scan was triggered
        discovered_at: When certificate was discovered
        notes: Analyst notes

    Example:
        ```python
        cert = CTCertificate(
            cert_id="12345678",
            issuer="Let's Encrypt",
            subject_cn="paypa1-login.com",
            san_domains=["paypa1-login.com", "www.paypa1-login.com"],
            matched_keywords=["paypal"],
            is_suspicious=True,
            confidence_score=90,
            threat_level="high"
        )
        ```
    """

    __tablename__ = "ct_certificates"

    # Primary Key
    id: Mapped[int] = mapped_column(primary_key=True)

    # Certificate Identity
    cert_id: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        unique=True,
        index=True,
        comment="Certificate ID from CT log"
    )

    fingerprint: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        unique=True,
        index=True,
        comment="SHA256 fingerprint"
    )

    # Certificate Details
    issuer: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="Certificate issuer"
    )

    subject_cn: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
        comment="Subject Common Name"
    )

    san_domains: Mapped[List[str]] = mapped_column(
        ARRAY(String),
        nullable=False,
        default=list,
        comment="Subject Alternative Names (all domains)"
    )

    # Validity Period
    not_before: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        comment="Certificate valid from"
    )

    not_after: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        comment="Certificate valid until"
    )

    # Discovery
    log_source: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
        comment="CT log source: crt.sh, google_argon, cloudflare_nimbus"
    )

    discovered_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=datetime.utcnow,
        index=True,
        comment="Discovery timestamp"
    )

    # Threat Assessment
    is_suspicious: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        index=True,
        comment="Whether certificate is flagged as suspicious"
    )

    matched_keywords: Mapped[Optional[List[str]]] = mapped_column(
        ARRAY(String),
        nullable=True,
        comment="Keywords that triggered detection"
    )

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

    # Action Taken
    scan_triggered: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        comment="Whether automatic scan was triggered"
    )

    # Additional Data
    raw_data: Mapped[Optional[dict]] = mapped_column(
        JSONB,
        nullable=True,
        comment="Raw certificate data from CT log"
    )

    notes: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        comment="Analyst notes"
    )

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=datetime.utcnow,
        comment="Record creation timestamp"
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        comment="Record update timestamp"
    )

    # Composite Indexes for Performance
    __table_args__ = (
        Index('idx_ct_cert_suspicious_discovered', 'is_suspicious', 'discovered_at'),
        Index('idx_ct_cert_threat_level', 'threat_level', 'discovered_at'),
        Index('idx_ct_cert_scan_triggered', 'scan_triggered', 'is_suspicious'),
    )

    def __repr__(self) -> str:
        return (
            f"<CTCertificate(id={self.id}, "
            f"subject='{self.subject_cn}', "
            f"suspicious={self.is_suspicious}, "
            f"threat='{self.threat_level}')>"
        )
