"""Scan and BatchScan models for URL analysis."""

from datetime import datetime
from decimal import Decimal
from typing import List, Optional

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import INET, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.models.base import Base


class Scan(Base):
    """Scan model for URL scan results and metadata.

    Attributes:
        id: Primary key
        user_id: Foreign key to users table
        url: Full URL to scan
        url_hash: SHA256 hash for deduplication
        scan_type: Type of scan (manual, batch, scheduled, api)
        status: Scan status (pending, processing, completed, failed)
        threat_level: Assessed threat level (safe, low, medium, high, critical)
        confidence_score: Confidence score (0.00 to 100.00)
        is_phishing: Boolean indicating if URL is phishing
        virustotal_result: VirusTotal API response (JSONB)
        urlvoid_result: URLVoid API response (JSONB)
        phishtank_result: PhishTank API response (JSONB)
        grinder_result: Grinder API response (JSONB)
        screenshot_url: S3/MinIO path to screenshot
        screenshot_hash: SHA256 hash for deduplication
        html_snapshot_url: Archived HTML path
        whois_data: WHOIS lookup data (JSONB)
        domain: Extracted domain name
        ip_address: Resolved IP address
        country_code: GeoIP country code
        hosting_provider: Hosting provider name
        scan_started_at: When scan started
        scan_completed_at: When scan completed
        created_at: Record creation timestamp
        scan_duration_ms: Total scan duration in milliseconds
    """

    __tablename__ = "scans"

    # Primary Key
    id: Mapped[int] = mapped_column(primary_key=True, index=True)

    # Foreign Key
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # URL Data
    url: Mapped[str] = mapped_column(Text, nullable=False)
    url_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    # Scan Metadata
    scan_type: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[str] = mapped_column(
        String(20), default="pending", nullable=False, index=True
    )

    # Threat Assessment
    threat_level: Mapped[Optional[str]] = mapped_column(String(20), index=True)
    confidence_score: Mapped[Optional[Decimal]] = mapped_column(Numeric(5, 2))
    is_phishing: Mapped[Optional[bool]] = mapped_column(Boolean)

    # API Results (JSONB for flexibility)
    virustotal_result: Mapped[Optional[dict]] = mapped_column(JSON)
    urlvoid_result: Mapped[Optional[dict]] = mapped_column(JSON)
    phishtank_result: Mapped[Optional[dict]] = mapped_column(JSON)
    grinder_result: Mapped[Optional[dict]] = mapped_column(JSON)

    # Evidence
    screenshot_url: Mapped[Optional[str]] = mapped_column(Text)
    screenshot_hash: Mapped[Optional[str]] = mapped_column(String(64))
    html_snapshot_url: Mapped[Optional[str]] = mapped_column(Text)

    # WHOIS Data (Sprint 2)
    whois_data: Mapped[Optional[dict]] = mapped_column(JSON)

    # Domain Metadata
    domain: Mapped[Optional[str]] = mapped_column(String(255), index=True)
    ip_address: Mapped[Optional[str]] = mapped_column(INET)
    country_code: Mapped[Optional[str]] = mapped_column(String(2))
    hosting_provider: Mapped[Optional[str]] = mapped_column(String(255))

    # Timestamps
    scan_started_at: Mapped[Optional[datetime]]
    scan_completed_at: Mapped[Optional[datetime]]
    created_at: Mapped[datetime] = mapped_column(
        default=datetime.utcnow, nullable=False, index=True
    )

    # Performance Metrics
    scan_duration_ms: Mapped[Optional[int]] = mapped_column(Integer)

    # Relationships
    user: Mapped["User"] = relationship("User", back_populates="scans")
    abuse_reports: Mapped[List["AbuseReport"]] = relationship(
        "AbuseReport", back_populates="scan"
    )
    domain_variants: Mapped[List["DomainVariant"]] = relationship(
        "DomainVariant", back_populates="scan", foreign_keys="[DomainVariant.scan_id]"
    )
    case_assignments: Mapped[List["CaseAssignment"]] = relationship(
        "CaseAssignment", back_populates="scan", foreign_keys="[CaseAssignment.scan_id]"
    )
    notes: Mapped[List["Note"]] = relationship(
        "Note", back_populates="scan", foreign_keys="[Note.scan_id]"
    )

    # Constraints & Indexes
    __table_args__ = (
        CheckConstraint(
            "status IN ('pending', 'processing', 'completed', 'failed')",
            name="check_status",
        ),
        CheckConstraint(
            "threat_level IN ('safe', 'low', 'medium', 'high', 'critical')",
            name="check_threat_level",
        ),
        CheckConstraint(
            "confidence_score BETWEEN 0 AND 100", name="check_confidence_score"
        ),
        Index("idx_scans_user_id", "user_id"),
        Index("idx_scans_url_hash", "url_hash"),
        Index("idx_scans_domain", "domain"),
        Index("idx_scans_threat_level", "threat_level"),
        Index("idx_scans_created_at", "created_at", postgresql_using="btree"),
        Index("idx_scans_status", "status"),
        Index("idx_scans_user_created", "user_id", "created_at"),
        Index(
            "idx_scans_virustotal_result",
            "virustotal_result",
            postgresql_using="gin",
        ),
    )

    def __repr__(self) -> str:
        """String representation of Scan."""
        return (
            f"<Scan(id={self.id}, url='{self.url[:50]}...', "
            f"threat_level='{self.threat_level}', status='{self.status}')>"
        )


class BatchScan(Base):
    """BatchScan model for batch URL scanning management.

    Attributes:
        id: Primary key
        user_id: Foreign key to users table
        batch_name: Optional user-defined batch name
        total_urls: Total number of URLs in batch
        completed_urls: Number of completed scans
        failed_urls: Number of failed scans
        status: Batch status (pending, processing, completed, failed)
        progress_percentage: Progress percentage (0.00 to 100.00)
        created_at: Batch creation timestamp
        started_at: Batch processing start time
        completed_at: Batch completion time
    """

    __tablename__ = "batch_scans"

    # Primary Key
    id: Mapped[int] = mapped_column(primary_key=True, index=True)

    # Foreign Key
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # Batch Metadata
    batch_name: Mapped[Optional[str]] = mapped_column(String(255))
    total_urls: Mapped[int] = mapped_column(Integer, nullable=False)
    completed_urls: Mapped[int] = mapped_column(Integer, default=0)
    failed_urls: Mapped[int] = mapped_column(Integer, default=0)

    # Status
    status: Mapped[str] = mapped_column(
        String(20), default="pending", nullable=False, index=True
    )
    progress_percentage: Mapped[Decimal] = mapped_column(
        Numeric(5, 2), default=Decimal("0.00")
    )

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        default=datetime.utcnow, nullable=False, index=True
    )
    started_at: Mapped[Optional[datetime]]
    completed_at: Mapped[Optional[datetime]]

    # Relationships
    user: Mapped["User"] = relationship("User", back_populates="batch_scans")

    # Constraints & Indexes
    __table_args__ = (
        CheckConstraint(
            "status IN ('pending', 'processing', 'completed', 'failed')",
            name="check_batch_status",
        ),
        Index("idx_batch_scans_user_id", "user_id"),
        Index("idx_batch_scans_status", "status"),
        Index("idx_batch_scans_created_at", "created_at"),
    )

    def __repr__(self) -> str:
        """String representation of BatchScan."""
        return (
            f"<BatchScan(id={self.id}, total={self.total_urls}, "
            f"completed={self.completed_urls}, status='{self.status}')>"
        )
