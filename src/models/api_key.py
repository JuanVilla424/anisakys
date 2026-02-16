"""API Key model for programmatic access."""

from datetime import datetime
from typing import List, Optional

from sqlalchemy import Boolean, ForeignKey, Index, String, ARRAY, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.models.base import Base


class APIKey(Base):
    """API Key model for programmatic access.

    Attributes:
        id: Primary key
        user_id: Foreign key to users table
        key_hash: SHA256 hash of the actual API key
        key_prefix: First 8 characters for display (e.g., ak_12345678...)
        name: User-defined name for the key
        scopes: Array of permissions (e.g., ['scan:read', 'scan:write'])
        rate_limit_tier: Override tier rate limit if needed
        is_active: Whether the key is currently active
        last_used_at: Last time the key was used
        expires_at: Expiration timestamp (NULL = never expires)
        created_at: Key creation timestamp
    """

    __tablename__ = "api_keys"

    # Primary Key
    id: Mapped[int] = mapped_column(primary_key=True, index=True)

    # Foreign Key
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # Key Data
    key_hash: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    key_prefix: Mapped[str] = mapped_column(String(20), nullable=False)

    # Metadata
    name: Mapped[Optional[str]] = mapped_column(String(100))
    scopes: Mapped[Optional[List[str]]] = mapped_column(ARRAY(Text))
    rate_limit_tier: Mapped[Optional[str]] = mapped_column(String(20))

    # Status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)

    # Timestamps
    last_used_at: Mapped[Optional[datetime]]
    expires_at: Mapped[Optional[datetime]] = mapped_column(index=True)
    created_at: Mapped[datetime] = mapped_column(default=datetime.utcnow, nullable=False)

    # Relationships
    user: Mapped["User"] = relationship("User", back_populates="api_keys")

    # Indexes
    __table_args__ = (
        Index("idx_api_keys_user_id", "user_id"),
        Index("idx_api_keys_key_hash", "key_hash"),
        Index("idx_api_keys_is_active", "is_active"),
        Index(
            "idx_api_keys_expires_at",
            "expires_at",
            postgresql_where="expires_at IS NOT NULL",
        ),
    )

    def __repr__(self) -> str:
        """String representation of APIKey."""
        return f"<APIKey(id={self.id}, prefix='{self.key_prefix}', active={self.is_active})>"
