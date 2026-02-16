"""API Key service for managing programmatic access."""

import hashlib
import secrets
from datetime import datetime
from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.api_key import APIKey
from src.models.user import User


class APIKeyService:
    """API Key service for generating and managing API keys.

    Example:
        ```python
        api_key_service = APIKeyService()

        # Generate new API key
        api_key, key_obj = await api_key_service.create_api_key(
            db, user_id=1, name="Production API Key"
        )

        # Validate API key
        key_obj = await api_key_service.validate_api_key(db, api_key)
        ```
    """

    KEY_PREFIX = "ak_"  # API Key prefix
    KEY_LENGTH = 32  # Length of the secret part (bytes)

    @staticmethod
    def generate_api_key() -> str:
        """Generate a new API key.

        Returns:
            API key string in format: ak_{random_hex}

        Example:
            ```python
            api_key = APIKeyService.generate_api_key()
            # Returns: ak_1234567890abcdef...
            ```
        """
        random_bytes = secrets.token_hex(APIKeyService.KEY_LENGTH)
        return f"{APIKeyService.KEY_PREFIX}{random_bytes}"

    @staticmethod
    def hash_api_key(api_key: str) -> str:
        """Hash an API key using SHA256.

        Args:
            api_key: API key to hash

        Returns:
            SHA256 hash of the API key

        Example:
            ```python
            key_hash = APIKeyService.hash_api_key("ak_1234567890abcdef...")
            ```
        """
        return hashlib.sha256(api_key.encode()).hexdigest()

    @staticmethod
    def get_key_prefix(api_key: str) -> str:
        """Extract first 16 characters of API key for display.

        Args:
            api_key: Full API key

        Returns:
            First 16 characters for display

        Example:
            ```python
            prefix = APIKeyService.get_key_prefix("ak_1234567890abcdef...")
            # Returns: ak_1234567890ab...
            ```
        """
        return api_key[:16] if len(api_key) >= 16 else api_key

    async def create_api_key(
        self,
        db: AsyncSession,
        user_id: int,
        name: Optional[str] = None,
        scopes: Optional[List[str]] = None,
        rate_limit_tier: Optional[str] = None,
        expires_at: Optional[datetime] = None,
    ) -> tuple[str, APIKey]:
        """Create a new API key for a user.

        Args:
            db: Database session
            user_id: User's ID
            name: Optional user-defined name for the key
            scopes: Optional list of permissions
            rate_limit_tier: Optional custom rate limit tier
            expires_at: Optional expiration timestamp

        Returns:
            Tuple of (plain API key string, APIKey object)
            NOTE: Plain key is returned only once, store it securely!

        Example:
            ```python
            api_key, key_obj = await api_key_service.create_api_key(
                db,
                user_id=1,
                name="Production API",
                scopes=["scan:read", "scan:write"]
            )
            # api_key: ak_1234567890abcdef... (store this!)
            # key_obj: APIKey database object
            ```
        """
        # Generate API key
        api_key = self.generate_api_key()
        key_hash = self.hash_api_key(api_key)
        key_prefix = self.get_key_prefix(api_key)

        # Create APIKey object
        api_key_obj = APIKey(
            user_id=user_id,
            key_hash=key_hash,
            key_prefix=key_prefix,
            name=name,
            scopes=scopes or ["scan:read", "scan:write"],
            rate_limit_tier=rate_limit_tier,
            is_active=True,
            expires_at=expires_at,
        )

        db.add(api_key_obj)
        await db.commit()
        await db.refresh(api_key_obj)

        # Return both plain key (only time it's visible) and object
        return api_key, api_key_obj

    async def validate_api_key(
        self, db: AsyncSession, api_key: str
    ) -> Optional[APIKey]:
        """Validate an API key and return the associated APIKey object.

        Args:
            db: Database session
            api_key: Plain API key to validate

        Returns:
            APIKey object if valid, None if invalid/expired/revoked

        Example:
            ```python
            key_obj = await api_key_service.validate_api_key(db, api_key)
            if key_obj:
                print(f"Valid key for user {key_obj.user_id}")
            else:
                print("Invalid API key")
            ```
        """
        key_hash = self.hash_api_key(api_key)

        result = await db.execute(
            select(APIKey).where(APIKey.key_hash == key_hash)
        )
        api_key_obj = result.scalar_one_or_none()

        if not api_key_obj:
            return None

        # Check if key is active
        if not api_key_obj.is_active:
            return None

        # Check if key is expired
        if api_key_obj.expires_at and api_key_obj.expires_at < datetime.utcnow():
            return None

        # Update last_used_at timestamp
        api_key_obj.last_used_at = datetime.utcnow()
        await db.commit()

        return api_key_obj

    async def list_user_api_keys(
        self, db: AsyncSession, user_id: int
    ) -> List[APIKey]:
        """List all API keys for a user.

        Args:
            db: Database session
            user_id: User's ID

        Returns:
            List of APIKey objects

        Example:
            ```python
            keys = await api_key_service.list_user_api_keys(db, user_id=1)
            for key in keys:
                print(f"{key.name}: {key.key_prefix}... (active: {key.is_active})")
            ```
        """
        result = await db.execute(
            select(APIKey).where(APIKey.user_id == user_id)
        )
        return list(result.scalars().all())

    async def revoke_api_key(
        self, db: AsyncSession, api_key_id: int, user_id: int
    ) -> bool:
        """Revoke an API key (set is_active = False).

        Args:
            db: Database session
            api_key_id: API key ID to revoke
            user_id: User's ID (for authorization)

        Returns:
            True if revoked successfully, False if not found or unauthorized

        Example:
            ```python
            success = await api_key_service.revoke_api_key(db, api_key_id=1, user_id=1)
            if success:
                print("API key revoked")
            ```
        """
        result = await db.execute(
            select(APIKey).where(
                APIKey.id == api_key_id, APIKey.user_id == user_id
            )
        )
        api_key_obj = result.scalar_one_or_none()

        if not api_key_obj:
            return False

        api_key_obj.is_active = False
        await db.commit()

        return True

    async def delete_api_key(
        self, db: AsyncSession, api_key_id: int, user_id: int
    ) -> bool:
        """Permanently delete an API key.

        Args:
            db: Database session
            api_key_id: API key ID to delete
            user_id: User's ID (for authorization)

        Returns:
            True if deleted successfully, False if not found or unauthorized

        Example:
            ```python
            success = await api_key_service.delete_api_key(db, api_key_id=1, user_id=1)
            if success:
                print("API key deleted permanently")
            ```
        """
        result = await db.execute(
            select(APIKey).where(
                APIKey.id == api_key_id, APIKey.user_id == user_id
            )
        )
        api_key_obj = result.scalar_one_or_none()

        if not api_key_obj:
            return False

        await db.delete(api_key_obj)
        await db.commit()

        return True
