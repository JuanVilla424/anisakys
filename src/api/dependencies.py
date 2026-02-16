"""FastAPI dependencies for dependency injection."""

from typing import AsyncGenerator, Optional
from fastapi import Depends, HTTPException, Header, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession

from src.database import AsyncSessionLocal
from src.services import AuthService, APIKeyService, ScanningService
from src.models.user import User


security = HTTPBearer()


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Database session dependency.

    Yields:
        AsyncSession for database operations
    """
    async with AsyncSessionLocal() as session:
        yield session


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db)
) -> User:
    """Get currently authenticated user from JWT token.

    Args:
        credentials: Bearer token credentials
        db: Database session

    Returns:
        Authenticated User object

    Raises:
        HTTPException: If token invalid or user not found
    """
    token = credentials.credentials
    auth_service = AuthService(db)

    user = await auth_service.verify_access_token(token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


async def get_optional_user(
    authorization: Optional[str] = Header(None),
    db: AsyncSession = Depends(get_db)
) -> Optional[User]:
    """Get user from token if provided (optional auth).

    Args:
        authorization: Optional Authorization header
        db: Database session

    Returns:
        User if token valid, None otherwise
    """
    if not authorization or not authorization.startswith("Bearer "):
        return None

    token = authorization.replace("Bearer ", "")
    auth_service = AuthService(db)

    return await auth_service.verify_access_token(token)


async def get_scanning_service(
    db: AsyncSession = Depends(get_db)
) -> ScanningService:
    """Get scanning service instance.

    Args:
        db: Database session

    Returns:
        ScanningService instance
    """
    return ScanningService(db)


async def verify_api_key(
    x_api_key: str = Header(...),
    db: AsyncSession = Depends(get_db)
) -> User:
    """Verify API key and return associated user.

    Args:
        x_api_key: API key from X-API-Key header
        db: Database session

    Returns:
        User associated with API key

    Raises:
        HTTPException: If API key invalid or expired
    """
    api_key_service = APIKeyService(db)

    api_key_obj = await api_key_service.validate_api_key(x_api_key)
    if not api_key_obj:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired API key"
        )

    # Increment usage count
    await api_key_service.increment_usage(api_key_obj.id)

    return api_key_obj.user
