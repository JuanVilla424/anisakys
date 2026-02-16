"""Authentication endpoints."""

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.dependencies import get_db, get_current_user
from src.services import AuthService
from src.models.user import User


router = APIRouter(prefix="/auth", tags=["Authentication"])


class RegisterRequest(BaseModel):
    """User registration request."""
    email: EmailStr
    password: str = Field(..., min_length=8, description="Minimum 8 characters")
    full_name: str = Field(..., min_length=2, max_length=100)


class LoginRequest(BaseModel):
    """User login request."""
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    """JWT token response."""
    access_token: str
    token_type: str = "bearer"
    expires_in: int = 3600  # 1 hour


class UserResponse(BaseModel):
    """User profile response."""
    id: int
    email: str
    full_name: str
    is_active: bool
    is_verified: bool

    class Config:
        from_attributes = True


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(
    request: RegisterRequest,
    db: AsyncSession = Depends(get_db)
):
    """Register new user account.

    Args:
        request: Registration data
        db: Database session

    Returns:
        Created user profile

    Raises:
        HTTPException: If email already registered
    """
    auth_service = AuthService(db)

    # Check if email exists
    existing_user = await auth_service.get_user_by_email(request.email)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )

    # Create user
    user = await auth_service.create_user(
        email=request.email,
        password=request.password,
        full_name=request.full_name
    )

    return UserResponse.from_orm(user)


@router.post("/login", response_model=TokenResponse)
async def login(
    request: LoginRequest,
    db: AsyncSession = Depends(get_db)
):
    """Login with email and password.

    Args:
        request: Login credentials
        db: Database session

    Returns:
        JWT access token

    Raises:
        HTTPException: If credentials invalid
    """
    auth_service = AuthService(db)

    # Authenticate user
    user = await auth_service.authenticate_user(request.email, request.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Generate token
    access_token = auth_service.create_access_token(user.id)

    return TokenResponse(access_token=access_token)


@router.get("/me", response_model=UserResponse)
async def get_current_user_profile(
    current_user: User = Depends(get_current_user)
):
    """Get current user profile.

    Args:
        current_user: Authenticated user from JWT

    Returns:
        User profile
    """
    return UserResponse.from_orm(current_user)


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Refresh access token.

    Args:
        current_user: Authenticated user from JWT
        db: Database session

    Returns:
        New JWT access token
    """
    auth_service = AuthService(db)
    access_token = auth_service.create_access_token(current_user.id)

    return TokenResponse(access_token=access_token)
