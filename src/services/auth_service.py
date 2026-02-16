"""Authentication service with JWT and bcrypt password hashing."""

from datetime import datetime, timedelta
from typing import Optional

from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.user import User

# Password hashing configuration
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT configuration
SECRET_KEY = "your-secret-key-change-this-in-production"  # TODO: Move to environment variable
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 24 hours
REFRESH_TOKEN_EXPIRE_DAYS = 30


class AuthService:
    """Authentication service for user registration, login, and JWT token management.

    Example:
        ```python
        auth_service = AuthService()

        # Register new user
        user = await auth_service.register_user(
            db, email="test@example.com", password="SecurePass123", full_name="Test User"
        )

        # Authenticate user
        user = await auth_service.authenticate_user(db, email="test@example.com", password="SecurePass123")

        # Create JWT tokens
        tokens = auth_service.create_access_token(user_id=user.id, email=user.email)
        ```
    """

    @staticmethod
    def hash_password(password: str) -> str:
        """Hash a password using bcrypt.

        Args:
            password: Plain text password

        Returns:
            Hashed password string

        Example:
            ```python
            hashed = AuthService.hash_password("MyPassword123")
            # Returns: $2b$12$KIX...
            ```
        """
        return pwd_context.hash(password)

    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """Verify a password against its hash.

        Args:
            plain_password: Plain text password to verify
            hashed_password: Hashed password to compare against

        Returns:
            True if password matches, False otherwise

        Example:
            ```python
            is_valid = AuthService.verify_password("MyPassword123", hashed_password)
            ```
        """
        return pwd_context.verify(plain_password, hashed_password)

    @staticmethod
    def create_access_token(
        user_id: int, email: str, expires_delta: Optional[timedelta] = None
    ) -> str:
        """Create a JWT access token.

        Args:
            user_id: User's ID
            email: User's email
            expires_delta: Optional custom expiration time

        Returns:
            JWT token string

        Example:
            ```python
            token = AuthService.create_access_token(user_id=1, email="test@example.com")
            # Returns: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
            ```
        """
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

        to_encode = {
            "sub": str(user_id),
            "email": email,
            "exp": expire,
            "type": "access",
        }
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        return encoded_jwt

    @staticmethod
    def create_refresh_token(user_id: int, email: str) -> str:
        """Create a JWT refresh token (longer expiration).

        Args:
            user_id: User's ID
            email: User's email

        Returns:
            JWT refresh token string

        Example:
            ```python
            refresh_token = AuthService.create_refresh_token(user_id=1, email="test@example.com")
            ```
        """
        expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

        to_encode = {
            "sub": str(user_id),
            "email": email,
            "exp": expire,
            "type": "refresh",
        }
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        return encoded_jwt

    @staticmethod
    def verify_token(token: str) -> Optional[dict]:
        """Verify and decode a JWT token.

        Args:
            token: JWT token to verify

        Returns:
            Token payload if valid, None otherwise

        Example:
            ```python
            payload = AuthService.verify_token(token)
            if payload:
                user_id = int(payload["sub"])
                email = payload["email"]
            ```
        """
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            return payload
        except JWTError:
            return None

    async def register_user(
        self,
        db: AsyncSession,
        email: str,
        password: str,
        full_name: Optional[str] = None,
        tier: str = "community",
    ) -> User:
        """Register a new user.

        Args:
            db: Database session
            email: User's email address
            password: Plain text password
            full_name: Optional full name
            tier: Subscription tier (default: community)

        Returns:
            Created User object

        Raises:
            ValueError: If email already exists

        Example:
            ```python
            user = await auth_service.register_user(
                db,
                email="test@example.com",
                password="SecurePass123",
                full_name="Test User"
            )
            ```
        """
        # Check if user already exists
        result = await db.execute(select(User).where(User.email == email))
        existing_user = result.scalar_one_or_none()
        if existing_user:
            raise ValueError(f"User with email {email} already exists")

        # Hash password
        password_hash = self.hash_password(password)

        # Create user
        user = User(
            email=email,
            password_hash=password_hash,
            full_name=full_name,
            tier=tier,
            status="active",
            email_verified=False,
        )

        db.add(user)
        await db.commit()
        await db.refresh(user)

        return user

    async def authenticate_user(
        self, db: AsyncSession, email: str, password: str
    ) -> Optional[User]:
        """Authenticate a user with email and password.

        Args:
            db: Database session
            email: User's email
            password: Plain text password

        Returns:
            User object if authentication successful, None otherwise

        Example:
            ```python
            user = await auth_service.authenticate_user(
                db,
                email="test@example.com",
                password="SecurePass123"
            )
            if user:
                print("Authentication successful")
            else:
                print("Invalid credentials")
            ```
        """
        result = await db.execute(select(User).where(User.email == email))
        user = result.scalar_one_or_none()

        if not user:
            return None

        if not self.verify_password(password, user.password_hash):
            return None

        # Update last login timestamp
        user.last_login_at = datetime.utcnow()
        await db.commit()

        return user

    async def get_user_by_id(self, db: AsyncSession, user_id: int) -> Optional[User]:
        """Get user by ID.

        Args:
            db: Database session
            user_id: User's ID

        Returns:
            User object if found, None otherwise

        Example:
            ```python
            user = await auth_service.get_user_by_id(db, user_id=1)
            ```
        """
        result = await db.execute(select(User).where(User.id == user_id))
        return result.scalar_one_or_none()

    async def get_user_by_email(self, db: AsyncSession, email: str) -> Optional[User]:
        """Get user by email.

        Args:
            db: Database session
            email: User's email

        Returns:
            User object if found, None otherwise

        Example:
            ```python
            user = await auth_service.get_user_by_email(db, email="test@example.com")
            ```
        """
        result = await db.execute(select(User).where(User.email == email))
        return result.scalar_one_or_none()
