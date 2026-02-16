"""Database configuration and session management for Anisakys Enterprise."""

from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    create_async_engine,
    async_sessionmaker,
)

from src.config import settings
from src.models.base import Base


# Create async engine with connection pooling
# Note: For async engines, SQLAlchemy automatically uses AsyncAdaptedQueuePool
engine = create_async_engine(
    settings.DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://"),
    pool_size=20,  # Persistent connections
    max_overflow=40,  # Burst capacity
    pool_pre_ping=True,  # Verify connection health
    pool_recycle=3600,  # Recycle connections every hour
    echo=False,  # Set to True for SQL debugging
)

# Create async session factory
AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Get database session dependency for FastAPI.

    Yields:
        AsyncSession: Database session

    Example:
        ```python
        @app.get("/users")
        async def get_users(db: AsyncSession = Depends(get_db)):
            result = await db.execute(select(User))
            return result.scalars().all()
        ```
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db() -> None:
    """Initialize database by creating all tables.

    This is for development/testing only. In production, use Alembic migrations.

    Example:
        ```python
        import asyncio
        from src.database import init_db

        asyncio.run(init_db())
        ```
    """
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def drop_db() -> None:
    """Drop all tables.

    WARNING: This will delete all data. Use only in development/testing.

    Example:
        ```python
        import asyncio
        from src.database import drop_db

        asyncio.run(drop_db())
        ```
    """
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
