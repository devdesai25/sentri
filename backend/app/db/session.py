import os
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.pool import NullPool

# Get database URL from environment variable with a default for development
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+asyncpg://postgres:postgres@localhost/sentri")

# Configure SQLAlchemy engine with proper pool size
engine = create_async_engine(
    DATABASE_URL,
    echo=os.getenv("SQL_ECHO", "False").lower() in ("true", "1", "t"),
    pool_size=int(os.getenv("DATABASE_POOL_SIZE", "5")),
    max_overflow=int(os.getenv("DATABASE_MAX_OVERFLOW", "10")),
    # Use NullPool in testing
    poolclass=NullPool if os.getenv("TESTING", "False").lower() in ("true", "1", "t") else None,
)

# Create session factory
AsyncSessionLocal = async_sessionmaker(
    engine, 
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


# Dependency to use in FastAPI endpoints
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Yield an async database session."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()