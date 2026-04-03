"""Database initialization and session management"""

from sqlalchemy.ext.declarative import declarative_base
from .config import engine, async_session_maker

# Base class for all SQLAlchemy models
Base = declarative_base()


async def init_db() -> None:
    """Initialize database by creating all tables

    Called during application startup to ensure database schema is created
    """
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def close_db() -> None:
    """Close database connections

    Called during application shutdown for cleanup
    """
    await engine.dispose()


def get_session_factory():
    """Get the async session factory for database operations"""
    return async_session_maker
