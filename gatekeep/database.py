"""
Async database engine and session management for GATEKEEP.

Uses SQLAlchemy 2.0 async API with aiosqlite. Configures WAL mode,
foreign key enforcement, and a 5-second busy timeout for SQLite.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from typing import Optional

from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import StaticPool

from gatekeep.config import get_config

_engine: Optional[AsyncEngine] = None
_session_factory: Optional[async_sessionmaker[AsyncSession]] = None


def _get_database_url() -> str:
    """Build the aiosqlite connection URL from config."""
    db_path = get_config().app.database_path
    return f"sqlite+aiosqlite:///{db_path}"


def _set_sqlite_pragmas(dbapi_conn, _connection_record) -> None:  # type: ignore[no-untyped-def]
    """Set SQLite pragmas on every new raw connection."""
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.execute("PRAGMA busy_timeout=30000")
    cursor.close()


def get_engine() -> AsyncEngine:
    """Return the singleton async engine, creating it on first call."""
    global _engine
    if _engine is None:
        url = _get_database_url()
        _engine = create_async_engine(
            url,
            echo=False,
            poolclass=StaticPool,
            connect_args={"check_same_thread": False},
        )
        # Register pragma hook on the underlying sync engine
        event.listen(_engine.sync_engine, "connect", _set_sqlite_pragmas)
    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    """Return the singleton session factory."""
    global _session_factory
    if _session_factory is None:
        _session_factory = async_sessionmaker(
            bind=get_engine(),
            class_=AsyncSession,
            expire_on_commit=False,
        )
    return _session_factory


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI dependency that yields an async database session.

    Usage in route handlers:
        async def my_route(db: AsyncSession = Depends(get_db)):
            ...
    """
    factory = get_session_factory()
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def init_db() -> None:
    """
    Create all tables defined in the ORM metadata.

    Should be called once during application startup. Imports models
    to ensure all table definitions are registered before creating.
    """
    from gatekeep.models import Base

    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Verify pragmas are active
    factory = get_session_factory()
    async with factory() as session:
        result = await session.execute(text("PRAGMA journal_mode"))
        journal_mode = result.scalar()
        result = await session.execute(text("PRAGMA foreign_keys"))
        fk_status = result.scalar()

    return None


async def close_db() -> None:
    """Dispose of the engine connection pool. Call on shutdown."""
    global _engine, _session_factory
    if _engine is not None:
        await _engine.dispose()
        _engine = None
        _session_factory = None
