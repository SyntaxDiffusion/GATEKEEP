"""
FastAPI dependency injection providers for GATEKEEP.

Centralizes session management, configuration access, service
instantiation, and privilege enforcement as injectable dependencies.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator

from fastapi import Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from gatekeep.config import GatekeepConfig
from gatekeep.config import get_config as _get_config
from gatekeep.database import get_db
from gatekeep.privileges import PrivilegeLevel, get_privilege_level


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Yield an async database session for the duration of a request.

    Commits on success, rolls back on exception. Delegates to the
    core get_db() generator.
    """
    async for session in get_db():
        yield session


def get_config() -> GatekeepConfig:
    """Return the global configuration singleton."""
    return _get_config()


async def get_scan_service(
    db: AsyncSession = Depends(get_db_session),
    config: GatekeepConfig = Depends(get_config),
) -> "ScanService":
    """
    Construct and return a ScanService instance with injected dependencies.

    Lazily imports ScanService to avoid circular imports during
    early application bootstrapping.
    """
    from gatekeep.services.scan_service import ScanService

    return ScanService(db=db, config=config)


async def verify_token(request: Request) -> None:
    """
    Dependency that verifies the Bearer token in the Authorization header.

    Compares the token against ``request.app.state.auth_token`` which is
    generated at startup.  Raises HTTP 401 if the token is missing or
    does not match.
    """
    expected = getattr(request.app.state, "auth_token", None)
    if expected is None:
        # Auth not configured (e.g. during tests) — allow through
        return

    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Missing or malformed Authorization header.",
        )

    token = auth_header[7:]  # strip "Bearer "
    if token != expected:
        raise HTTPException(
            status_code=401,
            detail="Invalid access token.",
        )


async def require_admin() -> PrivilegeLevel:
    """
    Dependency that enforces administrator privileges.

    Raises HTTP 403 if the process is not running with elevated
    permissions.

    Returns:
        PrivilegeLevel.ADMIN on success.
    """
    level = get_privilege_level()
    if level != PrivilegeLevel.ADMIN:
        raise HTTPException(
            status_code=403,
            detail={
                "status": "error",
                "data": None,
                "error": {
                    "message": (
                        "This endpoint requires administrator privileges. "
                        "Restart GATEKEEP with elevated permissions."
                    ),
                    "required_level": PrivilegeLevel.ADMIN.value,
                    "current_level": level.value,
                },
                "meta": None,
            },
        )
    return level
