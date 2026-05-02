"""
Monitoring and IOC API routes for GATEKEEP.

Provides endpoints to start/stop real-time packet monitoring, check
monitoring status, and manage the IOC indicator database.
"""

from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from gatekeep.api.deps import get_db_session, require_admin
from gatekeep.ioc.loader import get_indicator_stats, refresh_indicators
from gatekeep.privileges import PrivilegeLevel
from gatekeep.schemas import ApiResponse

router = APIRouter(prefix="/monitor", tags=["monitor"])
ioc_router = APIRouter(prefix="/ioc", tags=["monitor"])


# ---------------------------------------------------------------------------
# Request schemas
# ---------------------------------------------------------------------------


class StartMonitorRequest(BaseModel):
    """Request body for starting a monitoring session."""

    interface: str
    filters: Optional[dict[str, Any]] = None


# ---------------------------------------------------------------------------
# Monitor routes
# ---------------------------------------------------------------------------


def _get_monitor_service(request: Request):
    """Retrieve MonitorService from application state."""
    svc = getattr(request.app.state, "monitor_service", None)
    if svc is None:
        raise HTTPException(
            status_code=503,
            detail={
                "status": "error",
                "data": None,
                "error": {"message": "Monitor service is not available."},
                "meta": None,
            },
        )
    return svc


@router.post("/start", response_model=ApiResponse[dict[str, Any]])
async def start_monitoring(
    body: StartMonitorRequest,
    request: Request,
    _: PrivilegeLevel = Depends(require_admin),
) -> ApiResponse[dict[str, Any]]:
    """
    Start real-time packet capture on the specified interface.

    Requires administrator privileges — packet capture uses raw sockets.
    Returns the new monitoring session ID and initial status.
    Raises 403 if not running as administrator, 409 if monitoring is
    already active, and 503 if Npcap is unavailable or the interface
    does not exist.
    """
    svc = _get_monitor_service(request)

    if svc.is_active:
        raise HTTPException(
            status_code=409,
            detail={
                "status": "error",
                "data": None,
                "error": {
                    "message": (
                        "A monitoring session is already active. "
                        "Stop it before starting a new one."
                    )
                },
                "meta": None,
            },
        )

    try:
        session_id = await svc.start_monitoring(
            interface=body.interface,
            filters=body.filters,
        )
    except RuntimeError as exc:
        raise HTTPException(
            status_code=409,
            detail={
                "status": "error",
                "data": None,
                "error": {"message": str(exc)},
                "meta": None,
            },
        ) from exc
    except Exception as exc:
        # NpcapNotFoundError and InterfaceNotFoundError propagate to
        # the registered exception handlers; re-raise unchanged.
        raise

    return ApiResponse[dict[str, Any]](
        status="success",
        data={"session_id": session_id, "status": "running", "interface": body.interface},
    )


@router.post("/stop", response_model=ApiResponse[dict[str, Any]])
async def stop_monitoring(request: Request) -> ApiResponse[dict[str, Any]]:
    """
    Stop the currently active monitoring session.

    Returns a summary of the session including total packets captured
    and alerts generated.  Raises 409 if no session is active.
    """
    svc = _get_monitor_service(request)

    if not svc.is_active:
        raise HTTPException(
            status_code=409,
            detail={
                "status": "error",
                "data": None,
                "error": {"message": "No monitoring session is currently active."},
                "meta": None,
            },
        )

    try:
        summary = await svc.stop_monitoring()
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    return ApiResponse[dict[str, Any]](status="success", data=summary)


@router.get("/status", response_model=ApiResponse[dict[str, Any]])
async def get_monitoring_status(request: Request) -> ApiResponse[dict[str, Any]]:
    """
    Return the current monitoring state.

    Includes active flag, session ID, uptime in seconds, and packet
    count since the session started.
    """
    svc = _get_monitor_service(request)
    status = await svc.get_status()
    return ApiResponse[dict[str, Any]](status="success", data=status)


# ---------------------------------------------------------------------------
# IOC routes
# ---------------------------------------------------------------------------


@ioc_router.get("/status", response_model=ApiResponse[dict[str, Any]])
async def get_ioc_status(
    request: Request,
    db: AsyncSession = Depends(get_db_session),
) -> ApiResponse[dict[str, Any]]:
    """
    Return IOC indicator database status.

    Reports the last load timestamp, total indicator count, and
    data sources from the in-memory IOCMatcher as well as DB stats.
    """
    ioc_matcher = getattr(request.app.state, "ioc_matcher", None)

    in_memory: dict[str, Any] = {}
    if ioc_matcher is not None:
        last_updated = ioc_matcher.last_updated
        in_memory = {
            "indicator_count": ioc_matcher.indicator_count,
            "last_updated": last_updated.isoformat() if last_updated else None,
        }

    db_stats = await get_indicator_stats(db)

    return ApiResponse[dict[str, Any]](
        status="success",
        data={
            **db_stats,
            "in_memory": in_memory,
        },
    )


@ioc_router.post("/refresh", response_model=ApiResponse[dict[str, Any]])
async def refresh_ioc(
    request: Request,
    db: AsyncSession = Depends(get_db_session),
) -> ApiResponse[dict[str, Any]]:
    """
    Reload IOC indicators from the bundled JSON file.

    Updates both the database table and the in-memory IOCMatcher lookup
    structures.  Returns the count of newly loaded indicators.
    """
    # Refresh DB
    stats = await refresh_indicators(db)

    # Reload in-memory matcher
    ioc_matcher = getattr(request.app.state, "ioc_matcher", None)
    if ioc_matcher is not None:
        await ioc_matcher.load_indicators()

    return ApiResponse[dict[str, Any]](
        status="success",
        data={
            "loaded_count": stats.get("total_processed", 0),
            "inserted": stats.get("inserted", 0),
            "updated": stats.get("updated", 0),
            "errors": stats.get("errors", 0),
        },
    )
