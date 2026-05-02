"""
System information and health-check API routes.

Provides endpoints for application health, configuration inspection,
and network interface enumeration.
"""

from __future__ import annotations

import time
from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from gatekeep import __version__
from gatekeep.api.deps import get_config, get_db_session
from gatekeep.config import GatekeepConfig
from gatekeep.privileges import get_privilege_level
from gatekeep.schemas import ApiResponse, SystemHealth
from gatekeep.utils.network import get_all_interfaces

router = APIRouter(prefix="/system", tags=["system"])

_startup_time: float = time.monotonic()


def _check_npcap() -> bool:
    """Check whether Npcap/WinPcap is available for raw packet capture."""
    try:
        from scapy.arch.windows import get_windows_if_list  # type: ignore[import-untyped]

        get_windows_if_list()
        return True
    except Exception:
        # On non-Windows or if Npcap is not installed
        try:
            from scapy.config import conf  # type: ignore[import-untyped]

            _ = conf.iface
            return True
        except Exception:
            return False


@router.get("/health", response_model=ApiResponse[SystemHealth])
async def get_health(
    db: AsyncSession = Depends(get_db_session),
    config: GatekeepConfig = Depends(get_config),
) -> ApiResponse[SystemHealth]:
    """
    Return application health status including version, privilege
    level, Npcap availability, uptime, and database connectivity.
    """
    # Database connectivity check
    db_status = "ok"
    try:
        await db.execute(text("SELECT 1"))
    except Exception:
        db_status = "degraded"

    uptime = time.monotonic() - _startup_time
    privilege_level = get_privilege_level()
    npcap = _check_npcap()
    interfaces = get_all_interfaces()

    health = SystemHealth(
        status="healthy" if db_status == "ok" else "degraded",
        version=__version__,
        uptime_seconds=round(uptime, 2),
        privileges=privilege_level.value,
        npcap_available=npcap,
        interfaces=interfaces,
        database_status=db_status,
        ai_available=config.ai_available,
    )
    return ApiResponse[SystemHealth](status="success", data=health)


@router.get("/config", response_model=ApiResponse[dict[str, Any]])
async def get_system_config(
    config: GatekeepConfig = Depends(get_config),
) -> ApiResponse[dict[str, Any]]:
    """
    Return the active configuration with sensitive values redacted.

    Includes an ``ai_available`` flag indicating whether the Claude
    Agent SDK is installed and AI analysis is operational.
    """
    redacted = config.redacted()
    return ApiResponse[dict[str, Any]](status="success", data=redacted)


@router.get("/interfaces", response_model=ApiResponse[list[dict[str, Any]]])
async def list_interfaces() -> ApiResponse[list[dict[str, Any]]]:
    """
    List all network interfaces with their IPv4 addresses, MAC
    addresses, netmasks, and calculated subnets.
    """
    interfaces = get_all_interfaces()
    return ApiResponse[list[dict[str, Any]]](
        status="success",
        data=interfaces,
        meta={"count": len(interfaces)},
    )
