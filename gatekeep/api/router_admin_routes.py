"""
Router admin API routes.

Provides endpoints to connect to a Verizon Fios (Sagemcom G3100)
router's admin interface, retrieve connected device lists, and
query router system information.
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from gatekeep.engines.router_admin import FiosRouterClient
from gatekeep.logging_config import get_logger
from gatekeep.schemas import ApiResponse

router = APIRouter(prefix="/router", tags=["router"])
logger = get_logger("router_admin_routes")

_router_client: Optional[FiosRouterClient] = None


class RouterLoginRequest(BaseModel):
    """Request body for router authentication."""

    password: str
    router_ip: str = "192.168.1.1"


@router.post("/connect")
async def connect_router(body: RouterLoginRequest) -> ApiResponse:
    """Connect and authenticate with the router admin interface."""
    global _router_client  # noqa: PLW0603
    _router_client = FiosRouterClient(router_ip=body.router_ip)

    reachable = await _router_client.connect()
    if not reachable:
        raise HTTPException(status_code=503, detail="Cannot reach router")

    logged_in = await _router_client.login(body.password)
    if not logged_in:
        raise HTTPException(status_code=401, detail="Invalid router password")

    return ApiResponse(
        status="success",
        data={"message": "Connected to router", "router_ip": body.router_ip},
    )


@router.get("/devices")
async def get_router_devices() -> ApiResponse:
    """Get connected devices from router admin interface."""
    if _router_client is None:
        raise HTTPException(
            status_code=400,
            detail="Not connected to router. POST /api/v1/router/connect first.",
        )

    devices = await _router_client.get_connected_devices()
    return ApiResponse(
        status="success",
        data={
            "devices": [
                {
                    "hostname": d.hostname,
                    "ip_address": d.ip_address,
                    "mac_address": d.mac_address,
                    "connection_type": d.connection_type,
                    "is_online": d.is_online,
                }
                for d in devices
            ],
            "count": len(devices),
        },
    )


@router.get("/info")
async def get_router_system_info() -> ApiResponse:
    """Get router system information (model, firmware, DNS, etc.)."""
    if _router_client is None:
        raise HTTPException(
            status_code=400,
            detail="Not connected to router. POST /api/v1/router/connect first.",
        )

    info = await _router_client.get_router_info()
    return ApiResponse(
        status="success",
        data={
            "model": info.model,
            "firmware_version": info.firmware_version,
            "wan_ip": info.wan_ip,
            "wan_dns": info.wan_dns,
            "lan_ip": info.lan_ip,
            "wifi_ssid": info.wifi_ssid,
        },
    )


@router.get("/wifi-clients")
async def get_router_wifi_clients() -> ApiResponse:
    """Get WiFi-specific client information from the router."""
    if _router_client is None:
        raise HTTPException(
            status_code=400,
            detail="Not connected to router. POST /api/v1/router/connect first.",
        )

    clients = await _router_client.get_wifi_clients()
    return ApiResponse(
        status="success",
        data={"clients": clients, "count": len(clients)},
    )


@router.get("/status")
async def get_router_connection_status() -> ApiResponse:
    """Check if we have an active connection to the router."""
    connected = (
        _router_client is not None and _router_client._token is not None
    )
    return ApiResponse(
        status="success",
        data={"connected": connected},
    )


@router.post("/disconnect")
async def disconnect_router() -> ApiResponse:
    """Close the connection to the router admin interface."""
    global _router_client  # noqa: PLW0603
    if _router_client is not None:
        await _router_client.close()
        _router_client = None
    return ApiResponse(
        status="success",
        data={"message": "Disconnected from router"},
    )
