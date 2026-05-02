"""
Device inventory API routes for GATEKEEP.

Provides endpoints for listing discovered devices, retrieving
device details with port scan results, and viewing device history
across past scans.
"""

from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from gatekeep.api.deps import get_db_session
from gatekeep.logging_config import get_logger
from gatekeep.schemas import ApiResponse, DeviceDetail, DeviceResponse, PortResultResponse
from gatekeep.services.device_service import DeviceService

logger = get_logger(__name__)

router = APIRouter(prefix="/devices", tags=["devices"])


@router.get("", response_model=ApiResponse[list[DeviceResponse]])
async def list_devices(
    status: Optional[str] = None,
    db: AsyncSession = Depends(get_db_session),
) -> ApiResponse[list[DeviceResponse]]:
    """
    List all discovered devices with their latest state.

    Supports an optional ``?status=online`` query parameter to
    filter to devices seen within the last 10 minutes.
    """
    service = DeviceService()
    devices = await service.get_all_devices(db=db, status_filter=status)
    data = [DeviceResponse.model_validate(d) for d in devices]
    return ApiResponse[list[DeviceResponse]](
        status="success",
        data=data,
        meta={"count": len(data)},
    )


@router.get("/{device_id}", response_model=ApiResponse[DeviceDetail])
async def get_device(
    device_id: str,
    db: AsyncSession = Depends(get_db_session),
) -> ApiResponse[DeviceDetail]:
    """
    Retrieve a single device with port scan results and metadata.
    """
    service = DeviceService()
    device = await service.get_device(db=db, device_id=device_id)
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found")

    # Build open ports from the most recent device_scan
    open_ports: list[PortResultResponse] = []
    scan_count = len(device.device_scans)
    last_response_time: Optional[float] = None

    if device.device_scans:
        latest_ds = device.device_scans[-1]
        last_response_time = latest_ds.response_time_ms
        for pr in latest_ds.port_results:
            open_ports.append(PortResultResponse.model_validate(pr))

    detail = DeviceDetail(
        id=device.id,
        ip_address=device.ip_address,
        mac_address=device.mac_address,
        hostname=device.hostname,
        vendor=device.vendor,
        device_type=device.device_type,
        is_gateway=device.is_gateway,
        first_seen_at=device.first_seen_at,
        last_seen_at=device.last_seen_at,
        open_ports=open_ports,
        scan_count=scan_count,
        last_response_time_ms=last_response_time,
    )
    return ApiResponse[DeviceDetail](status="success", data=detail)


@router.get(
    "/{device_id}/history",
    response_model=ApiResponse[list[dict[str, Any]]],
)
async def get_device_history(
    device_id: str,
    days: int = 30,
    db: AsyncSession = Depends(get_db_session),
) -> ApiResponse[list[dict[str, Any]]]:
    """
    Retrieve scan history for a device over time.

    Returns a list of snapshots showing the device's state in each
    scan it appeared in over the last *days* days.
    """
    service = DeviceService()

    # Verify device exists
    device = await service.get_device(db=db, device_id=device_id)
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found")

    history = await service.get_device_history(
        db=db, device_id=device_id, days=days
    )
    return ApiResponse[list[dict[str, Any]]](
        status="success",
        data=history,
        meta={"device_id": device_id, "days": days, "count": len(history)},
    )
