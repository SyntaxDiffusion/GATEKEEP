"""
Alert management API routes for GATEKEEP.

Provides CRUD-like endpoints for security alerts: listing with
filters, fetching detail, acknowledging, and retrieving statistics.
"""

from __future__ import annotations

import json
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession

from gatekeep.api.deps import get_db_session
from gatekeep.schemas import AlertResponse, AlertUpdate, ApiResponse

router = APIRouter(prefix="/alerts", tags=["alerts"])


# ---------------------------------------------------------------------------
# Dependency helpers
# ---------------------------------------------------------------------------


def _get_alert_service(request: Request):
    """Retrieve AlertService from application state."""
    svc = getattr(request.app.state, "alert_service", None)
    if svc is None:
        raise HTTPException(
            status_code=503,
            detail={
                "status": "error",
                "data": None,
                "error": {"message": "Alert service is not available."},
                "meta": None,
            },
        )
    return svc


def _alert_to_response(alert) -> AlertResponse:
    """
    Convert an Alert ORM instance to an AlertResponse schema.

    Handles JSON-encoded evidence and ioc_reference fields.
    """
    evidence: Any = None
    if alert.evidence:
        try:
            evidence = json.loads(alert.evidence)
        except (json.JSONDecodeError, TypeError):
            evidence = {"raw": alert.evidence}

    ioc_ref: Any = None
    if alert.ioc_reference:
        try:
            ioc_ref = json.loads(alert.ioc_reference)
        except (json.JSONDecodeError, TypeError):
            ioc_ref = {"raw": alert.ioc_reference}

    return AlertResponse(
        id=alert.id,
        monitor_session_id=alert.monitor_session_id,
        scan_id=alert.scan_id,
        alert_type=alert.alert_type,
        severity=alert.severity,
        title=alert.title,
        description=alert.description,
        source_ip=alert.source_ip,
        destination_ip=alert.destination_ip,
        source_mac=alert.source_mac,
        evidence=evidence,
        ioc_reference=ioc_ref,
        is_acknowledged=alert.is_acknowledged,
        acknowledged_at=alert.acknowledged_at,
        notes=alert.notes,
        created_at=alert.created_at,
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/stats", response_model=ApiResponse[dict[str, Any]])
async def get_alert_stats(
    request: Request,
    period: str = Query(default="24h", description="Time period: 1h, 24h, 7d, 30d"),
    db: AsyncSession = Depends(get_db_session),
) -> ApiResponse[dict[str, Any]]:
    """
    Return aggregated alert statistics for the given time period.

    Query parameter ``period`` accepts: ``1h``, ``24h``, ``7d``, ``30d``.
    Returns total count, counts by severity and type, and an hourly trend.

    Note: This route is defined before ``/{alert_id}`` so FastAPI does
    not match "stats" as an alert_id path parameter.
    """
    svc = _get_alert_service(request)
    stats = await svc.get_alert_stats(db=db, period=period)
    return ApiResponse[dict[str, Any]](status="success", data=stats)


@router.get("", response_model=ApiResponse[list[AlertResponse]])
async def list_alerts(
    request: Request,
    severity: Optional[str] = Query(
        default=None,
        description="Filter by severity: low, medium, high, critical",
    ),
    acknowledged: Optional[bool] = Query(
        default=None,
        description="Filter by acknowledgement state",
    ),
    limit: int = Query(default=50, ge=1, le=500, description="Page size"),
    offset: int = Query(default=0, ge=0, description="Page offset"),
    db: AsyncSession = Depends(get_db_session),
) -> ApiResponse[list[AlertResponse]]:
    """
    List security alerts with optional filtering and pagination.

    Alerts are returned newest first.  Use ``severity`` to narrow to a
    single severity level, and ``acknowledged`` to filter by state.
    """
    svc = _get_alert_service(request)
    alerts = await svc.get_alerts(
        db=db,
        severity=severity,
        acknowledged=acknowledged,
        limit=limit,
        offset=offset,
    )
    data = [_alert_to_response(a) for a in alerts]
    return ApiResponse[list[AlertResponse]](
        status="success",
        data=data,
        meta={"count": len(data), "limit": limit, "offset": offset},
    )


@router.post("/acknowledge-all", response_model=ApiResponse[dict[str, Any]])
async def acknowledge_all_alerts(
    request: Request,
    db: AsyncSession = Depends(get_db_session),
) -> ApiResponse[dict[str, Any]]:
    """
    Acknowledge all currently unacknowledged alerts in bulk.

    Returns the count of alerts that were marked acknowledged.
    """
    svc = _get_alert_service(request)
    count = await svc.acknowledge_all_alerts(db=db)
    return ApiResponse[dict[str, Any]](
        status="success",
        data={"acknowledged_count": count},
    )


@router.get("/{alert_id}", response_model=ApiResponse[AlertResponse])
async def get_alert(
    alert_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db_session),
) -> ApiResponse[AlertResponse]:
    """
    Return the full detail record for a single alert.

    Raises 404 if the alert_id does not exist.
    """
    svc = _get_alert_service(request)
    try:
        alert = await svc.get_alert(db=db, alert_id=alert_id)
    except ValueError as exc:
        raise HTTPException(
            status_code=404,
            detail={
                "status": "error",
                "data": None,
                "error": {"message": str(exc)},
                "meta": None,
            },
        ) from exc

    return ApiResponse[AlertResponse](
        status="success",
        data=_alert_to_response(alert),
    )


@router.patch("/{alert_id}", response_model=ApiResponse[AlertResponse])
async def update_alert(
    alert_id: str,
    body: AlertUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db_session),
) -> ApiResponse[AlertResponse]:
    """
    Acknowledge an alert and/or attach analyst notes.

    Only ``is_acknowledged`` and ``notes`` fields are accepted.
    Setting ``is_acknowledged`` to ``true`` stamps the current UTC
    timestamp onto the record.  Raises 404 if the alert does not exist.
    """
    svc = _get_alert_service(request)

    try:
        alert = await svc.get_alert(db=db, alert_id=alert_id)
    except ValueError as exc:
        raise HTTPException(
            status_code=404,
            detail={
                "status": "error",
                "data": None,
                "error": {"message": str(exc)},
                "meta": None,
            },
        ) from exc

    # Apply acknowledgement if requested
    if body.is_acknowledged is True and not alert.is_acknowledged:
        alert = await svc.acknowledge_alert(
            db=db, alert_id=alert_id, notes=body.notes
        )
    elif body.notes is not None:
        # Update notes only (no re-acknowledgement needed)
        alert.notes = body.notes
        await db.flush()

    return ApiResponse[AlertResponse](
        status="success",
        data=_alert_to_response(alert),
    )
