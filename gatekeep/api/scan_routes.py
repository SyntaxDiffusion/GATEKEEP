"""
Scan management API routes for GATEKEEP.

Provides endpoints for starting, listing, retrieving, and deleting
network scans, as well as AI re-analysis on existing scan data.
"""

from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, Response
from sqlalchemy.ext.asyncio import AsyncSession

from gatekeep.api.deps import get_config, get_db_session
from gatekeep.config import GatekeepConfig
from gatekeep.database import get_session_factory
from gatekeep.logging_config import get_logger
from gatekeep.schemas import (
    AIAnalysisResponse,
    ApiResponse,
    ScanCreate,
    ScanDetail,
    ScanResponse,
    ScanSummary,
)
from gatekeep.services.scan_service import ScanService

logger = get_logger(__name__)

router = APIRouter(prefix="/scans", tags=["scans"])


def _get_ws_manager(request: Request) -> Any:
    """Retrieve the WebSocket manager from app state, if available."""
    return getattr(request.app.state, "ws_manager", None)


async def _run_scan_background(
    config: GatekeepConfig,
    interface: Optional[str],
    subnet: Optional[str],
    scan_type: str,
    ws_manager: Any,
) -> None:
    """
    Execute a full scan in a background task with its own DB session.

    Handles all errors internally -- updates the scan record to FAILED
    on any unrecoverable error.
    """
    factory = get_session_factory()
    async with factory() as db:
        try:
            service = ScanService(db=db, config=config)
            service.set_ws_manager(ws_manager)

            if scan_type in ("arp_discovery", "quick"):
                await service.run_quick_scan(
                    db=db,
                    interface=interface,
                    subnet=subnet,
                )
            else:
                await service.run_full_scan(
                    db=db,
                    interface=interface,
                    subnet=subnet,
                    scan_type=scan_type,
                )
            await db.commit()
        except Exception as exc:
            logger.error("background_scan_failed", error=str(exc))
            await db.rollback()
            # Try to mark scan as failed
            try:
                from gatekeep.models import Scan, ScanStatus
                from sqlalchemy import select

                result = await db.execute(
                    select(Scan)
                    .where(Scan.status.in_(["pending", "running"]))
                    .order_by(Scan.created_at.desc())
                    .limit(1)
                )
                scan = result.scalar_one_or_none()
                if scan:
                    from datetime import datetime, timezone

                    scan.status = ScanStatus.FAILED
                    scan.error_message = str(exc)
                    scan.completed_at = datetime.now(timezone.utc)
                    await db.commit()
            except Exception as inner_exc:
                logger.error("failed_to_mark_scan_failed", error=str(inner_exc))


async def _run_reanalysis_background(
    config: GatekeepConfig,
    scan_id: str,
    ws_manager: Any,
) -> None:
    """Run AI re-analysis in a background task with its own DB session."""
    factory = get_session_factory()
    async with factory() as db:
        try:
            service = ScanService(db=db, config=config)
            service.set_ws_manager(ws_manager)
            await service.run_reanalysis(db=db, scan_id=scan_id)
            await db.commit()
        except Exception as exc:
            logger.error(
                "background_reanalysis_failed",
                scan_id=scan_id,
                error=str(exc),
            )
            await db.rollback()


# ------------------------------------------------------------------
# Endpoints
# ------------------------------------------------------------------


@router.post("", status_code=202, response_model=ApiResponse[dict[str, Any]])
async def start_scan(
    body: ScanCreate,
    background_tasks: BackgroundTasks,
    request: Request,
    config: GatekeepConfig = Depends(get_config),
) -> ApiResponse[dict[str, Any]]:
    """
    Start a new network scan.

    The scan runs asynchronously as a background task. Returns
    immediately with a confirmation that the scan has been queued.
    """
    ws_manager = _get_ws_manager(request)
    scan_type = body.scan_type or "full_scan"

    background_tasks.add_task(
        _run_scan_background,
        config=config,
        interface=body.interface_name,
        subnet=body.subnet,
        scan_type=scan_type,
        ws_manager=ws_manager,
    )

    logger.info(
        "scan_queued",
        scan_type=scan_type,
        interface=body.interface_name,
        subnet=body.subnet,
    )

    return ApiResponse[dict[str, Any]](
        status="success",
        data={
            "message": "Scan queued successfully",
            "scan_type": scan_type,
            "status": "queued",
        },
    )


@router.get("", response_model=ApiResponse[list[ScanSummary]])
async def list_scans(
    limit: int = 50,
    offset: int = 0,
    db: AsyncSession = Depends(get_db_session),
    config: GatekeepConfig = Depends(get_config),
) -> ApiResponse[list[ScanSummary]]:
    """
    List past scans with pagination.

    Returns compact scan summaries ordered by creation time descending.
    """
    service = ScanService(db=db, config=config)
    scans = await service.list_scans(limit=limit, offset=offset)
    summaries = [ScanSummary.model_validate(s) for s in scans]
    return ApiResponse[list[ScanSummary]](
        status="success",
        data=summaries,
        meta={"limit": limit, "offset": offset, "count": len(summaries)},
    )


@router.get("/{scan_id}", response_model=ApiResponse[dict[str, Any]])
async def get_scan_detail(
    scan_id: str,
    db: AsyncSession = Depends(get_db_session),
    config: GatekeepConfig = Depends(get_config),
) -> ApiResponse[dict[str, Any]]:
    """
    Retrieve full scan detail including all nested results.
    """
    service = ScanService(db=db, config=config)
    detail = await service.get_scan_detail(db=db, scan_id=scan_id)
    if detail is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return ApiResponse[dict[str, Any]](status="success", data=detail)


@router.delete("/{scan_id}", status_code=204, response_class=Response)
async def delete_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db_session),
    config: GatekeepConfig = Depends(get_config),
):
    """
    Delete a scan and cascade all related records.
    """
    service = ScanService(db=db, config=config)
    deleted = await service.delete_scan(scan_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Scan not found")
    return Response(status_code=204)


@router.get(
    "/{scan_id}/ai-analysis",
    response_model=ApiResponse[dict[str, Any]],
)
async def get_ai_analysis(
    scan_id: str,
    db: AsyncSession = Depends(get_db_session),
    config: GatekeepConfig = Depends(get_config),
) -> ApiResponse[dict[str, Any]]:
    """
    Return the AI analysis for a specific scan.
    """
    service = ScanService(db=db, config=config)
    analysis = await service.get_ai_analysis(db=db, scan_id=scan_id)
    if analysis is None:
        raise HTTPException(
            status_code=404,
            detail="No AI analysis found for this scan",
        )
    return ApiResponse[dict[str, Any]](status="success", data=analysis)


@router.post(
    "/{scan_id}/reanalyze",
    status_code=202,
    response_model=ApiResponse[dict[str, Any]],
)
async def reanalyze_scan(
    scan_id: str,
    background_tasks: BackgroundTasks,
    request: Request,
    db: AsyncSession = Depends(get_db_session),
    config: GatekeepConfig = Depends(get_config),
) -> ApiResponse[dict[str, Any]]:
    """
    Re-run AI analysis on existing scan data.

    Runs as a background task and returns immediately.
    """
    # Verify scan exists
    service = ScanService(db=db, config=config)
    scan = await service.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    ws_manager = _get_ws_manager(request)
    background_tasks.add_task(
        _run_reanalysis_background,
        config=config,
        scan_id=scan_id,
        ws_manager=ws_manager,
    )

    return ApiResponse[dict[str, Any]](
        status="success",
        data={
            "message": "AI re-analysis queued",
            "scan_id": scan_id,
            "status": "queued",
        },
    )
