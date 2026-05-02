"""
Hardening and baseline management API routes for GATEKEEP.

Provides endpoints for:
- Retrieving and regenerating firewall hardening rules
- Creating, listing, retrieving, and deleting network baselines
- Running drift comparisons against a saved baseline

All responses are wrapped in the ApiResponse envelope.
"""

from __future__ import annotations

import uuid
from typing import Any, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from gatekeep.api.deps import get_config, get_db_session
from gatekeep.config import GatekeepConfig
from gatekeep.engines.ai_analyzer import AIAnalyzer
from gatekeep.engines.baseline_engine import BaselineEngine
from gatekeep.engines.firewall_generator import FirewallGenerator
from gatekeep.logging_config import get_logger
from gatekeep.schemas import (
    ApiResponse,
    BaselineCreate,
    BaselineResponse,
    DriftResponse,
    DeviceSnapshot,
    HardeningRecommendation as HardeningRecommendationSchema,
)
from gatekeep.services.baseline_service import BaselineService
from gatekeep.services.hardening_service import HardeningService

logger = get_logger(__name__)

router = APIRouter(tags=["hardening"])

# ---------------------------------------------------------------------------
# Request bodies
# ---------------------------------------------------------------------------


from pydantic import BaseModel


class GenerateRecommendationRequest(BaseModel):
    """Request body for forced rule regeneration."""

    scope: Optional[str] = "network"
    target_id: Optional[str] = None
    format: Optional[str] = "generic"


# ---------------------------------------------------------------------------
# Dependency providers
# ---------------------------------------------------------------------------


def _get_ai_analyzer(config: GatekeepConfig = Depends(get_config)) -> AIAnalyzer:
    """Instantiate the AI analyzer using the current config."""
    return AIAnalyzer(config=config.ai)


def _get_baseline_engine() -> BaselineEngine:
    return BaselineEngine()


def _get_firewall_generator(
    ai_analyzer: AIAnalyzer = Depends(_get_ai_analyzer),
) -> FirewallGenerator:
    return FirewallGenerator(ai_analyzer=ai_analyzer)


def _get_hardening_service(
    firewall_generator: FirewallGenerator = Depends(_get_firewall_generator),
    baseline_engine: BaselineEngine = Depends(_get_baseline_engine),
) -> HardeningService:
    return HardeningService(
        firewall_generator=firewall_generator,
        baseline_engine=baseline_engine,
    )


def _get_baseline_service(
    baseline_engine: BaselineEngine = Depends(_get_baseline_engine),
) -> BaselineService:
    return BaselineService(baseline_engine=baseline_engine)


# ---------------------------------------------------------------------------
# In-memory job tracker (lightweight; restarts clear it)
# ---------------------------------------------------------------------------

_background_jobs: dict[str, dict[str, Any]] = {}


async def _run_generate_job(
    job_id: str,
    scope: Optional[str],
    target_id: Optional[str],
    fmt: str,
    config: GatekeepConfig,
) -> None:
    """Background task: generate rules and update the job status dict."""
    from gatekeep.database import get_session_factory

    _background_jobs[job_id]["status"] = "running"
    try:
        factory = get_session_factory()
        async with factory() as db:
            ai = AIAnalyzer(config=config.ai)
            gen = FirewallGenerator(ai_analyzer=ai)
            be = BaselineEngine()
            svc = HardeningService(firewall_generator=gen, baseline_engine=be)

            device_id: Optional[str] = target_id if scope == "device" else None
            result = await svc.get_recommendations(
                db=db,
                device_id=device_id,
                fmt=fmt,
            )
            await db.commit()

        _background_jobs[job_id]["status"] = "completed"
        _background_jobs[job_id]["result_id"] = result.get("id")
        logger.info("hardening_routes.background_job_done", job_id=job_id)

    except Exception as exc:
        _background_jobs[job_id]["status"] = "failed"
        _background_jobs[job_id]["error"] = str(exc)
        logger.error(
            "hardening_routes.background_job_failed",
            job_id=job_id,
            error=str(exc),
        )


# ---------------------------------------------------------------------------
# Hardening recommendation routes
# ---------------------------------------------------------------------------


@router.get(
    "/hardening/recommendations",
    response_model=ApiResponse[HardeningRecommendationSchema],
    summary="Get firewall hardening rules",
    description=(
        "Generate and return firewall rules for the current network state. "
        "Rules are based on the most recent scan results, APT28 threat intel, "
        "and (when configured) AI-assisted analysis."
    ),
)
async def get_recommendations(
    device_id: Optional[str] = Query(
        default=None, description="Restrict rules to a specific device ID"
    ),
    format: str = Query(
        default="generic",
        description="Output format: iptables | windows_firewall | generic",
    ),
    db: AsyncSession = Depends(get_db_session),
    svc: HardeningService = Depends(_get_hardening_service),
) -> ApiResponse[HardeningRecommendationSchema]:
    """Return firewall hardening rules in the requested format."""
    try:
        result = await svc.get_recommendations(
            db=db,
            device_id=device_id,
            fmt=format,
        )
    except Exception as exc:
        logger.error("hardening_routes.get_recommendations_error", error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        ) from exc

    return ApiResponse(
        status="success",
        data=result,  # type: ignore[arg-type]
        meta={"rule_count": len(result.get("rules") or [])},
    )


@router.post(
    "/hardening/recommendations/generate",
    response_model=ApiResponse[dict[str, Any]],
    status_code=status.HTTP_202_ACCEPTED,
    summary="Force regeneration of hardening rules (async)",
    description=(
        "Enqueue a background job to regenerate firewall rules. "
        "Returns a job_id that can be polled or ignored. "
        "The completed rules will appear on GET /api/v1/hardening/recommendations."
    ),
)
async def generate_recommendations(
    body: GenerateRecommendationRequest,
    background_tasks: BackgroundTasks,
    config: GatekeepConfig = Depends(get_config),
) -> ApiResponse[dict[str, Any]]:
    """Enqueue asynchronous rule regeneration and return a job_id."""
    job_id = str(uuid.uuid4())
    fmt = (body.format or "generic").lower().strip()

    _background_jobs[job_id] = {
        "job_id": job_id,
        "status": "queued",
        "scope": body.scope,
        "target_id": body.target_id,
        "format": fmt,
    }

    background_tasks.add_task(
        _run_generate_job,
        job_id=job_id,
        scope=body.scope,
        target_id=body.target_id,
        fmt=fmt,
        config=config,
    )

    logger.info(
        "hardening_routes.generation_queued",
        job_id=job_id,
        scope=body.scope,
        format=fmt,
    )

    return ApiResponse(
        status="success",
        data={"job_id": job_id, "status": "queued"},
        meta={"message": "Rule generation started in the background."},
    )


# ---------------------------------------------------------------------------
# Baseline routes
# ---------------------------------------------------------------------------


@router.get(
    "/baselines",
    response_model=ApiResponse[list[BaselineResponse]],
    summary="List all network baselines",
)
async def list_baselines(
    db: AsyncSession = Depends(get_db_session),
    svc: HardeningService = Depends(_get_hardening_service),
) -> ApiResponse[list[BaselineResponse]]:
    """Return all saved network baselines ordered newest-first."""
    baselines = await svc.get_baselines(db=db)
    return ApiResponse(
        status="success",
        data=baselines,  # type: ignore[arg-type]
        meta={"count": len(baselines)},
    )


@router.post(
    "/baselines",
    response_model=ApiResponse[BaselineResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Create a new network baseline",
    description=(
        "Snapshot the current network state (devices, ports, DNS, router) "
        "and store it as a named baseline for future drift detection."
    ),
)
async def create_baseline(
    body: BaselineCreate,
    db: AsyncSession = Depends(get_db_session),
    svc: HardeningService = Depends(_get_hardening_service),
) -> ApiResponse[BaselineResponse]:
    """Capture and persist a new network baseline."""
    try:
        baseline = await svc.create_baseline(
            db=db,
            name=body.name,
            description=body.description,
        )
    except Exception as exc:
        logger.error("hardening_routes.create_baseline_error", error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        ) from exc

    return ApiResponse(
        status="success",
        data=baseline,  # type: ignore[arg-type]
        meta={"device_count": baseline.get("device_count", 0)},
    )


@router.get(
    "/baselines/{baseline_id}",
    response_model=ApiResponse[BaselineResponse],
    summary="Retrieve a specific baseline",
)
async def get_baseline(
    baseline_id: str,
    db: AsyncSession = Depends(get_db_session),
    svc: HardeningService = Depends(_get_hardening_service),
) -> ApiResponse[BaselineResponse]:
    """Return a baseline record by ID."""
    try:
        baseline = await svc.get_baseline(db=db, baseline_id=baseline_id)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc

    return ApiResponse(status="success", data=baseline)  # type: ignore[arg-type]


@router.delete(
    "/baselines/{baseline_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a baseline",
    response_class=Response,
)
async def delete_baseline(
    baseline_id: str,
    db: AsyncSession = Depends(get_db_session),
    baseline_svc: BaselineService = Depends(_get_baseline_service),
):
    """Delete a saved baseline. Returns 204 No Content on success."""
    try:
        await baseline_svc.delete(db=db, baseline_id=baseline_id)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get(
    "/baselines/{baseline_id}/drift",
    response_model=ApiResponse[DriftResponse],
    summary="Compare current state to a baseline",
    description=(
        "Scan the current network state and compare it against the specified "
        "baseline. Returns a list of drift items (new devices, IP changes, "
        "port changes, DNS changes, firmware changes)."
    ),
)
async def check_drift(
    baseline_id: str,
    db: AsyncSession = Depends(get_db_session),
    svc: HardeningService = Depends(_get_hardening_service),
) -> ApiResponse[DriftResponse]:
    """Return a drift report comparing the current state to the baseline."""
    try:
        drift = await svc.check_drift(db=db, baseline_id=baseline_id)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
    except Exception as exc:
        logger.error("hardening_routes.drift_error", error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        ) from exc

    # Convert internal dict to the DriftResponse schema shape
    drift_response = _build_drift_response(drift)

    return ApiResponse(
        status="success",
        data=drift_response,
        meta={"total_drifts": drift.get("summary", {}).get("total_drifts", 0)},
    )


# ---------------------------------------------------------------------------
# Helper: convert HardeningService drift dict → DriftResponse-compatible dict
# ---------------------------------------------------------------------------


def _build_drift_response(drift: dict[str, Any]) -> dict[str, Any]:
    """
    Convert the internal drift dict (from HardeningService) into the shape
    expected by the DriftResponse Pydantic schema.
    """
    new_devices: list[dict[str, Any]] = []
    missing_devices: list[dict[str, Any]] = []
    changed_devices: list[dict[str, Any]] = []

    for item in drift.get("drifts", []):
        dtype = item.get("drift_type")
        if dtype == "new_device":
            new_devices.append(
                {
                    "ip_address": item.get("device_ip") or "",
                    "mac_address": item.get("device_mac"),
                    "is_online": True,
                }
            )
        elif dtype == "missing_device":
            missing_devices.append(
                {
                    "ip_address": item.get("device_ip") or item.get("old_value") or "",
                    "mac_address": item.get("device_mac"),
                    "is_online": False,
                }
            )
        else:
            # ip_changed, new_port, closed_port, dns_changed, firmware_changed
            changed_devices.append(item)

    return {
        "baseline_id": drift.get("baseline_id", ""),
        "baseline_name": drift.get("baseline_name", ""),
        "new_devices": new_devices,
        "missing_devices": missing_devices,
        "changed_devices": changed_devices,
        "total_drift_count": drift.get("summary", {}).get("total_drifts", 0),
    }
