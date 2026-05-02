"""
Hardening orchestration service for GATEKEEP.

Coordinates the FirewallGenerator and BaselineEngine to expose a clean
service layer for hardening recommendations and baseline management.
All results are persisted to the database.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gatekeep.engines.baseline_engine import BaselineEngine, DriftReport
from gatekeep.engines.firewall_generator import FirewallGenerator
from gatekeep.logging_config import get_logger
from gatekeep.models import (
    Baseline,
    HardeningFormat,
    HardeningRecommendation,
)

logger = get_logger(__name__)


class HardeningService:
    """
    High-level service for firewall rule generation and baseline management.

    Wraps FirewallGenerator and BaselineEngine, adds persistence, and
    returns serialised dicts suitable for API responses.
    """

    def __init__(
        self,
        firewall_generator: FirewallGenerator,
        baseline_engine: BaselineEngine,
    ) -> None:
        self._generator = firewall_generator
        self._baseline_engine = baseline_engine

    # ------------------------------------------------------------------
    # Hardening recommendations
    # ------------------------------------------------------------------

    async def get_recommendations(
        self,
        db: AsyncSession,
        scan_id: Optional[str] = None,
        device_id: Optional[str] = None,
        fmt: str = "generic",
    ) -> dict[str, Any]:
        """
        Generate firewall rules and persist them as a HardeningRecommendation.

        Args:
            db:        Async database session.
            scan_id:   Scope rules to a specific scan result.
            device_id: Scope rules to a specific device.
            fmt:       Output format (iptables | windows_firewall | generic).

        Returns:
            Serialised HardeningRecommendation dict.
        """
        # Normalise and validate format
        normalised_fmt = self._normalise_format(fmt)

        result = await self._generator.generate_rules(
            db=db,
            scan_id=scan_id,
            device_id=device_id,
            fmt=normalised_fmt,
        )

        scope = "network" if not device_id else "device"
        rec = HardeningRecommendation(
            scope=scope,
            target_device_id=device_id,
            scan_id=scan_id,
            format=normalised_fmt,
            rules=json.dumps(result.rules),
            explanation=result.explanation,
            is_applied=False,
        )
        db.add(rec)
        await db.flush()

        logger.info(
            "hardening_service.recommendations_saved",
            recommendation_id=rec.id,
            rule_count=len(result.rules),
            format=normalised_fmt,
        )

        return self._serialise_recommendation(rec, result.rules)

    # ------------------------------------------------------------------
    # Baselines
    # ------------------------------------------------------------------

    async def create_baseline(
        self,
        db: AsyncSession,
        name: str,
        description: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Capture and persist a new network baseline snapshot.

        Returns:
            Serialised Baseline dict.
        """
        baseline_id = await self._baseline_engine.capture_baseline(
            db=db,
            name=name,
            description=description,
        )

        result = await db.execute(
            select(Baseline).where(Baseline.id == baseline_id)
        )
        baseline: Baseline = result.scalar_one()

        logger.info(
            "hardening_service.baseline_created",
            baseline_id=baseline_id,
            name=name,
        )

        return self._serialise_baseline(baseline)

    async def get_baselines(self, db: AsyncSession) -> list[dict[str, Any]]:
        """Return all baselines ordered newest-first."""
        result = await db.execute(
            select(Baseline).order_by(Baseline.created_at.desc())
        )
        baselines = result.scalars().all()
        return [self._serialise_baseline(b) for b in baselines]

    async def get_baseline(
        self, db: AsyncSession, baseline_id: str
    ) -> dict[str, Any]:
        """
        Return a single baseline by ID.

        Raises:
            ValueError: If the baseline does not exist.
        """
        result = await db.execute(
            select(Baseline).where(Baseline.id == baseline_id)
        )
        baseline: Optional[Baseline] = result.scalar_one_or_none()
        if baseline is None:
            raise ValueError(f"Baseline {baseline_id!r} not found.")
        return self._serialise_baseline(baseline)

    async def check_drift(
        self, db: AsyncSession, baseline_id: str
    ) -> dict[str, Any]:
        """
        Compare the current network state to the specified baseline.

        Returns:
            Serialised DriftReport dict.

        Raises:
            ValueError: If the baseline does not exist.
        """
        report: DriftReport = await self._baseline_engine.compare_to_baseline(
            db=db,
            baseline_id=baseline_id,
        )

        logger.info(
            "hardening_service.drift_checked",
            baseline_id=baseline_id,
            total_drifts=report.summary.get("total_drifts", 0),
        )

        return self._serialise_drift_report(report)

    # ------------------------------------------------------------------
    # Serialisation helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _serialise_recommendation(
        rec: HardeningRecommendation,
        rules: list[dict[str, Any]],
    ) -> dict[str, Any]:
        return {
            "id": rec.id,
            "scope": rec.scope,
            "target_device_id": rec.target_device_id,
            "scan_id": rec.scan_id,
            "format": rec.format,
            "rules": rules,
            "explanation": rec.explanation,
            "is_applied": rec.is_applied,
            "created_at": rec.created_at.isoformat() if rec.created_at else None,
        }

    @staticmethod
    def _serialise_baseline(baseline: Baseline) -> dict[str, Any]:
        snapshot_data: Any = None
        if baseline.snapshot:
            try:
                snapshot_data = json.loads(baseline.snapshot)
            except (json.JSONDecodeError, TypeError):
                snapshot_data = None
        return {
            "id": baseline.id,
            "name": baseline.name,
            "description": baseline.description,
            "device_count": baseline.device_count,
            "snapshot": snapshot_data,
            "created_at": baseline.created_at.isoformat() if baseline.created_at else None,
        }

    @staticmethod
    def _serialise_drift_report(report: DriftReport) -> dict[str, Any]:
        return {
            "baseline_id": report.baseline_id,
            "baseline_name": report.baseline_name,
            "captured_at": report.captured_at.isoformat(),
            "compared_at": report.compared_at.isoformat(),
            "drifts": [
                {
                    "drift_type": d.drift_type,
                    "severity": d.severity,
                    "description": d.description,
                    "device_ip": d.device_ip,
                    "device_mac": d.device_mac,
                    "old_value": d.old_value,
                    "new_value": d.new_value,
                }
                for d in report.drifts
            ],
            "summary": report.summary,
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _normalise_format(fmt: str) -> str:
        """Normalise and validate the requested output format."""
        fmt = fmt.lower().strip()
        allowed = {HardeningFormat.IPTABLES, HardeningFormat.WINDOWS_FIREWALL, HardeningFormat.GENERIC, HardeningFormat.PF}
        if fmt not in {str(f) for f in allowed}:
            return HardeningFormat.GENERIC
        return fmt
