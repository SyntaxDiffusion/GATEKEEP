"""
Baseline service (thin wrapper) for GATEKEEP.

Provides straightforward CRUD operations on Baseline records and
delegates drift comparison to BaselineEngine.
"""

from __future__ import annotations

from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gatekeep.engines.baseline_engine import BaselineEngine, DriftReport
from gatekeep.logging_config import get_logger
from gatekeep.models import Baseline

logger = get_logger(__name__)


class BaselineService:
    """
    Thin CRUD wrapper around the Baseline ORM model.

    Delegates snapshot capture and drift comparison to BaselineEngine;
    this class only manages database persistence and retrieval.
    """

    def __init__(self, baseline_engine: BaselineEngine) -> None:
        self._engine = baseline_engine

    # ------------------------------------------------------------------
    # Create
    # ------------------------------------------------------------------

    async def create(
        self,
        db: AsyncSession,
        name: str,
        description: Optional[str] = None,
    ) -> Baseline:
        """
        Capture the current network state and save it as a new baseline.

        Args:
            db:          Async database session.
            name:        Human-readable name for the baseline.
            description: Optional free-text description.

        Returns:
            The freshly persisted Baseline ORM instance.
        """
        baseline_id = await self._engine.capture_baseline(
            db=db, name=name, description=description
        )
        result = await db.execute(
            select(Baseline).where(Baseline.id == baseline_id)
        )
        baseline: Baseline = result.scalar_one()
        logger.info(
            "baseline_service.created",
            baseline_id=baseline_id,
            name=name,
        )
        return baseline

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    async def get_all(self, db: AsyncSession) -> list[Baseline]:
        """
        Return all baselines ordered newest-first.

        Returns:
            List of Baseline ORM instances (may be empty).
        """
        result = await db.execute(
            select(Baseline).order_by(Baseline.created_at.desc())
        )
        return list(result.scalars().all())

    async def get_one(self, db: AsyncSession, baseline_id: str) -> Baseline:
        """
        Return a single Baseline by ID.

        Raises:
            ValueError: If the baseline does not exist.
        """
        result = await db.execute(
            select(Baseline).where(Baseline.id == baseline_id)
        )
        baseline: Optional[Baseline] = result.scalar_one_or_none()
        if baseline is None:
            raise ValueError(f"Baseline {baseline_id!r} not found.")
        return baseline

    # ------------------------------------------------------------------
    # Delete
    # ------------------------------------------------------------------

    async def delete(self, db: AsyncSession, baseline_id: str) -> None:
        """
        Delete a baseline record.

        Raises:
            ValueError: If the baseline does not exist.
        """
        baseline = await self.get_one(db, baseline_id)
        await db.delete(baseline)
        await db.flush()
        logger.info("baseline_service.deleted", baseline_id=baseline_id)

    # ------------------------------------------------------------------
    # Drift
    # ------------------------------------------------------------------

    async def check_drift(
        self, db: AsyncSession, baseline_id: str
    ) -> DriftReport:
        """
        Compare the current network state to the specified baseline.

        Args:
            db:          Async database session.
            baseline_id: UUID of the baseline to compare against.

        Returns:
            DriftReport with detected changes.

        Raises:
            ValueError: If the baseline does not exist.
        """
        return await self._engine.compare_to_baseline(
            db=db, baseline_id=baseline_id
        )
