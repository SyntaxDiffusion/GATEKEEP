"""
IOC feed loader for GATEKEEP.

Provides functions to load threat intelligence from JSON files,
persist indicators to the database (upserting on the unique
indicator_type + value constraint), and retrieve summary statistics.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from gatekeep.logging_config import get_logger
from gatekeep.models import IOCIndicator, IndicatorType

log = get_logger(__name__)

# Default IOC file path
_DEFAULT_IOC_PATH = Path(__file__).resolve().parent / "apt28_indicators.json"


async def load_ioc_file(filepath: str | None = None) -> dict[str, Any]:
    """
    Load and validate an IOC JSON file.

    Args:
        filepath: Absolute or relative path to the IOC JSON file.
                  Defaults to the bundled apt28_indicators.json.

    Returns:
        The parsed JSON dict with ``metadata`` and ``indicators`` keys.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the file is not valid JSON or missing required keys.
    """
    path = Path(filepath) if filepath else _DEFAULT_IOC_PATH

    if not path.exists():
        raise FileNotFoundError(f"IOC file not found: {path}")

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in IOC file {path}: {exc}") from exc

    # Basic structure validation
    if "metadata" not in data:
        raise ValueError(f"IOC file {path} missing 'metadata' key")
    if "indicators" not in data:
        raise ValueError(f"IOC file {path} missing 'indicators' key")

    metadata = data["metadata"]
    required_meta = {"name", "version", "last_updated"}
    missing = required_meta - set(metadata.keys())
    if missing:
        raise ValueError(
            f"IOC file metadata missing required keys: {missing}"
        )

    log.info(
        "ioc_file_loaded",
        path=str(path),
        name=metadata.get("name"),
        version=metadata.get("version"),
    )

    return data


async def refresh_indicators(
    db_session: AsyncSession,
    filepath: str | None = None,
) -> dict[str, Any]:
    """
    Load IOCs from file and upsert into the ioc_indicators database table.

    Uses INSERT ... ON CONFLICT (indicator_type, value) DO UPDATE to
    merge new data with existing records, preserving primary keys.

    Args:
        db_session: An active async SQLAlchemy session.
        filepath: Path to the IOC JSON file.

    Returns:
        A summary dict with counts of inserted and updated indicators.
    """
    data = await load_ioc_file(filepath)
    metadata = data["metadata"]
    indicators = data["indicators"]
    threat_actor = metadata.get("name", "Unknown")
    sources = metadata.get("sources", [])
    source_str = ", ".join(sources) if sources else "Unknown"

    stats = {"inserted": 0, "updated": 0, "errors": 0, "total_processed": 0}

    # --- IPv4 CIDR ranges ---
    for entry in indicators.get("ipv4_ranges", []):
        cidr = entry.get("cidr", "")
        if not cidr:
            continue
        stats["total_processed"] += 1
        await _upsert_indicator(
            db_session,
            indicator_type=IndicatorType.IP_ADDRESS,
            value=cidr,
            threat_actor=threat_actor,
            campaign=entry.get("campaign", ""),
            confidence=_confidence_to_float(entry.get("confidence", "medium")),
            description=f"CIDR range associated with {threat_actor}",
            source=source_str,
            stats=stats,
        )

    # --- Specific IPv4 addresses ---
    for entry in indicators.get("ipv4_specific", []):
        ip = entry.get("ip", "")
        if not ip:
            continue
        stats["total_processed"] += 1
        await _upsert_indicator(
            db_session,
            indicator_type=IndicatorType.IP_ADDRESS,
            value=ip,
            threat_actor=threat_actor,
            campaign=entry.get("campaign", ""),
            confidence=_confidence_to_float(entry.get("confidence", "medium")),
            description=(
                f"Specific IP associated with {threat_actor}, "
                f"first seen {entry.get('first_seen', 'unknown')}"
            ),
            source=source_str,
            stats=stats,
        )

    # --- Domains ---
    for entry in indicators.get("domains", []):
        domain = entry.get("domain", "")
        if not domain:
            continue
        stats["total_processed"] += 1
        note = entry.get("note", "")
        desc = f"{entry.get('type', 'domain')} indicator for {threat_actor}"
        if note:
            desc += f" - {note}"
        await _upsert_indicator(
            db_session,
            indicator_type=IndicatorType.DOMAIN,
            value=domain.lower(),
            threat_actor=threat_actor,
            campaign="FrostArmada",
            confidence=0.7,
            description=desc,
            source=source_str,
            stats=stats,
        )

    # --- Ports ---
    for entry in indicators.get("ports", []):
        port = entry.get("port")
        if port is None:
            continue
        stats["total_processed"] += 1
        await _upsert_indicator(
            db_session,
            indicator_type=IndicatorType.PORT,
            value=str(port),
            threat_actor=threat_actor,
            campaign=entry.get("campaign", ""),
            confidence=0.9,
            description=entry.get("description", f"Port {port}"),
            source=source_str,
            stats=stats,
        )

    await db_session.flush()

    log.info(
        "ioc_indicators_refreshed",
        total_processed=stats["total_processed"],
        inserted=stats["inserted"],
        updated=stats["updated"],
        errors=stats["errors"],
    )

    return stats


async def get_indicator_stats(db_session: AsyncSession) -> dict[str, Any]:
    """
    Return summary statistics for the IOC indicator table.

    Args:
        db_session: An active async SQLAlchemy session.

    Returns:
        A dict with counts by type, total count, last updated timestamp,
        and source list.
    """
    # Count by type
    result = await db_session.execute(
        select(
            IOCIndicator.indicator_type,
            func.count(IOCIndicator.id).label("count"),
        ).group_by(IOCIndicator.indicator_type)
    )
    counts_by_type: dict[str, int] = {}
    for row in result:
        counts_by_type[row.indicator_type] = row.count

    # Total count
    total_result = await db_session.execute(
        select(func.count(IOCIndicator.id))
    )
    total = total_result.scalar() or 0

    # Last updated
    last_updated_result = await db_session.execute(
        select(func.max(IOCIndicator.created_at))
    )
    last_updated = last_updated_result.scalar()

    # Distinct sources
    source_result = await db_session.execute(
        select(IOCIndicator.source).distinct().where(IOCIndicator.source.isnot(None))
    )
    sources = [row[0] for row in source_result if row[0]]

    # Distinct threat actors
    actor_result = await db_session.execute(
        select(IOCIndicator.threat_actor)
        .distinct()
        .where(IOCIndicator.threat_actor.isnot(None))
    )
    threat_actors = [row[0] for row in actor_result if row[0]]

    return {
        "total_indicators": total,
        "counts_by_type": counts_by_type,
        "last_updated": last_updated.isoformat() if last_updated else None,
        "sources": sources,
        "threat_actors": threat_actors,
        "active_count": total,  # All loaded indicators default to active
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


async def _upsert_indicator(
    db_session: AsyncSession,
    *,
    indicator_type: str,
    value: str,
    threat_actor: str,
    campaign: str,
    confidence: float,
    description: str,
    source: str,
    stats: dict[str, int],
) -> None:
    """
    Insert or update a single IOC indicator.

    Uses a SELECT-then-INSERT/UPDATE pattern compatible with SQLite
    (which does not support ``ON CONFLICT ... DO UPDATE`` via the
    ORM layer cleanly with async).
    """
    try:
        result = await db_session.execute(
            select(IOCIndicator).where(
                IOCIndicator.indicator_type == indicator_type,
                IOCIndicator.value == value,
            )
        )
        existing = result.scalar_one_or_none()

        if existing:
            existing.threat_actor = threat_actor
            existing.campaign = campaign
            existing.confidence = confidence
            existing.description = description
            existing.source = source
            existing.is_active = True
            stats["updated"] += 1
        else:
            indicator = IOCIndicator(
                indicator_type=indicator_type,
                value=value,
                threat_actor=threat_actor,
                campaign=campaign,
                confidence=confidence,
                description=description,
                source=source,
                is_active=True,
            )
            db_session.add(indicator)
            stats["inserted"] += 1

    except Exception as exc:
        log.error(
            "ioc_upsert_error",
            indicator_type=indicator_type,
            value=value,
            error=str(exc),
        )
        stats["errors"] += 1


def _confidence_to_float(level: str) -> float:
    """Convert a textual confidence level to a numeric score."""
    mapping = {
        "low": 0.3,
        "medium": 0.6,
        "high": 0.9,
        "critical": 1.0,
    }
    return mapping.get(level.lower(), 0.5)
