"""
Alert management service for GATEKEEP.

Handles creation, deduplication, severity escalation, querying, and
acknowledgement of security alerts.  Broadcasts all state changes to
subscribed WebSocket clients.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from gatekeep.config import AlertConfig
from gatekeep.logging_config import get_logger
from gatekeep.models import Alert, AlertSeverity
from gatekeep.websocket.events import CHANNEL_ALERTS, EventType, create_event

log = get_logger(__name__)

# Deduplication window in seconds
_DEDUP_WINDOW_SECONDS = 300


class AlertService:
    """
    Creates, deduplicates, and manages security alerts.

    Alerts are persisted to the database and broadcast over WebSocket
    to all clients subscribed to the ``alerts`` channel.

    Severity escalation is applied at creation time based on alert_type
    using the ``AlertConfig.severity_escalation`` mapping; if the
    mapping specifies a higher severity than the caller provided, the
    escalated value wins.
    """

    _SEVERITY_ORDER: dict[str, int] = {
        AlertSeverity.LOW: 0,
        AlertSeverity.MEDIUM: 1,
        AlertSeverity.HIGH: 2,
        AlertSeverity.CRITICAL: 3,
    }

    def __init__(self, config: AlertConfig, ws_manager: Any) -> None:
        self._config = config
        self._ws_manager = ws_manager

    # ------------------------------------------------------------------
    # Alert creation
    # ------------------------------------------------------------------

    async def create_alert(
        self,
        db: AsyncSession,
        alert_type: str,
        severity: str,
        title: str,
        description: str,
        source_ip: Optional[str] = None,
        destination_ip: Optional[str] = None,
        source_mac: Optional[str] = None,
        evidence: Optional[dict[str, Any]] = None,
        ioc_reference: Optional[dict[str, Any]] = None,
        monitor_session_id: Optional[str] = None,
        scan_id: Optional[str] = None,
    ) -> Alert:
        """
        Persist a new alert after dedup check and severity escalation.

        Deduplication: if an alert with the same ``alert_type``,
        ``source_ip``, and ``destination_ip`` already exists within
        ``_DEDUP_WINDOW_SECONDS``, this call is a no-op and the
        existing alert is returned.

        Severity escalation: if ``alert_type`` appears in the config
        mapping and the mapped severity is higher than the requested
        one, the higher severity is used.

        Args:
            db: Active async database session.
            alert_type: Machine-readable alert category (e.g. "port_scan").
            severity: Requested severity level ("low"|"medium"|"high"|"critical").
            title: Human-readable alert headline.
            description: Detailed description of the threat.
            source_ip: Origin IP address of the suspicious traffic.
            destination_ip: Target IP address.
            source_mac: Origin MAC address.
            evidence: Arbitrary supporting data dict serialised to JSON.
            ioc_reference: IOC match metadata dict serialised to JSON.
            monitor_session_id: FK to the monitoring session that generated it.
            scan_id: FK to the scan that generated it (if applicable).

        Returns:
            The created (or existing deduplicated) Alert ORM instance.
        """
        # Normalise severity
        severity = severity.lower()
        if severity not in self._SEVERITY_ORDER:
            severity = AlertSeverity.MEDIUM

        # Apply severity escalation from config
        escalated = self._config.severity_escalation.get(alert_type.lower())
        if escalated and self._SEVERITY_ORDER.get(escalated, -1) > self._SEVERITY_ORDER.get(severity, 0):
            severity = escalated

        # Deduplication check
        existing = await self._find_duplicate(
            db, alert_type, source_ip, destination_ip
        )
        if existing is not None:
            log.debug(
                "alert_deduplicated",
                alert_type=alert_type,
                source_ip=source_ip,
                existing_id=existing.id,
            )
            return existing

        # Serialise evidence / IOC reference
        evidence_json: Optional[str] = None
        if evidence:
            try:
                evidence_json = json.dumps(evidence)
            except (TypeError, ValueError):
                evidence_json = json.dumps({"raw": str(evidence)})

        ioc_json: Optional[str] = None
        if ioc_reference:
            try:
                ioc_json = json.dumps(ioc_reference)
            except (TypeError, ValueError):
                ioc_json = json.dumps({"raw": str(ioc_reference)})

        alert = Alert(
            alert_type=alert_type,
            severity=severity,
            title=title,
            description=description,
            source_ip=source_ip,
            destination_ip=destination_ip,
            source_mac=source_mac,
            evidence=evidence_json,
            ioc_reference=ioc_json,
            monitor_session_id=monitor_session_id,
            scan_id=scan_id,
            is_acknowledged=False,
        )

        db.add(alert)
        await db.flush()  # Populate alert.id without committing

        log.info(
            "alert_created",
            alert_id=alert.id,
            alert_type=alert_type,
            severity=severity,
            source_ip=source_ip,
        )

        # Broadcast
        await self._broadcast_alert(alert, EventType.ALERT_NEW)

        return alert

    # ------------------------------------------------------------------
    # Querying
    # ------------------------------------------------------------------

    async def get_alerts(
        self,
        db: AsyncSession,
        severity: Optional[str] = None,
        acknowledged: Optional[bool] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Alert]:
        """
        Return a paginated list of alerts with optional filters.

        Args:
            db: Active async database session.
            severity: If provided, filter to this severity level only.
            acknowledged: If provided, filter by acknowledgement state.
            limit: Maximum number of results to return.
            offset: Number of results to skip (for pagination).

        Returns:
            List of Alert ORM instances, newest first.
        """
        stmt = select(Alert).order_by(Alert.created_at.desc())

        if severity is not None:
            stmt = stmt.where(Alert.severity == severity.lower())

        if acknowledged is not None:
            stmt = stmt.where(Alert.is_acknowledged == acknowledged)

        stmt = stmt.offset(offset).limit(limit)

        result = await db.execute(stmt)
        return list(result.scalars().all())

    async def get_alert(self, db: AsyncSession, alert_id: str) -> Alert:
        """
        Fetch a single alert by ID.

        Args:
            db: Active async database session.
            alert_id: UUID string of the alert.

        Returns:
            The Alert ORM instance.

        Raises:
            ValueError: If the alert is not found.
        """
        result = await db.execute(select(Alert).where(Alert.id == alert_id))
        alert = result.scalar_one_or_none()
        if alert is None:
            raise ValueError(f"Alert '{alert_id}' not found")
        return alert

    # ------------------------------------------------------------------
    # Acknowledgement
    # ------------------------------------------------------------------

    async def acknowledge_alert(
        self,
        db: AsyncSession,
        alert_id: str,
        notes: Optional[str] = None,
    ) -> Alert:
        """
        Mark an alert as acknowledged and optionally attach notes.

        Broadcasts an ``alert_updated`` WebSocket event after persisting.

        Args:
            db: Active async database session.
            alert_id: UUID string of the alert to acknowledge.
            notes: Optional analyst notes to attach.

        Returns:
            The updated Alert ORM instance.

        Raises:
            ValueError: If the alert is not found.
        """
        alert = await self.get_alert(db, alert_id)
        alert.is_acknowledged = True
        alert.acknowledged_at = datetime.now(timezone.utc)
        if notes is not None:
            alert.notes = notes

        await db.flush()

        log.info(
            "alert_acknowledged",
            alert_id=alert_id,
            notes_provided=notes is not None,
        )

        await self._broadcast_alert(alert, EventType.ALERT_UPDATED)
        return alert

    async def acknowledge_all_alerts(self, db: AsyncSession) -> int:
        """
        Mark all currently unacknowledged alerts as acknowledged.

        Args:
            db: Active async database session.

        Returns:
            The number of alerts that were acknowledged.
        """
        stmt = select(Alert).where(Alert.is_acknowledged == False)  # noqa: E712
        result = await db.execute(stmt)
        alerts = list(result.scalars().all())

        now = datetime.now(timezone.utc)
        for alert in alerts:
            alert.is_acknowledged = True
            alert.acknowledged_at = now

        await db.flush()

        count = len(alerts)
        log.info("alerts_acknowledged_all", count=count)
        return count

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    async def get_alert_stats(
        self, db: AsyncSession, period: str = "24h"
    ) -> dict[str, Any]:
        """
        Return aggregated alert statistics for the given time period.

        Parsed period values: ``"1h"``, ``"24h"``, ``"7d"``, ``"30d"``.
        Unknown values fall back to 24h.

        Returns a dict with keys:
        - ``total``: int
        - ``by_severity``: dict mapping severity -> count
        - ``by_type``: dict mapping alert_type -> count
        - ``trend``: list of ``{"hour": ISO-str, "count": int}`` dicts
          covering the whole period in 1-hour buckets
        - ``unacknowledged``: int
        """
        since = self._parse_period(period)

        # Total
        total_result = await db.execute(
            select(func.count(Alert.id)).where(Alert.created_at >= since)
        )
        total: int = total_result.scalar() or 0

        # Unacknowledged
        unack_result = await db.execute(
            select(func.count(Alert.id)).where(
                and_(Alert.created_at >= since, Alert.is_acknowledged == False)  # noqa: E712
            )
        )
        unacknowledged: int = unack_result.scalar() or 0

        # By severity
        sev_result = await db.execute(
            select(Alert.severity, func.count(Alert.id).label("cnt"))
            .where(Alert.created_at >= since)
            .group_by(Alert.severity)
        )
        by_severity: dict[str, int] = {row.severity: row.cnt for row in sev_result}

        # By type
        type_result = await db.execute(
            select(Alert.alert_type, func.count(Alert.id).label("cnt"))
            .where(Alert.created_at >= since)
            .group_by(Alert.alert_type)
        )
        by_type: dict[str, int] = {row.alert_type: row.cnt for row in type_result}

        # Hourly trend — fetch all alerts in period then bucket in Python
        # (SQLite lacks date_trunc; this stays DB-agnostic and handles
        #  multi-day periods cleanly)
        trend_result = await db.execute(
            select(Alert.created_at).where(Alert.created_at >= since)
        )
        trend = self._build_hourly_trend(
            [row[0] for row in trend_result], since
        )

        return {
            "total": total,
            "unacknowledged": unacknowledged,
            "by_severity": by_severity,
            "by_type": by_type,
            "trend": trend,
            "period": period,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _find_duplicate(
        self,
        db: AsyncSession,
        alert_type: str,
        source_ip: Optional[str],
        destination_ip: Optional[str],
    ) -> Optional[Alert]:
        """Check whether a matching alert exists within the dedup window."""
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=_DEDUP_WINDOW_SECONDS)

        conditions = [
            Alert.alert_type == alert_type,
            Alert.created_at >= cutoff,
        ]

        if source_ip is not None:
            conditions.append(Alert.source_ip == source_ip)
        else:
            conditions.append(Alert.source_ip.is_(None))

        if destination_ip is not None:
            conditions.append(Alert.destination_ip == destination_ip)
        else:
            conditions.append(Alert.destination_ip.is_(None))

        result = await db.execute(
            select(Alert)
            .where(and_(*conditions))
            .order_by(Alert.created_at.desc())
            .limit(1)
        )
        return result.scalar_one_or_none()

    async def _broadcast_alert(self, alert: Alert, event_type: EventType) -> None:
        """Serialize an alert and broadcast it to the alerts channel."""
        try:
            payload = self._alert_to_dict(alert)
            event = create_event(event_type, payload)
            await self._ws_manager.broadcast(CHANNEL_ALERTS, event)
        except Exception as exc:
            log.warning("alert_broadcast_failed", alert_id=alert.id, error=str(exc))

    @staticmethod
    def _alert_to_dict(alert: Alert) -> dict[str, Any]:
        """Convert an Alert ORM instance to a JSON-serialisable dict."""
        evidence: Any = None
        if alert.evidence:
            try:
                evidence = json.loads(alert.evidence)
            except (json.JSONDecodeError, TypeError):
                evidence = alert.evidence

        ioc_ref: Any = None
        if alert.ioc_reference:
            try:
                ioc_ref = json.loads(alert.ioc_reference)
            except (json.JSONDecodeError, TypeError):
                ioc_ref = alert.ioc_reference

        return {
            "id": alert.id,
            "alert_type": alert.alert_type,
            "severity": alert.severity,
            "title": alert.title,
            "description": alert.description,
            "source_ip": alert.source_ip,
            "destination_ip": alert.destination_ip,
            "source_mac": alert.source_mac,
            "evidence": evidence,
            "ioc_reference": ioc_ref,
            "is_acknowledged": alert.is_acknowledged,
            "acknowledged_at": (
                alert.acknowledged_at.isoformat() if alert.acknowledged_at else None
            ),
            "notes": alert.notes,
            "monitor_session_id": alert.monitor_session_id,
            "scan_id": alert.scan_id,
            "created_at": alert.created_at.isoformat() if alert.created_at else None,
        }

    @staticmethod
    def _parse_period(period: str) -> datetime:
        """
        Convert a period string to an absolute UTC cutoff datetime.

        Recognises: ``"1h"``, ``"24h"``, ``"7d"``, ``"30d"``.
        Falls back to 24h for unrecognised values.
        """
        now = datetime.now(timezone.utc)
        mapping: dict[str, timedelta] = {
            "1h": timedelta(hours=1),
            "24h": timedelta(hours=24),
            "7d": timedelta(days=7),
            "30d": timedelta(days=30),
        }
        delta = mapping.get(period, timedelta(hours=24))
        return now - delta

    @staticmethod
    def _build_hourly_trend(
        timestamps: list[datetime], since: datetime
    ) -> list[dict[str, Any]]:
        """
        Bucket a list of alert timestamps into 1-hour slots.

        Returns a list of dicts ordered chronologically, covering every
        hour from ``since`` through to now.  Hours with no alerts have
        count 0.
        """
        now = datetime.now(timezone.utc)

        # Build a slot map: truncated_hour -> count
        bucket: dict[datetime, int] = {}
        for ts in timestamps:
            # Normalise tz-aware comparisons
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            slot = ts.replace(minute=0, second=0, microsecond=0)
            bucket[slot] = bucket.get(slot, 0) + 1

        # Enumerate every hour in the period
        trend: list[dict[str, Any]] = []
        cursor = since.replace(minute=0, second=0, microsecond=0)
        while cursor <= now:
            trend.append(
                {
                    "hour": cursor.isoformat(),
                    "count": bucket.get(cursor, 0),
                }
            )
            cursor += timedelta(hours=1)

        return trend
