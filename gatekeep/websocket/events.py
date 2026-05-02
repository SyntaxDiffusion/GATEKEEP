"""
WebSocket event type definitions for GATEKEEP.

Defines the event taxonomy, channel constants, and a factory function
that produces standardized event envelopes sent over WebSocket
connections.  Every outbound message conforms to the envelope schema
so clients can parse events generically.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone
from typing import Any


# ---------------------------------------------------------------------------
# Channel constants
# ---------------------------------------------------------------------------

CHANNEL_ALERTS: str = "alerts"
CHANNEL_SCAN_PROGRESS: str = "scan_progress"
CHANNEL_MONITOR_STATS: str = "monitor_stats"
CHANNEL_SYSTEM: str = "system"

ALL_CHANNELS: frozenset[str] = frozenset(
    {CHANNEL_ALERTS, CHANNEL_SCAN_PROGRESS, CHANNEL_MONITOR_STATS, CHANNEL_SYSTEM}
)


# ---------------------------------------------------------------------------
# Event types
# ---------------------------------------------------------------------------


class EventType(enum.StrEnum):
    """Enumeration of all WebSocket event types."""

    # Connection lifecycle
    CONNECTED = "connected"
    SUBSCRIBED = "subscribed"

    # Scan progress
    SCAN_STARTED = "scan_started"
    SCAN_DEVICE_FOUND = "scan_device_found"
    SCAN_PHASE = "scan_phase"
    SCAN_COMPLETED = "scan_completed"
    SCAN_ERROR = "scan_error"

    # Alerts
    ALERT_NEW = "alert_new"
    ALERT_UPDATED = "alert_updated"

    # Monitor
    MONITOR_STATS = "monitor_stats"
    MONITOR_ANOMALY = "monitor_anomaly"

    # System
    SYSTEM_PING = "system_ping"
    SYSTEM_PONG = "system_pong"


# ---------------------------------------------------------------------------
# Event factory
# ---------------------------------------------------------------------------


def create_event(event_type: EventType, data: dict[str, Any] | None = None) -> dict[str, Any]:
    """
    Create a standardized event envelope.

    Every WebSocket message uses this structure so clients can dispatch
    on ``type`` and extract ``data`` without per-event parsing logic.

    Args:
        event_type: The event classification.
        data: Arbitrary payload for this event.

    Returns:
        A dict with keys: type, data, timestamp (ISO-8601), event_id (UUID4).
    """
    return {
        "type": str(event_type),
        "data": data or {},
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_id": str(uuid.uuid4()),
    }
