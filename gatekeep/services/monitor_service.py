"""
Real-time network monitoring service for GATEKEEP.

Orchestrates the live packet processing pipeline:
  packet capture → anomaly detection → IOC matching → alert creation
  → WebSocket broadcast

Maintains a single active monitoring session at a time.  Call
``start_monitoring`` to begin, ``stop_monitoring`` to halt.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gatekeep.logging_config import get_logger
from gatekeep.models import MonitorSession, MonitorStatus
from gatekeep.utils.network import resolve_interface_name
from gatekeep.websocket.events import (
    CHANNEL_MONITOR_STATS,
    EventType,
    create_event,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from gatekeep.config import GatekeepConfig
    from gatekeep.engines.anomaly_detector import AnomalyDetector
    from gatekeep.engines.ioc_matcher import IOCMatcher
    from gatekeep.engines.packet_capture import PacketCapture
    from gatekeep.services.alert_service import AlertService
    from gatekeep.websocket.manager import ConnectionManager

log = get_logger(__name__)

# Broadcast monitor_stats every N packets
_DEFAULT_STATS_BROADCAST_INTERVAL = 100


class MonitorService:
    """
    Orchestrates real-time packet capture and threat processing.

    Lifecycle::

        svc = MonitorService(...)
        session_id = await svc.start_monitoring("eth0")
        # ... capture runs in background callbacks ...
        summary = await svc.stop_monitoring()

    Only one monitoring session is supported at a time.  Attempting to
    start while already active raises ``RuntimeError``.
    """

    def __init__(
        self,
        config: "GatekeepConfig",
        db_session_factory: Any,
        ws_manager: "ConnectionManager",
        ioc_matcher: "IOCMatcher",
        anomaly_detector: "AnomalyDetector",
        packet_capture: "PacketCapture",
        alert_service: "AlertService",
        stats_broadcast_interval: int = _DEFAULT_STATS_BROADCAST_INTERVAL,
    ) -> None:
        self._config = config
        self._db_session_factory = db_session_factory
        self._ws_manager = ws_manager
        self._ioc_matcher = ioc_matcher
        self._anomaly_detector = anomaly_detector
        self._packet_capture = packet_capture
        self._alert_service = alert_service
        self._stats_broadcast_interval = stats_broadcast_interval

        # Session state
        self._session_id: Optional[str] = None
        self._db_session_id: Optional[str] = None  # UUID of MonitorSession row
        self._interface: Optional[str] = None
        self._start_time: Optional[datetime] = None
        self._packet_count: int = 0
        self._alert_count: int = 0
        self._is_active: bool = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def is_active(self) -> bool:
        """Whether a monitoring session is currently running."""
        return self._is_active

    async def start_monitoring(
        self,
        interface: str,
        filters: Optional[dict[str, Any]] = None,
    ) -> str:
        """
        Start a new monitoring session on the given interface.

        Creates a ``MonitorSession`` record in the database, starts
        the packet capture engine, and wires up ``_process_packet`` as
        the per-packet callback.

        Args:
            interface: Network interface name to capture on.
            filters: Optional capture filter parameters (reserved for
                     future BPF filter support).

        Returns:
            The database UUID of the new MonitorSession.

        Raises:
            RuntimeError: If monitoring is already active.
        """
        if self._is_active:
            raise RuntimeError(
                f"Monitoring is already active on interface '{self._interface}'. "
                "Stop the current session before starting a new one."
            )

        # Resolve display name to scapy-compatible name
        interface = resolve_interface_name(interface)

        # Create the DB session record
        db_session_id = await self._create_db_session(interface)
        self._db_session_id = db_session_id

        # Start capture engine — this may raise NpcapNotFoundError or
        # InterfaceNotFoundError which propagate to the caller
        capture_session_id = await self._packet_capture.start(
            interface, self._process_packet
        )

        self._session_id = capture_session_id
        self._interface = interface
        self._start_time = datetime.now(timezone.utc)
        self._packet_count = 0
        self._alert_count = 0
        self._is_active = True

        log.info(
            "monitoring_started",
            db_session_id=db_session_id,
            capture_session_id=capture_session_id,
            interface=interface,
        )

        return db_session_id

    async def stop_monitoring(self) -> dict[str, Any]:
        """
        Stop the active monitoring session.

        Halts packet capture, persists final statistics to the DB, and
        returns a summary dictionary.

        Returns:
            Dict with keys: session_id, interface, packets_captured,
            alerts_generated, duration_seconds, stopped_at.

        Raises:
            RuntimeError: If no monitoring session is currently active.
        """
        if not self._is_active:
            raise RuntimeError("No monitoring session is currently active.")

        # Stop capture engine
        try:
            stats = await self._packet_capture.stop()
        except Exception as exc:
            log.error("packet_capture_stop_error", error=str(exc))
            stats = None

        stopped_at = datetime.now(timezone.utc)
        duration = (
            (stopped_at - self._start_time).total_seconds()
            if self._start_time
            else 0.0
        )

        packets = stats.packets_captured if stats else self._packet_count

        # Update DB record
        if self._db_session_id:
            await self._update_db_session(
                self._db_session_id,
                status=MonitorStatus.STOPPED,
                stopped_at=stopped_at,
                packet_count=packets,
                alert_count=self._alert_count,
            )

        summary: dict[str, Any] = {
            "session_id": self._db_session_id,
            "interface": self._interface,
            "packets_captured": packets,
            "alerts_generated": self._alert_count,
            "duration_seconds": round(duration, 2),
            "stopped_at": stopped_at.isoformat(),
        }

        log.info(
            "monitoring_stopped",
            **{k: v for k, v in summary.items() if k != "stopped_at"},
        )

        # Reset state
        self._is_active = False
        self._session_id = None
        self._interface = None
        self._start_time = None

        return summary

    async def get_status(self) -> dict[str, Any]:
        """
        Return the current monitoring state.

        Returns:
            Dict with keys: is_active, session_id, interface, uptime_seconds,
            packet_count, alert_count.
        """
        uptime: Optional[float] = None
        if self._is_active and self._start_time:
            uptime = round(
                (datetime.now(timezone.utc) - self._start_time).total_seconds(), 2
            )

        return {
            "is_active": self._is_active,
            "session_id": self._db_session_id,
            "interface": self._interface,
            "uptime_seconds": uptime,
            "packet_count": self._packet_count,
            "alert_count": self._alert_count,
        }

    # ------------------------------------------------------------------
    # Packet processing pipeline
    # ------------------------------------------------------------------

    async def _process_packet(self, packet: Any) -> None:
        """
        Per-packet callback wired to PacketCapture.

        Extracts IP / TCP / UDP / DNS fields, runs anomaly detection and
        IOC matching, creates alerts for positive detections, and
        periodically broadcasts monitoring statistics.

        All exceptions are caught internally so a single bad packet
        cannot break the capture loop.
        """
        self._packet_count += 1

        try:
            packet_info = self._extract_packet_info(packet)
        except Exception as exc:
            log.debug("packet_extract_failed", error=str(exc))
            # Periodic stats broadcast still fires
            await self._maybe_broadcast_stats()
            return

        # --- Anomaly detection ---
        try:
            anomaly = await self._anomaly_detector.evaluate(packet)
        except Exception as exc:
            log.debug("anomaly_eval_failed", error=str(exc))
            anomaly = None

        if anomaly:
            await self._handle_anomaly(anomaly, packet_info)

        # --- IOC matching ---
        try:
            ioc_match = await self._ioc_matcher.check_packet(packet_info)
        except Exception as exc:
            log.debug("ioc_check_failed", error=str(exc))
            ioc_match = None

        if ioc_match:
            await self._handle_ioc_match(ioc_match, packet_info)

        # --- Periodic stats broadcast ---
        await self._maybe_broadcast_stats()

    # ------------------------------------------------------------------
    # Detection handlers
    # ------------------------------------------------------------------

    async def _handle_anomaly(self, anomaly: Any, packet_info: dict[str, Any]) -> None:
        """Create an alert and broadcast a WebSocket event for an anomaly."""
        try:
            async with self._db_session_factory() as db:
                alert = await self._alert_service.create_alert(
                    db=db,
                    alert_type=anomaly.type,
                    severity=anomaly.severity,
                    title=self._anomaly_title(anomaly),
                    description=anomaly.description,
                    source_ip=anomaly.source_ip,
                    destination_ip=anomaly.destination_ip,
                    source_mac=packet_info.get("src_mac"),
                    evidence=anomaly.evidence,
                    monitor_session_id=self._db_session_id,
                )
                await db.commit()
                self._alert_count += 1

            # Broadcast anomaly event to monitor_stats channel
            event = create_event(
                EventType.MONITOR_ANOMALY,
                {
                    "type": anomaly.type,
                    "severity": anomaly.severity,
                    "description": anomaly.description,
                    "source_ip": anomaly.source_ip,
                    "destination_ip": anomaly.destination_ip,
                    "alert_id": alert.id,
                    "confidence": anomaly.confidence,
                },
            )
            await self._ws_manager.broadcast(CHANNEL_MONITOR_STATS, event)

        except Exception as exc:
            log.error("anomaly_alert_failed", error=str(exc), anomaly_type=anomaly.type)

    async def _handle_ioc_match(
        self, ioc_match: Any, packet_info: dict[str, Any]
    ) -> None:
        """Create a CRITICAL alert for an IOC match and broadcast."""
        try:
            ioc_ref = {
                "indicator_type": ioc_match.indicator_type,
                "matched_value": ioc_match.matched_value,
                "threat_actor": ioc_match.threat_actor,
                "campaign": ioc_match.campaign,
                "confidence": ioc_match.confidence,
                "source_reference": ioc_match.source_reference,
            }

            title = (
                f"IOC Match: {ioc_match.threat_actor} indicator detected "
                f"({ioc_match.indicator_type}: {ioc_match.matched_value})"
            )

            async with self._db_session_factory() as db:
                alert = await self._alert_service.create_alert(
                    db=db,
                    alert_type="ioc_match",
                    severity="critical",
                    title=title,
                    description=ioc_match.description,
                    source_ip=packet_info.get("src_ip"),
                    destination_ip=packet_info.get("dst_ip"),
                    source_mac=packet_info.get("src_mac"),
                    ioc_reference=ioc_ref,
                    monitor_session_id=self._db_session_id,
                )
                await db.commit()
                self._alert_count += 1

            event = create_event(
                EventType.MONITOR_ANOMALY,
                {
                    "type": "ioc_match",
                    "severity": "critical",
                    "description": ioc_match.description,
                    "matched_value": ioc_match.matched_value,
                    "indicator_type": ioc_match.indicator_type,
                    "threat_actor": ioc_match.threat_actor,
                    "alert_id": alert.id,
                },
            )
            await self._ws_manager.broadcast(CHANNEL_MONITOR_STATS, event)

        except Exception as exc:
            log.error(
                "ioc_alert_failed",
                error=str(exc),
                matched_value=ioc_match.matched_value,
            )

    # ------------------------------------------------------------------
    # Stats broadcast
    # ------------------------------------------------------------------

    async def _maybe_broadcast_stats(self) -> None:
        """Broadcast monitor statistics every N packets."""
        if self._packet_count % self._stats_broadcast_interval == 0:
            uptime: Optional[float] = None
            if self._start_time:
                uptime = round(
                    (datetime.now(timezone.utc) - self._start_time).total_seconds(), 2
                )

            event = create_event(
                EventType.MONITOR_STATS,
                {
                    "session_id": self._db_session_id,
                    "interface": self._interface,
                    "packet_count": self._packet_count,
                    "alert_count": self._alert_count,
                    "uptime_seconds": uptime,
                    "is_active": self._is_active,
                },
            )
            try:
                await self._ws_manager.broadcast(CHANNEL_MONITOR_STATS, event)
            except Exception as exc:
                log.debug("stats_broadcast_failed", error=str(exc))

    # ------------------------------------------------------------------
    # Packet field extraction
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_packet_info(packet: Any) -> dict[str, Any]:
        """
        Pull IP/TCP/UDP/DNS fields from a scapy packet into a flat dict.

        Returns an empty (but valid) dict if none of the expected layers
        are present.
        """
        info: dict[str, Any] = {}

        try:
            from scapy.layers.inet import IP, TCP, UDP
            from scapy.layers.dns import DNS, DNSQR

            if packet.haslayer(IP):
                ip_layer = packet[IP]
                info["src_ip"] = ip_layer.src
                info["dst_ip"] = ip_layer.dst

                if packet.haslayer(TCP):
                    tcp_layer = packet[TCP]
                    info["src_port"] = tcp_layer.sport
                    info["dst_port"] = tcp_layer.dport
                    info["protocol"] = "tcp"

                elif packet.haslayer(UDP):
                    udp_layer = packet[UDP]
                    info["src_port"] = udp_layer.sport
                    info["dst_port"] = udp_layer.dport
                    info["protocol"] = "udp"

            if packet.haslayer(DNS) and packet.haslayer(DNSQR):
                raw_name = packet[DNSQR].qname
                if isinstance(raw_name, bytes):
                    info["dns_query"] = raw_name.decode("utf-8", errors="ignore")
                else:
                    info["dns_query"] = str(raw_name)

            # Ethernet layer for MAC addresses
            try:
                from scapy.layers.l2 import Ether
                if packet.haslayer(Ether):
                    ether_layer = packet[Ether]
                    info["src_mac"] = ether_layer.src
                    info["dst_mac"] = ether_layer.dst
            except ImportError:
                pass

        except Exception as exc:
            log.debug("packet_info_extract_error", error=str(exc))

        return info

    # ------------------------------------------------------------------
    # Database helpers
    # ------------------------------------------------------------------

    async def _create_db_session(self, interface: str) -> str:
        """Insert a new MonitorSession record and return its ID."""
        async with self._db_session_factory() as db:
            session = MonitorSession(
                interface_name=interface,
                status=MonitorStatus.RUNNING,
                started_at=datetime.now(timezone.utc),
                packet_count=0,
                alert_count=0,
            )
            db.add(session)
            await db.flush()
            session_id = session.id
            await db.commit()

        return session_id

    async def _update_db_session(
        self,
        session_id: str,
        status: str,
        stopped_at: datetime,
        packet_count: int,
        alert_count: int,
    ) -> None:
        """Update an existing MonitorSession with final stats."""
        try:
            async with self._db_session_factory() as db:
                result = await db.execute(
                    select(MonitorSession).where(MonitorSession.id == session_id)
                )
                session = result.scalar_one_or_none()
                if session:
                    session.status = status
                    session.stopped_at = stopped_at
                    session.packet_count = packet_count
                    session.alert_count = alert_count
                    await db.commit()
        except Exception as exc:
            log.error(
                "monitor_session_update_failed",
                session_id=session_id,
                error=str(exc),
            )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _anomaly_title(anomaly: Any) -> str:
        """Derive a short, human-readable title from an Anomaly."""
        titles: dict[str, str] = {
            "port_scan": "Port Scan Detected",
            "syn_flood": "SYN Flood Attack Detected",
            "dns_tunneling": "DNS Tunneling Suspected",
        }
        return titles.get(anomaly.type, f"Anomaly Detected: {anomaly.type.replace('_', ' ').title()}")
