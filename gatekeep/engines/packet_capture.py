"""
Packet capture engine for GATEKEEP.

Wraps scapy's AsyncSniffer to provide an async-friendly interface
for live packet capture on a network interface.  Each captured
packet is forwarded to a user-supplied callback for real-time
anomaly detection and IOC matching.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from gatekeep.config import MonitoringConfig
from gatekeep.exceptions import GatekeepError, NpcapNotFoundError
from gatekeep.logging_config import get_logger
from gatekeep.utils.network import resolve_interface_name

log = get_logger(__name__)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class CaptureStats:
    """Statistics from a completed or stopped capture session."""

    session_id: str
    packets_captured: int
    bytes_captured: int
    duration_seconds: float
    start_time: datetime
    stop_time: datetime


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class CaptureError(GatekeepError):
    """Raised when packet capture encounters an unrecoverable error."""

    pass


class InterfaceNotFoundError(GatekeepError):
    """Raised when the requested network interface does not exist."""

    def __init__(self, interface: str) -> None:
        super().__init__(
            f"Network interface '{interface}' not found. "
            f"Check available interfaces and ensure the name is correct.",
            details={"interface": interface},
        )


# ---------------------------------------------------------------------------
# Packet capture engine
# ---------------------------------------------------------------------------


class PacketCapture:
    """
    Async packet capture engine wrapping scapy AsyncSniffer.

    Provides start/stop lifecycle management, per-packet callbacks,
    and basic capture statistics (packet count, byte count, duration).

    Usage::

        capture = PacketCapture(config)
        session_id = await capture.start("eth0", my_callback)
        # ... later ...
        stats = await capture.stop()
    """

    def __init__(self, config: MonitoringConfig) -> None:
        self._config = config
        self._sniffer: Any = None
        self._session_id: Optional[str] = None
        self._is_running: bool = False
        self._packet_count: int = 0
        self._bytes_captured: int = 0
        self._start_time: Optional[datetime] = None
        self._callback: Optional[Callable] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def start(self, interface: str, callback: Callable) -> str:
        """
        Start capturing packets on the specified interface.

        Each captured packet is passed to ``callback`` which should
        accept a single scapy Packet argument.  The callback is
        scheduled on the event loop to maintain async compatibility.

        Args:
            interface: Name of the network interface to sniff on.
            callback: Callable invoked for every captured packet.

        Returns:
            The session ID for this capture run.

        Raises:
            CaptureError: If a capture is already running.
            NpcapNotFoundError: If scapy cannot import due to missing Npcap.
            InterfaceNotFoundError: If the interface does not exist.
        """
        if self._is_running:
            raise CaptureError(
                "A capture session is already running. Stop it before starting a new one.",
                details={"current_session_id": self._session_id},
            )

        # Resolve display name to scapy-compatible name
        interface = resolve_interface_name(interface)

        # Import scapy lazily so the rest of the application works
        # even when Npcap is not installed.
        try:
            from scapy.all import AsyncSniffer, conf, get_if_list
        except ImportError as exc:
            raise NpcapNotFoundError() from exc

        # Validate interface exists
        try:
            available_interfaces = await asyncio.to_thread(get_if_list)
        except Exception as exc:
            raise NpcapNotFoundError() from exc

        if interface not in available_interfaces:
            raise InterfaceNotFoundError(interface)

        self._session_id = str(uuid.uuid4())
        self._packet_count = 0
        self._bytes_captured = 0
        self._callback = callback
        self._loop = asyncio.get_running_loop()

        def _packet_handler(packet: Any) -> None:
            """Synchronous handler invoked by scapy's sniffer thread."""
            self._packet_count += 1
            try:
                self._bytes_captured += len(bytes(packet))
            except Exception:
                pass  # Some packets may not serialize cleanly

            # Schedule the async callback on the event loop
            if self._loop is not None and self._callback is not None:
                try:
                    self._loop.call_soon_threadsafe(
                        asyncio.ensure_future,
                        self._invoke_callback(packet),
                    )
                except RuntimeError:
                    # Event loop may be closed during shutdown
                    pass

        try:
            sniffer = AsyncSniffer(
                iface=interface,
                prn=_packet_handler,
                store=False,
            )
            # Start the sniffer in a thread so it doesn't block the event loop
            await asyncio.to_thread(sniffer.start)
        except PermissionError as exc:
            raise CaptureError(
                "Insufficient permissions for packet capture. "
                "Run GATEKEEP with administrator privileges.",
                details={"interface": interface},
            ) from exc
        except OSError as exc:
            error_msg = str(exc).lower()
            if "npcap" in error_msg or "winpcap" in error_msg or "pcap" in error_msg:
                raise NpcapNotFoundError() from exc
            raise CaptureError(
                f"Failed to start capture on interface '{interface}': {exc}",
                details={"interface": interface},
            ) from exc

        self._sniffer = sniffer
        self._is_running = True
        self._start_time = datetime.now(timezone.utc)

        log.info(
            "packet_capture_started",
            session_id=self._session_id,
            interface=interface,
        )

        return self._session_id

    async def stop(self) -> CaptureStats:
        """
        Stop the running capture and return session statistics.

        Returns:
            A CaptureStats dataclass with totals for this session.

        Raises:
            CaptureError: If no capture session is currently running.
        """
        if not self._is_running or self._sniffer is None:
            raise CaptureError("No capture session is currently running.")

        try:
            await asyncio.to_thread(self._sniffer.stop)
        except Exception as exc:
            log.warning("sniffer_stop_error", error=str(exc))

        stop_time = datetime.now(timezone.utc)
        start_time = self._start_time or stop_time

        duration = (stop_time - start_time).total_seconds()

        stats = CaptureStats(
            session_id=self._session_id or "",
            packets_captured=self._packet_count,
            bytes_captured=self._bytes_captured,
            duration_seconds=duration,
            start_time=start_time,
            stop_time=stop_time,
        )

        log.info(
            "packet_capture_stopped",
            session_id=stats.session_id,
            packets=stats.packets_captured,
            bytes=stats.bytes_captured,
            duration_seconds=round(stats.duration_seconds, 2),
        )

        # Reset state
        self._sniffer = None
        self._is_running = False
        self._callback = None
        self._loop = None

        return stats

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def is_running(self) -> bool:
        """Whether a capture session is currently active."""
        return self._is_running

    @property
    def packet_count(self) -> int:
        """Number of packets captured in the current session."""
        return self._packet_count

    @property
    def session_id(self) -> Optional[str]:
        """Session ID of the current or most recent capture."""
        return self._session_id

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    async def _invoke_callback(self, packet: Any) -> None:
        """
        Invoke the user callback, handling both sync and async variants.
        """
        if self._callback is None:
            return

        try:
            result = self._callback(packet)
            if asyncio.iscoroutine(result):
                await result
        except Exception as exc:
            log.error(
                "packet_callback_error",
                error=str(exc),
                session_id=self._session_id,
            )
