"""
WebSocket connection manager for GATEKEEP.

Manages the full lifecycle of WebSocket connections: acceptance,
channel subscription, targeted and broadcast messaging, and a
background heartbeat loop that prunes unresponsive clients.

Thread safety is ensured via asyncio.Lock on all mutations to
shared connection state.
"""

from __future__ import annotations

import asyncio
import uuid
from typing import Any

from fastapi import WebSocket, WebSocketDisconnect

from gatekeep.logging_config import get_logger
from gatekeep.websocket.events import (
    ALL_CHANNELS,
    CHANNEL_SYSTEM,
    EventType,
    create_event,
)

log = get_logger(__name__)


class ConnectionManager:
    """
    Manages active WebSocket connections and channel subscriptions.

    Each accepted connection is assigned a unique session ID and is
    automatically subscribed to the ``system`` channel.  Clients may
    subscribe to additional channels (alerts, scan_progress,
    monitor_stats) at any time.

    The heartbeat loop runs as a background task, pinging every
    connection at a configurable interval and dropping any that fail
    to respond.
    """

    def __init__(self, heartbeat_interval: int = 30, max_connections: int = 10) -> None:
        # session_id -> WebSocket
        self._connections: dict[str, WebSocket] = {}
        # session_id -> set of channel names
        self._subscriptions: dict[str, set[str]] = {}
        # Protects mutations to _connections and _subscriptions
        self._lock = asyncio.Lock()
        self._heartbeat_interval = heartbeat_interval
        self._max_connections = max_connections

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------

    async def connect(self, websocket: WebSocket) -> str:
        """
        Accept a WebSocket connection and register it.

        Assigns a unique session ID, subscribes to the system channel,
        and sends a ``connected`` event with the session ID.

        Args:
            websocket: The incoming FastAPI WebSocket.

        Returns:
            The assigned session ID.

        Raises:
            WebSocketDisconnect: If the maximum connection limit is reached.
        """
        async with self._lock:
            if len(self._connections) >= self._max_connections:
                await websocket.close(code=1013, reason="Maximum connections reached")
                raise WebSocketDisconnect(
                    code=1013, reason="Maximum connections reached"
                )

            await websocket.accept()
            session_id = str(uuid.uuid4())
            self._connections[session_id] = websocket
            self._subscriptions[session_id] = {CHANNEL_SYSTEM}

        log.info("websocket_connected", session_id=session_id)

        # Send connection confirmation
        event = create_event(
            EventType.CONNECTED,
            {
                "session_id": session_id,
                "channels": [CHANNEL_SYSTEM],
                "available_channels": sorted(ALL_CHANNELS),
            },
        )
        await self._safe_send(session_id, event)

        return session_id

    async def disconnect(self, session_id: str) -> None:
        """
        Remove a connection and clean up its subscriptions.

        Silently ignores unknown session IDs so callers need not
        check membership first.

        Args:
            session_id: The session to remove.
        """
        async with self._lock:
            ws = self._connections.pop(session_id, None)
            self._subscriptions.pop(session_id, None)

        if ws is not None:
            log.info("websocket_disconnected", session_id=session_id)
            try:
                await ws.close()
            except Exception:
                pass  # Connection may already be closed

    # ------------------------------------------------------------------
    # Subscriptions
    # ------------------------------------------------------------------

    async def subscribe(self, session_id: str, channels: list[str]) -> None:
        """
        Subscribe a session to one or more channels.

        Invalid channel names are silently ignored.  After updating
        subscriptions, a ``subscribed`` event is sent to the client
        listing its current channel set.

        Args:
            session_id: The connection to update.
            channels: Channel names to add.
        """
        valid_channels = {ch for ch in channels if ch in ALL_CHANNELS}
        if not valid_channels:
            return

        async with self._lock:
            if session_id not in self._subscriptions:
                return
            self._subscriptions[session_id].update(valid_channels)
            current_channels = sorted(self._subscriptions[session_id])

        log.debug(
            "websocket_subscribed",
            session_id=session_id,
            channels=current_channels,
        )

        event = create_event(
            EventType.SUBSCRIBED,
            {"channels": current_channels},
        )
        await self._safe_send(session_id, event)

    # ------------------------------------------------------------------
    # Messaging
    # ------------------------------------------------------------------

    async def broadcast(self, channel: str, event: dict[str, Any]) -> None:
        """
        Send an event to all connections subscribed to a channel.

        Connections that fail to receive the message are scheduled for
        disconnection but do not block the broadcast to other clients.

        Args:
            channel: The target channel name.
            event: The event envelope to send.
        """
        async with self._lock:
            targets = [
                (sid, ws)
                for sid, ws in self._connections.items()
                if channel in self._subscriptions.get(sid, set())
            ]

        failed: list[str] = []
        for session_id, ws in targets:
            try:
                await ws.send_json(event)
            except Exception:
                log.warning(
                    "broadcast_send_failed",
                    session_id=session_id,
                    channel=channel,
                )
                failed.append(session_id)

        # Clean up failed connections
        for session_id in failed:
            await self.disconnect(session_id)

    async def send_personal(self, session_id: str, event: dict[str, Any]) -> None:
        """
        Send an event to a specific connection.

        If the send fails, the connection is disconnected.

        Args:
            session_id: The target session.
            event: The event envelope to send.
        """
        success = await self._safe_send(session_id, event)
        if not success:
            await self.disconnect(session_id)

    # ------------------------------------------------------------------
    # Heartbeat
    # ------------------------------------------------------------------

    async def heartbeat_loop(self) -> None:
        """
        Background coroutine that pings all connections periodically.

        Sends a ``system_ping`` event every ``heartbeat_interval``
        seconds.  Connections that raise during the send are pruned.

        This coroutine runs indefinitely and should be launched as an
        asyncio task during application startup.
        """
        log.info(
            "heartbeat_loop_started",
            interval_seconds=self._heartbeat_interval,
        )
        while True:
            await asyncio.sleep(self._heartbeat_interval)

            async with self._lock:
                session_ids = list(self._connections.keys())

            if not session_ids:
                continue

            ping_event = create_event(EventType.SYSTEM_PING, {"message": "ping"})
            failed: list[str] = []

            for session_id in session_ids:
                success = await self._safe_send(session_id, ping_event)
                if not success:
                    failed.append(session_id)

            for session_id in failed:
                log.warning("heartbeat_failed", session_id=session_id)
                await self.disconnect(session_id)

            if failed:
                log.info(
                    "heartbeat_pruned",
                    pruned_count=len(failed),
                    remaining=len(session_ids) - len(failed),
                )

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def active_connections(self) -> int:
        """Return the number of active connections."""
        return len(self._connections)

    @property
    def session_ids(self) -> list[str]:
        """Return a snapshot of all active session IDs."""
        return list(self._connections.keys())

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _safe_send(self, session_id: str, event: dict[str, Any]) -> bool:
        """
        Attempt to send JSON to a specific session.

        Returns True on success, False on any exception (connection
        closed, broken pipe, etc.).
        """
        async with self._lock:
            ws = self._connections.get(session_id)

        if ws is None:
            return False

        try:
            await ws.send_json(event)
            return True
        except WebSocketDisconnect:
            log.debug("send_websocket_disconnect", session_id=session_id)
            return False
        except Exception as exc:
            log.debug(
                "send_failed",
                session_id=session_id,
                error=str(exc),
            )
            return False
