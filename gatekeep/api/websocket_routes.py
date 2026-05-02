"""
WebSocket endpoint for GATEKEEP real-time event streaming.

Accepts connections at ``ws://<host>/ws/events``, manages channel
subscriptions, and handles client heartbeat responses.  Delegates
all connection lifecycle management to the shared ConnectionManager
stored on ``app.state.ws_manager``.
"""

from __future__ import annotations

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from gatekeep.logging_config import get_logger

log = get_logger(__name__)

router = APIRouter(tags=["websocket"])


@router.websocket("/ws/events")
async def websocket_events(websocket: WebSocket) -> None:
    """
    WebSocket endpoint for real-time GATEKEEP event streaming.

    On connection:
    - Registers the client with ConnectionManager (auto-subscribes to system)
    - Sends a ``connected`` event with session ID and available channels

    Accepted client messages:
    - ``{"type": "subscribe", "channels": [...]}``
      Subscribe to one or more named channels.
    - ``{"type": "pong"}``
      Heartbeat response; acknowledged silently.

    Any other message type is ignored.  Malformed JSON is discarded.
    The connection is cleaned up on disconnect or any unrecoverable error.
    """
    ws_manager = websocket.app.state.ws_manager if hasattr(websocket.app.state, "ws_manager") else None

    if ws_manager is None:
        # WebSocket infrastructure not ready; reject cleanly
        await websocket.close(code=1013, reason="Service unavailable")
        return

    session_id: str | None = None

    try:
        session_id = await ws_manager.connect(websocket)

        while True:
            try:
                message = await websocket.receive_json()
            except WebSocketDisconnect:
                raise
            except Exception:
                # Malformed or non-JSON message — discard and continue
                try:
                    raw = await websocket.receive_text()
                    log.debug(
                        "websocket_non_json_message",
                        session_id=session_id,
                        preview=raw[:100] if raw else "",
                    )
                except WebSocketDisconnect:
                    raise
                except Exception:
                    pass
                continue

            msg_type = message.get("type") if isinstance(message, dict) else None

            if msg_type == "subscribe":
                channels = message.get("channels", [])
                if isinstance(channels, list):
                    await ws_manager.subscribe(session_id, channels)

            elif msg_type == "pong":
                # Client responded to our heartbeat ping — no action needed
                log.debug("websocket_pong_received", session_id=session_id)

            else:
                log.debug(
                    "websocket_unknown_message_type",
                    session_id=session_id,
                    msg_type=msg_type,
                )

    except WebSocketDisconnect as exc:
        log.info(
            "websocket_client_disconnected",
            session_id=session_id,
            code=exc.code,
        )
    except Exception as exc:
        log.warning(
            "websocket_error",
            session_id=session_id,
            error=str(exc),
        )
    finally:
        if session_id is not None:
            await ws_manager.disconnect(session_id)
