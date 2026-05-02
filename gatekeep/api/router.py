"""
Top-level API router for GATEKEEP.

Mounts all versioned sub-routers under the /api/v1 prefix.  The
WebSocket endpoint is mounted directly on the FastAPI app (no prefix)
so it resolves at ``/ws/events``.
"""

from __future__ import annotations

from fastapi import APIRouter

from gatekeep.api.alert_routes import router as alert_router
from gatekeep.api.device_routes import router as device_router
from gatekeep.api.dns_routes import router as dns_router
from gatekeep.api.hardening_routes import router as hardening_router
from gatekeep.api.monitor_routes import ioc_router, router as monitor_router
from gatekeep.api.router_admin_routes import router as router_admin_router
from gatekeep.api.scan_routes import router as scan_router
from gatekeep.api.system_routes import router as system_router
from gatekeep.api.websocket_routes import router as websocket_router

api_router = APIRouter(prefix="/api/v1")

# Mount sub-routers
api_router.include_router(system_router)
api_router.include_router(scan_router)
api_router.include_router(device_router)
api_router.include_router(dns_router)
api_router.include_router(monitor_router)
api_router.include_router(ioc_router)
api_router.include_router(alert_router)
api_router.include_router(hardening_router)
api_router.include_router(router_admin_router)

# WebSocket router — registered separately in create_app so it lives
# at the root path (no /api/v1 prefix).  Exposed here so app.py can
# import it cleanly.
ws_router = websocket_router
