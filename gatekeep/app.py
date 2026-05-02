"""
FastAPI application factory for GATEKEEP.

Creates and configures the FastAPI instance with middleware, exception
handlers, static file serving, and database lifecycle management.
"""

from __future__ import annotations

import asyncio
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from gatekeep import __app_name__, __version__
from gatekeep.api.router import api_router, ws_router
from gatekeep.config import get_config
from gatekeep.database import close_db, get_session_factory, init_db
from gatekeep.exceptions import register_exception_handlers
from gatekeep.logging_config import get_logger, setup_logging
from gatekeep.privileges import get_privilege_level

logger = get_logger(__name__)


def _check_npcap_available() -> bool:
    """Probe whether Npcap/libpcap is usable for raw packet capture.

    On Windows, checks for the presence of ``wpcap.dll`` in the standard
    Npcap install locations.  On other platforms, attempts a lightweight
    scapy import.
    """
    import os
    import platform

    if platform.system().lower() == "windows":
        system32 = os.path.join(
            os.environ.get("WINDIR", r"C:\Windows"), "System32"
        )
        npcap_dir = os.path.join(system32, "Npcap")
        # WinPcap compat mode puts wpcap.dll directly in System32
        if os.path.isfile(os.path.join(system32, "wpcap.dll")):
            return True
        # Npcap without compat mode puts it in System32\Npcap
        if os.path.isfile(os.path.join(npcap_dir, "wpcap.dll")):
            return True
        return False

    # Non-Windows: try importing scapy as a basic availability check
    try:
        from scapy.config import conf  # type: ignore[import-untyped]

        _ = conf.iface
        return True
    except Exception:
        return False


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Application lifespan context manager.

    Startup sequence:
    1. Load and validate configuration
    2. Configure structured logging
    3. Initialise the database (create tables)
    4. Instantiate WebSocket ConnectionManager → app.state.ws_manager
    5. Instantiate IOCMatcher and load indicators → app.state.ioc_matcher
    6. Instantiate AnomalyDetector → app.state.anomaly_detector
    7. Instantiate PacketCapture (if Npcap available) → app.state.packet_capture
    8. Instantiate AlertService → app.state.alert_service
    9. Instantiate MonitorService → app.state.monitor_service
    10. Launch WebSocket heartbeat as a background task

    Shutdown:
    - Cancel heartbeat task
    - Close database connections
    """
    config = get_config()

    # ----------------------------------------------------------------
    # 1. Logging
    # ----------------------------------------------------------------
    setup_logging(
        log_level=config.app.log_level,
        log_dir="logs",
    )

    logger.info(
        "starting_application",
        app=__app_name__,
        version=__version__,
        host=config.app.host,
        port=config.app.port,
    )

    # ----------------------------------------------------------------
    # 2. Database
    # ----------------------------------------------------------------
    await init_db()
    logger.info("database_initialized", path=config.app.database_path)

    # ----------------------------------------------------------------
    # 3. Privileges / Npcap
    # ----------------------------------------------------------------
    priv_level = get_privilege_level()
    logger.info(
        "privilege_level_detected",
        level=priv_level.value,
        capabilities=priv_level.capabilities,
    )

    npcap = _check_npcap_available()
    if npcap:
        logger.info("npcap_available", status="installed")
    else:
        logger.warning(
            "npcap_unavailable",
            message="Npcap not found. Raw packet capture will be unavailable.",
        )

    logger.info("ai_configuration", ai_available=config.ai_available)

    # ----------------------------------------------------------------
    # 4. WebSocket ConnectionManager
    # ----------------------------------------------------------------
    from gatekeep.websocket.manager import ConnectionManager

    ws_manager = ConnectionManager(
        heartbeat_interval=config.websocket.heartbeat_interval,
        max_connections=config.websocket.max_connections,
    )
    app.state.ws_manager = ws_manager
    logger.info(
        "websocket_manager_ready",
        heartbeat_interval=config.websocket.heartbeat_interval,
        max_connections=config.websocket.max_connections,
    )

    # ----------------------------------------------------------------
    # 5. IOC Matcher
    # ----------------------------------------------------------------
    from gatekeep.engines.ioc_matcher import IOCMatcher

    ioc_matcher = IOCMatcher()
    await ioc_matcher.load_indicators()
    app.state.ioc_matcher = ioc_matcher
    logger.info(
        "ioc_matcher_ready",
        indicator_count=ioc_matcher.indicator_count,
    )

    # ----------------------------------------------------------------
    # 6. Anomaly Detector
    # ----------------------------------------------------------------
    from gatekeep.engines.anomaly_detector import AnomalyDetector

    anomaly_detector = AnomalyDetector(config.monitoring)
    app.state.anomaly_detector = anomaly_detector
    logger.info("anomaly_detector_ready")

    # ----------------------------------------------------------------
    # 7. Packet Capture (only if Npcap is available)
    # ----------------------------------------------------------------
    packet_capture = None
    if npcap:
        from gatekeep.engines.packet_capture import PacketCapture

        packet_capture = PacketCapture(config.monitoring)
        app.state.packet_capture = packet_capture
        logger.info("packet_capture_ready")
    else:
        app.state.packet_capture = None
        logger.warning(
            "packet_capture_unavailable",
            reason="Npcap not installed; monitoring endpoints will report 503.",
        )

    # ----------------------------------------------------------------
    # 8. Alert Service
    # ----------------------------------------------------------------
    from gatekeep.services.alert_service import AlertService

    alert_service = AlertService(
        config=config.alerts,
        ws_manager=ws_manager,
    )
    app.state.alert_service = alert_service
    logger.info("alert_service_ready")

    # ----------------------------------------------------------------
    # 9. Monitor Service
    # ----------------------------------------------------------------
    monitor_service = None
    if packet_capture is not None:
        from gatekeep.services.monitor_service import MonitorService

        monitor_service = MonitorService(
            config=config,
            db_session_factory=get_session_factory(),
            ws_manager=ws_manager,
            ioc_matcher=ioc_matcher,
            anomaly_detector=anomaly_detector,
            packet_capture=packet_capture,
            alert_service=alert_service,
        )
        logger.info("monitor_service_ready")
    else:
        logger.warning(
            "monitor_service_unavailable",
            reason="PacketCapture not initialised.",
        )

    app.state.monitor_service = monitor_service

    # ----------------------------------------------------------------
    # 10. WebSocket heartbeat background task
    # ----------------------------------------------------------------
    heartbeat_task = asyncio.create_task(
        ws_manager.heartbeat_loop(),
        name="ws_heartbeat",
    )
    logger.info("application_ready")

    # ----------------------------------------------------------------
    # Hand control to the application
    # ----------------------------------------------------------------
    yield

    # ----------------------------------------------------------------
    # Shutdown
    # ----------------------------------------------------------------
    logger.info("shutting_down")

    heartbeat_task.cancel()
    try:
        await heartbeat_task
    except asyncio.CancelledError:
        pass

    if monitor_service is not None and monitor_service.is_active:
        try:
            await monitor_service.stop_monitoring()
        except Exception as exc:
            logger.warning("monitor_service_stop_error", error=str(exc))

    await close_db()
    logger.info("database_connections_closed")


def create_app() -> FastAPI:
    """
    Build and return the fully configured FastAPI application.

    This is the factory function referenced by run.py and uvicorn.
    """
    app = FastAPI(
        title=__app_name__,
        version=__version__,
        description=(
            "Network security analysis platform — scans local networks, "
            "detects threats, identifies vulnerabilities, and provides "
            "AI-driven security recommendations."
        ),
        lifespan=lifespan,
    )

    # CORS middleware for local development
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://localhost:8443",
            "http://127.0.0.1:8443",
        ],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Register exception handlers
    register_exception_handlers(app)

    # Include versioned API router (/api/v1/...)
    app.include_router(api_router)

    # Include WebSocket router at root path (/ws/events)
    app.include_router(ws_router)

    # Mount static files (frontend)
    static_path = Path("frontend")
    if static_path.is_dir():
        app.mount(
            "/static",
            StaticFiles(directory=str(static_path)),
            name="static",
        )

    # Root route serves index.html
    @app.get("/", include_in_schema=False, response_model=None)
    async def root():
        index_path = static_path / "index.html"
        if index_path.is_file():
            return FileResponse(str(index_path))
        return JSONResponse(
            content={
                "app": __app_name__,
                "version": __version__,
                "docs": "/docs",
                "api": "/api/v1/system/health",
            }
        )

    return app


# Module-level app instance for uvicorn
app = create_app()
