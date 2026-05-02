"""
Custom exceptions and FastAPI exception handlers for GATEKEEP.

Provides a hierarchy of domain-specific exceptions and registers
handlers that convert them into consistent ApiResponse error envelopes.
"""

from __future__ import annotations

import os
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse


class GatekeepError(Exception):
    """Base exception for all GATEKEEP errors."""

    def __init__(self, message: str, details: Any = None) -> None:
        self.message = message
        self.details = details
        super().__init__(self.message)


class ScanError(GatekeepError):
    """Raised when a network scan fails."""

    pass


class NetworkError(GatekeepError):
    """Raised on network connectivity or interface errors."""

    pass


class AIAnalysisError(GatekeepError):
    """Raised when AI analysis fails (API error, timeout, rate limit)."""

    pass


class NpcapNotFoundError(GatekeepError):
    """Raised when Npcap/WinPcap is not installed on Windows."""

    def __init__(self) -> None:
        super().__init__(
            "Npcap is not installed. Raw packet capture requires Npcap "
            "(https://npcap.com). Install it and restart GATEKEEP.",
            details={"install_url": "https://npcap.com/#download"},
        )


class InsufficientPrivilegesError(GatekeepError):
    """Raised when an operation requires elevated privileges."""

    def __init__(self, operation: str) -> None:
        super().__init__(
            f"Operation '{operation}' requires administrator privileges. "
            f"Restart GATEKEEP with elevated permissions.",
            details={"operation": operation},
        )


class ConfigError(GatekeepError):
    """Raised on configuration loading or validation errors."""

    pass


def _error_response(status_code: int, message: str, details: Any = None) -> JSONResponse:
    """Build a standardized JSON error response."""
    body: dict[str, Any] = {
        "status": "error",
        "data": None,
        "error": {
            "message": message,
        },
        "meta": None,
    }
    if details is not None:
        body["error"]["details"] = details
    return JSONResponse(status_code=status_code, content=body)


async def gatekeep_error_handler(_request: Request, exc: GatekeepError) -> JSONResponse:
    """Handle base GatekeepError and its subclasses."""
    return _error_response(500, exc.message, exc.details)


async def scan_error_handler(_request: Request, exc: ScanError) -> JSONResponse:
    """Handle scan-related errors."""
    return _error_response(422, exc.message, exc.details)


async def network_error_handler(_request: Request, exc: NetworkError) -> JSONResponse:
    """Handle network-related errors."""
    return _error_response(503, exc.message, exc.details)


async def ai_analysis_error_handler(_request: Request, exc: AIAnalysisError) -> JSONResponse:
    """Handle AI analysis errors."""
    return _error_response(502, exc.message, exc.details)


async def npcap_error_handler(_request: Request, exc: NpcapNotFoundError) -> JSONResponse:
    """Handle missing Npcap errors."""
    return _error_response(503, exc.message, exc.details)


async def privilege_error_handler(
    _request: Request, exc: InsufficientPrivilegesError
) -> JSONResponse:
    """Handle insufficient privilege errors."""
    return _error_response(403, exc.message, exc.details)


async def config_error_handler(_request: Request, exc: ConfigError) -> JSONResponse:
    """Handle configuration errors."""
    return _error_response(500, exc.message, exc.details)


def _is_debug_mode() -> bool:
    """Return True when the application is running in debug/development mode."""
    return os.environ.get("GATEKEEP_DEBUG", "").lower() in ("1", "true", "yes")


async def unhandled_error_handler(_request: Request, exc: Exception) -> JSONResponse:
    """Catch-all handler for unhandled exceptions.

    In production the response is intentionally generic to avoid leaking
    internal details. Full error information is only included when
    GATEKEEP_DEBUG is enabled.
    """
    if _is_debug_mode():
        details: Any = {"type": type(exc).__name__, "message": str(exc)}
    else:
        details = None
    return _error_response(500, "An internal error occurred.", details=details)


def register_exception_handlers(app: FastAPI) -> None:
    """Register all GATEKEEP exception handlers on the FastAPI app."""
    app.add_exception_handler(ScanError, scan_error_handler)  # type: ignore[arg-type]
    app.add_exception_handler(NetworkError, network_error_handler)  # type: ignore[arg-type]
    app.add_exception_handler(AIAnalysisError, ai_analysis_error_handler)  # type: ignore[arg-type]
    app.add_exception_handler(NpcapNotFoundError, npcap_error_handler)  # type: ignore[arg-type]
    app.add_exception_handler(InsufficientPrivilegesError, privilege_error_handler)  # type: ignore[arg-type]
    app.add_exception_handler(ConfigError, config_error_handler)  # type: ignore[arg-type]
    app.add_exception_handler(GatekeepError, gatekeep_error_handler)  # type: ignore[arg-type]
    app.add_exception_handler(Exception, unhandled_error_handler)
