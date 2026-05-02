"""
Privilege detection and enforcement for GATEKEEP.

Determines whether the process is running with administrator (elevated)
privileges and provides a decorator to gate endpoints that require them.
"""

from __future__ import annotations

import ctypes
import enum
import functools
import platform
from typing import Any, Callable

from fastapi import HTTPException


class PrivilegeLevel(enum.StrEnum):
    """Operating system privilege level."""

    ADMIN = "admin"
    USER = "user"

    @property
    def capabilities(self) -> list[str]:
        """List capabilities available at this privilege level."""
        base = [
            "view_scan_results",
            "view_alerts",
            "view_system_health",
            "ai_analysis",
        ]
        if self == PrivilegeLevel.ADMIN:
            return base + [
                "arp_scan",
                "raw_packet_capture",
                "real_time_monitoring",
                "port_scan_syn",
                "network_interface_bind",
            ]
        return base + [
            "port_scan_connect",
            "dns_check",
            "router_fingerprint_http",
        ]


def detect_privilege_level() -> PrivilegeLevel:
    """
    Detect the current process privilege level.

    On Windows, checks via ctypes whether the process token has
    administrator elevation. On other platforms, checks for UID 0.

    Returns:
        PrivilegeLevel.ADMIN if elevated, PrivilegeLevel.USER otherwise.
    """
    system = platform.system().lower()

    if system == "windows":
        try:
            is_admin: bool = bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
            return PrivilegeLevel.ADMIN if is_admin else PrivilegeLevel.USER
        except (AttributeError, OSError):
            return PrivilegeLevel.USER
    else:
        # Unix-like systems
        import os

        return PrivilegeLevel.ADMIN if os.getuid() == 0 else PrivilegeLevel.USER


_cached_level: PrivilegeLevel | None = None


def get_privilege_level() -> PrivilegeLevel:
    """Return the cached privilege level, detecting on first call."""
    global _cached_level
    if _cached_level is None:
        _cached_level = detect_privilege_level()
    return _cached_level


def require_admin(func: Callable[..., Any]) -> Callable[..., Any]:
    """
    Decorator that enforces administrator privileges on a route handler.

    Raises HTTP 403 if the process is not running elevated.
    """

    @functools.wraps(func)
    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        level = get_privilege_level()
        if level != PrivilegeLevel.ADMIN:
            raise HTTPException(
                status_code=403,
                detail={
                    "status": "error",
                    "data": None,
                    "error": {
                        "message": (
                            "This operation requires administrator privileges. "
                            "Restart GATEKEEP with elevated permissions."
                        ),
                        "required_level": PrivilegeLevel.ADMIN.value,
                        "current_level": level.value,
                        "capabilities": level.capabilities,
                    },
                    "meta": None,
                },
            )
        return await func(*args, **kwargs)

    return wrapper
