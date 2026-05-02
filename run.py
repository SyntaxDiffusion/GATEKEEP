"""
GATEKEEP entry point.

Launches the uvicorn ASGI server with the FastAPI application.
Checks for administrator privileges on startup and prints a
status banner before serving.
"""

from __future__ import annotations

import argparse
import sys


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="gatekeep",
        description="GATEKEEP - Network Security Analysis Platform",
    )
    parser.add_argument(
        "--host",
        type=str,
        default=None,
        help="Bind address (default: from config.json, fallback 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="Bind port (default: from config.json, fallback 8443)",
    )
    parser.add_argument(
        "--reload",
        action="store_true",
        default=False,
        help="Enable auto-reload for development",
    )
    return parser.parse_args()


def print_banner(host: str, port: int, is_admin: bool) -> None:
    """Print the startup status banner."""
    priv_status = "ADMIN" if is_admin else "USER (limited)"
    print()
    print("=" * 58)
    print("  GATEKEEP - Network Security Analysis Platform")
    print("=" * 58)
    print(f"  Address   : http://{host}:{port}")
    print(f"  API docs  : http://{host}:{port}/docs")
    print(f"  Privileges: {priv_status}")
    if not is_admin:
        print()
        print("  WARNING: Running without admin privileges.")
        print("  Some features (ARP scan, packet capture) are unavailable.")
        print("  Restart with elevated permissions for full functionality.")
    print("=" * 58)
    print()


def main() -> None:
    """Application entry point."""
    args = parse_args()

    # Load config for defaults
    from gatekeep.config import get_config

    config = get_config()

    host = args.host or config.app.host
    port = args.port or config.app.port

    # Detect privileges
    from gatekeep.privileges import detect_privilege_level, PrivilegeLevel

    priv_level = detect_privilege_level()
    is_admin = priv_level == PrivilegeLevel.ADMIN

    print_banner(host, port, is_admin)

    # Launch uvicorn
    import uvicorn

    uvicorn.run(
        "gatekeep.app:app",
        host=host,
        port=port,
        reload=args.reload,
        log_level=config.app.log_level.lower(),
    )


if __name__ == "__main__":
    main()
