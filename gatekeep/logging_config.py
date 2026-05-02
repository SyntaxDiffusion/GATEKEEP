"""
Structured logging configuration for GATEKEEP.

Sets up structlog with JSON formatting, console rendering, and
rotating file output. All application modules should obtain loggers
through get_logger().
"""

from __future__ import annotations

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

import structlog


_configured = False


def setup_logging(log_level: str = "INFO", log_dir: str = "logs") -> None:
    """
    Configure structlog and stdlib logging for the application.

    Sets up:
    - Console output with colored, human-readable rendering
    - File output with JSON formatting and rotation (10 MB, 5 backups)
    - Shared processors for timestamps, log level, caller info

    Args:
        log_level: Logging level string (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        log_dir: Directory for log files.
    """
    global _configured
    if _configured:
        return

    log_path = Path(log_dir)
    log_path.mkdir(parents=True, exist_ok=True)
    log_file = log_path / "gatekeep.log"

    numeric_level = getattr(logging, log_level.upper(), logging.INFO)

    # Shared processors applied to every log entry
    shared_processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.UnicodeDecoder(),
    ]

    # Configure structlog
    structlog.configure(
        processors=[
            *shared_processors,
            structlog.stdlib.filter_by_level,
            structlog.processors.format_exc_info,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # Console formatter — human-readable with colors
    console_formatter = structlog.stdlib.ProcessorFormatter(
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            structlog.dev.ConsoleRenderer(colors=sys.stderr.isatty()),
        ],
        foreign_pre_chain=shared_processors,
    )

    # File formatter — JSON for machine parsing
    file_formatter = structlog.stdlib.ProcessorFormatter(
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            structlog.processors.JSONRenderer(),
        ],
        foreign_pre_chain=shared_processors,
    )

    # Console handler
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setFormatter(console_formatter)
    console_handler.setLevel(numeric_level)

    # Rotating file handler — 10 MB per file, 5 backups
    file_handler = RotatingFileHandler(
        str(log_file),
        maxBytes=10 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    file_handler.setFormatter(file_formatter)
    file_handler.setLevel(numeric_level)

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)
    # Clear any existing handlers to avoid duplicates on re-init
    root_logger.handlers.clear()
    root_logger.addHandler(console_handler)
    root_logger.addHandler(file_handler)

    # Suppress noisy third-party loggers
    for noisy in ("uvicorn.access", "aiosqlite", "httpcore", "httpx"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    _configured = True


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """
    Obtain a named structlog logger.

    If logging has not been configured yet, performs a default setup
    so that early callers still get working loggers.

    Args:
        name: Logger name, typically __name__ of the calling module.

    Returns:
        A bound structlog logger instance.
    """
    if not _configured:
        setup_logging()
    return structlog.get_logger(name)


def reset_logging() -> None:
    """Reset logging state. Useful for testing."""
    global _configured
    _configured = False
