"""
Configuration management for GATEKEEP.

Loads settings from config.json and environment variables using
Pydantic Settings. Provides a singleton accessor for the global config.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings


class PortsConfig(BaseModel):
    """Port group configuration for network scanning."""

    common: list[int] = Field(
        default_factory=lambda: [21, 22, 23, 25, 53, 80, 443, 445, 3389, 8080, 8443]
    )
    apt28_indicators: list[int] = Field(default_factory=lambda: [56777, 35681])
    iot_common: list[int] = Field(default_factory=lambda: [1883, 5683, 8883, 9100])

    @property
    def all_ports(self) -> list[int]:
        """Return combined list of all configured ports, deduplicated."""
        combined = set(self.common + self.apt28_indicators + self.iot_common)
        return sorted(combined)


class AppConfig(BaseModel):
    """Core application settings."""

    host: str = "127.0.0.1"
    port: int = 8443
    debug: bool = False
    log_level: str = "INFO"
    database_path: str = "data/gatekeep.db"
    static_files_path: str = "frontend"

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper = v.upper()
        if upper not in allowed:
            raise ValueError(f"log_level must be one of {allowed}, got {v!r}")
        return upper

    @field_validator("port")
    @classmethod
    def validate_port(cls, v: int) -> int:
        if not 1 <= v <= 65535:
            raise ValueError(f"port must be between 1 and 65535, got {v}")
        return v


class NetworkConfig(BaseModel):
    """Network scanning settings."""

    scan_timeout: int = 30
    arp_timeout: int = 3
    port_scan_timeout: int = 2
    max_concurrent_port_scans: int = 50
    ports: PortsConfig = Field(default_factory=PortsConfig)

    @field_validator("scan_timeout", "arp_timeout", "port_scan_timeout")
    @classmethod
    def validate_positive_timeout(cls, v: int) -> int:
        if v <= 0:
            raise ValueError(f"Timeout must be positive, got {v}")
        return v

    @field_validator("max_concurrent_port_scans")
    @classmethod
    def validate_max_scans(cls, v: int) -> int:
        if not 1 <= v <= 500:
            raise ValueError(f"max_concurrent_port_scans must be 1-500, got {v}")
        return v


class DNSConfig(BaseModel):
    """DNS security check settings."""

    test_domains: list[str] = Field(
        default_factory=lambda: [
            "www.google.com",
            "www.microsoft.com",
            "www.cloudflare.com",
        ]
    )
    trusted_resolvers: list[str] = Field(
        default_factory=lambda: ["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9"]
    )
    check_interval: int = 60


class AIConfig(BaseModel):
    """AI analysis settings (Claude Agent SDK — no API key needed)."""

    model: str = "claude-sonnet-4-20250514"
    max_tokens: int = 4096
    temperature: float = 0.2
    timeout: int = 60

    @field_validator("temperature")
    @classmethod
    def validate_temperature(cls, v: float) -> float:
        if not 0.0 <= v <= 1.0:
            raise ValueError(f"temperature must be between 0.0 and 1.0, got {v}")
        return v

    @field_validator("max_tokens")
    @classmethod
    def validate_max_tokens(cls, v: int) -> int:
        if not 1 <= v <= 128000:
            raise ValueError(f"max_tokens must be 1-128000, got {v}")
        return v


class PortScanThreshold(BaseModel):
    """Threshold settings for port scan anomaly detection."""

    port_count: int = 15
    time_window: int = 10


class SynFloodThreshold(BaseModel):
    """Threshold settings for SYN flood detection."""

    syn_count: int = 200
    time_window: int = 5


class DNSTunnelingThreshold(BaseModel):
    """Threshold settings for DNS tunneling detection."""

    entropy_threshold: float = 4.5
    min_length: int = 50


class AnomalyThresholds(BaseModel):
    """Anomaly detection threshold configuration."""

    port_scan: PortScanThreshold = Field(default_factory=PortScanThreshold)
    syn_flood: SynFloodThreshold = Field(default_factory=SynFloodThreshold)
    dns_tunneling: DNSTunnelingThreshold = Field(default_factory=DNSTunnelingThreshold)


class MonitoringConfig(BaseModel):
    """Real-time monitoring settings."""

    anomaly_thresholds: AnomalyThresholds = Field(default_factory=AnomalyThresholds)


class AlertConfig(BaseModel):
    """Alert severity escalation mapping."""

    severity_escalation: dict[str, str] = Field(
        default_factory=lambda: {
            "ioc_match": "critical",
            "apt28_port": "critical",
            "dns_hijack": "critical",
            "port_scan": "medium",
            "syn_flood": "high",
            "dns_tunnel": "high",
            "vulnerable_router": "high",
        }
    )

    @field_validator("severity_escalation")
    @classmethod
    def validate_severity_values(cls, v: dict[str, str]) -> dict[str, str]:
        allowed = {"low", "medium", "high", "critical"}
        for key, severity in v.items():
            if severity.lower() not in allowed:
                raise ValueError(
                    f"Invalid severity {severity!r} for {key!r}. Must be one of {allowed}"
                )
        return {k: val.lower() for k, val in v.items()}


class WebSocketConfig(BaseModel):
    """WebSocket connection settings."""

    heartbeat_interval: int = 30
    timeout: int = 10
    max_connections: int = 10

    @field_validator("max_connections")
    @classmethod
    def validate_max_connections(cls, v: int) -> int:
        if not 1 <= v <= 100:
            raise ValueError(f"max_connections must be 1-100, got {v}")
        return v


class GatekeepConfig(BaseSettings):
    """
    Root configuration model for the GATEKEEP application.

    Loads structured config from config.json. AI analysis uses the
    Claude Agent SDK which authenticates via Claude Code — no API key needed.
    """

    app: AppConfig = Field(default_factory=AppConfig)
    network: NetworkConfig = Field(default_factory=NetworkConfig)
    dns: DNSConfig = Field(default_factory=DNSConfig)
    ai: AIConfig = Field(default_factory=AIConfig)
    monitoring: MonitoringConfig = Field(default_factory=MonitoringConfig)
    alerts: AlertConfig = Field(default_factory=AlertConfig)
    websocket: WebSocketConfig = Field(default_factory=WebSocketConfig)

    model_config = {
        "env_prefix": "",
        "extra": "ignore",
        "populate_by_name": True,
    }

    @property
    def ai_available(self) -> bool:
        """Check whether the Claude Agent SDK is importable."""
        try:
            import claude_agent_sdk  # noqa: F401
            return True
        except ImportError:
            return False

    def redacted(self) -> dict:
        """Return config dict with sensitive values redacted."""
        data = self.model_dump()
        data["ai"]["ai_available"] = self.ai_available
        return data


def _load_config_json() -> dict:
    """Load and parse config.json from the working directory."""
    config_path = Path("config.json")
    if not config_path.exists():
        return {}
    with open(config_path, "r", encoding="utf-8") as f:
        return json.load(f)


_config_instance: Optional[GatekeepConfig] = None


def get_config() -> GatekeepConfig:
    """
    Return the singleton GatekeepConfig instance.

    On first call, loads config.json and merges with environment
    variables. Subsequent calls return the cached instance.
    """
    global _config_instance
    if _config_instance is None:
        json_data = _load_config_json()
        _config_instance = GatekeepConfig(**json_data)
    return _config_instance


def reset_config() -> None:
    """Reset the config singleton. Useful for testing."""
    global _config_instance
    _config_instance = None
