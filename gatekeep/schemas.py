"""
Pydantic request/response schemas for the GATEKEEP REST API.

These schemas define the public contract for API consumers and are
used for request validation, response serialization, and OpenAPI
documentation generation.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime
from typing import Any, Generic, Optional, TypeVar

from pydantic import BaseModel, Field, field_validator

T = TypeVar("T")


# ---------------------------------------------------------------------------
# Generic API envelope
# ---------------------------------------------------------------------------


class ApiResponse(BaseModel, Generic[T]):
    """Standard API response envelope wrapping all responses."""

    status: str = "success"
    data: Optional[T] = None
    error: Optional[dict[str, Any]] = None
    meta: Optional[dict[str, Any]] = None


# ---------------------------------------------------------------------------
# Scans
# ---------------------------------------------------------------------------


class ScanCreate(BaseModel):
    """Request body to initiate a new scan."""

    scan_type: str = Field(
        ...,
        description="Type of scan to run",
        examples=["arp_discovery", "port_scan", "dns_check", "router_fingerprint", "full_scan"],
    )
    interface_name: Optional[str] = Field(
        default=None, description="Network interface to scan on"
    )
    subnet: Optional[str] = Field(
        default=None,
        description="Target subnet in CIDR notation, e.g. 192.168.1.0/24",
    )
    options: Optional[dict[str, Any]] = Field(
        default=None, description="Additional scan-specific options"
    )

    @field_validator("subnet")
    @classmethod
    def validate_subnet(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        try:
            network = ipaddress.ip_network(v, strict=False)
        except ValueError:
            raise ValueError(f"Invalid CIDR notation: {v}")
        # Must be private range
        private_ranges = [
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
            ipaddress.ip_network("169.254.0.0/16"),
        ]
        if not any(network.subnet_of(r) for r in private_ranges):
            raise ValueError("Subnet must be a private (RFC1918) address range")
        if network.prefixlen < 16:
            raise ValueError("Subnet prefix must be /16 or smaller to prevent excessive scanning")
        return str(network)


class ScanSummary(BaseModel):
    """Compact scan representation for list views."""

    id: str
    scan_type: str
    status: str
    device_count: int = 0
    alert_count: int = 0
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_at: datetime

    model_config = {"from_attributes": True}


class ScanResponse(BaseModel):
    """Full scan record without nested details."""

    id: str
    scan_type: str
    status: str
    interface_name: Optional[str] = None
    subnet: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    device_count: int = 0
    alert_count: int = 0
    error_message: Optional[str] = None
    created_at: datetime

    model_config = {"from_attributes": True}


class ScanDetail(ScanResponse):
    """Extended scan response including nested results."""

    devices: list[DeviceSnapshot] = Field(default_factory=list)
    dns_checks: list[DNSCheckResponse] = Field(default_factory=list)
    router_fingerprints: list[RouterFingerprintResponse] = Field(default_factory=list)
    ai_analysis: Optional[AIAnalysisResponse] = None
    alerts: list[AlertResponse] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Devices
# ---------------------------------------------------------------------------


class DeviceResponse(BaseModel):
    """Public device representation."""

    id: str
    ip_address: str
    mac_address: Optional[str] = None
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    device_type: Optional[str] = None
    is_gateway: bool = False
    first_seen_at: datetime
    last_seen_at: datetime

    model_config = {"from_attributes": True}


class PortResultResponse(BaseModel):
    """Port scan result for a device."""

    port: int
    protocol: str = "tcp"
    state: str
    service_name: Optional[str] = None
    banner: Optional[str] = None
    is_suspicious: bool = False

    model_config = {"from_attributes": True}


class DeviceDetail(DeviceResponse):
    """Extended device view with port scan results."""

    open_ports: list[PortResultResponse] = Field(default_factory=list)
    scan_count: int = 0
    last_response_time_ms: Optional[float] = None


class DeviceSnapshot(BaseModel):
    """Device state within a specific scan."""

    ip_address: str
    mac_address: Optional[str] = None
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    is_online: bool = True
    response_time_ms: Optional[float] = None
    open_ports: list[PortResultResponse] = Field(default_factory=list)

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# DNS Checks
# ---------------------------------------------------------------------------


class DNSCheckResponse(BaseModel):
    """DNS integrity check result."""

    id: str
    resolver_ip: str
    query_domain: str
    expected_ips: Optional[list[str]] = None
    actual_ips: Optional[list[str]] = None
    is_hijacked: bool = False
    hijack_type: Optional[str] = None
    details: Optional[str] = None
    checked_at: datetime

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Router Fingerprints
# ---------------------------------------------------------------------------


class RouterFingerprintResponse(BaseModel):
    """Router fingerprint analysis result."""

    id: str
    device_id: str
    manufacturer: Optional[str] = None
    model: Optional[str] = None
    firmware_version: Optional[str] = None
    is_vulnerable: bool = False
    vulnerability_details: Optional[list[dict[str, Any]]] = None
    admin_panel_url: Optional[str] = None
    fingerprint_method: Optional[str] = None

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# AI Analysis
# ---------------------------------------------------------------------------


class AIAnalysisResponse(BaseModel):
    """AI-generated security analysis result."""

    id: str
    scan_id: str
    model_used: str
    risk_level: str
    risk_score: float
    summary: str
    findings: list[dict[str, Any]] = Field(default_factory=list)
    recommendations: list[dict[str, Any]] = Field(default_factory=list)
    tokens_used: int = 0
    latency_ms: float = 0.0

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------


class AlertResponse(BaseModel):
    """Security alert record."""

    id: str
    monitor_session_id: Optional[str] = None
    scan_id: Optional[str] = None
    alert_type: str
    severity: str
    title: str
    description: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_mac: Optional[str] = None
    evidence: Optional[dict[str, Any]] = None
    ioc_reference: Optional[dict[str, Any]] = None
    is_acknowledged: bool = False
    acknowledged_at: Optional[datetime] = None
    notes: Optional[str] = None
    created_at: datetime

    model_config = {"from_attributes": True}


class AlertUpdate(BaseModel):
    """Request body to update an alert (acknowledge, add notes)."""

    is_acknowledged: Optional[bool] = None
    notes: Optional[str] = None


# ---------------------------------------------------------------------------
# System Health
# ---------------------------------------------------------------------------


class SystemHealth(BaseModel):
    """System health and capabilities report."""

    status: str = "healthy"
    version: str
    uptime_seconds: float = 0.0
    privileges: str
    npcap_available: bool = False
    interfaces: list[dict[str, Any]] = Field(default_factory=list)
    database_status: str = "ok"
    ai_available: bool = False


# ---------------------------------------------------------------------------
# Baselines
# ---------------------------------------------------------------------------


class BaselineCreate(BaseModel):
    """Request body to create a network baseline snapshot."""

    name: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = None


class BaselineResponse(BaseModel):
    """Saved network baseline."""

    id: str
    name: str
    description: Optional[str] = None
    device_count: int = 0
    snapshot: Optional[list[dict[str, Any]]] = None
    created_at: datetime

    model_config = {"from_attributes": True}


class DriftResponse(BaseModel):
    """Drift analysis between current state and a baseline."""

    baseline_id: str
    baseline_name: str
    new_devices: list[DeviceSnapshot] = Field(default_factory=list)
    missing_devices: list[DeviceSnapshot] = Field(default_factory=list)
    changed_devices: list[dict[str, Any]] = Field(default_factory=list)
    total_drift_count: int = 0


# ---------------------------------------------------------------------------
# Hardening
# ---------------------------------------------------------------------------


class HardeningRecommendation(BaseModel):
    """Firewall rule / hardening recommendation."""

    id: str
    scope: str
    target_device_id: Optional[str] = None
    scan_id: Optional[str] = None
    format: str
    rules: Optional[list[dict[str, Any]]] = None
    explanation: Optional[str] = None
    is_applied: bool = False
    created_at: datetime

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Rebuild forward references for models with nested types
# ---------------------------------------------------------------------------

ScanDetail.model_rebuild()
