"""
SQLAlchemy ORM models for GATEKEEP.

Defines all database tables across all project phases including
network scans, device inventory, DNS checks, router fingerprinting,
AI analysis, real-time monitoring, alerts, IOC indicators, baselines,
and hardening recommendations.

All primary keys are UUIDs stored as TEXT.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _uuid() -> str:
    """Generate a new UUID4 string."""
    return str(uuid.uuid4())


def _utcnow() -> datetime:
    """Return the current UTC datetime."""
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class ScanStatus(enum.StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanType(enum.StrEnum):
    ARP_DISCOVERY = "arp_discovery"
    PORT_SCAN = "port_scan"
    DNS_CHECK = "dns_check"
    ROUTER_FINGERPRINT = "router_fingerprint"
    FULL_SCAN = "full_scan"


class PortState(enum.StrEnum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"


class RiskLevel(enum.StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertSeverity(enum.StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class MonitorStatus(enum.StrEnum):
    RUNNING = "running"
    STOPPED = "stopped"
    ERROR = "error"


class IndicatorType(enum.StrEnum):
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    PORT = "port"
    MAC_ADDRESS = "mac_address"
    USER_AGENT = "user_agent"
    HASH = "hash"


class HardeningFormat(enum.StrEnum):
    IPTABLES = "iptables"
    WINDOWS_FIREWALL = "windows_firewall"
    PF = "pf"
    GENERIC = "generic"


# ---------------------------------------------------------------------------
# Base
# ---------------------------------------------------------------------------


class Base(DeclarativeBase):
    """Declarative base for all GATEKEEP models."""

    pass


# ---------------------------------------------------------------------------
# Scans
# ---------------------------------------------------------------------------


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=_uuid
    )
    scan_type: Mapped[str] = mapped_column(String(30), nullable=False)
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default=ScanStatus.PENDING
    )
    interface_name: Mapped[Optional[str]] = mapped_column(String(100))
    subnet: Mapped[Optional[str]] = mapped_column(String(18))
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    device_count: Mapped[int] = mapped_column(Integer, default=0)
    alert_count: Mapped[int] = mapped_column(Integer, default=0)
    error_message: Mapped[Optional[str]] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow
    )

    # Relationships
    device_scans: Mapped[list["DeviceScan"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    dns_checks: Mapped[list["DNSCheck"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    router_fingerprints: Mapped[list["RouterFingerprint"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    ai_analyses: Mapped[list["AIAnalysis"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    alerts: Mapped[list["Alert"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    hardening_recommendations: Mapped[list["HardeningRecommendation"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )


# ---------------------------------------------------------------------------
# Devices
# ---------------------------------------------------------------------------


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=_uuid
    )
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    mac_address: Mapped[Optional[str]] = mapped_column(String(17))
    hostname: Mapped[Optional[str]] = mapped_column(String(255))
    vendor: Mapped[Optional[str]] = mapped_column(String(255))
    device_type: Mapped[Optional[str]] = mapped_column(String(50))
    is_gateway: Mapped[bool] = mapped_column(Boolean, default=False)
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow
    )

    # Relationships
    device_scans: Mapped[list["DeviceScan"]] = relationship(
        back_populates="device", cascade="all, delete-orphan"
    )
    router_fingerprints: Mapped[list["RouterFingerprint"]] = relationship(
        back_populates="device", cascade="all, delete-orphan"
    )
    hardening_recommendations: Mapped[list["HardeningRecommendation"]] = relationship(
        back_populates="target_device", cascade="all, delete-orphan"
    )


# ---------------------------------------------------------------------------
# Device Scans (join between scans and devices)
# ---------------------------------------------------------------------------


class DeviceScan(Base):
    __tablename__ = "device_scans"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=_uuid
    )
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    device_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("devices.id", ondelete="CASCADE"), nullable=False
    )
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    is_online: Mapped[bool] = mapped_column(Boolean, default=True)
    response_time_ms: Mapped[Optional[float]] = mapped_column(Float)

    # Relationships
    scan: Mapped["Scan"] = relationship(back_populates="device_scans")
    device: Mapped["Device"] = relationship(back_populates="device_scans")
    port_results: Mapped[list["PortResult"]] = relationship(
        back_populates="device_scan", cascade="all, delete-orphan"
    )


# ---------------------------------------------------------------------------
# Port Results
# ---------------------------------------------------------------------------


class PortResult(Base):
    __tablename__ = "port_results"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=_uuid
    )
    device_scan_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("device_scans.id", ondelete="CASCADE"),
        nullable=False,
    )
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(10), nullable=False, default="tcp")
    state: Mapped[str] = mapped_column(
        String(10), nullable=False, default=PortState.CLOSED
    )
    service_name: Mapped[Optional[str]] = mapped_column(String(100))
    banner: Mapped[Optional[str]] = mapped_column(Text)
    is_suspicious: Mapped[bool] = mapped_column(Boolean, default=False)

    # Relationships
    device_scan: Mapped["DeviceScan"] = relationship(back_populates="port_results")


# ---------------------------------------------------------------------------
# DNS Checks
# ---------------------------------------------------------------------------


class DNSCheck(Base):
    __tablename__ = "dns_checks"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=_uuid
    )
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    resolver_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    query_domain: Mapped[str] = mapped_column(String(255), nullable=False)
    expected_ips: Mapped[Optional[str]] = mapped_column(Text)  # JSON
    actual_ips: Mapped[Optional[str]] = mapped_column(Text)  # JSON
    is_hijacked: Mapped[bool] = mapped_column(Boolean, default=False)
    hijack_type: Mapped[Optional[str]] = mapped_column(String(50))
    details: Mapped[Optional[str]] = mapped_column(Text)
    checked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow
    )

    # Relationships
    scan: Mapped["Scan"] = relationship(back_populates="dns_checks")


# ---------------------------------------------------------------------------
# Router Fingerprints
# ---------------------------------------------------------------------------


class RouterFingerprint(Base):
    __tablename__ = "router_fingerprints"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=_uuid
    )
    device_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("devices.id", ondelete="CASCADE"), nullable=False
    )
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    manufacturer: Mapped[Optional[str]] = mapped_column(String(100))
    model: Mapped[Optional[str]] = mapped_column(String(100))
    firmware_version: Mapped[Optional[str]] = mapped_column(String(100))
    is_vulnerable: Mapped[bool] = mapped_column(Boolean, default=False)
    vulnerability_details: Mapped[Optional[str]] = mapped_column(Text)  # JSON
    admin_panel_url: Mapped[Optional[str]] = mapped_column(String(500))
    fingerprint_method: Mapped[Optional[str]] = mapped_column(String(50))

    # Relationships
    device: Mapped["Device"] = relationship(back_populates="router_fingerprints")
    scan: Mapped["Scan"] = relationship(back_populates="router_fingerprints")


# ---------------------------------------------------------------------------
# AI Analyses
# ---------------------------------------------------------------------------


class AIAnalysis(Base):
    __tablename__ = "ai_analyses"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=_uuid
    )
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    model_used: Mapped[str] = mapped_column(String(100), nullable=False)
    risk_level: Mapped[str] = mapped_column(String(20), nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    findings: Mapped[Optional[str]] = mapped_column(Text)  # JSON
    recommendations: Mapped[Optional[str]] = mapped_column(Text)  # JSON
    raw_response: Mapped[Optional[str]] = mapped_column(Text)
    tokens_used: Mapped[int] = mapped_column(Integer, default=0)
    latency_ms: Mapped[float] = mapped_column(Float, default=0.0)

    # Relationships
    scan: Mapped["Scan"] = relationship(back_populates="ai_analyses")


# ---------------------------------------------------------------------------
# Monitor Sessions
# ---------------------------------------------------------------------------


class MonitorSession(Base):
    __tablename__ = "monitor_sessions"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=_uuid
    )
    interface_name: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default=MonitorStatus.RUNNING
    )
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow
    )
    stopped_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    packet_count: Mapped[int] = mapped_column(Integer, default=0)
    alert_count: Mapped[int] = mapped_column(Integer, default=0)

    # Relationships
    alerts: Mapped[list["Alert"]] = relationship(
        back_populates="monitor_session", cascade="all, delete-orphan"
    )


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=_uuid
    )
    monitor_session_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        ForeignKey("monitor_sessions.id", ondelete="SET NULL"),
    )
    scan_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        ForeignKey("scans.id", ondelete="SET NULL"),
    )
    alert_type: Mapped[str] = mapped_column(String(50), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    source_ip: Mapped[Optional[str]] = mapped_column(String(45))
    destination_ip: Mapped[Optional[str]] = mapped_column(String(45))
    source_mac: Mapped[Optional[str]] = mapped_column(String(17))
    evidence: Mapped[Optional[str]] = mapped_column(Text)  # JSON
    ioc_reference: Mapped[Optional[str]] = mapped_column(Text)  # JSON
    is_acknowledged: Mapped[bool] = mapped_column(Boolean, default=False)
    acknowledged_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True)
    )
    notes: Mapped[Optional[str]] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow
    )

    # Relationships
    monitor_session: Mapped[Optional["MonitorSession"]] = relationship(
        back_populates="alerts"
    )
    scan: Mapped[Optional["Scan"]] = relationship(back_populates="alerts")


# ---------------------------------------------------------------------------
# IOC Indicators
# ---------------------------------------------------------------------------


class IOCIndicator(Base):
    __tablename__ = "ioc_indicators"
    __table_args__ = (
        UniqueConstraint("indicator_type", "value", name="uq_ioc_type_value"),
    )

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=_uuid
    )
    indicator_type: Mapped[str] = mapped_column(String(30), nullable=False)
    value: Mapped[str] = mapped_column(String(500), nullable=False)
    threat_actor: Mapped[Optional[str]] = mapped_column(String(100))
    campaign: Mapped[Optional[str]] = mapped_column(String(200))
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    description: Mapped[Optional[str]] = mapped_column(Text)
    source: Mapped[Optional[str]] = mapped_column(String(255))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow
    )


# ---------------------------------------------------------------------------
# Baselines
# ---------------------------------------------------------------------------


class Baseline(Base):
    __tablename__ = "baselines"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=_uuid
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    device_count: Mapped[int] = mapped_column(Integer, default=0)
    snapshot: Mapped[Optional[str]] = mapped_column(Text)  # JSON
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow
    )


# ---------------------------------------------------------------------------
# Hardening Recommendations
# ---------------------------------------------------------------------------


class HardeningRecommendation(Base):
    __tablename__ = "hardening_recommendations"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=_uuid
    )
    scope: Mapped[str] = mapped_column(String(50), nullable=False)
    target_device_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        ForeignKey("devices.id", ondelete="SET NULL"),
    )
    scan_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        ForeignKey("scans.id", ondelete="SET NULL"),
    )
    format: Mapped[str] = mapped_column(
        String(30), nullable=False, default=HardeningFormat.GENERIC
    )
    rules: Mapped[Optional[str]] = mapped_column(Text)  # JSON
    explanation: Mapped[Optional[str]] = mapped_column(Text)
    is_applied: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow
    )

    # Relationships
    target_device: Mapped[Optional["Device"]] = relationship(
        back_populates="hardening_recommendations"
    )
    scan: Mapped[Optional["Scan"]] = relationship(
        back_populates="hardening_recommendations"
    )


# ---------------------------------------------------------------------------
# System Meta (key-value store)
# ---------------------------------------------------------------------------


class SystemMeta(Base):
    __tablename__ = "system_meta"

    key: Mapped[str] = mapped_column(String(100), primary_key=True)
    value: Mapped[Optional[str]] = mapped_column(Text)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow
    )
