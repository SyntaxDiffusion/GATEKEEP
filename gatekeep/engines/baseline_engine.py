"""
Baseline capture and drift detection engine for GATEKEEP.

Snapshots the current network state (devices, ports, DNS, router) into
the ``baselines`` table, then compares a later live scan against that
snapshot to detect meaningful changes (new devices, IP changes, port
changes, DNS and firmware drift).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gatekeep.logging_config import get_logger
from gatekeep.models import (
    Baseline,
    Device,
    DeviceScan,
    DNSCheck,
    PortResult,
    PortState,
    RouterFingerprint,
    Scan,
    ScanStatus,
)

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Dataclasses returned to callers
# ---------------------------------------------------------------------------


@dataclass
class DriftItem:
    """A single detected deviation between the baseline and the current state."""

    drift_type: str          # new_device | missing_device | ip_changed | new_port | closed_port | dns_changed | firmware_changed
    severity: str            # low | medium | high | critical
    description: str
    device_ip: Optional[str] = None
    device_mac: Optional[str] = None
    old_value: Optional[str] = None
    new_value: Optional[str] = None


@dataclass
class DriftReport:
    """Full drift analysis result."""

    baseline_id: str
    baseline_name: str
    captured_at: datetime
    compared_at: datetime
    drifts: list[DriftItem] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Severity map
# ---------------------------------------------------------------------------

_SEVERITY: dict[str, str] = {
    "new_device": "high",
    "missing_device": "medium",
    "ip_changed": "medium",
    "new_port": "high",
    "closed_port": "low",
    "dns_changed": "critical",
    "firmware_changed": "high",
}


def _sev(drift_type: str) -> str:
    return _SEVERITY.get(drift_type, "medium")


# ---------------------------------------------------------------------------
# BaselineEngine
# ---------------------------------------------------------------------------


class BaselineEngine:
    """
    Captures network-state snapshots and detects drift against them.

    Relies entirely on data already stored in the database — no raw
    packet capture is performed here.
    """

    def __init__(self) -> None:
        pass

    # ------------------------------------------------------------------
    # Capture
    # ------------------------------------------------------------------

    async def capture_baseline(
        self,
        db: AsyncSession,
        name: str,
        description: Optional[str] = None,
    ) -> str:
        """
        Snapshot the current network state and persist it as a baseline.

        Queries the most recent completed scan for all device/port/DNS/
        router data, serialises it as a JSON snapshot, and stores it in
        the ``baselines`` table.

        Args:
            db:          Async database session.
            name:        Human-readable baseline name.
            description: Optional description.

        Returns:
            The UUID of the newly created baseline record.
        """
        logger.info("baseline_engine.capture_start", name=name)

        snapshot = await self._build_snapshot(db)
        device_count = len(snapshot.get("devices", []))

        baseline = Baseline(
            name=name,
            description=description,
            device_count=device_count,
            snapshot=json.dumps(snapshot, default=str),
        )
        db.add(baseline)
        await db.flush()

        logger.info(
            "baseline_engine.capture_complete",
            baseline_id=baseline.id,
            device_count=device_count,
        )
        return baseline.id

    # ------------------------------------------------------------------
    # Compare
    # ------------------------------------------------------------------

    async def compare_to_baseline(
        self,
        db: AsyncSession,
        baseline_id: str,
    ) -> DriftReport:
        """
        Compare the current network state to a stored baseline.

        Loads the baseline snapshot, fetches fresh lightweight state,
        then runs seven drift checks.

        Args:
            db:           Async database session.
            baseline_id:  UUID of the baseline to compare against.

        Returns:
            DriftReport with a list of DriftItem objects and a summary.

        Raises:
            ValueError: If the baseline_id does not exist.
        """
        result = await db.execute(
            select(Baseline).where(Baseline.id == baseline_id)
        )
        baseline: Optional[Baseline] = result.scalar_one_or_none()
        if baseline is None:
            raise ValueError(f"Baseline {baseline_id!r} not found.")

        captured_at: datetime = baseline.created_at
        snapshot: dict[str, Any] = json.loads(baseline.snapshot or "{}")

        logger.info(
            "baseline_engine.compare_start",
            baseline_id=baseline_id,
            captured_at=str(captured_at),
        )

        # Build fresh current state
        current = await self._build_snapshot(db)
        compared_at = datetime.now(timezone.utc)

        drifts: list[DriftItem] = []

        drifts.extend(self._check_devices(snapshot, current))
        drifts.extend(self._check_ports(snapshot, current))
        drifts.extend(self._check_dns(snapshot, current))
        drifts.extend(self._check_router(snapshot, current))

        # Build summary
        by_type: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for d in drifts:
            by_type[d.drift_type] = by_type.get(d.drift_type, 0) + 1
            by_severity[d.severity] = by_severity.get(d.severity, 0) + 1

        summary: dict[str, Any] = {
            "total_drifts": len(drifts),
            "by_type": by_type,
            "by_severity": by_severity,
            "baseline_device_count": len(snapshot.get("devices", [])),
            "current_device_count": len(current.get("devices", [])),
        }

        logger.info(
            "baseline_engine.compare_complete",
            baseline_id=baseline_id,
            total_drifts=len(drifts),
        )

        return DriftReport(
            baseline_id=baseline_id,
            baseline_name=baseline.name,
            captured_at=captured_at,
            compared_at=compared_at,
            drifts=drifts,
            summary=summary,
        )

    # ------------------------------------------------------------------
    # Snapshot builder
    # ------------------------------------------------------------------

    async def _build_snapshot(self, db: AsyncSession) -> dict[str, Any]:
        """
        Query the database and build a normalised state dict.

        Uses the latest completed scan as the reference point. Falls
        back to all known devices if no completed scan exists.
        """
        # Latest completed scan
        scan_result = await db.execute(
            select(Scan)
            .where(Scan.status == ScanStatus.COMPLETED)
            .order_by(Scan.completed_at.desc())
            .limit(1)
        )
        latest_scan: Optional[Scan] = scan_result.scalar_one_or_none()
        scan_id: Optional[str] = latest_scan.id if latest_scan else None

        # All known devices
        dev_result = await db.execute(select(Device))
        all_devices = dev_result.scalars().all()

        # Open ports per device (from latest scan)
        ports_by_device: dict[str, list[dict[str, Any]]] = {}
        if scan_id:
            ds_result = await db.execute(
                select(DeviceScan).where(DeviceScan.scan_id == scan_id)
            )
            for ds in ds_result.scalars().all():
                pr_result = await db.execute(
                    select(PortResult).where(
                        PortResult.device_scan_id == ds.id,
                        PortResult.state == PortState.OPEN,
                    )
                )
                ports = pr_result.scalars().all()
                if ports:
                    ports_by_device[ds.device_id] = [
                        {
                            "port": p.port,
                            "protocol": p.protocol,
                            "service_name": p.service_name,
                        }
                        for p in ports
                    ]

        # DNS checks from latest scan
        dns_snapshot: list[dict[str, Any]] = []
        if scan_id:
            dns_result = await db.execute(
                select(DNSCheck).where(DNSCheck.scan_id == scan_id)
            )
            for chk in dns_result.scalars().all():
                dns_snapshot.append(
                    {
                        "resolver_ip": chk.resolver_ip,
                        "query_domain": chk.query_domain,
                        "is_hijacked": chk.is_hijacked,
                        "actual_ips": json.loads(chk.actual_ips) if chk.actual_ips else [],
                    }
                )

        # Router fingerprint from latest scan
        router_snapshot: Optional[dict[str, Any]] = None
        if scan_id:
            rf_result = await db.execute(
                select(RouterFingerprint)
                .where(RouterFingerprint.scan_id == scan_id)
                .limit(1)
            )
            rf = rf_result.scalar_one_or_none()
            if rf:
                router_snapshot = {
                    "manufacturer": rf.manufacturer,
                    "model": rf.model,
                    "firmware_version": rf.firmware_version,
                    "is_vulnerable": rf.is_vulnerable,
                }

        # Serialise devices
        devices_out: list[dict[str, Any]] = []
        for dev in all_devices:
            entry: dict[str, Any] = {
                "id": dev.id,
                "ip_address": dev.ip_address,
                "mac_address": dev.mac_address,
                "hostname": dev.hostname,
                "vendor": dev.vendor,
                "is_gateway": dev.is_gateway,
            }
            if dev.id in ports_by_device:
                entry["open_ports"] = ports_by_device[dev.id]
            else:
                entry["open_ports"] = []
            devices_out.append(entry)

        # Unique DNS resolvers seen
        resolver_ips = list({d["resolver_ip"] for d in dns_snapshot})

        return {
            "scan_id": scan_id,
            "devices": devices_out,
            "dns_checks": dns_snapshot,
            "resolver_ips": resolver_ips,
            "router": router_snapshot,
            "captured_at": datetime.now(timezone.utc).isoformat(),
        }

    # ------------------------------------------------------------------
    # Drift checks
    # ------------------------------------------------------------------

    def _check_devices(
        self,
        baseline: dict[str, Any],
        current: dict[str, Any],
    ) -> list[DriftItem]:
        """Detect new devices, missing devices, and IP changes."""
        drifts: list[DriftItem] = []

        baseline_devices: list[dict[str, Any]] = baseline.get("devices", [])
        current_devices: list[dict[str, Any]] = current.get("devices", [])

        # Index by MAC (normalised lower-case, strip None)
        def _mac_key(dev: dict[str, Any]) -> Optional[str]:
            mac = dev.get("mac_address")
            return mac.lower().strip() if mac else None

        baseline_by_mac: dict[str, dict[str, Any]] = {}
        for dev in baseline_devices:
            key = _mac_key(dev)
            if key:
                baseline_by_mac[key] = dev

        current_by_mac: dict[str, dict[str, Any]] = {}
        for dev in current_devices:
            key = _mac_key(dev)
            if key:
                current_by_mac[key] = dev

        # New devices (in current but not in baseline)
        for mac, dev in current_by_mac.items():
            if mac not in baseline_by_mac:
                drifts.append(
                    DriftItem(
                        drift_type="new_device",
                        severity=_sev("new_device"),
                        description=(
                            f"New device appeared on the network: "
                            f"{dev.get('ip_address')} "
                            f"({dev.get('vendor') or 'unknown vendor'}, MAC {mac})"
                        ),
                        device_ip=dev.get("ip_address"),
                        device_mac=mac,
                        new_value=dev.get("ip_address"),
                    )
                )

        # Missing devices (in baseline but not in current)
        for mac, dev in baseline_by_mac.items():
            if mac not in current_by_mac:
                drifts.append(
                    DriftItem(
                        drift_type="missing_device",
                        severity=_sev("missing_device"),
                        description=(
                            f"Device no longer visible: "
                            f"{dev.get('ip_address')} "
                            f"({dev.get('vendor') or 'unknown vendor'}, MAC {mac})"
                        ),
                        device_ip=dev.get("ip_address"),
                        device_mac=mac,
                        old_value=dev.get("ip_address"),
                    )
                )

        # IP changes (same MAC, different IP)
        for mac in baseline_by_mac.keys() & current_by_mac.keys():
            old_ip = baseline_by_mac[mac].get("ip_address")
            new_ip = current_by_mac[mac].get("ip_address")
            if old_ip != new_ip:
                drifts.append(
                    DriftItem(
                        drift_type="ip_changed",
                        severity=_sev("ip_changed"),
                        description=(
                            f"Device MAC {mac} changed IP from {old_ip} to {new_ip}"
                        ),
                        device_ip=new_ip,
                        device_mac=mac,
                        old_value=old_ip,
                        new_value=new_ip,
                    )
                )

        return drifts

    def _check_ports(
        self,
        baseline: dict[str, Any],
        current: dict[str, Any],
    ) -> list[DriftItem]:
        """Detect new or closed open ports on known devices."""
        drifts: list[DriftItem] = []

        # Build port sets indexed by MAC address
        def _port_map(devices: list[dict[str, Any]]) -> dict[str, set[str]]:
            """Return {mac: {"80/tcp", "443/tcp", ...}}."""
            m: dict[str, set[str]] = {}
            for dev in devices:
                mac = dev.get("mac_address")
                if not mac:
                    continue
                mac = mac.lower().strip()
                ports: set[str] = set()
                for p in dev.get("open_ports", []):
                    ports.add(f"{p['port']}/{p.get('protocol', 'tcp')}")
                m[mac] = ports
            return m

        baseline_ports = _port_map(baseline.get("devices", []))
        current_ports = _port_map(current.get("devices", []))

        # Map MAC → IP for description enrichment
        current_ip_by_mac: dict[str, str] = {
            (dev.get("mac_address") or "").lower().strip(): dev.get("ip_address", "")
            for dev in current.get("devices", [])
        }

        for mac in set(baseline_ports) | set(current_ports):
            old_set = baseline_ports.get(mac, set())
            new_set = current_ports.get(mac, set())
            device_ip = current_ip_by_mac.get(mac, mac)

            for port_str in new_set - old_set:
                drifts.append(
                    DriftItem(
                        drift_type="new_port",
                        severity=_sev("new_port"),
                        description=(
                            f"New open port {port_str} detected on device {device_ip} (MAC {mac})"
                        ),
                        device_ip=device_ip,
                        device_mac=mac,
                        new_value=port_str,
                    )
                )

            for port_str in old_set - new_set:
                drifts.append(
                    DriftItem(
                        drift_type="closed_port",
                        severity=_sev("closed_port"),
                        description=(
                            f"Previously open port {port_str} is now closed on device "
                            f"{device_ip} (MAC {mac})"
                        ),
                        device_ip=device_ip,
                        device_mac=mac,
                        old_value=port_str,
                    )
                )

        return drifts

    def _check_dns(
        self,
        baseline: dict[str, Any],
        current: dict[str, Any],
    ) -> list[DriftItem]:
        """Detect changes in observed DNS resolver IPs."""
        drifts: list[DriftItem] = []

        old_resolvers: set[str] = set(baseline.get("resolver_ips", []))
        new_resolvers: set[str] = set(current.get("resolver_ips", []))

        for resolver in new_resolvers - old_resolvers:
            drifts.append(
                DriftItem(
                    drift_type="dns_changed",
                    severity=_sev("dns_changed"),
                    description=(
                        f"New DNS resolver detected: {resolver}. "
                        "Router DNS settings may have been changed."
                    ),
                    new_value=resolver,
                )
            )

        for resolver in old_resolvers - new_resolvers:
            drifts.append(
                DriftItem(
                    drift_type="dns_changed",
                    severity=_sev("dns_changed"),
                    description=(
                        f"DNS resolver {resolver} is no longer present. "
                        "DNS configuration may have changed."
                    ),
                    old_value=resolver,
                )
            )

        # Check for newly hijacked DNS responses
        baseline_hijacked = {
            d["resolver_ip"]
            for d in baseline.get("dns_checks", [])
            if d.get("is_hijacked")
        }
        current_hijacked = {
            d["resolver_ip"]
            for d in current.get("dns_checks", [])
            if d.get("is_hijacked")
        }
        for resolver in current_hijacked - baseline_hijacked:
            drifts.append(
                DriftItem(
                    drift_type="dns_changed",
                    severity="critical",
                    description=(
                        f"DNS hijacking NEWLY detected via resolver {resolver}. "
                        "This is a strong indicator of router compromise."
                    ),
                    new_value=f"hijacked:{resolver}",
                )
            )

        return drifts

    def _check_router(
        self,
        baseline: dict[str, Any],
        current: dict[str, Any],
    ) -> list[DriftItem]:
        """Detect router firmware version changes."""
        drifts: list[DriftItem] = []

        old_router: Optional[dict[str, Any]] = baseline.get("router")
        new_router: Optional[dict[str, Any]] = current.get("router")

        if not old_router or not new_router:
            return drifts

        old_fw = old_router.get("firmware_version")
        new_fw = new_router.get("firmware_version")

        if old_fw and new_fw and old_fw != new_fw:
            drifts.append(
                DriftItem(
                    drift_type="firmware_changed",
                    severity=_sev("firmware_changed"),
                    description=(
                        f"Router firmware changed from {old_fw!r} to {new_fw!r} "
                        f"({new_router.get('model', 'unknown model')}). "
                        "Verify this update was intentional."
                    ),
                    old_value=old_fw,
                    new_value=new_fw,
                )
            )

        return drifts
