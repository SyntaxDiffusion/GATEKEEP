"""
Scan orchestration service for GATEKEEP.

Manages the lifecycle of network scans -- creation, execution
delegation, status tracking, and result retrieval.  Contains the
full-scan orchestrator that drives ARP discovery, DNS checking,
port scanning, router fingerprinting, and AI analysis.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from gatekeep.config import GatekeepConfig
from gatekeep.logging_config import get_logger
from gatekeep.models import (
    AIAnalysis,
    Alert,
    Device,
    DeviceScan,
    DNSCheck,
    PortResult,
    RouterFingerprint,
    Scan,
    ScanStatus,
    ScanType,
)
from gatekeep.privileges import get_privilege_level

logger = get_logger(__name__)


class ScanService:
    """
    Service layer for scan management.

    Encapsulates all database operations related to scans and
    coordinates with engine modules for actual scan execution.
    """

    def __init__(self, db: AsyncSession, config: GatekeepConfig) -> None:
        self._db = db
        self._config = config
        self._ws_manager: Any = None

    def set_ws_manager(self, manager: Any) -> None:
        """Attach the WebSocket connection manager for progress broadcasts."""
        self._ws_manager = manager

    # ------------------------------------------------------------------
    # CRUD helpers (preserved from original)
    # ------------------------------------------------------------------

    async def create_scan(
        self,
        scan_type: str,
        interface_name: Optional[str] = None,
        subnet: Optional[str] = None,
    ) -> Scan:
        """
        Create a new scan record in PENDING status.

        Args:
            scan_type: One of the ScanType enum values.
            interface_name: Network interface to scan on.
            subnet: Target subnet in CIDR notation.

        Returns:
            The newly created Scan ORM instance.
        """
        scan = Scan(
            scan_type=scan_type,
            status=ScanStatus.PENDING,
            interface_name=interface_name,
            subnet=subnet,
        )
        self._db.add(scan)
        await self._db.flush()
        logger.info(
            "scan_created",
            scan_id=scan.id,
            scan_type=scan_type,
            subnet=subnet,
        )
        return scan

    async def get_scan(self, scan_id: str) -> Optional[Scan]:
        """Retrieve a scan by ID."""
        result = await self._db.execute(
            select(Scan).where(Scan.id == scan_id)
        )
        return result.scalar_one_or_none()

    async def list_scans(
        self,
        limit: int = 50,
        offset: int = 0,
        scan_type: Optional[str] = None,
        status: Optional[str] = None,
    ) -> list[Scan]:
        """
        List scans with optional filtering, ordered by creation time desc.

        Args:
            limit: Maximum number of results.
            offset: Number of results to skip.
            scan_type: Filter by scan type.
            status: Filter by scan status.

        Returns:
            List of Scan instances.
        """
        query = select(Scan).order_by(Scan.created_at.desc())

        if scan_type is not None:
            query = query.where(Scan.scan_type == scan_type)
        if status is not None:
            query = query.where(Scan.status == status)

        query = query.limit(limit).offset(offset)
        result = await self._db.execute(query)
        return list(result.scalars().all())

    async def delete_scan(self, scan_id: str) -> bool:
        """Delete a scan and all cascade-related records. Returns True if found."""
        scan = await self.get_scan(scan_id)
        if scan is None:
            return False
        await self._db.delete(scan)
        await self._db.flush()
        logger.info("scan_deleted", scan_id=scan_id)
        return True

    async def mark_running(self, scan: Scan) -> Scan:
        """Transition a scan to RUNNING status."""
        scan.status = ScanStatus.RUNNING
        scan.started_at = datetime.now(timezone.utc)
        await self._db.flush()
        logger.info("scan_started", scan_id=scan.id)
        return scan

    async def mark_completed(
        self,
        scan: Scan,
        device_count: int = 0,
        alert_count: int = 0,
    ) -> Scan:
        """Transition a scan to COMPLETED status."""
        scan.status = ScanStatus.COMPLETED
        scan.completed_at = datetime.now(timezone.utc)
        scan.device_count = device_count
        scan.alert_count = alert_count
        await self._db.flush()
        logger.info(
            "scan_completed",
            scan_id=scan.id,
            device_count=device_count,
            alert_count=alert_count,
        )
        return scan

    async def mark_failed(self, scan: Scan, error_message: str) -> Scan:
        """Transition a scan to FAILED status with an error message."""
        scan.status = ScanStatus.FAILED
        scan.completed_at = datetime.now(timezone.utc)
        scan.error_message = error_message
        await self._db.flush()
        logger.error(
            "scan_failed",
            scan_id=scan.id,
            error=error_message,
        )
        return scan

    async def cancel_scan(self, scan: Scan) -> Scan:
        """Cancel a pending or running scan."""
        scan.status = ScanStatus.CANCELLED
        scan.completed_at = datetime.now(timezone.utc)
        await self._db.flush()
        logger.info("scan_cancelled", scan_id=scan.id)
        return scan

    # ------------------------------------------------------------------
    # Full scan orchestration
    # ------------------------------------------------------------------

    async def run_full_scan(
        self,
        db: AsyncSession,
        interface: Optional[str] = None,
        subnet: Optional[str] = None,
        scan_type: str = "full_scan",
    ) -> Scan:
        """
        Orchestrate a full network security scan.

        Phases:
        1. ARP discovery
        2. DNS integrity check
        3. Port scan on discovered devices
        4. Router fingerprint on gateway
        5. AI analysis of aggregated results

        Each phase is wrapped in try/except so that a failure in one
        phase does not abort the entire scan.
        """
        # Use the provided db session (background task gets its own)
        alert_count = 0
        device_count = 0

        # 1. Create scan record
        scan = Scan(
            scan_type=scan_type,
            status=ScanStatus.PENDING,
            interface_name=interface,
            subnet=subnet,
        )
        db.add(scan)
        await db.flush()
        scan_id = scan.id
        logger.info("full_scan_created", scan_id=scan_id)

        # 2. Mark running
        scan.status = ScanStatus.RUNNING
        scan.started_at = datetime.now(timezone.utc)
        await db.flush()
        await self._broadcast_progress("scan_started", {"scan_id": scan_id})

        # Track discovered devices for later phases
        discovered_devices: list[dict[str, Any]] = []
        gateway_device: Optional[dict[str, Any]] = None
        dns_results: list[Any] = []
        port_results_all: dict[str, list[Any]] = {}
        router_info: Optional[Any] = None

        # ---- Phase: ARP Discovery ----
        try:
            await self._broadcast_progress(
                "scan_progress",
                {"scan_id": scan_id, "phase": "arp_discovery", "status": "running"},
            )

            from gatekeep.engines.network_scanner import NetworkScanner

            scanner = NetworkScanner(self._config.network)
            devices = await scanner.discover(interface=interface, subnet=subnet)

            for dev in devices:
                # Upsert device by MAC address
                db_device = await self._upsert_device(
                    db,
                    ip=dev.ip,
                    mac=dev.mac,
                    vendor=dev.vendor,
                    hostname=dev.hostname,
                    device_type="gateway" if dev.is_gateway else "unknown",
                    is_gateway=dev.is_gateway,
                )

                # Create device_scan junction record
                device_scan = DeviceScan(
                    scan_id=scan_id,
                    device_id=db_device.id,
                    ip_address=dev.ip,
                    is_online=True,
                    response_time_ms=dev.response_time_ms,
                )
                db.add(device_scan)

                dev_info = {
                    "ip": dev.ip,
                    "mac": dev.mac,
                    "vendor": dev.vendor,
                    "hostname": dev.hostname,
                    "is_gateway": dev.is_gateway,
                    "device_id": db_device.id,
                    "device_scan_id": None,  # will be set after flush
                }
                discovered_devices.append(dev_info)
                if dev.is_gateway:
                    gateway_device = dev_info

            await db.flush()

            # Backfill device_scan IDs from the flushed records
            ds_result = await db.execute(
                select(DeviceScan).where(DeviceScan.scan_id == scan_id)
            )
            ds_records = list(ds_result.scalars().all())
            ds_map = {ds.device_id: ds.id for ds in ds_records}
            for dev_info in discovered_devices:
                dev_info["device_scan_id"] = ds_map.get(dev_info["device_id"])

            device_count = len(discovered_devices)
            logger.info(
                "arp_phase_complete",
                scan_id=scan_id,
                device_count=device_count,
            )
            await self._broadcast_progress(
                "scan_progress",
                {
                    "scan_id": scan_id,
                    "phase": "arp_discovery",
                    "status": "completed",
                    "device_count": device_count,
                },
            )
        except Exception as exc:
            logger.error("arp_phase_error", scan_id=scan_id, error=str(exc))
            await self._broadcast_progress(
                "scan_progress",
                {"scan_id": scan_id, "phase": "arp_discovery", "status": "error", "error": str(exc)},
            )

        # ---- Phase: Enhanced Discovery (SSDP, NetBIOS) ----
        try:
            await self._broadcast_progress(
                "scan_progress",
                {"scan_id": scan_id, "phase": "enhanced_discovery", "status": "running"},
            )

            from gatekeep.engines.network_discovery import NetworkDiscovery

            discovery = NetworkDiscovery()
            device_ips = [d["ip"] for d in discovered_devices]
            extra_info = await discovery.discover_all(device_ips)

            # Enrich device records with discovered names
            for dev_info in discovered_devices:
                ip = dev_info["ip"]
                if ip in extra_info:
                    info = extra_info[ip]
                    if info.netbios_name:
                        dev_info["netbios_name"] = info.netbios_name
                    if info.upnp_friendly_name:
                        dev_info["upnp_name"] = info.upnp_friendly_name
                    if info.upnp_model:
                        dev_info["upnp_model"] = info.upnp_model
                    if info.upnp_manufacturer:
                        dev_info["upnp_manufacturer"] = info.upnp_manufacturer
                    if info.ssdp_server:
                        dev_info["ssdp_server"] = info.ssdp_server

            logger.info(
                "enhanced_discovery_phase_complete",
                scan_id=scan_id,
                enriched_count=len(extra_info),
            )
            await self._broadcast_progress(
                "scan_progress",
                {
                    "scan_id": scan_id,
                    "phase": "enhanced_discovery",
                    "status": "completed",
                    "enriched_count": len(extra_info),
                },
            )
        except Exception as exc:
            logger.warning("enhanced_discovery_error", scan_id=scan_id, error=str(exc))
            await self._broadcast_progress(
                "scan_progress",
                {"scan_id": scan_id, "phase": "enhanced_discovery", "status": "error", "error": str(exc)},
            )

        # ---- Phase: DNS Check ----
        try:
            await self._broadcast_progress(
                "scan_progress",
                {"scan_id": scan_id, "phase": "dns_check", "status": "running"},
            )

            from gatekeep.engines.dns_checker import DNSChecker

            dns_checker = DNSChecker(self._config.dns)
            dns_check_results = await dns_checker.full_check()
            dns_results = dns_check_results

            for result in dns_check_results:
                for rr in result.resolution_results:
                    dns_record = DNSCheck(
                        scan_id=scan_id,
                        resolver_ip=rr.resolver_ip,
                        query_domain=rr.domain,
                        expected_ips=json.dumps(rr.control_ips) if rr.control_ips else None,
                        actual_ips=json.dumps(rr.resolved_ips) if rr.resolved_ips else None,
                        is_hijacked=rr.is_hijacked,
                        hijack_type=rr.hijack_type,
                        details=rr.details,
                    )
                    db.add(dns_record)

                    # Create CRITICAL alert for hijacked DNS
                    if rr.is_hijacked:
                        alert_count += await self._create_alert(
                            db,
                            scan_id=scan_id,
                            alert_type="dns_hijack",
                            severity="critical",
                            title=f"DNS Hijacking Detected: {rr.domain}",
                            description=(
                                f"DNS resolution for {rr.domain} via {rr.resolver_ip} "
                                f"returned unexpected IPs. {rr.details or ''}"
                            ),
                            evidence=json.dumps({
                                "domain": rr.domain,
                                "resolver": rr.resolver_ip,
                                "expected": rr.control_ips,
                                "actual": rr.resolved_ips,
                                "hijack_type": rr.hijack_type,
                            }),
                        )

                # Also alert on malicious resolvers
                if result.is_malicious:
                    alert_count += await self._create_alert(
                        db,
                        scan_id=scan_id,
                        alert_type="dns_hijack",
                        severity="critical",
                        title=f"Malicious DNS Resolver Detected: {result.resolver_ip}",
                        description=(
                            f"System DNS resolver {result.resolver_ip} matches known "
                            f"APT28 malicious infrastructure. {result.details or ''}"
                        ),
                        source_ip=result.resolver_ip,
                        evidence=json.dumps({
                            "resolver_ip": result.resolver_ip,
                            "campaign": result.malicious_campaign,
                        }),
                    )

            await db.flush()
            logger.info("dns_phase_complete", scan_id=scan_id)
            await self._broadcast_progress(
                "scan_progress",
                {"scan_id": scan_id, "phase": "dns_check", "status": "completed"},
            )
        except Exception as exc:
            logger.error("dns_phase_error", scan_id=scan_id, error=str(exc))
            await self._broadcast_progress(
                "scan_progress",
                {"scan_id": scan_id, "phase": "dns_check", "status": "error", "error": str(exc)},
            )

        # ---- Phase: Port Scan (full scan only) ----
        if scan_type in (ScanType.FULL_SCAN, "full_scan"):
            try:
                await self._broadcast_progress(
                    "scan_progress",
                    {"scan_id": scan_id, "phase": "port_scan", "status": "running"},
                )

                from gatekeep.engines.port_scanner import PortScanner

                port_scanner = PortScanner(self._config.network)
                privilege_level = get_privilege_level()

                for dev_info in discovered_devices:
                    try:
                        results = await port_scanner.scan_device(
                            dev_info["ip"],
                            privilege_level=privilege_level,
                        )
                        port_results_all[dev_info["ip"]] = results
                        device_scan_id = dev_info.get("device_scan_id")
                        if device_scan_id is None:
                            continue

                        for pr in results:
                            if pr.state == "open":
                                port_record = PortResult(
                                    device_scan_id=device_scan_id,
                                    port=pr.port,
                                    protocol=pr.protocol,
                                    state=pr.state,
                                    service_name=pr.service_name,
                                    banner=pr.banner,
                                    is_suspicious=pr.is_suspicious,
                                )
                                db.add(port_record)

                                # Alert on APT28 indicator ports
                                if pr.is_suspicious and pr.port in (56777, 35681):
                                    alert_count += await self._create_alert(
                                        db,
                                        scan_id=scan_id,
                                        alert_type="apt28_port",
                                        severity="critical",
                                        title=f"APT28 Indicator Port {pr.port} Open on {dev_info['ip']}",
                                        description=(
                                            f"Port {pr.port}/{pr.protocol} is open on "
                                            f"{dev_info['ip']}. {pr.suspicion_reason or ''}"
                                        ),
                                        source_ip=dev_info["ip"],
                                        evidence=json.dumps({
                                            "port": pr.port,
                                            "service": pr.service_name,
                                            "banner": pr.banner,
                                        }),
                                    )
                    except Exception as dev_exc:
                        logger.warning(
                            "port_scan_device_error",
                            scan_id=scan_id,
                            device_ip=dev_info["ip"],
                            error=str(dev_exc),
                        )

                await db.flush()
                logger.info("port_scan_phase_complete", scan_id=scan_id)
                await self._broadcast_progress(
                    "scan_progress",
                    {"scan_id": scan_id, "phase": "port_scan", "status": "completed"},
                )
            except Exception as exc:
                logger.error("port_scan_phase_error", scan_id=scan_id, error=str(exc))
                await self._broadcast_progress(
                    "scan_progress",
                    {"scan_id": scan_id, "phase": "port_scan", "status": "error", "error": str(exc)},
                )

        # ---- Phase: Router Fingerprint (full scan only) ----
        if scan_type in (ScanType.FULL_SCAN, "full_scan") and gateway_device:
            try:
                await self._broadcast_progress(
                    "scan_progress",
                    {"scan_id": scan_id, "phase": "router_fingerprint", "status": "running"},
                )

                from gatekeep.engines.router_fingerprint import RouterFingerprinter

                fingerprinter = RouterFingerprinter(self._config.network)
                router_info = await fingerprinter.fingerprint(
                    ip=gateway_device["ip"],
                    mac=gateway_device["mac"],
                )

                vuln_details_json = (
                    json.dumps(router_info.vulnerability_details)
                    if router_info.vulnerability_details
                    else None
                )

                fp_record = RouterFingerprint(
                    device_id=gateway_device["device_id"],
                    scan_id=scan_id,
                    manufacturer=router_info.manufacturer,
                    model=router_info.model,
                    firmware_version=router_info.firmware_version,
                    is_vulnerable=router_info.is_vulnerable,
                    vulnerability_details=vuln_details_json,
                    admin_panel_url=router_info.admin_panel_url,
                    fingerprint_method=router_info.fingerprint_method,
                )
                db.add(fp_record)

                if router_info.is_vulnerable:
                    alert_count += await self._create_alert(
                        db,
                        scan_id=scan_id,
                        alert_type="vulnerable_router",
                        severity="high",
                        title=f"Vulnerable Router Detected: {router_info.manufacturer or 'Unknown'} {router_info.model or 'Unknown'}",
                        description=(
                            f"The gateway router at {gateway_device['ip']} has been "
                            f"identified as a model known to be targeted by APT28. "
                            f"Firmware: {router_info.firmware_version or 'unknown'}."
                        ),
                        source_ip=gateway_device["ip"],
                        evidence=vuln_details_json,
                    )

                await db.flush()
                logger.info("router_fingerprint_phase_complete", scan_id=scan_id)
                await self._broadcast_progress(
                    "scan_progress",
                    {"scan_id": scan_id, "phase": "router_fingerprint", "status": "completed"},
                )
            except Exception as exc:
                logger.error(
                    "router_fingerprint_phase_error",
                    scan_id=scan_id,
                    error=str(exc),
                )
                await self._broadcast_progress(
                    "scan_progress",
                    {"scan_id": scan_id, "phase": "router_fingerprint", "status": "error", "error": str(exc)},
                )

        # ---- Phase: AI Analysis (full scan only) ----
        if scan_type in (ScanType.FULL_SCAN, "full_scan"):
            try:
                await self._broadcast_progress(
                    "scan_progress",
                    {"scan_id": scan_id, "phase": "ai_analysis", "status": "running"},
                )

                ai_scan_data = self._build_ai_scan_data(
                    scan_id=scan_id,
                    subnet=subnet,
                    discovered_devices=discovered_devices,
                    dns_results=dns_results,
                    port_results=port_results_all,
                    router_info=router_info,
                )
                ai_result = await self._run_ai_analysis(ai_scan_data)

                if ai_result is not None:
                    ai_record = AIAnalysis(
                        scan_id=scan_id,
                        model_used=ai_result.model_used,
                        risk_level=ai_result.risk_level,
                        risk_score=float(ai_result.risk_score),
                        summary=ai_result.summary,
                        findings=json.dumps(ai_result.findings) if ai_result.findings else None,
                        recommendations=json.dumps(ai_result.recommendations) if ai_result.recommendations else None,
                        raw_response=None,
                        tokens_used=ai_result.tokens_used,
                        latency_ms=float(ai_result.latency_ms),
                    )
                    db.add(ai_record)
                    await db.flush()

                logger.info("ai_analysis_phase_complete", scan_id=scan_id)
                await self._broadcast_progress(
                    "scan_progress",
                    {"scan_id": scan_id, "phase": "ai_analysis", "status": "completed"},
                )
            except Exception as exc:
                logger.error("ai_analysis_phase_error", scan_id=scan_id, error=str(exc))
                await self._broadcast_progress(
                    "scan_progress",
                    {"scan_id": scan_id, "phase": "ai_analysis", "status": "error", "error": str(exc)},
                )

        # ---- Mark scan completed ----
        scan.status = ScanStatus.COMPLETED
        scan.completed_at = datetime.now(timezone.utc)
        scan.device_count = device_count
        scan.alert_count = alert_count
        await db.flush()

        await self._broadcast_progress(
            "scan_completed",
            {
                "scan_id": scan_id,
                "device_count": device_count,
                "alert_count": alert_count,
            },
        )
        logger.info(
            "full_scan_completed",
            scan_id=scan_id,
            device_count=device_count,
            alert_count=alert_count,
        )
        return scan

    async def run_quick_scan(
        self,
        db: AsyncSession,
        interface: Optional[str] = None,
        subnet: Optional[str] = None,
    ) -> Scan:
        """
        Quick scan: ARP discovery + DNS check only.

        Skips port scanning, router fingerprinting, and AI analysis.
        """
        return await self.run_full_scan(
            db=db,
            interface=interface,
            subnet=subnet,
            scan_type=ScanType.ARP_DISCOVERY,
        )

    async def run_reanalysis(
        self,
        db: AsyncSession,
        scan_id: str,
    ) -> Optional[AIAnalysis]:
        """
        Re-run AI analysis on an existing scan's data.

        Loads all stored results and feeds them to the AI analyzer.
        """
        detail = await self.get_scan_detail(db, scan_id)
        if detail is None:
            return None

        ai_scan_data = {
            "id": scan_id,
            "timestamp": detail.get("started_at", ""),
            "subnet": detail.get("subnet", ""),
            "devices": detail.get("devices", []),
            "dns_check": detail.get("dns_check", {}),
            "alerts": detail.get("alerts", []),
        }

        ai_result = await self._run_ai_analysis(ai_scan_data)
        if ai_result is None:
            return None

        ai_record = AIAnalysis(
            scan_id=scan_id,
            model_used=ai_result.model_used,
            risk_level=ai_result.risk_level,
            risk_score=float(ai_result.risk_score),
            summary=ai_result.summary,
            findings=json.dumps(ai_result.findings) if ai_result.findings else None,
            recommendations=json.dumps(ai_result.recommendations) if ai_result.recommendations else None,
            raw_response=None,
            tokens_used=ai_result.tokens_used,
            latency_ms=float(ai_result.latency_ms),
        )
        db.add(ai_record)
        await db.flush()
        return ai_record

    # ------------------------------------------------------------------
    # Scan detail retrieval
    # ------------------------------------------------------------------

    async def get_scan_detail(self, db: AsyncSession, scan_id: str) -> Optional[dict[str, Any]]:
        """
        Return full scan detail including all related records.
        """
        result = await db.execute(
            select(Scan)
            .where(Scan.id == scan_id)
            .options(
                selectinload(Scan.device_scans).selectinload(DeviceScan.port_results),
                selectinload(Scan.device_scans).selectinload(DeviceScan.device),
                selectinload(Scan.dns_checks),
                selectinload(Scan.router_fingerprints),
                selectinload(Scan.ai_analyses),
                selectinload(Scan.alerts),
            )
        )
        scan = result.scalar_one_or_none()
        if scan is None:
            return None

        # Build devices list with port results
        devices: list[dict[str, Any]] = []
        for ds in scan.device_scans:
            dev = ds.device
            open_ports = [
                {
                    "port": pr.port,
                    "protocol": pr.protocol,
                    "state": pr.state,
                    "service_name": pr.service_name,
                    "banner": pr.banner,
                    "is_suspicious": pr.is_suspicious,
                }
                for pr in ds.port_results
            ]
            devices.append({
                "ip_address": ds.ip_address,
                "mac_address": dev.mac_address if dev else None,
                "hostname": dev.hostname if dev else None,
                "vendor": dev.vendor if dev else None,
                "is_online": ds.is_online,
                "response_time_ms": ds.response_time_ms,
                "is_gateway": dev.is_gateway if dev else False,
                "open_ports": open_ports,
            })

        # DNS checks
        dns_checks = [
            {
                "id": dc.id,
                "resolver_ip": dc.resolver_ip,
                "query_domain": dc.query_domain,
                "expected_ips": json.loads(dc.expected_ips) if dc.expected_ips else None,
                "actual_ips": json.loads(dc.actual_ips) if dc.actual_ips else None,
                "is_hijacked": dc.is_hijacked,
                "hijack_type": dc.hijack_type,
                "details": dc.details,
                "checked_at": dc.checked_at.isoformat() if dc.checked_at else None,
            }
            for dc in scan.dns_checks
        ]

        # Router fingerprints
        fingerprints = [
            {
                "id": rf.id,
                "device_id": rf.device_id,
                "manufacturer": rf.manufacturer,
                "model": rf.model,
                "firmware_version": rf.firmware_version,
                "is_vulnerable": rf.is_vulnerable,
                "vulnerability_details": (
                    json.loads(rf.vulnerability_details)
                    if rf.vulnerability_details
                    else None
                ),
                "admin_panel_url": rf.admin_panel_url,
                "fingerprint_method": rf.fingerprint_method,
            }
            for rf in scan.router_fingerprints
        ]

        # AI analysis (most recent)
        ai_analysis = None
        if scan.ai_analyses:
            latest = scan.ai_analyses[-1]
            ai_analysis = {
                "id": latest.id,
                "scan_id": latest.scan_id,
                "model_used": latest.model_used,
                "risk_level": latest.risk_level,
                "risk_score": latest.risk_score,
                "summary": latest.summary,
                "findings": json.loads(latest.findings) if latest.findings else [],
                "recommendations": json.loads(latest.recommendations) if latest.recommendations else [],
                "tokens_used": latest.tokens_used,
                "latency_ms": latest.latency_ms,
            }

        # Alerts
        alerts = [
            {
                "id": a.id,
                "alert_type": a.alert_type,
                "severity": a.severity,
                "title": a.title,
                "description": a.description,
                "source_ip": a.source_ip,
                "evidence": json.loads(a.evidence) if a.evidence else None,
                "is_acknowledged": a.is_acknowledged,
                "created_at": a.created_at.isoformat() if a.created_at else None,
            }
            for a in scan.alerts
        ]

        return {
            "id": scan.id,
            "scan_type": scan.scan_type,
            "status": scan.status,
            "interface_name": scan.interface_name,
            "subnet": scan.subnet,
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            "device_count": scan.device_count,
            "alert_count": scan.alert_count,
            "error_message": scan.error_message,
            "created_at": scan.created_at.isoformat() if scan.created_at else None,
            "devices": devices,
            "dns_checks": dns_checks,
            "router_fingerprints": fingerprints,
            "ai_analysis": ai_analysis,
            "alerts": alerts,
        }

    async def get_ai_analysis(self, db: AsyncSession, scan_id: str) -> Optional[dict[str, Any]]:
        """Return the latest AI analysis for a scan."""
        result = await db.execute(
            select(AIAnalysis)
            .where(AIAnalysis.scan_id == scan_id)
            .order_by(AIAnalysis.id.desc())
            .limit(1)
        )
        record = result.scalar_one_or_none()
        if record is None:
            return None

        return {
            "id": record.id,
            "scan_id": record.scan_id,
            "model_used": record.model_used,
            "risk_level": record.risk_level,
            "risk_score": record.risk_score,
            "summary": record.summary,
            "findings": json.loads(record.findings) if record.findings else [],
            "recommendations": json.loads(record.recommendations) if record.recommendations else [],
            "tokens_used": record.tokens_used,
            "latency_ms": record.latency_ms,
        }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    async def _upsert_device(
        self,
        db: AsyncSession,
        ip: str,
        mac: Optional[str],
        vendor: Optional[str],
        hostname: Optional[str],
        device_type: Optional[str],
        is_gateway: bool,
    ) -> Device:
        """Insert or update a device by MAC address."""
        existing: Optional[Device] = None
        if mac:
            result = await db.execute(
                select(Device).where(Device.mac_address == mac)
            )
            existing = result.scalar_one_or_none()

        if existing:
            existing.ip_address = ip
            existing.last_seen_at = datetime.now(timezone.utc)
            if vendor:
                existing.vendor = vendor
            if hostname:
                existing.hostname = hostname
            if device_type and device_type != "unknown":
                existing.device_type = device_type
            existing.is_gateway = is_gateway
            await db.flush()
            return existing

        device = Device(
            ip_address=ip,
            mac_address=mac,
            vendor=vendor,
            hostname=hostname,
            device_type=device_type,
            is_gateway=is_gateway,
        )
        db.add(device)
        await db.flush()
        return device

    async def _create_alert(
        self,
        db: AsyncSession,
        scan_id: str,
        alert_type: str,
        severity: str,
        title: str,
        description: str,
        source_ip: Optional[str] = None,
        evidence: Optional[str] = None,
    ) -> int:
        """
        Create an alert record. Returns 1 (count increment) on success.
        """
        alert = Alert(
            scan_id=scan_id,
            alert_type=alert_type,
            severity=severity,
            title=title,
            description=description,
            source_ip=source_ip,
            evidence=evidence,
        )
        db.add(alert)
        await db.flush()
        logger.warning(
            "alert_created",
            scan_id=scan_id,
            alert_type=alert_type,
            severity=severity,
            title=title,
        )
        return 1

    async def _broadcast_progress(self, event_type: str, data: dict[str, Any]) -> None:
        """Send WebSocket event if manager is available."""
        if self._ws_manager is not None:
            try:
                await self._ws_manager.broadcast(
                    "scan_progress",
                    {"type": event_type, **data},
                )
            except Exception as exc:
                logger.debug("ws_broadcast_failed", error=str(exc))

    async def _run_ai_analysis(self, scan_data: dict[str, Any]) -> Any:
        """Run AI analysis via Claude Agent SDK."""
        from gatekeep.engines.ai_analyzer import AIAnalyzer

        analyzer = AIAnalyzer(config=self._config.ai)
        if not analyzer.available:
            logger.info("ai_analysis_skipped", reason="agent_sdk_not_installed")
            return None

        return await analyzer.analyze_scan(scan_data)

    def _build_ai_scan_data(
        self,
        scan_id: str,
        subnet: Optional[str],
        discovered_devices: list[dict[str, Any]],
        dns_results: list[Any],
        port_results: dict[str, list[Any]],
        router_info: Any,
    ) -> dict[str, Any]:
        """Aggregate all scan results into a structured dict for AI analysis."""
        devices_data: list[dict[str, Any]] = []
        for dev in discovered_devices:
            dev_ports = port_results.get(dev["ip"], [])
            open_ports = [
                {
                    "port": p.port,
                    "protocol": p.protocol,
                    "state": p.state,
                    "service_name": p.service_name,
                    "banner": p.banner,
                    "is_suspicious": p.is_suspicious,
                }
                for p in dev_ports
                if p.state == "open"
            ]
            dev_entry: dict[str, Any] = {
                "ip_address": dev["ip"],
                "mac_address": dev["mac"],
                "vendor": dev.get("vendor"),
                "hostname": dev.get("hostname"),
                "is_gateway": dev.get("is_gateway", False),
                "device_type": "gateway" if dev.get("is_gateway") else "unknown",
                "open_ports": open_ports,
            }
            # Include enhanced discovery fields when available
            if dev.get("netbios_name"):
                dev_entry["netbios_name"] = dev["netbios_name"]
            if dev.get("upnp_name"):
                dev_entry["upnp_name"] = dev["upnp_name"]
            if dev.get("upnp_model"):
                dev_entry["upnp_model"] = dev["upnp_model"]
            if dev.get("upnp_manufacturer"):
                dev_entry["upnp_manufacturer"] = dev["upnp_manufacturer"]
            if dev.get("ssdp_server"):
                dev_entry["ssdp_server"] = dev["ssdp_server"]
            devices_data.append(dev_entry)

        # DNS check data
        dns_data: dict[str, Any] = {}
        if dns_results:
            hijacked_domains = []
            system_dns = []
            status = "clean"
            for dr in dns_results:
                system_dns.append(dr.resolver_ip)
                if dr.is_malicious:
                    status = "hijacked"
                for rr in dr.resolution_results:
                    if rr.is_hijacked:
                        status = "hijacked"
                        hijacked_domains.append({
                            "domain": rr.domain,
                            "expected_ips": rr.control_ips,
                            "actual_ips": rr.resolved_ips,
                        })
            dns_data = {
                "system_dns_servers": system_dns,
                "status": status,
                "hijacked_domains": hijacked_domains,
            }

        # Router fingerprint data
        router_data: dict[str, Any] = {}
        if router_info is not None:
            router_data = {
                "manufacturer": router_info.manufacturer,
                "model": router_info.model,
                "firmware_version": router_info.firmware_version,
                "is_vulnerable": router_info.is_vulnerable,
                "vulnerability_details": router_info.vulnerability_details,
            }

        return {
            "id": scan_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "subnet": subnet,
            "devices": devices_data,
            "dns_check": dns_data,
            "router_fingerprint": router_data,
            "alerts": [],
        }
