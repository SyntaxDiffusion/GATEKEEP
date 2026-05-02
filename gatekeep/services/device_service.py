"""
Device management service for GATEKEEP.

Provides CRUD operations for the device inventory, including
upsert-by-MAC, history tracking across scans, and status filtering.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from gatekeep.logging_config import get_logger
from gatekeep.models import Device, DeviceScan, PortResult

logger = get_logger(__name__)


class DeviceService:
    """
    Service layer for device inventory management.

    All methods are stateless class methods operating on the provided
    database session, keeping the service easy to instantiate.
    """

    async def get_all_devices(
        self,
        db: AsyncSession,
        status_filter: Optional[str] = None,
    ) -> list[Device]:
        """
        Return all known devices, optionally filtered by online status.

        Args:
            db: Async database session.
            status_filter: If ``"online"``, only returns devices seen in the
                           last 10 minutes. If ``None``, returns all.

        Returns:
            List of Device ORM instances.
        """
        query = select(Device).order_by(Device.last_seen_at.desc())

        if status_filter == "online":
            cutoff = datetime.now(timezone.utc) - timedelta(minutes=10)
            query = query.where(Device.last_seen_at >= cutoff)

        result = await db.execute(query)
        return list(result.scalars().all())

    async def get_device(
        self,
        db: AsyncSession,
        device_id: str,
    ) -> Optional[Device]:
        """
        Return a single device by ID with its latest scan data.

        Eagerly loads related device_scans and their port results so
        callers can inspect open ports without additional queries.
        """
        result = await db.execute(
            select(Device)
            .where(Device.id == device_id)
            .options(
                selectinload(Device.device_scans)
                .selectinload(DeviceScan.port_results),
            )
        )
        return result.scalar_one_or_none()

    async def get_device_history(
        self,
        db: AsyncSession,
        device_id: str,
        days: int = 30,
    ) -> list[dict]:
        """
        Return device scan appearances over the last *days* days.

        Each entry represents one scan in which the device appeared,
        including its IP at that time, online status, response time,
        and open ports discovered.

        Args:
            db: Async database session.
            device_id: UUID of the device.
            days: Number of days of history to retrieve.

        Returns:
            List of snapshot dicts, one per scan appearance.
        """
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)

        result = await db.execute(
            select(DeviceScan)
            .where(DeviceScan.device_id == device_id)
            .options(
                selectinload(DeviceScan.port_results),
                selectinload(DeviceScan.scan),
            )
            .order_by(DeviceScan.id.desc())
        )
        device_scans = list(result.scalars().all())

        history: list[dict] = []
        for ds in device_scans:
            scan = ds.scan
            if scan and scan.created_at and scan.created_at < cutoff:
                continue

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

            history.append({
                "scan_id": ds.scan_id,
                "scan_type": scan.scan_type if scan else None,
                "scan_status": scan.status if scan else None,
                "scanned_at": scan.started_at.isoformat() if scan and scan.started_at else None,
                "ip_address": ds.ip_address,
                "is_online": ds.is_online,
                "response_time_ms": ds.response_time_ms,
                "open_ports": open_ports,
            })

        return history

    async def upsert_device(
        self,
        db: AsyncSession,
        ip: str,
        mac: Optional[str],
        vendor: Optional[str] = None,
        hostname: Optional[str] = None,
        device_type: Optional[str] = None,
        is_gateway: bool = False,
    ) -> Device:
        """
        Insert or update a device, matching on MAC address.

        If a device with the given MAC already exists, its IP, vendor,
        hostname, and last_seen_at fields are updated. Otherwise a new
        record is created.

        Args:
            db: Async database session.
            ip: Current IP address of the device.
            mac: MAC address (unique identifier).
            vendor: OUI-derived vendor name.
            hostname: Reverse-DNS hostname.
            device_type: Device classification.
            is_gateway: Whether this is the network gateway.

        Returns:
            The upserted Device ORM instance.
        """
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
            logger.debug(
                "device_updated",
                device_id=existing.id,
                ip=ip,
                mac=mac,
            )
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
        logger.info(
            "device_created",
            device_id=device.id,
            ip=ip,
            mac=mac,
        )
        return device
