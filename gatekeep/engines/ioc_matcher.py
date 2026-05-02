"""
Indicator of Compromise (IOC) matching engine for GATEKEEP.

Loads structured threat intelligence from IOC JSON files and provides
O(1) lookup for IP addresses, domains, and ports observed in live
network traffic.  CIDR ranges are checked via standard-library
ipaddress membership tests.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from gatekeep.logging_config import get_logger

log = get_logger(__name__)

# Default IOC file path relative to the package
_DEFAULT_IOC_PATH = Path(__file__).resolve().parent.parent / "ioc" / "apt28_indicators.json"


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class IOCMatch:
    """Result of a positive IOC match against observed traffic."""

    indicator_type: str  # "ip", "domain", "port"
    matched_value: str
    threat_actor: str
    campaign: str
    confidence: float
    description: str
    source_reference: str


# ---------------------------------------------------------------------------
# Internal indicator storage
# ---------------------------------------------------------------------------


@dataclass
class _IPRangeEntry:
    """A CIDR range with associated threat metadata."""

    network: ipaddress.IPv4Network
    campaign: str
    confidence: str


@dataclass
class _IPEntry:
    """A specific IP with associated threat metadata."""

    ip: str
    campaign: str
    confidence: str
    first_seen: str = ""


@dataclass
class _DomainEntry:
    """A domain indicator with metadata."""

    domain: str
    indicator_type: str
    note: str = ""


@dataclass
class _PortEntry:
    """A suspicious port indicator."""

    port: int
    protocol: str
    campaign: str
    description: str


# ---------------------------------------------------------------------------
# IOC Matcher
# ---------------------------------------------------------------------------


class IOCMatcher:
    """
    Matches observed network artifacts against known threat indicators.

    On initialization, loads the APT28 indicator file and builds
    efficient lookup structures:

    - IP addresses: ``set`` for O(1) exact-match lookup
    - CIDR ranges: list of ``IPv4Network`` objects checked via
      ``ip_address in network``
    - Domains: ``set`` for O(1) lookup
    - Ports: ``set`` for O(1) lookup

    Usage::

        matcher = IOCMatcher()
        await matcher.load_indicators()
        match = await matcher.check_packet(packet_info)
    """

    def __init__(self) -> None:
        self._ip_set: set[str] = set()
        self._ip_ranges: list[_IPRangeEntry] = []
        self._domain_set: set[str] = set()
        self._port_set: set[int] = set()

        # Full metadata for match reporting
        self._ip_meta: dict[str, dict[str, str]] = {}
        self._range_meta: dict[str, dict[str, str]] = {}
        self._domain_meta: dict[str, dict[str, str]] = {}
        self._port_meta: dict[int, dict[str, str]] = {}

        self._indicator_count: int = 0
        self._last_updated: Optional[datetime] = None
        self._threat_actor: str = "APT28"
        self._sources: list[str] = []
        self._loaded: bool = False

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    async def load_indicators(self, filepath: str | None = None) -> None:
        """
        Parse an IOC JSON file into efficient lookup structures.

        Args:
            filepath: Path to the IOC JSON file.  Defaults to the
                      bundled apt28_indicators.json.
        """
        path = Path(filepath) if filepath else _DEFAULT_IOC_PATH

        if not path.exists():
            log.error("ioc_file_not_found", path=str(path))
            return

        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError) as exc:
            log.error("ioc_file_load_error", path=str(path), error=str(exc))
            return

        metadata = data.get("metadata", {})
        self._threat_actor = metadata.get("name", "Unknown")
        self._sources = metadata.get("sources", [])
        last_updated_str = metadata.get("last_updated", "")
        if last_updated_str:
            try:
                self._last_updated = datetime.fromisoformat(last_updated_str).replace(
                    tzinfo=timezone.utc
                )
            except ValueError:
                self._last_updated = datetime.now(timezone.utc)
        else:
            self._last_updated = datetime.now(timezone.utc)

        indicators = data.get("indicators", {})
        count = 0

        # --- IPv4 CIDR ranges ---
        for entry in indicators.get("ipv4_ranges", []):
            cidr = entry.get("cidr", "")
            try:
                network = ipaddress.IPv4Network(cidr, strict=False)
                range_entry = _IPRangeEntry(
                    network=network,
                    campaign=entry.get("campaign", ""),
                    confidence=entry.get("confidence", "medium"),
                )
                self._ip_ranges.append(range_entry)
                self._range_meta[cidr] = {
                    "campaign": range_entry.campaign,
                    "confidence": range_entry.confidence,
                }
                count += 1
            except (ValueError, TypeError) as exc:
                log.warning("invalid_cidr", cidr=cidr, error=str(exc))

        # --- Specific IPv4 addresses ---
        for entry in indicators.get("ipv4_specific", []):
            ip = entry.get("ip", "")
            if ip:
                self._ip_set.add(ip)
                self._ip_meta[ip] = {
                    "campaign": entry.get("campaign", ""),
                    "confidence": entry.get("confidence", "medium"),
                    "first_seen": entry.get("first_seen", ""),
                }
                count += 1

        # --- Domains ---
        for entry in indicators.get("domains", []):
            domain = entry.get("domain", "").lower()
            if domain:
                self._domain_set.add(domain)
                self._domain_meta[domain] = {
                    "type": entry.get("type", ""),
                    "note": entry.get("note", ""),
                }
                count += 1

        # --- Ports ---
        for entry in indicators.get("ports", []):
            port = entry.get("port")
            if port is not None:
                self._port_set.add(int(port))
                self._port_meta[int(port)] = {
                    "protocol": entry.get("protocol", "tcp"),
                    "campaign": entry.get("campaign", ""),
                    "description": entry.get("description", ""),
                }
                count += 1

        self._indicator_count = count
        self._loaded = True

        log.info(
            "ioc_indicators_loaded",
            path=str(path),
            total=count,
            ip_specific=len(self._ip_set),
            ip_ranges=len(self._ip_ranges),
            domains=len(self._domain_set),
            ports=len(self._port_set),
        )

    # ------------------------------------------------------------------
    # Packet-level matching
    # ------------------------------------------------------------------

    async def check_packet(self, packet_info: dict[str, Any]) -> IOCMatch | None:
        """
        Check extracted packet fields against all indicator sets.

        Expects a dict with optional keys: ``src_ip``, ``dst_ip``,
        ``dns_query``, ``dst_port``.

        Returns the first match found, or None.

        Args:
            packet_info: Extracted packet fields.

        Returns:
            An IOCMatch on the first hit, or None.
        """
        if not self._loaded:
            await self.load_indicators()

        # Check source IP
        src_ip = packet_info.get("src_ip")
        if src_ip:
            match = await self.check_ip(src_ip)
            if match:
                return match

        # Check destination IP
        dst_ip = packet_info.get("dst_ip")
        if dst_ip:
            match = await self.check_ip(dst_ip)
            if match:
                return match

        # Check DNS query
        dns_query = packet_info.get("dns_query")
        if dns_query:
            match = await self.check_dns_query(dns_query)
            if match:
                return match

        # Check destination port
        dst_port = packet_info.get("dst_port")
        if dst_port is not None:
            match = self._check_port(int(dst_port))
            if match:
                return match

        return None

    # ------------------------------------------------------------------
    # Individual check methods
    # ------------------------------------------------------------------

    async def check_ip(self, ip: str) -> IOCMatch | None:
        """
        Check a single IP address against known malicious IPs and CIDR ranges.

        Args:
            ip: The IP address to check.

        Returns:
            An IOCMatch if the IP is in the indicator set, else None.
        """
        if not self._loaded:
            await self.load_indicators()

        # Exact match
        if ip in self._ip_set:
            meta = self._ip_meta.get(ip, {})
            return IOCMatch(
                indicator_type="ip",
                matched_value=ip,
                threat_actor=self._threat_actor,
                campaign=meta.get("campaign", "Unknown"),
                confidence=self._confidence_to_float(meta.get("confidence", "medium")),
                description=(
                    f"IP address {ip} matches known {self._threat_actor} "
                    f"infrastructure (campaign: {meta.get('campaign', 'Unknown')})"
                ),
                source_reference=", ".join(self._sources),
            )

        # CIDR range check
        try:
            addr = ipaddress.IPv4Address(ip)
        except (ValueError, TypeError):
            return None

        for range_entry in self._ip_ranges:
            if addr in range_entry.network:
                cidr_str = str(range_entry.network)
                return IOCMatch(
                    indicator_type="ip",
                    matched_value=ip,
                    threat_actor=self._threat_actor,
                    campaign=range_entry.campaign,
                    confidence=self._confidence_to_float(range_entry.confidence),
                    description=(
                        f"IP address {ip} falls within known {self._threat_actor} "
                        f"CIDR range {cidr_str} (campaign: {range_entry.campaign})"
                    ),
                    source_reference=", ".join(self._sources),
                )

        return None

    async def check_dns_query(self, domain: str) -> IOCMatch | None:
        """
        Check a DNS query domain against known indicators.

        Args:
            domain: The queried domain name.

        Returns:
            An IOCMatch if the domain is in the indicator set, else None.
        """
        if not self._loaded:
            await self.load_indicators()

        clean = domain.rstrip(".").lower()

        if clean in self._domain_set:
            meta = self._domain_meta.get(clean, {})
            note = meta.get("note", "")
            desc = (
                f"DNS query for '{clean}' matches {self._threat_actor} "
                f"indicator ({meta.get('type', 'unknown')})"
            )
            if note:
                desc += f". Note: {note}"

            return IOCMatch(
                indicator_type="domain",
                matched_value=clean,
                threat_actor=self._threat_actor,
                campaign="FrostArmada",
                confidence=0.7,  # Targeted services may have legitimate traffic
                description=desc,
                source_reference=", ".join(self._sources),
            )

        return None

    def _check_port(self, port: int) -> IOCMatch | None:
        """
        Check a destination port against suspicious port indicators.

        Args:
            port: The destination port number.

        Returns:
            An IOCMatch if the port is flagged, else None.
        """
        if port in self._port_set:
            meta = self._port_meta.get(port, {})
            return IOCMatch(
                indicator_type="port",
                matched_value=str(port),
                threat_actor=self._threat_actor,
                campaign=meta.get("campaign", "Unknown"),
                confidence=0.9,
                description=(
                    f"Destination port {port}/{meta.get('protocol', 'tcp')} "
                    f"matches known {self._threat_actor} infrastructure. "
                    f"{meta.get('description', '')}"
                ),
                source_reference=", ".join(self._sources),
            )

        return None

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def indicator_count(self) -> int:
        """Total number of loaded indicators."""
        return self._indicator_count

    @property
    def last_updated(self) -> Optional[datetime]:
        """Timestamp of the last IOC data update."""
        return self._last_updated

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _confidence_to_float(level: str) -> float:
        """Convert a textual confidence level to a numeric score."""
        mapping = {
            "low": 0.3,
            "medium": 0.6,
            "high": 0.9,
            "critical": 1.0,
        }
        return mapping.get(level.lower(), 0.5)
