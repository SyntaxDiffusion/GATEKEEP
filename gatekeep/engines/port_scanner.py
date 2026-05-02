"""
Port scanning engine for GATEKEEP.

Provides both privileged SYN scanning (via scapy) and unprivileged
TCP-connect scanning. Identifies open services, grabs banners, and
flags ports associated with APT28 indicators of compromise.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Optional

from gatekeep.config import NetworkConfig
from gatekeep.exceptions import NpcapNotFoundError
from gatekeep.logging_config import get_logger
from gatekeep.privileges import PrivilegeLevel

log = get_logger(__name__)

# Well-known port -> service name mapping
_SERVICE_MAP: dict[int, str] = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    67: "dhcp-server",
    68: "dhcp-client",
    80: "http",
    110: "pop3",
    119: "nntp",
    123: "ntp",
    135: "msrpc",
    137: "netbios-ns",
    138: "netbios-dgm",
    139: "netbios-ssn",
    143: "imap",
    161: "snmp",
    162: "snmp-trap",
    389: "ldap",
    443: "https",
    445: "microsoft-ds",
    465: "smtps",
    514: "syslog",
    515: "printer",
    587: "submission",
    631: "ipp",
    636: "ldaps",
    993: "imaps",
    995: "pop3s",
    1080: "socks",
    1433: "mssql",
    1434: "mssql-browser",
    1521: "oracle-db",
    1723: "pptp",
    1883: "mqtt",
    2049: "nfs",
    2222: "alt-ssh",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5683: "coap",
    5900: "vnc",
    5985: "winrm-http",
    5986: "winrm-https",
    6379: "redis",
    8080: "http-proxy",
    8291: "mikrotik-winbox",
    8443: "https-alt",
    8728: "mikrotik-api",
    8729: "mikrotik-api-ssl",
    8883: "mqtt-ssl",
    9100: "jetdirect",
    9200: "elasticsearch",
    27017: "mongodb",
    35681: "apt28-indicator",
    56777: "apt28-indicator",
}

# APT28 indicator ports and their IOC context
_APT28_PORTS: dict[int, str] = {
    56777: (
        "APT28 FrostArmada C2 — non-standard high port used for "
        "reverse-tunnel command-and-control on compromised SOHO routers"
    ),
    35681: (
        "APT28 Dying Ember/Moobot — exfiltration channel observed "
        "on compromised Ubiquiti EdgeRouter infrastructure"
    ),
}

# Known-suspicious banner fragments
_SUSPICIOUS_BANNERS: list[tuple[str, str]] = [
    (
        "dnsmasq-2.85",
        "FrostArmada IOC: dnsmasq 2.85 is a known indicator of "
        "APT28-modified DNS forwarder on compromised routers",
    ),
]


@dataclass
class PortResult:
    """Scan result for a single port on a target host."""

    port: int
    protocol: str = "tcp"
    state: str = "closed"  # open | closed | filtered
    service_name: Optional[str] = None
    banner: Optional[str] = None
    is_suspicious: bool = False
    suspicion_reason: Optional[str] = None


class PortScanner:
    """
    Scans TCP ports on target hosts, optionally using SYN scanning
    when running with admin privileges.
    """

    def __init__(self, config: NetworkConfig) -> None:
        self._config = config
        self._timeout = config.port_scan_timeout
        self._max_concurrent = config.max_concurrent_port_scans

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def scan_device(
        self,
        ip: str,
        ports: Optional[list[int]] = None,
        privilege_level: PrivilegeLevel = PrivilegeLevel.USER,
    ) -> list[PortResult]:
        """
        Scan ports on a single device.

        When running as admin, uses a SYN scan via scapy for speed
        and stealth. Otherwise uses asyncio TCP connect scanning.

        Args:
            ip: Target IPv4 address.
            ports: Specific ports to scan. Defaults to all configured
                   ports (common + APT28 indicators + IoT).
            privilege_level: Current process privilege level.

        Returns:
            List of :class:`PortResult`, one per scanned port.
        """
        if ports is None:
            ports = self._config.ports.all_ports

        log.info(
            "port_scan_start",
            target=ip,
            port_count=len(ports),
            mode="syn" if privilege_level == PrivilegeLevel.ADMIN else "connect",
        )

        if privilege_level == PrivilegeLevel.ADMIN:
            results = await self._syn_scan(ip, ports)
        else:
            results = await self._connect_scan(ip, ports)

        # Attempt banner grabs on open ports
        banner_tasks = []
        open_results = [r for r in results if r.state == "open"]
        for result in open_results:
            banner_tasks.append(self._grab_banner(ip, result))

        if banner_tasks:
            await asyncio.gather(*banner_tasks, return_exceptions=True)

        # Classify suspicion for all ports
        for result in results:
            is_sus, reason = self._classify_suspicion(result.port, result.banner)
            if is_sus:
                result.is_suspicious = True
                result.suspicion_reason = reason

        open_count = sum(1 for r in results if r.state == "open")
        suspicious_count = sum(1 for r in results if r.is_suspicious)
        log.info(
            "port_scan_complete",
            target=ip,
            total=len(results),
            open=open_count,
            suspicious=suspicious_count,
        )

        return results

    async def scan_multiple(
        self,
        targets: list[str],
        ports: Optional[list[int]] = None,
        privilege_level: PrivilegeLevel = PrivilegeLevel.USER,
    ) -> dict[str, list[PortResult]]:
        """
        Scan ports on multiple targets concurrently.

        Limits concurrency with a semaphore based on
        ``config.max_concurrent_port_scans``.

        Args:
            targets: List of IPv4 addresses to scan.
            ports: Specific ports, or *None* for defaults.
            privilege_level: Current process privilege level.

        Returns:
            Dict mapping each IP to its list of :class:`PortResult`.
        """
        semaphore = asyncio.Semaphore(self._max_concurrent)
        results: dict[str, list[PortResult]] = {}

        async def _scan_one(ip: str) -> tuple[str, list[PortResult]]:
            async with semaphore:
                res = await self.scan_device(ip, ports, privilege_level)
                return ip, res

        tasks = [asyncio.create_task(_scan_one(ip)) for ip in targets]
        completed = await asyncio.gather(*tasks, return_exceptions=True)

        for item in completed:
            if isinstance(item, tuple):
                ip, port_results = item
                results[ip] = port_results
            elif isinstance(item, Exception):
                log.warning("multi_scan_target_error", error=str(item))

        return results

    # ------------------------------------------------------------------
    # TCP connect scan (unprivileged)
    # ------------------------------------------------------------------

    async def _connect_scan(
        self, ip: str, ports: list[int]
    ) -> list[PortResult]:
        """Perform an async TCP connect scan on all specified ports."""
        semaphore = asyncio.Semaphore(self._max_concurrent)

        async def _probe(port: int) -> PortResult:
            async with semaphore:
                state = await self._tcp_connect_scan(
                    ip, port, self._timeout
                )
                return PortResult(
                    port=port,
                    protocol="tcp",
                    state=state,
                    service_name=self._get_service_name(port),
                )

        tasks = [asyncio.create_task(_probe(p)) for p in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        port_results: list[PortResult] = []
        for r in results:
            if isinstance(r, PortResult):
                port_results.append(r)
            elif isinstance(r, Exception):
                log.debug("connect_scan_port_error", target=ip, error=str(r))

        return sorted(port_results, key=lambda pr: pr.port)

    @staticmethod
    async def _tcp_connect_scan(
        ip: str, port: int, timeout: float
    ) -> str:
        """
        Attempt a TCP connection to determine port state.

        Returns:
            ``"open"`` if the connection succeeds,
            ``"filtered"`` on timeout,
            ``"closed"`` on connection refused / OS error.
        """
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=timeout
            )
            writer.close()
            await writer.wait_closed()
            return "open"
        except asyncio.TimeoutError:
            return "filtered"
        except (ConnectionRefusedError, OSError):
            return "closed"

    # ------------------------------------------------------------------
    # SYN scan (privileged, via scapy)
    # ------------------------------------------------------------------

    async def _syn_scan(
        self, ip: str, ports: list[int]
    ) -> list[PortResult]:
        """
        Perform a SYN (half-open) scan using scapy.

        Sends TCP SYN packets and interprets the response:
        - SYN-ACK -> open
        - RST -> closed
        - No response -> filtered

        Runs in a thread because scapy is synchronous.
        """
        try:
            results = await asyncio.to_thread(
                self._syn_scan_sync, ip, ports, self._timeout
            )
            return results
        except Exception as exc:
            err_msg = str(exc).lower()
            if "npcap" in err_msg or "winpcap" in err_msg or "pcap" in err_msg:
                raise NpcapNotFoundError()
            log.warning(
                "syn_scan_fallback_to_connect",
                target=ip,
                error=str(exc),
            )
            # Fallback to connect scan
            return await self._connect_scan(ip, ports)

    def _syn_scan_sync(
        self, ip: str, ports: list[int], timeout: float
    ) -> list[PortResult]:
        """Synchronous SYN scan via scapy (executed in a worker thread)."""
        from scapy.all import IP, TCP, sr  # type: ignore[import-untyped]

        # Build SYN packets for all ports
        packets = IP(dst=ip) / TCP(dport=ports, flags="S")

        answered, unanswered = sr(packets, timeout=timeout, verbose=0)

        # Track which ports got responses
        responded_ports: dict[int, str] = {}
        for sent, received in answered:
            sport = received[TCP].sport
            flags = received[TCP].flags

            if flags & 0x12 == 0x12:  # SYN-ACK
                responded_ports[sport] = "open"
            elif flags & 0x04:  # RST
                responded_ports[sport] = "closed"
            else:
                responded_ports[sport] = "filtered"

        results: list[PortResult] = []
        for port in ports:
            state = responded_ports.get(port, "filtered")
            results.append(
                PortResult(
                    port=port,
                    protocol="tcp",
                    state=state,
                    service_name=self._get_service_name(port),
                )
            )

        return sorted(results, key=lambda pr: pr.port)

    # ------------------------------------------------------------------
    # Banner grabbing
    # ------------------------------------------------------------------

    async def _grab_banner(
        self, ip: str, result: PortResult, timeout: float = 2.0
    ) -> None:
        """
        Attempt to read a service banner from an open port.

        Connects, reads up to 1024 bytes within the timeout, and
        stores the decoded banner on the :class:`PortResult`.
        """
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, result.port),
                timeout=timeout,
            )
            try:
                banner_bytes = await asyncio.wait_for(
                    reader.read(1024), timeout=timeout
                )
                if banner_bytes:
                    result.banner = banner_bytes.decode("utf-8", errors="replace").strip()
            except asyncio.TimeoutError:
                pass
            finally:
                writer.close()
                await writer.wait_closed()
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            pass

    # ------------------------------------------------------------------
    # Classification helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _get_service_name(port: int) -> str:
        """Map a port number to its well-known service name."""
        return _SERVICE_MAP.get(port, f"unknown-{port}")

    @staticmethod
    def _classify_suspicion(
        port: int, banner: Optional[str]
    ) -> tuple[bool, Optional[str]]:
        """
        Determine whether a port/banner combination is suspicious.

        Returns:
            ``(is_suspicious, reason_string_or_None)``
        """
        # APT28 indicator ports
        if port in _APT28_PORTS:
            return True, _APT28_PORTS[port]

        # Check banner for known-suspicious strings
        if banner:
            banner_lower = banner.lower()
            for fragment, reason in _SUSPICIOUS_BANNERS:
                if fragment.lower() in banner_lower:
                    return True, reason

        # Port 53 with suspicious banner
        if port == 53 and banner:
            banner_lower = banner.lower()
            if "dnsmasq" in banner_lower:
                return True, (
                    "DNS service running dnsmasq on a device — "
                    "verify this is expected; compromised routers often "
                    "expose modified dnsmasq instances"
                )

        return False, None
