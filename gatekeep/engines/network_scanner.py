"""
Network discovery engine for GATEKEEP.

Uses ARP scanning via scapy to discover devices on the local network,
identify vendors via OUI database lookup, detect randomized MACs, and
resolve hostnames via reverse DNS.

When Npcap/WinPcap is not installed, falls back to a ping-sweep + ARP
table approach that works on any Windows machine without extra drivers.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import re
import socket
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from gatekeep.config import NetworkConfig
from gatekeep.exceptions import (
    InsufficientPrivilegesError,
    NetworkError,
)
from gatekeep.logging_config import get_logger
from gatekeep.utils.network import (
    get_default_gateway,
    get_local_ip,
    get_subnet_cidr,
    mac_to_vendor,
)

log = get_logger(__name__)

# Characters in the second hex digit of a MAC that indicate the
# locally-administered bit is set (bit 1 of the first octet).
_RANDOMIZED_MAC_SECOND_CHARS = frozenset("2367ABEFabef")

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"


@dataclass
class DiscoveredDevice:
    """A device found during ARP network discovery."""

    ip: str
    mac: str
    vendor: Optional[str] = None
    is_gateway: bool = False
    is_randomized_mac: bool = False
    response_time_ms: float = 0.0
    hostname: Optional[str] = None


class NetworkScanner:
    """
    Discovers devices on the local network via ARP broadcast scanning.

    Uses scapy for raw ARP requests, looks up MAC vendors from the
    IEEE OUI prefix database, and performs reverse DNS for hostnames.
    """

    def __init__(self, config: NetworkConfig) -> None:
        self._config = config
        self._oui_db = self._load_oui_database()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def discover(
        self,
        interface: Optional[str] = None,
        subnet: Optional[str] = None,
    ) -> list[DiscoveredDevice]:
        """
        Perform network discovery on the specified (or auto-detected) subnet.

        Tries scapy ARP scanning first (requires Npcap/WinPcap).  When the
        raw-packet backend is unavailable, falls back to a ping sweep + OS
        ARP-table approach that works on any Windows machine.

        Args:
            interface: Network interface name. Auto-detected if *None*.
            subnet: CIDR notation subnet (e.g. ``192.168.1.0/24``).
                    Auto-detected if *None*.

        Returns:
            List of :class:`DiscoveredDevice` for every host that
            responded to the scan.

        Raises:
            InsufficientPrivilegesError: Process lacks admin rights.
            NetworkError: Interface not found or unreachable.
        """
        if subnet is None:
            subnet = get_subnet_cidr()
            if subnet is None:
                raise NetworkError(
                    "Could not auto-detect local subnet. "
                    "Please specify a subnet in CIDR notation."
                )
            log.info("auto_detected_subnet", subnet=subnet)

        gateway_ip = get_default_gateway()

        log.info(
            "arp_discovery_start",
            subnet=subnet,
            interface=interface,
            gateway_ip=gateway_ip,
            timeout=self._config.arp_timeout,
        )

        # ----------------------------------------------------------
        # Try scapy ARP scan first; fall back to ping sweep + ARP table
        # ----------------------------------------------------------
        answered: list[tuple] = []
        scapy_ok = self._is_scapy_l2_available()

        if scapy_ok:
            try:
                answered = await asyncio.to_thread(
                    self._arp_scan,
                    subnet,
                    interface,
                    self._config.arp_timeout,
                )
            except PermissionError:
                raise InsufficientPrivilegesError("arp_scan")
            except OSError as exc:
                msg = str(exc)
                if "No such device" in msg or "failed to open adapter" in msg.lower():
                    raise NetworkError(
                        f"Network interface not found or inaccessible: {interface or '(auto)'}",
                        details={"original_error": msg},
                    )
                # For other OS errors (e.g. winpcap runtime failure),
                # fall through to the ping-sweep fallback.
                log.warning(
                    "scapy_arp_failed",
                    error=msg,
                    fallback="ping_sweep",
                )
                answered = await self._ping_sweep_discovery(subnet)
            except Exception as exc:
                log.warning(
                    "scapy_arp_failed",
                    error=str(exc),
                    fallback="ping_sweep",
                )
                answered = await self._ping_sweep_discovery(subnet)
        else:
            log.warning(
                "scapy_l2_unavailable",
                fallback="ping_sweep",
            )
            answered = await self._ping_sweep_discovery(subnet)

        # ----------------------------------------------------------
        # Build DiscoveredDevice list from scan results
        # ----------------------------------------------------------
        local_ip = get_local_ip()
        devices: list[DiscoveredDevice] = []
        for sent, received, elapsed_ms in answered:
            ip = received.psrc
            mac = received.hwsrc.upper()

            # Skip the local machine's entry if it has a zeroed MAC
            # (ping sweep sees itself respond but can't read its own
            # MAC from the ARP table)
            if mac == "00:00:00:00:00:00" and ip == local_ip:
                log.debug("skipping_self", ip=ip)
                continue
            # Also skip any other zeroed-MAC entries (broadcast artifacts)
            if mac == "00:00:00:00:00:00":
                log.debug("skipping_zero_mac", ip=ip)
                continue

            vendor = mac_to_vendor(mac, self._oui_db)
            is_gw = gateway_ip is not None and ip == gateway_ip
            is_random = self._is_randomized_mac(mac)

            device = DiscoveredDevice(
                ip=ip,
                mac=mac,
                vendor=vendor,
                is_gateway=is_gw,
                is_randomized_mac=is_random,
                response_time_ms=round(elapsed_ms, 2),
            )
            devices.append(device)

        log.info("arp_discovery_raw_done", device_count=len(devices))

        # Resolve hostnames concurrently
        hostname_tasks = [
            self.get_device_hostname(d.ip) for d in devices
        ]
        hostnames = await asyncio.gather(*hostname_tasks, return_exceptions=True)
        for device, hostname in zip(devices, hostnames):
            if isinstance(hostname, str):
                device.hostname = hostname

        log.info(
            "arp_discovery_complete",
            device_count=len(devices),
            gateway_found=any(d.is_gateway for d in devices),
        )
        return devices

    async def get_device_hostname(self, ip: str) -> Optional[str]:
        """
        Attempt a reverse DNS lookup for the given IP address.

        Returns the hostname if found, *None* otherwise.
        """
        try:
            result = await asyncio.to_thread(
                socket.gethostbyaddr, ip
            )
            hostname = result[0]
            # Ignore numeric-only "hostnames" that are just the IP
            if hostname and hostname != ip:
                return hostname
        except (socket.herror, socket.gaierror, OSError):
            pass
        return None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _load_oui_database() -> dict[str, str]:
        """Load OUI prefix -> vendor mapping from JSON data file."""
        oui_path = _DATA_DIR / "oui_prefixes.json"
        try:
            with open(oui_path, "r", encoding="utf-8") as fh:
                raw: dict[str, str] = json.load(fh)
            # Strip internal metadata keys
            return {k: v for k, v in raw.items() if not k.startswith("_")}
        except (FileNotFoundError, json.JSONDecodeError) as exc:
            log.warning("oui_db_load_failed", path=str(oui_path), error=str(exc))
            return {}

    @staticmethod
    def _is_randomized_mac(mac: str) -> bool:
        """
        Detect whether a MAC address is locally administered (randomized).

        The locally-administered bit is bit 1 of the first octet. In the
        common ``AA:BB:CC:DD:EE:FF`` notation, this corresponds to the
        second hex character being one of ``2 3 6 7 A B E F``.
        """
        cleaned = mac.replace(":", "").replace("-", "").replace(".", "")
        if len(cleaned) < 2:
            return False
        return cleaned[1] in _RANDOMIZED_MAC_SECOND_CHARS

    @staticmethod
    def _is_scapy_l2_available() -> bool:
        """
        Check whether scapy's Layer 2 raw packet backend is usable.

        Returns *True* if scapy is importable **and** the underlying pcap
        driver (Npcap / WinPcap / libpcap) is present.  Returns *False*
        otherwise, so the caller can fall back to a non-raw alternative.
        """
        try:
            from scapy.all import conf as scapy_conf  # type: ignore[import-untyped]
        except ImportError:
            return False

        import platform

        if platform.system().lower() == "windows":
            import os

            system32 = os.path.join(
                os.environ.get("WINDIR", r"C:\Windows"), "System32"
            )
            npcap_dir = os.path.join(system32, "Npcap")
            # Npcap in WinPcap-compat mode puts wpcap.dll in System32
            if os.path.isfile(os.path.join(system32, "wpcap.dll")):
                return True
            # Npcap without compat mode puts it in System32\Npcap
            if os.path.isfile(os.path.join(npcap_dir, "wpcap.dll")):
                return True
            return False

        # Non-Windows: assume libpcap is available if scapy imported OK
        return True

    # ------------------------------------------------------------------
    # Ping-sweep fallback (no Npcap required)
    # ------------------------------------------------------------------

    async def _ping_sweep_discovery(self, subnet: str) -> list[tuple]:
        """Discover devices via ping sweep + ARP table (no Npcap needed).

        Sends ICMP echo requests to every host in *subnet* to populate the
        OS ARP cache, then reads ``arp -a`` to harvest IP/MAC mappings.

        Returns a list of ``(None, response_obj, elapsed_ms)`` tuples that
        match the format produced by :meth:`_arp_scan`, where
        ``response_obj`` exposes ``.psrc`` (IP) and ``.hwsrc`` (MAC).
        """
        network = ipaddress.IPv4Network(subnet, strict=False)
        log.info(
            "ping_sweep_start",
            subnet=subnet,
            host_count=network.num_addresses,
        )

        # -- Step 1: ping all hosts concurrently to populate ARP cache ----

        async def ping_host(ip_str: str) -> tuple[str, bool, float]:
            start = time.time()
            try:
                proc = await asyncio.create_subprocess_exec(
                    "ping", "-n", "1", "-w", "500", ip_str,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await asyncio.wait_for(proc.wait(), timeout=2.0)
                elapsed = (time.time() - start) * 1000
                return (ip_str, proc.returncode == 0, elapsed)
            except Exception:
                return (ip_str, False, 0.0)

        hosts = [str(ip) for ip in network.hosts()]
        results: dict[str, float] = {}
        batch_size = 50
        for i in range(0, len(hosts), batch_size):
            batch = hosts[i : i + batch_size]
            batch_results = await asyncio.gather(
                *[ping_host(ip) for ip in batch]
            )
            for ip_str, alive, elapsed in batch_results:
                if alive:
                    results[ip_str] = elapsed

        log.info("ping_sweep_complete", alive_count=len(results))

        # -- Step 2: read the OS ARP table --------------------------------

        try:
            proc = await asyncio.create_subprocess_exec(
                "arp", "-a",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await proc.communicate()
            arp_output = stdout.decode("utf-8", errors="replace")
        except Exception as exc:
            log.error("arp_table_read_failed", error=str(exc))
            arp_output = ""

        # Parse lines like:
        #   192.168.1.1     aa-bb-cc-dd-ee-ff     dynamic
        arp_entries: dict[str, str] = {}
        arp_pattern = re.compile(
            r"(\d+\.\d+\.\d+\.\d+)\s+"
            r"([\da-fA-F]{2}[:-][\da-fA-F]{2}[:-][\da-fA-F]{2}[:-]"
            r"[\da-fA-F]{2}[:-][\da-fA-F]{2}[:-][\da-fA-F]{2})\s+"
            r"(\w+)"
        )
        for line in arp_output.split("\n"):
            m = arp_pattern.search(line)
            if m:
                ip = m.group(1)
                mac = m.group(2).upper().replace("-", ":")
                entry_type = m.group(3).lower()
                if entry_type == "dynamic" and mac != "FF:FF:FF:FF:FF:FF":
                    arp_entries[ip] = mac

        log.info("arp_table_parsed", entries=len(arp_entries))

        # -- Step 3: build result tuples ----------------------------------

        class _FakeResponse:
            """Minimal stand-in for a scapy ARP response packet."""

            __slots__ = ("psrc", "hwsrc")

            def __init__(self, ip: str, mac: str) -> None:
                self.psrc = ip
                self.hwsrc = mac

        discovered: list[tuple] = []
        all_ips = set(results.keys()) | set(arp_entries.keys())
        for ip in all_ips:
            mac = arp_entries.get(ip, "00:00:00:00:00:00")
            elapsed = results.get(ip, 0.0)
            # Include if we have a real MAC, or the host responded to ping
            if mac != "00:00:00:00:00:00" or ip in results:
                discovered.append(
                    (None, _FakeResponse(ip, mac), elapsed)
                )

        log.info("ping_sweep_devices", count=len(discovered))
        return discovered

    @staticmethod
    def _arp_scan(
        subnet: str,
        interface: Optional[str],
        timeout: int,
    ) -> list[tuple]:
        """
        Perform a synchronous ARP scan using scapy (called in a thread).

        Returns a list of ``(sent_pkt, recv_pkt, elapsed_ms)`` tuples.
        """
        from scapy.all import ARP, Ether, srp  # type: ignore[import-untyped]

        arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)

        kwargs: dict = {"timeout": timeout, "verbose": 0}
        if interface:
            kwargs["iface"] = interface

        start = time.perf_counter()
        answered, _ = srp(arp_request, **kwargs)
        base_elapsed = (time.perf_counter() - start) * 1000  # ms

        results: list[tuple] = []
        for i, (sent, received) in enumerate(answered):
            # scapy doesn't expose per-packet timing, so distribute
            # the total elapsed time proportionally as an estimate.
            pkt_elapsed = base_elapsed * ((i + 1) / max(len(answered), 1))
            results.append((sent, received, pkt_elapsed))

        return results
