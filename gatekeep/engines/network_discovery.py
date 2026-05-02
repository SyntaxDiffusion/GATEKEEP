"""
Enhanced network discovery using SSDP/UPnP and NetBIOS.

These broadcast protocols allow device identification beyond simple
MAC vendor lookup -- discovering friendly names, device models,
manufacturers, and Windows/SMB hostnames.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
import struct
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

import httpx

from gatekeep.logging_config import get_logger


def _is_private_url(url: str) -> bool:
    """Check if a URL points to a private/link-local IP address.

    Only allows fetching UPnP descriptions from RFC 1918 or link-local
    addresses.  Rejects DNS hostnames to prevent DNS rebinding SSRF.
    """
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return False
        addr = ipaddress.ip_address(hostname)
        return addr.is_private or addr.is_link_local
    except ValueError:
        # hostname is a DNS name, not a raw IP — reject to prevent SSRF
        return False


@dataclass
class DiscoveryInfo:
    """Additional device information from network discovery protocols."""

    ip: str
    mdns_name: Optional[str] = None
    ssdp_server: Optional[str] = None
    ssdp_location: Optional[str] = None
    upnp_friendly_name: Optional[str] = None
    upnp_model: Optional[str] = None
    upnp_manufacturer: Optional[str] = None
    netbios_name: Optional[str] = None
    netbios_domain: Optional[str] = None


class NetworkDiscovery:
    """Discover additional device information via broadcast protocols.

    Runs SSDP (UPnP) and NetBIOS queries concurrently to enrich
    the device data collected during ARP/ping discovery.
    """

    def __init__(self) -> None:
        self._logger = get_logger("network_discovery")

    async def discover_all(
        self, target_ips: list[str]
    ) -> dict[str, DiscoveryInfo]:
        """Run all discovery protocols and merge results by IP.

        Args:
            target_ips: List of IP addresses to investigate.

        Returns:
            Dict mapping IP address to DiscoveryInfo.
        """
        results: dict[str, DiscoveryInfo] = {}

        # Run both protocols concurrently
        ssdp_task = asyncio.create_task(self._ssdp_discover())
        netbios_task = asyncio.create_task(self._netbios_discover(target_ips))

        ssdp_results = await ssdp_task
        netbios_results = await netbios_task

        # Merge SSDP results
        for ip, info in ssdp_results.items():
            if ip not in results:
                results[ip] = DiscoveryInfo(ip=ip)
            results[ip].ssdp_server = info.get("server")
            results[ip].ssdp_location = info.get("location")
            results[ip].upnp_friendly_name = info.get("friendly_name")
            results[ip].upnp_model = info.get("model")
            results[ip].upnp_manufacturer = info.get("manufacturer")

        # Merge NetBIOS results
        for ip, info in netbios_results.items():
            if ip not in results:
                results[ip] = DiscoveryInfo(ip=ip)
            results[ip].netbios_name = info.get("name")
            results[ip].netbios_domain = info.get("domain")

        self._logger.info(
            "discovery_complete",
            total_ips=len(results),
            ssdp_found=len(ssdp_results),
            netbios_found=len(netbios_results),
        )
        return results

    # ------------------------------------------------------------------
    # SSDP / UPnP discovery
    # ------------------------------------------------------------------

    async def _ssdp_discover(
        self, timeout: float = 4.0
    ) -> dict[str, dict[str, str]]:
        """Discover UPnP/SSDP devices on the network.

        Sends an M-SEARCH multicast to ``239.255.255.250:1900`` and
        collects responses.  For each responder that advertises a
        LOCATION URL, attempts to fetch the UPnP device description
        XML to extract friendly name, model, and manufacturer.
        """
        results: dict[str, dict[str, str]] = {}

        msearch = (
            "M-SEARCH * HTTP/1.1\r\n"
            "HOST: 239.255.255.250:1900\r\n"
            'MAN: "ssdp:discover"\r\n'
            "MX: 3\r\n"
            "ST: ssdp:all\r\n"
            "\r\n"
        )

        try:
            sock = socket.socket(
                socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP
            )
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(timeout)
            sock.sendto(msearch.encode(), ("239.255.255.250", 1900))

            loop = asyncio.get_event_loop()
            end_time = loop.time() + timeout

            while loop.time() < end_time:
                try:
                    data, addr = await loop.run_in_executor(
                        None, lambda: sock.recvfrom(4096)
                    )
                    ip = addr[0]
                    response = data.decode("utf-8", errors="replace")

                    info: dict[str, str] = {}
                    for line in response.split("\r\n"):
                        if ":" in line:
                            key, _, value = line.partition(":")
                            info[key.strip().lower()] = value.strip()

                    if ip not in results:
                        results[ip] = {
                            "server": info.get("server", ""),
                            "location": info.get("location", ""),
                        }
                except socket.timeout:
                    break
                except Exception:
                    break

            sock.close()

            # Fetch UPnP device descriptions from LOCATION URLs
            async with httpx.AsyncClient(verify=False, timeout=3) as client:
                for ip, info in list(results.items()):
                    location = info.get("location", "")
                    if location and location.startswith("http") and _is_private_url(location):
                        try:
                            r = await client.get(location)
                            xml = r.text
                            fn = re.search(
                                r"<friendlyName>(.*?)</friendlyName>", xml
                            )
                            model = re.search(
                                r"<modelName>(.*?)</modelName>", xml
                            )
                            mfr = re.search(
                                r"<manufacturer>(.*?)</manufacturer>", xml
                            )
                            if fn:
                                results[ip]["friendly_name"] = fn.group(1)
                            if model:
                                results[ip]["model"] = model.group(1)
                            if mfr:
                                results[ip]["manufacturer"] = mfr.group(1)
                        except Exception:
                            pass

        except Exception as e:
            self._logger.warning("ssdp_failed", error=str(e))

        self._logger.info("ssdp_complete", devices=len(results))
        return results

    # ------------------------------------------------------------------
    # NetBIOS Name Service queries
    # ------------------------------------------------------------------

    async def _netbios_discover(
        self, target_ips: list[str], timeout: float = 2.0
    ) -> dict[str, dict[str, str]]:
        """Query NetBIOS names for target IPs (UDP port 137).

        Sends a NetBIOS Name Service NBSTAT wildcard query to each
        target IP and parses the response to extract the workstation
        name and domain/workgroup.
        """
        results: dict[str, dict[str, str]] = {}

        # NetBIOS NBSTAT wildcard query packet
        # Encoded "*" (wildcard) name for NBSTAT query
        query = (
            b"\x01\x00"  # Transaction ID
            b"\x00\x00"  # Flags
            b"\x00\x01"  # Questions: 1
            b"\x00\x00"  # Answer RRs
            b"\x00\x00"  # Authority RRs
            b"\x00\x00"  # Additional RRs
            b"\x20"  # Name length (32)
            + b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"  # Encoded * (wildcard)
            + b"\x00"  # Name terminator
            b"\x00\x21"  # Type: NBSTAT
            b"\x00\x01"  # Class: IN
        )

        async def query_host(
            ip: str,
        ) -> Optional[tuple[str, dict[str, str]]]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(timeout)
                sock.sendto(query, (ip, 137))
                data, _ = await asyncio.get_event_loop().run_in_executor(
                    None, lambda s=sock: s.recvfrom(1024)
                )
                sock.close()

                # Parse the NBSTAT response
                if len(data) > 57:
                    num_names = data[56]
                    names: list[str] = []
                    offset = 57
                    for _ in range(min(num_names, 10)):
                        if offset + 18 > len(data):
                            break
                        name = (
                            data[offset : offset + 15]
                            .decode("ascii", errors="replace")
                            .strip()
                        )
                        name_type = data[offset + 15]
                        flags = struct.unpack(
                            ">H", data[offset + 16 : offset + 18]
                        )[0]
                        # Type 0x00 = workstation, GROUP bit (0x8000) unset
                        if name and name_type == 0x00 and not (flags & 0x8000):
                            names.append(name)
                        offset += 18

                    if names:
                        return (
                            ip,
                            {
                                "name": names[0],
                                "domain": names[1] if len(names) > 1 else "",
                            },
                        )
            except Exception:
                pass
            return None

        # Query all target IPs concurrently
        tasks = [query_host(ip) for ip in target_ips]
        responses = await asyncio.gather(*tasks)

        for resp in responses:
            if resp:
                ip, info = resp
                results[ip] = info

        self._logger.info("netbios_complete", hosts_found=len(results))
        return results
