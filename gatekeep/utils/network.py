"""
Network utility functions for GATEKEEP.

Provides helpers for querying local network configuration, subnet
calculations, IP classification, and OUI-based vendor lookups.
"""

from __future__ import annotations

import ipaddress
import socket
import subprocess
from typing import Optional

import netifaces


def get_default_gateway() -> Optional[str]:
    """
    Return the IP address of the default gateway.

    Uses multiple fallback approaches because netifaces2 does not
    implement ``gateways()``.

    1. Parse ``ipconfig`` output (Windows).
    2. Probe common gateway addresses.
    3. Fall back to ``netifaces.gateways()`` (works on older netifaces).
    """
    # Approach 1: Parse 'ipconfig' output on Windows
    try:
        result = subprocess.run(
            ["ipconfig"], capture_output=True, text=True, timeout=5
        )
        lines = result.stdout.split('\n')
        in_gateway_section = False
        for line in lines:
            if 'Default Gateway' in line:
                # The IPv4 gateway may be on this line or a continuation line
                after_colon = line.split(':', 1)[-1].strip()
                if after_colon and after_colon[0].isdigit():
                    return after_colon
                # Mark that we're in a gateway section; IPv4 may follow
                in_gateway_section = True
                continue
            if in_gateway_section:
                stripped = line.strip()
                if stripped and stripped[0].isdigit():
                    return stripped
                # Non-continuation line — stop looking under this gateway
                if stripped and not stripped[0].isdigit():
                    in_gateway_section = False
    except Exception:
        pass

    # Approach 2: Check common gateway addresses
    for candidate in ['192.168.1.1', '192.168.0.1', '10.0.0.1', '172.16.0.1']:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((candidate, 80))
            sock.close()
            if result == 0:
                return candidate
        except Exception:
            pass

    # Approach 3: Try netifaces.gateways() as last resort
    try:
        gateways = netifaces.gateways()
        default = gateways.get("default", {})
        if netifaces.AF_INET in default:
            return str(default[netifaces.AF_INET][0])
    except Exception:
        pass

    return None


def get_local_ip() -> Optional[str]:
    """
    Return this machine's primary local IP address.

    Uses a UDP socket trick to determine which interface the OS
    would use to reach an external address, without actually
    sending traffic.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            # Connect to a public DNS — no traffic is actually sent
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        # Fallback: iterate interfaces
        for iface_name in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface_name)
            ipv4_list = addrs.get(netifaces.AF_INET, [])
            for addr_info in ipv4_list:
                ip = addr_info.get("addr", "")
                if ip and ip != "127.0.0.1":
                    return ip
        return None


def get_subnet_cidr(ip: Optional[str] = None) -> Optional[str]:
    """
    Return the subnet in CIDR notation for the given or local IP.

    Inspects netifaces address information to find the netmask
    and computes the network address with prefix length.

    Args:
        ip: Specific IP to look up. If None, uses get_local_ip().

    Returns:
        Subnet string like "192.168.1.0/24", or None if not found.
    """
    if ip is None:
        ip = get_local_ip()
    if ip is None:
        return None

    for iface_name in netifaces.interfaces():
        addrs = netifaces.ifaddresses(iface_name)
        ipv4_list = addrs.get(netifaces.AF_INET, [])
        for addr_info in ipv4_list:
            if addr_info.get("addr") == ip:
                # netifaces uses "netmask", netifaces2 uses "mask"
                netmask = addr_info.get("netmask") or addr_info.get("mask")
                if netmask:
                    network = ipaddress.IPv4Network(
                        f"{ip}/{netmask}", strict=False
                    )
                    return str(network)
    return None


def ip_in_range(ip: str, cidr: str) -> bool:
    """
    Check whether an IP address falls within a CIDR subnet.

    Args:
        ip: IP address string, e.g. "192.168.1.42".
        cidr: CIDR notation string, e.g. "192.168.1.0/24".

    Returns:
        True if the IP is within the subnet, False otherwise.
    """
    try:
        return ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(cidr, strict=False)
    except (ipaddress.AddressValueError, ValueError):
        return False


def mac_to_vendor(mac: str, oui_db: Optional[dict[str, str]] = None) -> Optional[str]:
    """
    Look up the vendor/manufacturer for a MAC address via OUI prefix.

    Uses the first 3 octets (OUI) of the MAC address to find
    the manufacturer in the provided lookup dictionary.

    Args:
        mac: MAC address string in any common format
             (e.g. "AA:BB:CC:DD:EE:FF" or "AA-BB-CC-DD-EE-FF").
        oui_db: Dictionary mapping uppercase OUI prefixes
                (e.g. "AABBCC") to vendor names. If None, returns None.

    Returns:
        Vendor name string, or None if not found.
    """
    if oui_db is None:
        return None

    # Normalize MAC: strip separators and uppercase
    cleaned = mac.upper().replace(":", "").replace("-", "").replace(".", "")
    if len(cleaned) < 6:
        return None

    oui_prefix = cleaned[:6]
    return oui_db.get(oui_prefix)


def is_private_ip(ip: str) -> bool:
    """
    Check whether an IP address belongs to an RFC 1918 private range.

    Private ranges:
    - 10.0.0.0/8
    - 172.16.0.0/12
    - 192.168.0.0/16

    Also considers 127.0.0.0/8 (loopback) and 169.254.0.0/16
    (link-local) as non-routable.

    Args:
        ip: IP address string.

    Returns:
        True if the address is private/non-routable, False otherwise.
    """
    try:
        addr = ipaddress.IPv4Address(ip)
        return addr.is_private
    except (ipaddress.AddressValueError, ValueError):
        return False


def _build_scapy_name_map() -> dict[str, str]:
    """Build a mapping from netifaces description to scapy interface name.

    On Windows, netifaces uses the adapter description as the interface
    name (e.g. ``Intel(R) Wi-Fi 6 AX201 160MHz``) while scapy uses a
    shorter Windows connection name (e.g. ``Wi-Fi``).  Packet capture
    requires the scapy name, so we build a lookup table from
    description → scapy name.
    """
    try:
        from scapy.arch.windows import get_windows_if_list  # type: ignore[import-untyped]

        mapping: dict[str, str] = {}
        for iface in get_windows_if_list():
            desc = iface.get("description", "")
            name = iface.get("name", "")
            if desc and name:
                mapping[desc] = name
        return mapping
    except Exception:
        return {}


def resolve_interface_name(name: str) -> str:
    """Resolve an interface name to its scapy-compatible form.

    Accepts either a scapy name (e.g. ``'Wi-Fi'``) or a netifaces
    description (e.g. ``'Intel(R) Wi-Fi 6 AX201 160MHz'``) and
    returns the scapy name.  If the name cannot be resolved, it is
    returned unchanged.
    """
    scapy_map = _build_scapy_name_map()
    # If it's already a scapy name, return it
    if name in scapy_map.values():
        return name
    # If it's a description, resolve it
    if name in scapy_map:
        return scapy_map[name]
    # Return as-is if not found
    return name


def get_all_interfaces() -> list[dict]:
    """
    List all network interfaces with their IPv4 addresses, MACs, and subnets.

    Returns:
        List of dicts with keys: name, display_name, scapy_name,
        ipv4, mac, netmask, subnet.  ``name`` is the scapy-compatible
        name when available (required for packet capture); ``display_name``
        is the human-readable adapter description.
    """
    scapy_map = _build_scapy_name_map()

    results: list[dict] = []
    for iface_name in netifaces.interfaces():
        addrs = netifaces.ifaddresses(iface_name)
        ipv4_list = addrs.get(netifaces.AF_INET, [])
        mac_list = addrs.get(netifaces.AF_LINK, [])

        mac_addr = mac_list[0].get("addr", "") if mac_list else ""

        # Resolve the scapy-compatible name for this interface
        scapy_name = scapy_map.get(iface_name, iface_name)

        for addr_info in ipv4_list:
            ip_addr = addr_info.get("addr", "")
            # netifaces uses "netmask", netifaces2 uses "mask"
            netmask = addr_info.get("netmask", "") or addr_info.get("mask", "")
            subnet = ""
            if ip_addr and netmask:
                try:
                    network = ipaddress.IPv4Network(
                        f"{ip_addr}/{netmask}", strict=False
                    )
                    subnet = str(network)
                except ValueError:
                    pass

            results.append(
                {
                    "name": scapy_name,
                    "display_name": iface_name,
                    "scapy_name": scapy_name,
                    "ipv4": ip_addr,
                    "mac": mac_addr,
                    "netmask": netmask,
                    "subnet": subnet,
                }
            )

    return results
