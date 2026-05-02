"""
Fios Router (Sagemcom G3100) admin interface client.

Authenticates via the router's CGI API and retrieves:
- Connected device list with hostnames
- DHCP lease table
- DNS settings
- WiFi client information
- System/firmware info
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any, Optional

import httpx

from gatekeep.logging_config import get_logger


@dataclass
class RouterDevice:
    """A device as reported by the router's admin interface."""

    hostname: str = ""
    ip_address: str = ""
    mac_address: str = ""
    connection_type: str = ""  # wifi_2g, wifi_5g, ethernet
    is_online: bool = True
    signal_strength: int = 0  # dBm for wifi clients
    rx_bytes: int = 0
    tx_bytes: int = 0


@dataclass
class RouterInfo:
    """Router system information."""

    model: str = ""
    firmware_version: str = ""
    serial_number: str = ""
    uptime: str = ""
    wan_ip: str = ""
    wan_dns: list[str] = field(default_factory=list)
    lan_ip: str = ""
    wifi_enabled: bool = True
    wifi_ssid: str = ""


class FiosRouterClient:
    """Client for Verizon Fios Router (Sagemcom) admin API.

    Auth flow (reverse-engineered from the router's JavaScript):
      1. GET ``/loginStatus.cgi`` -> ``{"loginToken": "...", "islogin": "0"}``
      2. Compute password hash: ``SHA-512(loginToken + MD5(password))``
      3. POST ``/goform/login`` with the hashed password
      4. All subsequent CGI requests use the session cookie
    """

    def __init__(self, router_ip: str = "192.168.1.1") -> None:
        self.base_url = f"https://{router_ip}"
        self.router_ip = router_ip
        self._token: Optional[str] = None
        self._client: Optional[httpx.AsyncClient] = None
        self._logger = get_logger("router_admin")

    # ------------------------------------------------------------------
    # Cryptographic helpers (replicate the router's JS login_encode)
    # ------------------------------------------------------------------

    @staticmethod
    def _md5(text: str) -> str:
        """Compute MD5 hex digest (equivalent to ``ArcMD5`` in the router JS)."""
        return hashlib.md5(text.encode("utf-8")).hexdigest()

    @staticmethod
    def _login_encode(password: str, login_token: str) -> str:
        """Replicate the Fios ``login_encode(e, t)`` JavaScript function.

        .. code-block:: javascript

            function login_encode(e, t) {
                if ("" == t) return ArcMD5(e);
                let i = new jsSHA(t + ArcMD5(e), "ASCII");
                return i.getHash("SHA-512", "HEX");
            }

        Returns:
            Hex-encoded hash suitable for the ``loginPassword`` form field.
        """
        if not login_token:
            return FiosRouterClient._md5(password)

        md5_pass = FiosRouterClient._md5(password)
        combined = login_token + md5_pass
        return hashlib.sha512(combined.encode("ascii")).hexdigest()

    # ------------------------------------------------------------------
    # Connection / authentication
    # ------------------------------------------------------------------

    async def connect(self) -> bool:
        """Test reachability of the router without authenticating.

        Creates the underlying ``httpx.AsyncClient`` and attempts to
        reach ``/loginStatus.cgi``.

        Returns:
            ``True`` if the router responded successfully.
        """
        try:
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                verify=False,
                timeout=10,
            )
            r = await self._client.get("/loginStatus.cgi")
            data = r.json()
            self._logger.info("router_reachable", is_login=data.get("islogin"))
            return True
        except Exception as e:
            self._logger.error("router_unreachable", error=str(e))
            return False

    async def login(self, password: str) -> bool:
        """Authenticate with the router admin interface.

        Args:
            password: The router admin password (plaintext).

        Returns:
            ``True`` if login succeeded and a session token was obtained.
        """
        if self._client is None:
            await self.connect()

        try:
            # Step 1: Get login token
            r = await self._client.get("/loginStatus.cgi")
            status = r.json()
            login_token = status.get("loginToken", "")

            if status.get("islogin") == "1":
                self._token = status.get("token", "")
                self._logger.info("already_logged_in")
                return True

            # Step 2: Compute password hash
            password_hash = self._login_encode(password, login_token)

            # Step 3: Submit login
            login_data = {
                "loginUsername": "admin",
                "loginPassword": password_hash,
            }

            await self._client.post(
                "/goform/login",
                data=login_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )

            # Step 4: Verify login succeeded
            r2 = await self._client.get("/loginStatus.cgi")
            status2 = r2.json()

            if status2.get("islogin") == "1":
                self._token = status2.get("token", "")
                self._logger.info("login_success")
                return True
            else:
                self._logger.warning("login_failed")
                return False

        except Exception as e:
            self._logger.error("login_error", error=str(e))
            return False

    # ------------------------------------------------------------------
    # CGI data fetching
    # ------------------------------------------------------------------

    async def _get_cgi(self, cgi_name: str) -> Optional[dict[str, Any]]:
        """Fetch a CGI endpoint and return parsed data.

        The Fios router returns JavaScript variable assignments like::

            var device_list = [{...}];

        This method parses both plain JSON and JS variable assignment
        formats into Python dicts.
        """
        if self._client is None:
            return None

        try:
            r = await self._client.get(f"/cgi/cgi_{cgi_name}.js")
            if r.status_code != 200:
                return None

            text = r.text.strip()

            # Try JSON parse first
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                pass

            # Parse JS variable assignments: var name = value;
            result: dict[str, Any] = {}
            pattern = re.compile(
                r"(?:var|let|const)\s+(\w+)\s*=\s*"
                r"([\[{].*?[}\]]|\"[^\"]*\"|'[^']*'|\d+(?:\.\d+)?)\s*;",
                re.DOTALL,
            )
            for match in pattern.finditer(text):
                var_name = match.group(1)
                var_value = match.group(2)
                try:
                    result[var_name] = json.loads(var_value)
                except json.JSONDecodeError:
                    result[var_name] = var_value

            return result if result else {"_raw": text}

        except Exception as e:
            self._logger.debug("cgi_fetch_failed", cgi=cgi_name, error=str(e))
            return None

    # ------------------------------------------------------------------
    # Device discovery
    # ------------------------------------------------------------------

    async def get_connected_devices(self) -> list[RouterDevice]:
        """Get all devices connected to the router."""
        devices: list[RouterDevice] = []

        # Try multiple possible CGI endpoints for device lists
        for cgi_name in ("device", "device_list", "clients", "host", "hosts"):
            data = await self._get_cgi(cgi_name)
            if data and data != {"_raw": ""}:
                self._logger.info("device_cgi_found", endpoint=cgi_name)
                devices = self._parse_device_list(data)
                if devices:
                    break

        # Fallback: try DHCP leases
        if not devices:
            for cgi_name in ("dhcp", "dhcp_lease", "dhcp_leases"):
                data = await self._get_cgi(cgi_name)
                if data and data != {"_raw": ""}:
                    devices = self._parse_dhcp_leases(data)
                    if devices:
                        break

        self._logger.info("devices_retrieved", count=len(devices))
        return devices

    def _parse_device_list(self, data: dict[str, Any]) -> list[RouterDevice]:
        """Parse device list from various CGI response formats."""
        devices: list[RouterDevice] = []

        for _key, value in data.items():
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, dict) and (
                        "ip" in item
                        or "ipv4" in item
                        or "IP" in item
                        or "mac" in item
                    ):
                        dev = RouterDevice(
                            hostname=item.get(
                                "hostname",
                                item.get("name", item.get("HostName", "")),
                            ),
                            ip_address=item.get(
                                "ip",
                                item.get(
                                    "ipv4",
                                    item.get("IP", item.get("IPAddress", "")),
                                ),
                            ),
                            mac_address=item.get(
                                "mac",
                                item.get(
                                    "MAC",
                                    item.get(
                                        "MACAddress", item.get("macAddr", "")
                                    ),
                                ),
                            ),
                            connection_type=item.get(
                                "connection",
                                item.get("type", item.get("interface", "")),
                            ),
                            is_online=(
                                "1"
                                == str(
                                    item.get(
                                        "online",
                                        item.get(
                                            "active", item.get("Active", "1")
                                        ),
                                    )
                                )
                            ),
                        )
                        if dev.ip_address or dev.mac_address:
                            devices.append(dev)

        return devices

    def _parse_dhcp_leases(self, data: dict[str, Any]) -> list[RouterDevice]:
        """Parse DHCP lease data into RouterDevice objects."""
        devices: list[RouterDevice] = []
        for _key, value in data.items():
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        dev = RouterDevice(
                            hostname=item.get(
                                "hostname", item.get("name", "")
                            ),
                            ip_address=item.get(
                                "ip", item.get("ipaddr", "")
                            ),
                            mac_address=item.get(
                                "mac", item.get("macaddr", "")
                            ),
                        )
                        if dev.ip_address or dev.mac_address:
                            devices.append(dev)
        return devices

    # ------------------------------------------------------------------
    # System information
    # ------------------------------------------------------------------

    async def get_router_info(self) -> RouterInfo:
        """Get router system information (model, firmware, WAN, DNS)."""
        info = RouterInfo(lan_ip=self.router_ip)

        for cgi_name in ("system", "sysinfo", "about", "status", "overview"):
            data = await self._get_cgi(cgi_name)
            if data and "_raw" not in data:
                for _key, value in data.items():
                    if isinstance(value, dict):
                        info.model = value.get(
                            "model", value.get("ModelName", info.model)
                        )
                        info.firmware_version = value.get(
                            "firmware",
                            value.get(
                                "FirmwareVersion",
                                value.get("fw_ver", info.firmware_version),
                            ),
                        )
                        info.serial_number = value.get(
                            "serial",
                            value.get("SerialNumber", info.serial_number),
                        )
                        info.wan_ip = value.get(
                            "wan_ip", value.get("WanIP", info.wan_ip)
                        )
                if info.model:
                    break

        # Get DNS info
        for cgi_name in ("dns", "dns_status", "wan", "wan_status"):
            data = await self._get_cgi(cgi_name)
            if data and "_raw" not in data:
                for _key, value in data.items():
                    if isinstance(value, dict):
                        dns1 = value.get(
                            "dns1",
                            value.get("DNS1", value.get("primary_dns", "")),
                        )
                        dns2 = value.get(
                            "dns2",
                            value.get("DNS2", value.get("secondary_dns", "")),
                        )
                        if dns1:
                            info.wan_dns = [d for d in [dns1, dns2] if d]
                            break

        return info

    # ------------------------------------------------------------------
    # WiFi-specific queries
    # ------------------------------------------------------------------

    async def get_wifi_clients(self) -> list[dict[str, Any]]:
        """Get WiFi-specific client information."""
        for cgi_name in ("wifi", "wireless", "wifi_client", "wifi_status"):
            data = await self._get_cgi(cgi_name)
            if data and "_raw" not in data:
                return self._extract_list(data)
        return []

    @staticmethod
    def _extract_list(data: dict[str, Any]) -> list[dict[str, Any]]:
        """Extract the first list found in a CGI response."""
        for value in data.values():
            if isinstance(value, list) and value:
                return value
        return []

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None
