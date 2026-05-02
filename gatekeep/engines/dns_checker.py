"""
DNS security checker engine for GATEKEEP.

Validates the system's configured DNS resolvers against a trusted list,
detects FrostArmada/APT28 rogue DNS infrastructure, and performs
comparative resolution tests to identify DNS hijacking.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import re
import subprocess
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Optional

from gatekeep.config import DNSConfig
from gatekeep.exceptions import NetworkError
from gatekeep.logging_config import get_logger

log = get_logger(__name__)

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"

# Domains specifically targeted by FrostArmada for credential interception
_FROSTARMADA_TARGET_DOMAINS = [
    "autodiscover-s.outlook.com",
    "imap-mail.outlook.com",
    "pop-mail.outlook.com",
    "smtp-mail.outlook.com",
    "outlook.office365.com",
    "login.microsoftonline.com",
]

# Control resolver for comparative resolution checks
_CONTROL_RESOLVER = "8.8.8.8"
_CONTROL_RESOLVER_ALT = "1.1.1.1"

# Microsoft's legitimate IP ranges for email/auth services
# These are the ASNs and prefixes Microsoft uses for Outlook, Azure AD, etc.
MICROSOFT_LEGITIMATE_RANGES = [
    "13.64.0.0/11",      # Microsoft Azure
    "20.0.0.0/11",       # Microsoft Azure
    "20.33.0.0/16",      # Microsoft
    "20.40.0.0/13",      # Microsoft Azure
    "20.48.0.0/12",      # Microsoft Azure
    "20.64.0.0/10",      # Microsoft Azure
    "20.128.0.0/16",     # Microsoft Azure
    "20.150.0.0/15",     # Microsoft Azure
    "20.160.0.0/12",     # Microsoft Azure
    "20.184.0.0/13",     # Microsoft Azure
    "20.192.0.0/10",     # Microsoft Azure
    "23.0.0.0/12",       # Akamai CDN (Microsoft uses for www.microsoft.com)
    "23.32.0.0/11",      # Akamai CDN
    "23.64.0.0/14",      # Akamai CDN
    "23.192.0.0/11",     # Akamai CDN (23.192-23.223)
    "23.72.0.0/13",      # Akamai CDN (23.72-23.79)
    "2.16.0.0/13",       # Akamai CDN (Europe)
    "104.64.0.0/10",     # Akamai CDN (104.64-104.127)
    "40.64.0.0/10",      # Microsoft Azure
    "40.96.0.0/12",      # Microsoft 365
    "40.104.0.0/15",     # Microsoft 365
    "40.112.0.0/13",     # Microsoft Azure
    "40.120.0.0/14",     # Microsoft Azure
    "52.96.0.0/12",      # Microsoft 365
    "52.112.0.0/14",     # Microsoft 365
    "52.120.0.0/14",     # Microsoft 365
    "104.40.0.0/13",     # Microsoft Azure
    "104.208.0.0/13",    # Microsoft Azure
    "131.253.0.0/16",    # Microsoft
    "132.245.0.0/16",    # Microsoft
    "150.171.0.0/16",    # Microsoft
    "157.55.0.0/16",     # Microsoft
    "157.56.0.0/14",     # Microsoft
    "191.232.0.0/13",    # Microsoft Azure
    "204.79.197.0/24",   # Microsoft
]

# Microsoft domains where CDN/geo load balancing causes legitimate IP divergence
_MICROSOFT_TARGETED_DOMAINS = {
    "autodiscover-s.outlook.com",
    "imap-mail.outlook.com",
    "outlook.live.com",
    "outlook.office365.com",
    "pop-mail.outlook.com",
    "smtp-mail.outlook.com",
    "login.microsoftonline.com",
    "www.microsoft.com",
}


def _is_ip_in_known_ranges(ip: str, ranges: list[str]) -> bool:
    """Check if an IP falls within any of the given CIDR ranges."""
    try:
        addr = ipaddress.IPv4Address(ip)
        return any(addr in ipaddress.IPv4Network(r, strict=False) for r in ranges)
    except (ValueError, ipaddress.AddressValueError):
        return False


class DNSStatus(StrEnum):
    """Overall DNS health status."""

    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    HIJACKED = "hijacked"


@dataclass
class ResolutionResult:
    """Result of a comparative DNS resolution test."""

    domain: str
    resolver_ip: str
    resolved_ips: list[str] = field(default_factory=list)
    control_ips: list[str] = field(default_factory=list)
    matches: bool = True
    is_hijacked: bool = False
    hijack_type: Optional[str] = None
    details: Optional[str] = None
    error: Optional[str] = None


@dataclass
class DNSCheckResult:
    """Result of a DNS security check for a single resolver."""

    resolver_ip: str
    resolver_name: Optional[str] = None
    is_trusted: bool = False
    is_malicious: bool = False
    malicious_campaign: Optional[str] = None
    status: DNSStatus = DNSStatus.CLEAN
    details: Optional[str] = None
    resolution_results: list[ResolutionResult] = field(default_factory=list)


class DNSChecker:
    """
    Validates DNS configuration against trusted resolvers and known
    APT28 FrostArmada infrastructure.

    Performs comparative resolution checks to detect DNS hijacking
    targeting Microsoft authentication endpoints.
    """

    def __init__(self, config: DNSConfig) -> None:
        self._config = config
        self._trusted_data = self._load_trusted_resolvers()
        self._trusted_ips = self._build_trusted_ip_set()
        self._malicious_ranges = self._build_malicious_ranges()
        self._malicious_specific = self._build_malicious_specific_ips()
        self._isp_ranges = self._build_isp_ranges()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def check_system_dns(self) -> list[DNSCheckResult]:
        """
        Inspect the system's configured DNS servers.

        Retrieves DNS servers from the OS, checks each against the
        trusted resolver list and known-malicious ranges, and returns
        a status verdict per resolver.
        """
        system_dns = await self._get_system_dns_servers()
        if not system_dns:
            log.warning("no_system_dns_found")
            return [
                DNSCheckResult(
                    resolver_ip="(none)",
                    status=DNSStatus.SUSPICIOUS,
                    details="Could not detect any configured DNS servers on this system.",
                )
            ]

        log.info("system_dns_detected", servers=system_dns)
        results: list[DNSCheckResult] = []

        for dns_ip in system_dns:
            result = self._evaluate_resolver(dns_ip)
            results.append(result)

        return results

    async def check_dns_resolution(
        self,
        resolver_ip: str,
        domain: str,
    ) -> ResolutionResult:
        """
        Resolve a domain via the specified resolver and compare to a
        control resolver (Google DNS 8.8.8.8).

        If results differ significantly, flag as potential hijacking.
        """
        resolved_ips, resolve_err = await self._resolve_domain(resolver_ip, domain)
        control_ips, control_err = await self._resolve_domain(_CONTROL_RESOLVER, domain)

        # Fallback control resolver if primary fails
        if control_err and not control_ips:
            control_ips, control_err = await self._resolve_domain(
                _CONTROL_RESOLVER_ALT, domain
            )

        result = ResolutionResult(
            domain=domain,
            resolver_ip=resolver_ip,
            resolved_ips=resolved_ips,
            control_ips=control_ips,
        )

        if resolve_err:
            result.error = resolve_err
            result.details = f"Resolution via {resolver_ip} failed: {resolve_err}"
            return result

        if not resolved_ips:
            result.matches = False
            result.details = f"No IPs returned by {resolver_ip} for {domain}"
            return result

        # Compare resolved IPs against control
        if control_ips:
            resolved_set = set(resolved_ips)
            control_set = set(control_ips)
            overlap = resolved_set & control_set

            if not overlap:
                # No IP overlap — apply domain-specific logic before flagging
                if domain.lower() in _MICROSOFT_TARGETED_DOMAINS:
                    # For Microsoft domains: hijacked only if resolved IPs are
                    # NOT in known Microsoft-owned ranges. Divergence alone is
                    # expected due to CDN/geo load balancing.
                    all_legit = all(
                        _is_ip_in_known_ranges(ip, MICROSOFT_LEGITIMATE_RANGES)
                        for ip in resolved_ips
                    )
                    if all_legit:
                        # IPs differ from control but are all legitimate Microsoft
                        result.matches = False
                        result.is_hijacked = False
                        result.details = (
                            "IPs differ from control resolver (CDN/geo load "
                            "balancing) but all resolve to legitimate Microsoft "
                            "infrastructure"
                        )
                        log.info(
                            "dns_microsoft_cdn_variation",
                            domain=domain,
                            resolver=resolver_ip,
                            resolved=resolved_ips,
                            control=control_ips,
                        )
                    else:
                        # Some IPs are NOT in Microsoft ranges — suspicious
                        non_ms_ips = [
                            ip for ip in resolved_ips
                            if not _is_ip_in_known_ranges(ip, MICROSOFT_LEGITIMATE_RANGES)
                        ]
                        result.matches = False
                        result.is_hijacked = True
                        result.hijack_type = "frostarmada_credential_intercept"
                        result.details = (
                            f"CRITICAL: IPs {non_ms_ips} do NOT belong to "
                            f"Microsoft — possible DNS hijacking "
                            f"(FrostArmada indicator)"
                        )
                        log.critical(
                            "dns_hijack_detected",
                            domain=domain,
                            resolver=resolver_ip,
                            resolved=resolved_ips,
                            control=control_ips,
                            non_microsoft_ips=non_ms_ips,
                            hijack_type=result.hijack_type,
                        )
                else:
                    # Non-Microsoft domain: no overlap is suspicious, but check
                    # whether both sets belong to the same major CDN provider
                    # (e.g. two different Akamai IPs for google.com is not
                    # hijacking).  We use a simple heuristic: flag as hijacked
                    # only when the control IPs resolve but the user-resolver
                    # IPs are in an entirely different /8 block than every
                    # control IP, which strongly suggests redirection.
                    control_slash8s = {ip.split(".")[0] for ip in control_ips}
                    resolved_slash8s = {ip.split(".")[0] for ip in resolved_ips}
                    slash8_overlap = control_slash8s & resolved_slash8s

                    is_target = domain.lower() in [
                        d.lower() for d in _FROSTARMADA_TARGET_DOMAINS
                    ]

                    if slash8_overlap:
                        # Same /8 — likely CDN variation within the same provider
                        result.matches = False
                        result.is_hijacked = False
                        result.details = (
                            f"DNS resolution for {domain} returned different IPs "
                            f"than control resolver but within the same network "
                            f"block — likely CDN/geo variation, not hijacking"
                        )
                        log.info(
                            "dns_cdn_variation",
                            domain=domain,
                            resolver=resolver_ip,
                            resolved=resolved_ips,
                            control=control_ips,
                        )
                    else:
                        result.matches = False
                        result.is_hijacked = True
                        result.hijack_type = (
                            "frostarmada_credential_intercept"
                            if is_target
                            else "dns_redirect"
                        )
                        result.details = (
                            f"DNS resolution for {domain} via {resolver_ip} "
                            f"returned {resolved_ips} which does not overlap "
                            f"with control resolver results {control_ips}. "
                        )
                        if is_target:
                            result.details += (
                                "This domain is a known FrostArmada/APT28 target "
                                "for credential interception via DNS hijacking."
                            )
                        log.critical(
                            "dns_hijack_detected",
                            domain=domain,
                            resolver=resolver_ip,
                            resolved=resolved_ips,
                            control=control_ips,
                            hijack_type=result.hijack_type,
                        )
            else:
                result.matches = True
                result.details = f"Resolution consistent with control ({len(overlap)} overlapping IPs)"
        else:
            result.details = "Control resolver also failed; comparison inconclusive"

        return result

    async def full_check(self) -> list[DNSCheckResult]:
        """
        Run a comprehensive DNS security check.

        Performs:
        1. System DNS server evaluation against trusted/malicious lists
        2. Resolution checks for all configured test domains
        3. Resolution checks for FrostArmada-targeted Microsoft domains

        Returns a list of :class:`DNSCheckResult` with all findings.
        """
        log.info("dns_full_check_start")

        # Step 1 — evaluate system resolvers
        system_results = await self.check_system_dns()

        # Collect resolver IPs that were actually found
        resolver_ips = [
            r.resolver_ip for r in system_results if r.resolver_ip != "(none)"
        ]

        if not resolver_ips:
            log.warning("dns_full_check_no_resolvers")
            return system_results

        # Step 2 — build the set of domains to check
        check_domains = list(self._config.test_domains)
        for target in _FROSTARMADA_TARGET_DOMAINS:
            if target not in check_domains:
                check_domains.append(target)

        # Step 3 — run resolution checks concurrently
        tasks: list[asyncio.Task] = []
        for resolver_ip in resolver_ips:
            for domain in check_domains:
                tasks.append(
                    asyncio.create_task(
                        self.check_dns_resolution(resolver_ip, domain)
                    )
                )

        resolution_results: list[ResolutionResult] = []
        if tasks:
            completed = await asyncio.gather(*tasks, return_exceptions=True)
            for item in completed:
                if isinstance(item, ResolutionResult):
                    resolution_results.append(item)
                elif isinstance(item, Exception):
                    log.warning("dns_resolution_task_error", error=str(item))

        # Attach resolution results to the matching system-result entry
        for sys_result in system_results:
            sys_result.resolution_results = [
                rr for rr in resolution_results
                if rr.resolver_ip == sys_result.resolver_ip
            ]
            # Escalate status if any resolution was hijacked
            if any(rr.is_hijacked for rr in sys_result.resolution_results):
                sys_result.status = DNSStatus.HIJACKED
                sys_result.details = (
                    (sys_result.details or "")
                    + " DNS resolution hijacking detected for one or more domains."
                ).strip()

        log.info(
            "dns_full_check_complete",
            resolver_count=len(resolver_ips),
            domain_count=len(check_domains),
            hijacked_count=sum(
                1 for rr in resolution_results if rr.is_hijacked
            ),
        )

        return system_results

    # ------------------------------------------------------------------
    # Resolver evaluation
    # ------------------------------------------------------------------

    def _evaluate_resolver(self, ip: str) -> DNSCheckResult:
        """
        Classify a DNS resolver IP as trusted, malicious, ISP, or unknown.
        """
        result = DNSCheckResult(resolver_ip=ip)

        # Check against known malicious IPs/ranges first (highest priority)
        mal_campaign = self._check_malicious(ip)
        if mal_campaign:
            result.is_malicious = True
            result.malicious_campaign = mal_campaign
            result.status = DNSStatus.HIJACKED
            result.details = (
                f"DNS server {ip} matches known APT28 malicious infrastructure "
                f"(campaign: {mal_campaign}). This is a CRITICAL indicator of compromise."
            )
            log.critical(
                "malicious_dns_detected",
                ip=ip,
                campaign=mal_campaign,
            )
            return result

        # Check trusted public resolvers
        trusted_name = self._trusted_ips.get(ip)
        if trusted_name:
            result.is_trusted = True
            result.resolver_name = trusted_name
            result.status = DNSStatus.CLEAN
            result.details = f"Trusted public resolver: {trusted_name}"
            return result

        # Check ISP ranges
        isp_name = self._check_isp(ip)
        if isp_name:
            result.is_trusted = True
            result.resolver_name = isp_name
            result.status = DNSStatus.CLEAN
            result.details = f"Known ISP DNS: {isp_name}"
            return result

        # Unknown resolver — not in any recognized list
        result.status = DNSStatus.SUSPICIOUS
        result.details = (
            f"DNS server {ip} is not recognized as a trusted public resolver "
            f"or known ISP DNS. This may be a corporate/internal DNS or could "
            f"indicate tampering. Manual verification recommended."
        )
        log.warning("unknown_dns_resolver", ip=ip)
        return result

    def _check_malicious(self, ip: str) -> Optional[str]:
        """Return campaign name if IP falls within known-malicious ranges."""
        try:
            addr = ipaddress.IPv4Address(ip)
        except (ipaddress.AddressValueError, ValueError):
            return None

        # Check specific IPs first
        if ip in self._malicious_specific:
            return self._malicious_specific[ip]

        # Check CIDR ranges
        for network, campaign in self._malicious_ranges:
            if addr in network:
                return campaign

        return None

    def _check_isp(self, ip: str) -> Optional[str]:
        """Return ISP name if IP falls within known ISP DNS ranges."""
        try:
            addr = ipaddress.IPv4Address(ip)
        except (ipaddress.AddressValueError, ValueError):
            return None

        for network, provider in self._isp_ranges:
            if addr in network:
                return provider

        return None

    # ------------------------------------------------------------------
    # DNS resolution
    # ------------------------------------------------------------------

    async def _resolve_domain(
        self, resolver_ip: str, domain: str, timeout: float = 5.0
    ) -> tuple[list[str], Optional[str]]:
        """
        Resolve *domain* via *resolver_ip* using dnspython.

        Returns ``(list_of_ips, error_string_or_None)``.
        """
        try:
            ips = await asyncio.to_thread(
                self._sync_resolve, resolver_ip, domain, timeout
            )
            return ips, None
        except Exception as exc:
            return [], str(exc)

    @staticmethod
    def _sync_resolve(
        resolver_ip: str, domain: str, timeout: float
    ) -> list[str]:
        """Synchronous DNS resolution with dnspython."""
        import dns.resolver  # type: ignore[import-untyped]

        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [resolver_ip]
        resolver.lifetime = timeout
        resolver.timeout = timeout

        try:
            answers = resolver.resolve(domain, "A")
            return sorted(str(rdata) for rdata in answers)
        except dns.resolver.NXDOMAIN:
            return []
        except dns.resolver.NoAnswer:
            return []
        except dns.resolver.NoNameservers:
            raise RuntimeError(
                f"No response from resolver {resolver_ip} for {domain}"
            )
        except dns.exception.Timeout:
            raise RuntimeError(
                f"Timeout resolving {domain} via {resolver_ip}"
            )

    # ------------------------------------------------------------------
    # System DNS detection
    # ------------------------------------------------------------------

    async def _get_system_dns_servers(self) -> list[str]:
        """
        Retrieve the system's configured DNS servers.

        On Windows, parses ``ipconfig /all`` output. Falls back to
        reading the registry if ipconfig is unavailable.
        """
        try:
            return await asyncio.to_thread(self._parse_ipconfig_dns)
        except Exception as exc:
            log.warning("ipconfig_dns_detection_failed", error=str(exc))
            try:
                return await asyncio.to_thread(self._read_registry_dns)
            except Exception as exc2:
                log.warning("registry_dns_detection_failed", error=str(exc2))
                return []

    @staticmethod
    def _parse_ipconfig_dns() -> list[str]:
        """Parse DNS servers from ``ipconfig /all`` output."""
        result = subprocess.run(
            ["ipconfig", "/all"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        output = result.stdout

        dns_servers: list[str] = []
        in_dns_section = False
        ip_pattern = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")

        for line in output.splitlines():
            stripped = line.strip()
            if "DNS Servers" in line or "DNS-Server" in line:
                in_dns_section = True
                match = ip_pattern.search(stripped)
                if match:
                    dns_servers.append(match.group(1))
            elif in_dns_section:
                # Continuation lines are indented and contain only an IP
                match = ip_pattern.match(stripped)
                if match and not any(
                    kw in line
                    for kw in (":", "Subnet", "Gateway", "DHCP", "Lease", "Adapter")
                ):
                    dns_servers.append(match.group(1))
                else:
                    in_dns_section = False

        # Deduplicate while preserving order
        seen: set[str] = set()
        unique: list[str] = []
        for ip in dns_servers:
            if ip not in seen:
                seen.add(ip)
                unique.append(ip)
        return unique

    @staticmethod
    def _read_registry_dns() -> list[str]:
        """
        Read DNS servers from the Windows registry.

        Enumerates network adapter interface GUIDs under
        ``HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces``
        and reads the ``NameServer`` and ``DhcpNameServer`` values.
        """
        import winreg  # type: ignore[import-error]

        base_key = (
            r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
        )
        dns_servers: list[str] = []
        ip_pattern = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")

        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base_key) as interfaces:
                idx = 0
                while True:
                    try:
                        guid = winreg.EnumKey(interfaces, idx)
                        idx += 1
                    except OSError:
                        break

                    try:
                        with winreg.OpenKey(interfaces, guid) as iface_key:
                            for value_name in ("NameServer", "DhcpNameServer"):
                                try:
                                    val, _ = winreg.QueryValueEx(
                                        iface_key, value_name
                                    )
                                    if val:
                                        for ip in ip_pattern.findall(str(val)):
                                            dns_servers.append(ip)
                                except OSError:
                                    pass
                    except OSError:
                        pass
        except OSError as exc:
            raise RuntimeError(f"Cannot read DNS from registry: {exc}")

        # Deduplicate
        seen: set[str] = set()
        unique: list[str] = []
        for ip in dns_servers:
            if ip not in seen:
                seen.add(ip)
                unique.append(ip)
        return unique

    # ------------------------------------------------------------------
    # Data loading
    # ------------------------------------------------------------------

    @staticmethod
    def _load_trusted_resolvers() -> dict:
        """Load the trusted-resolvers JSON database."""
        path = _DATA_DIR / "dns_trusted_resolvers.json"
        try:
            with open(path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except (FileNotFoundError, json.JSONDecodeError) as exc:
            log.warning("trusted_resolvers_load_failed", path=str(path), error=str(exc))
            return {}

    def _build_trusted_ip_set(self) -> dict[str, str]:
        """
        Build a mapping of ``{ip: resolver_name}`` from the trusted
        resolver data.
        """
        mapping: dict[str, str] = {}
        for entry in self._trusted_data.get("resolvers", []):
            name = entry.get("name", "Unknown")
            for ip in entry.get("ips", []):
                mapping[ip] = name
        return mapping

    def _build_malicious_ranges(
        self,
    ) -> list[tuple[ipaddress.IPv4Network, str]]:
        """Parse malicious CIDR ranges from the trusted-resolvers data."""
        ranges: list[tuple[ipaddress.IPv4Network, str]] = []
        mal = self._trusted_data.get("known_malicious_dns", {})

        for campaign_key in ("apt28_frostarmada", "apt28_dying_ember"):
            cidrs = mal.get(campaign_key, [])
            campaign_label = campaign_key.replace("_", " ").title()
            for cidr in cidrs:
                try:
                    net = ipaddress.IPv4Network(cidr, strict=False)
                    ranges.append((net, campaign_label))
                except (ipaddress.AddressValueError, ValueError):
                    log.warning("invalid_malicious_cidr", cidr=cidr)

        return ranges

    def _build_malicious_specific_ips(self) -> dict[str, str]:
        """
        Build a dict of ``{ip: campaign}`` from the specific-IP entries
        in the malicious DNS data.
        """
        mapping: dict[str, str] = {}
        mal = self._trusted_data.get("known_malicious_dns", {})
        for entry in mal.get("specific_ips", []):
            ip = entry.get("ip")
            campaign = entry.get("campaign", "Unknown")
            if ip:
                mapping[ip] = campaign
        return mapping

    def _build_isp_ranges(
        self,
    ) -> list[tuple[ipaddress.IPv4Network, str]]:
        """Parse known ISP DNS ranges from the trusted-resolvers data."""
        ranges: list[tuple[ipaddress.IPv4Network, str]] = []
        isp_data = self._trusted_data.get("isp_common_dns", {})
        for entry in isp_data.get("ranges", []):
            cidr = entry.get("cidr")
            provider = entry.get("provider", "Unknown ISP")
            if cidr:
                try:
                    net = ipaddress.IPv4Network(cidr, strict=False)
                    ranges.append((net, provider))
                except (ipaddress.AddressValueError, ValueError):
                    log.warning("invalid_isp_cidr", cidr=cidr)
        return ranges
