"""
Firewall rule generation engine for GATEKEEP.

Produces firewall rules in multiple formats (iptables, Windows Firewall,
generic) from live network state data. Uses the AI analyzer for context-
aware rule generation and falls back to a comprehensive static rule set
when AI is unavailable.
"""

from __future__ import annotations

import json
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gatekeep.engines.ai_analyzer import AIAnalyzer, HardeningResult
from gatekeep.logging_config import get_logger
from gatekeep.models import (
    Device,
    DeviceScan,
    DNSCheck,
    HardeningRecommendation as HardeningRecommendationModel,
    PortResult,
    PortState,
    RouterFingerprint,
    Scan,
    ScanStatus,
)

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# APT28 / Operation Masquerade threat intelligence
# ---------------------------------------------------------------------------

_APT28_PORTS: list[int] = [56777, 35681]

_APT28_IP_RANGES: list[str] = [
    "5.226.137.0/24",
    "37.221.64.0/24",
    "77.83.197.0/24",
    "79.141.161.0/24",
    "185.237.166.0/24",
    "185.220.101.0/24",
    "193.218.145.0/24",
    "194.165.16.0/24",
    "45.142.212.0/24",
    "91.108.4.0/22",
]

_TRUSTED_DNS_RESOLVERS: list[str] = [
    "8.8.8.8",
    "8.8.4.4",
    "1.1.1.1",
    "1.0.0.1",
    "9.9.9.9",
]


class FirewallGenerator:
    """
    Generates firewall rules tailored to the current network state.

    Supports three output formats:
    - ``iptables``       — Linux iptables commands
    - ``windows_firewall`` — Windows netsh advfirewall commands
    - ``generic``        — Human-readable rule descriptions

    AI-assisted generation is attempted first; static/template rules are
    always included as the foundation (and full fallback).
    """

    def __init__(self, ai_analyzer: AIAnalyzer) -> None:
        self._ai = ai_analyzer

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def generate_rules(
        self,
        db: AsyncSession,
        scan_id: Optional[str] = None,
        device_id: Optional[str] = None,
        fmt: str = "generic",
    ) -> HardeningResult:
        """
        Build firewall rules for the current network state.

        Queries the database for the latest scan results, discovered
        devices, open ports, DNS checks, and router info, then asks the
        AI analyzer for context-aware additions. Static rules are always
        generated as a baseline.

        Args:
            db:        Async database session.
            scan_id:   Restrict context to a specific scan (optional).
            device_id: Restrict rules to a specific device (optional).
            fmt:       Output format — ``iptables``, ``windows_firewall``,
                       or ``generic``.

        Returns:
            HardeningResult containing merged rules and a plain-language
            explanation.
        """
        logger.info(
            "firewall_generator.generate_rules",
            scan_id=scan_id,
            device_id=device_id,
            format=fmt,
        )

        # 1. Gather network state from the database
        network_state = await self._gather_network_state(db, scan_id, device_id)

        # 2. Generate static rules (always available, no AI needed)
        static_rules = self._generate_static_rules(network_state, fmt)

        # 3. Attempt AI-assisted generation
        ai_result = await self._ai.generate_hardening_advice(network_state, fmt)

        # 4. Merge: AI rules first (if any), then any static rules not already
        #    covered. Use the AI explanation when available.
        merged_rules = self._merge_rules(ai_result.rules, static_rules)

        explanation = ai_result.explanation
        if not explanation or explanation.startswith("AI hardening advice unavailable"):
            explanation = self._build_static_explanation(network_state, fmt)

        logger.info(
            "firewall_generator.rules_generated",
            total_rules=len(merged_rules),
            ai_rules=len(ai_result.rules),
            static_rules=len(static_rules),
            format=fmt,
        )

        return HardeningResult(
            rules=merged_rules,
            explanation=explanation,
            format=fmt,
            model_used=ai_result.model_used,
        )

    # ------------------------------------------------------------------
    # Database helpers
    # ------------------------------------------------------------------

    async def _gather_network_state(
        self,
        db: AsyncSession,
        scan_id: Optional[str],
        device_id: Optional[str],
    ) -> dict[str, Any]:
        """Query the database and build a network-state snapshot dict."""

        # Resolve the target scan
        resolved_scan_id = scan_id
        if resolved_scan_id is None:
            result = await db.execute(
                select(Scan)
                .where(Scan.status == ScanStatus.COMPLETED)
                .order_by(Scan.completed_at.desc())
                .limit(1)
            )
            latest_scan: Optional[Scan] = result.scalar_one_or_none()
            resolved_scan_id = latest_scan.id if latest_scan else None

        # Devices (optionally filtered)
        device_query = select(Device)
        if device_id:
            device_query = device_query.where(Device.id == device_id)
        devices_result = await db.execute(device_query)
        devices = devices_result.scalars().all()

        # Open ports per device (within the target scan scope)
        open_ports_map: dict[str, list[dict[str, Any]]] = {}
        if resolved_scan_id:
            ds_result = await db.execute(
                select(DeviceScan).where(DeviceScan.scan_id == resolved_scan_id)
            )
            device_scans = ds_result.scalars().all()
            for ds in device_scans:
                if device_id and ds.device_id != device_id:
                    continue
                pr_result = await db.execute(
                    select(PortResult).where(
                        PortResult.device_scan_id == ds.id,
                        PortResult.state == PortState.OPEN,
                    )
                )
                ports = pr_result.scalars().all()
                if ports:
                    open_ports_map[ds.device_id] = [
                        {
                            "port": p.port,
                            "protocol": p.protocol,
                            "service_name": p.service_name,
                            "is_suspicious": p.is_suspicious,
                            "banner": p.banner,
                        }
                        for p in ports
                    ]

        # DNS checks
        dns_findings: list[dict[str, Any]] = []
        if resolved_scan_id:
            dns_result = await db.execute(
                select(DNSCheck).where(DNSCheck.scan_id == resolved_scan_id)
            )
            for chk in dns_result.scalars().all():
                dns_findings.append(
                    {
                        "resolver_ip": chk.resolver_ip,
                        "query_domain": chk.query_domain,
                        "is_hijacked": chk.is_hijacked,
                        "hijack_type": chk.hijack_type,
                        "actual_ips": json.loads(chk.actual_ips) if chk.actual_ips else [],
                    }
                )

        # Router fingerprint
        router_info: Optional[dict[str, Any]] = None
        if resolved_scan_id:
            rf_result = await db.execute(
                select(RouterFingerprint)
                .where(RouterFingerprint.scan_id == resolved_scan_id)
                .limit(1)
            )
            rf = rf_result.scalar_one_or_none()
            if rf:
                router_info = {
                    "manufacturer": rf.manufacturer,
                    "model": rf.model,
                    "firmware_version": rf.firmware_version,
                    "is_vulnerable": rf.is_vulnerable,
                    "admin_panel_url": rf.admin_panel_url,
                }

        # Serialize devices
        devices_out: list[dict[str, Any]] = []
        for dev in devices:
            d: dict[str, Any] = {
                "id": dev.id,
                "ip_address": dev.ip_address,
                "mac_address": dev.mac_address,
                "hostname": dev.hostname,
                "vendor": dev.vendor,
                "device_type": dev.device_type,
                "is_gateway": dev.is_gateway,
            }
            if dev.id in open_ports_map:
                d["open_ports"] = open_ports_map[dev.id]
            devices_out.append(d)

        # Find the gateway
        gateway_ip: Optional[str] = None
        for dev in devices:
            if dev.is_gateway:
                gateway_ip = dev.ip_address
                break

        # Detect any open APT28 indicator ports
        suspicious_ports: list[dict[str, Any]] = []
        for dev_id, ports in open_ports_map.items():
            for p in ports:
                if p["port"] in _APT28_PORTS or p.get("is_suspicious"):
                    suspicious_ports.append({"device_id": dev_id, **p})

        hijacked_dns = [c for c in dns_findings if c["is_hijacked"]]

        return {
            "scan_id": resolved_scan_id,
            "device_id_filter": device_id,
            "devices": devices_out,
            "open_ports_map": open_ports_map,
            "dns_findings": dns_findings,
            "hijacked_dns": hijacked_dns,
            "router": router_info,
            "gateway_ip": gateway_ip,
            "suspicious_ports": suspicious_ports,
            "apt28_ports": _APT28_PORTS,
            "apt28_ip_ranges": _APT28_IP_RANGES,
            "trusted_dns_resolvers": _TRUSTED_DNS_RESOLVERS,
        }

    # ------------------------------------------------------------------
    # Static rule generation (format dispatch)
    # ------------------------------------------------------------------

    def _generate_static_rules(
        self, findings: dict[str, Any], fmt: str
    ) -> list[dict[str, Any]]:
        """Dispatch static rule generation to the appropriate formatter."""
        if fmt == "iptables":
            return self._generate_iptables_rules(findings)
        if fmt == "windows_firewall":
            return self._generate_windows_firewall_rules(findings)
        return self._generate_generic_rules(findings)

    # ------------------------------------------------------------------
    # iptables
    # ------------------------------------------------------------------

    def _generate_iptables_rules(self, findings: dict[str, Any]) -> list[dict[str, Any]]:
        """
        Generate Linux iptables command strings.

        Returns a list of dicts with keys:
          ``id``, ``rule``, ``description``, ``category``, ``command``,
          ``rationale``.
        """
        rules: list[dict[str, Any]] = []
        rule_id = 1

        def _add(rule_str: str, description: str, category: str, rationale: str = "") -> None:
            nonlocal rule_id
            rules.append(
                {
                    "id": f"iptables-{rule_id:03d}",
                    "command": rule_str,
                    "rule": rule_str,
                    "description": description,
                    "category": category,
                    "rationale": rationale or description,
                }
            )
            rule_id += 1

        # --- APT28 SSH tunnel ports -----------------------------------------
        for port in _APT28_PORTS:
            _add(
                f"iptables -A INPUT -p tcp --dport {port} -j DROP",
                f"Block APT28 SSH tunnel port {port} inbound",
                "apt28_port",
                f"Port {port} is used by APT28/Forest Blizzard as a covert SSH tunnel. "
                "Drop all unsolicited inbound connections.",
            )
            _add(
                f"iptables -A OUTPUT -p tcp --dport {port} -j DROP",
                f"Block APT28 SSH tunnel port {port} outbound",
                "apt28_port",
                f"Prevent this host from initiating connections to APT28 C2 on port {port}.",
            )

        # --- Known malicious APT28 IP ranges -----------------------------------
        for cidr in _APT28_IP_RANGES:
            _add(
                f"iptables -A INPUT -s {cidr} -j DROP",
                f"Block known APT28 IP range {cidr} inbound",
                "malicious_ip",
                f"IP range {cidr} is associated with APT28 / Operation Masquerade "
                "infrastructure. Drop all inbound traffic.",
            )
            _add(
                f"iptables -A OUTPUT -d {cidr} -j DROP",
                f"Block known APT28 IP range {cidr} outbound",
                "malicious_ip",
                f"Prevent outbound exfiltration or C2 contact to APT28 range {cidr}.",
            )

        # --- Restrict DNS to trusted resolvers ---------------------------------
        for resolver in _TRUSTED_DNS_RESOLVERS:
            _add(
                f"iptables -A OUTPUT -p udp --dport 53 -d {resolver} -j ACCEPT",
                f"Allow DNS over UDP to trusted resolver {resolver}",
                "dns_restriction",
                f"Permit outbound DNS queries to the trusted resolver {resolver}.",
            )
            _add(
                f"iptables -A OUTPUT -p tcp --dport 53 -d {resolver} -j ACCEPT",
                f"Allow DNS over TCP to trusted resolver {resolver}",
                "dns_restriction",
                f"Permit outbound DNS-over-TCP to the trusted resolver {resolver}.",
            )
        _add(
            "iptables -A OUTPUT -p udp --dport 53 -j DROP",
            "Block DNS over UDP to any other resolver",
            "dns_restriction",
            "Drop DNS UDP queries that are not directed to an approved resolver, "
            "preventing DNS hijacking or tunneling through rogue servers.",
        )
        _add(
            "iptables -A OUTPUT -p tcp --dport 53 -j DROP",
            "Block DNS over TCP to any other resolver",
            "dns_restriction",
            "Drop DNS TCP queries to unapproved resolvers.",
        )

        # --- Block WAN-side remote management ports ----------------------------
        for mgmt_port in [23, 7547, 8080, 8443, 8888, 37215, 49152]:
            _add(
                f"iptables -A INPUT -p tcp --dport {mgmt_port} -j DROP",
                f"Block WAN-side management port {mgmt_port}",
                "remote_management",
                f"Port {mgmt_port} is commonly used for router/device remote management "
                "and should not accept inbound connections from the internet.",
            )

        # --- Block open suspicious ports found during scan ----------------------
        for entry in findings.get("suspicious_ports", []):
            port = entry.get("port")
            if port and port not in _APT28_PORTS:
                _add(
                    f"iptables -A INPUT -p tcp --dport {port} -j DROP",
                    f"Block suspicious open port {port} found in scan",
                    "suspicious_port",
                    f"Port {port} was flagged as suspicious during the network scan.",
                )

        # --- Hijacked DNS remediation ------------------------------------------
        for chk in findings.get("hijacked_dns", []):
            resolver = chk.get("resolver_ip")
            if resolver and resolver not in _TRUSTED_DNS_RESOLVERS:
                _add(
                    f"iptables -A OUTPUT -d {resolver} -j DROP",
                    f"Block rogue DNS resolver {resolver}",
                    "dns_hijack",
                    f"DNS resolver {resolver} was detected as serving hijacked responses. "
                    "Block all outbound traffic to this IP.",
                )

        # --- Default input policy (append last) --------------------------------
        _add(
            "iptables -P INPUT DROP",
            "Set default INPUT policy to DROP (deny-all)",
            "default_policy",
            "Adopt a default-deny posture for all inbound traffic not explicitly allowed.",
        )
        _add(
            "iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
            "Allow established/related inbound connections",
            "default_policy",
            "Permit return traffic for connections initiated by this host.",
        )
        _add(
            "iptables -A INPUT -i lo -j ACCEPT",
            "Allow loopback traffic",
            "default_policy",
            "Loopback interface traffic must always be permitted.",
        )

        return rules

    # ------------------------------------------------------------------
    # Windows Firewall
    # ------------------------------------------------------------------

    def _generate_windows_firewall_rules(
        self, findings: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """
        Generate Windows ``netsh advfirewall`` command strings.

        Returns a list of dicts with keys:
          ``id``, ``command``, ``rule``, ``description``, ``category``,
          ``rationale``.
        """
        rules: list[dict[str, Any]] = []
        rule_id = 1

        def _add(cmd: str, description: str, category: str, rationale: str = "") -> None:
            nonlocal rule_id
            rules.append(
                {
                    "id": f"winfw-{rule_id:03d}",
                    "command": cmd,
                    "rule": cmd,
                    "description": description,
                    "category": category,
                    "rationale": rationale or description,
                }
            )
            rule_id += 1

        # --- APT28 SSH tunnel ports --------------------------------------------
        for port in _APT28_PORTS:
            _add(
                f'netsh advfirewall firewall add rule name="Block APT28 Port {port} In" '
                f"dir=in action=block protocol=tcp localport={port}",
                f"Block APT28 SSH tunnel port {port} inbound",
                "apt28_port",
                f"APT28/Forest Blizzard uses port {port} for covert SSH tunnels.",
            )
            _add(
                f'netsh advfirewall firewall add rule name="Block APT28 Port {port} Out" '
                f"dir=out action=block protocol=tcp remoteport={port}",
                f"Block APT28 SSH tunnel port {port} outbound",
                "apt28_port",
                f"Prevent outbound connections to APT28 C2 on port {port}.",
            )

        # --- Known malicious APT28 IP ranges -----------------------------------
        # Windows Firewall uses RemoteAddress for IP-based rules
        for cidr in _APT28_IP_RANGES:
            _add(
                f'netsh advfirewall firewall add rule name="Block APT28 Range {cidr} In" '
                f"dir=in action=block remoteip={cidr}",
                f"Block known APT28 IP range {cidr} inbound",
                "malicious_ip",
                f"IP range {cidr} is associated with APT28 C2 infrastructure.",
            )
            _add(
                f'netsh advfirewall firewall add rule name="Block APT28 Range {cidr} Out" '
                f"dir=out action=block remoteip={cidr}",
                f"Block known APT28 IP range {cidr} outbound",
                "malicious_ip",
                f"Prevent data exfiltration to APT28 range {cidr}.",
            )

        # --- Restrict DNS - block all non-trusted resolvers --------------------
        trusted_joined = ",".join(_TRUSTED_DNS_RESOLVERS)
        _add(
            f'netsh advfirewall firewall add rule name="Allow DNS to Trusted Resolvers" '
            f"dir=out action=allow protocol=udp remoteport=53 remoteip={trusted_joined}",
            "Allow DNS UDP to trusted resolvers only",
            "dns_restriction",
            "Permit outbound DNS queries only to approved resolvers.",
        )
        _add(
            f'netsh advfirewall firewall add rule name="Allow DNS TCP to Trusted Resolvers" '
            f"dir=out action=allow protocol=tcp remoteport=53 remoteip={trusted_joined}",
            "Allow DNS TCP to trusted resolvers only",
            "dns_restriction",
            "Permit outbound DNS-over-TCP only to approved resolvers.",
        )
        _add(
            'netsh advfirewall firewall add rule name="Block Untrusted DNS UDP" '
            "dir=out action=block protocol=udp remoteport=53",
            "Block DNS UDP to any resolver not in the allowlist",
            "dns_restriction",
            "Deny DNS queries to unapproved resolvers that may be rogue servers.",
        )
        _add(
            'netsh advfirewall firewall add rule name="Block Untrusted DNS TCP" '
            "dir=out action=block protocol=tcp remoteport=53",
            "Block DNS TCP to any resolver not in the allowlist",
            "dns_restriction",
            "Deny DNS-over-TCP to unapproved resolvers.",
        )

        # --- Block WAN-side remote management ----------------------------------
        for mgmt_port in [23, 7547, 8080, 8443, 8888, 37215, 49152]:
            _add(
                f'netsh advfirewall firewall add rule name="Block Mgmt Port {mgmt_port}" '
                f"dir=in action=block protocol=tcp localport={mgmt_port}",
                f"Block WAN-side management port {mgmt_port} inbound",
                "remote_management",
                f"Port {mgmt_port} is a common remote management vector.",
            )

        # --- Suspicious ports from scan ----------------------------------------
        for entry in findings.get("suspicious_ports", []):
            port = entry.get("port")
            if port and port not in _APT28_PORTS:
                _add(
                    f'netsh advfirewall firewall add rule name="Block Suspicious Port {port}" '
                    f"dir=in action=block protocol=tcp localport={port}",
                    f"Block suspicious open port {port} found during scan",
                    "suspicious_port",
                    f"Port {port} was flagged as suspicious during the network scan.",
                )

        # --- Rogue DNS resolvers -----------------------------------------------
        for chk in findings.get("hijacked_dns", []):
            resolver = chk.get("resolver_ip")
            if resolver and resolver not in _TRUSTED_DNS_RESOLVERS:
                _add(
                    f'netsh advfirewall firewall add rule name="Block Rogue DNS {resolver}" '
                    f"dir=out action=block remoteip={resolver}",
                    f"Block outbound traffic to rogue DNS resolver {resolver}",
                    "dns_hijack",
                    f"Resolver {resolver} was detected serving hijacked DNS responses.",
                )

        return rules

    # ------------------------------------------------------------------
    # Generic (human-readable)
    # ------------------------------------------------------------------

    def _generate_generic_rules(self, findings: dict[str, Any]) -> list[dict[str, Any]]:
        """
        Generate human-readable rule descriptions without platform-specific
        syntax. Useful as a vendor-neutral guide.
        """
        rules: list[dict[str, Any]] = []
        rule_id = 1

        def _add(description: str, category: str, details: str, priority: str = "high") -> None:
            nonlocal rule_id
            rules.append(
                {
                    "id": f"rule-{rule_id:03d}",
                    "command": description,
                    "rule": description,
                    "description": description,
                    "category": category,
                    "rationale": details,
                    "priority": priority,
                }
            )
            rule_id += 1

        # APT28 ports
        for port in _APT28_PORTS:
            _add(
                f"Block TCP port {port} inbound and outbound on all interfaces",
                "apt28_port",
                f"Port {port} is used by APT28 (Forest Blizzard/Fancy Bear) as a covert SSH "
                "tunnel for persistent access. No legitimate service should use this port "
                "on a home network.",
            )

        # Malicious IP ranges
        for cidr in _APT28_IP_RANGES:
            _add(
                f"Block all traffic to/from IP range {cidr}",
                "malicious_ip",
                f"The IP range {cidr} is known APT28 operational infrastructure linked to "
                "Operation Masquerade.",
                priority="critical",
            )

        # DNS restriction
        resolvers_str = ", ".join(_TRUSTED_DNS_RESOLVERS)
        _add(
            f"Restrict outbound DNS (port 53) to trusted resolvers only: {resolvers_str}",
            "dns_restriction",
            "Allowing DNS queries to arbitrary resolvers enables DNS hijacking attacks "
            "like those used in Operation Masquerade. Restrict to vetted resolvers.",
        )

        # WAN management
        _add(
            "Disable inbound access to router/device management ports "
            "(23, 7547, 8080, 8443, 37215) from the internet",
            "remote_management",
            "WAN-side access to management interfaces enables remote exploitation. "
            "Only allow management from the LAN.",
        )

        # Suspicious ports
        for entry in findings.get("suspicious_ports", []):
            port = entry.get("port")
            svc = entry.get("service_name", "unknown service")
            if port and port not in _APT28_PORTS:
                _add(
                    f"Block inbound access to port {port} ({svc}) unless required",
                    "suspicious_port",
                    f"Port {port} was flagged as suspicious during the scan. "
                    "Verify the service is intentional; block if not.",
                    priority="medium",
                )

        # Hijacked DNS
        for chk in findings.get("hijacked_dns", []):
            resolver = chk.get("resolver_ip")
            domain = chk.get("query_domain")
            if resolver and resolver not in _TRUSTED_DNS_RESOLVERS:
                _add(
                    f"Block outbound traffic to rogue DNS resolver {resolver} "
                    f"(detected hijacking {domain})",
                    "dns_hijack",
                    f"DNS resolver {resolver} was observed returning malicious responses for "
                    f"{domain}. This is a strong indicator of router compromise.",
                    priority="critical",
                )

        # Vulnerable router
        router = findings.get("router") or {}
        if router.get("is_vulnerable"):
            model = router.get("model", "your router")
            _add(
                f"Update firmware on {model} immediately and disable WAN remote management",
                "vulnerable_router",
                f"{model} has known exploitable vulnerabilities. APT28 specifically targets "
                "this model in Operation Masquerade. Update the firmware now and disable "
                "remote management from the WAN side.",
                priority="critical",
            )

        # Default-deny reminder
        _add(
            "Adopt a default-deny firewall policy: block all inbound traffic "
            "not explicitly permitted by the rules above",
            "default_policy",
            "A default-deny posture ensures that only approved traffic reaches "
            "your network devices, minimising the attack surface.",
            priority="high",
        )

        return rules

    # ------------------------------------------------------------------
    # Merge helpers
    # ------------------------------------------------------------------

    def _merge_rules(
        self,
        ai_rules: list[dict[str, Any]],
        static_rules: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """
        Combine AI-generated and static rules.

        AI rules come first. Static rules are appended, skipping any
        whose ``command`` string is already present in the AI set to
        avoid exact duplicates.
        """
        seen_commands: set[str] = set()
        merged: list[dict[str, Any]] = []

        for rule in ai_rules:
            cmd = (rule.get("command") or "").strip()
            if cmd not in seen_commands:
                seen_commands.add(cmd)
                merged.append(rule)

        for rule in static_rules:
            cmd = (rule.get("command") or "").strip()
            if cmd not in seen_commands:
                seen_commands.add(cmd)
                merged.append(rule)

        return merged

    # ------------------------------------------------------------------
    # Static explanation builder
    # ------------------------------------------------------------------

    def _build_static_explanation(
        self, network_state: dict[str, Any], fmt: str
    ) -> str:
        """Build a plain-language explanation without AI."""
        device_count = len(network_state.get("devices", []))
        suspicious_count = len(network_state.get("suspicious_ports", []))
        hijacked_count = len(network_state.get("hijacked_dns", []))
        router = network_state.get("router") or {}

        lines: list[str] = [
            f"These {fmt} firewall rules were generated based on your current network state "
            f"({device_count} device(s) detected).",
            "",
            "The rules address four key threat areas:",
            "",
            "1. APT28 indicator ports (56777, 35681) — blocked inbound and outbound. "
            "These ports are used by Russian state-sponsored hackers for persistent backdoor access.",
            "",
            "2. Known malicious IP ranges — all traffic to and from "
            f"{len(_APT28_IP_RANGES)} APT28-linked IP ranges is blocked.",
            "",
            "3. DNS protection — outbound DNS restricted to trusted resolvers "
            f"({', '.join(_TRUSTED_DNS_RESOLVERS)}), preventing DNS hijacking.",
            "",
            "4. Remote management lockdown — WAN-side management ports blocked to prevent "
            "remote exploitation.",
        ]

        if suspicious_count:
            lines.append(
                f"\nAdditionally, {suspicious_count} suspicious port(s) found during the last "
                "scan have been blocked."
            )
        if hijacked_count:
            lines.append(
                f"\nCRITICAL: {hijacked_count} DNS hijack(s) detected. Rules blocking the rogue "
                "resolver(s) have been included — change your router DNS settings immediately."
            )
        if router.get("is_vulnerable"):
            lines.append(
                f"\nCRITICAL: Router model '{router.get('model')}' has known vulnerabilities. "
                "Update its firmware immediately."
            )

        return "\n".join(lines)
