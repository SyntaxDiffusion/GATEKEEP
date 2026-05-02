"""
AI Analyzer Engine for GATEKEEP.

Uses the Claude Agent SDK to perform deep security analysis on network
scan results, traffic anomalies, and to generate network hardening advice.
Results are cached in-memory (SHA-256 keyed, 1-hour TTL) to avoid redundant
API calls.

The Agent SDK authenticates via Claude Code's existing session -- no API
key management is needed.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from gatekeep.config import AIConfig
from gatekeep.logging_config import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Cache TTL
# ---------------------------------------------------------------------------

_CACHE_TTL_SECONDS: float = 3600.0  # 1 hour

# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class AIAnalysisResult:
    """Result of an AI-powered security analysis."""

    risk_level: str          # critical, high, medium, low, info, unknown, error
    risk_score: int          # 0-100
    summary: str
    findings: list[dict[str, Any]]
    recommendations: list[dict[str, Any]]
    network_health: dict[str, Any]
    model_used: str
    tokens_used: int
    latency_ms: int
    cached: bool = False


@dataclass
class HardeningResult:
    """Result of AI-generated network hardening advice."""

    rules: list[dict[str, Any]]
    explanation: str
    format: str
    model_used: str


# ---------------------------------------------------------------------------
# System prompts
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """You are GATEKEEP AI Analyst — an elite cybersecurity analyst specializing in home network security. You perform thorough, methodical threat assessments with the depth of a professional penetration tester writing a client report.

THREAT CONTEXT (April 2026):
The FBI/NSA disclosed Operation Masquerade — Russian GRU Unit 26165 (APT28/Fancy Bear/Forest Blizzard) compromised 18,000+ home routers across 120+ countries. The attack exploits CVE-2023-50224 in TP-Link routers to hijack DNS settings, redirecting Microsoft email authentication to credential-harvesting servers via the "FrostArmada" campaign. A separate campaign (Operation Dying Ember) targeted Ubiquiti EdgeRouters using Moobot malware.

ANALYSIS FRAMEWORK — Evaluate every scan finding against these categories:

1. **DNS INTEGRITY** (FrostArmada primary vector)
   - Are DNS servers pointing to RFC1918 router IPs (normal) or external IPs?
   - Do any DNS server IPs match APT28 ranges: 5.226.137.x, 37.221.64.x, 77.83.197.x, 79.141.161.x, 185.237.166.x, 64.44.154.x, 79.141.173.x, 103.140.186.x, 185.234.73.x?
   - Did resolution tests for Microsoft domains (autodiscover-s.outlook.com, imap-mail.outlook.com, login.microsoftonline.com) return IPs in legitimate Microsoft/Akamai ranges?
   - Is there evidence of DNS-over-HTTPS bypassing router DNS?

2. **ROUTER VULNERABILITY** (Entry point for both campaigns)
   - Is the router a TP-Link model on the CVE-2023-50224 target list?
   - Is the router a Ubiquiti EdgeRouter (Operation Dying Ember target)?
   - Is the router a MikroTik model (used in Ukrainian-targeted operations)?
   - Is firmware up to date? Are default credentials likely in use?
   - Is remote management (WAN-side admin access) potentially enabled?

3. **NETWORK INDICATOR ANALYSIS** (Post-compromise indicators)
   - Are APT28 signature ports open: TCP 56777, TCP 35681 (SSH tunnels)?
   - Is the "dnsmasq-2.85" banner present on port 53 (FrostArmada IOC)?
   - Are there unexpected services on management ports (23, 135, 445, 3389)?
   - Are there devices with suspicious port profiles (multiple high ports open)?

4. **DEVICE INVENTORY ASSESSMENT**
   - How many devices are on the network? Is this count reasonable for a home?
   - Are there unknown/unidentified devices that could be rogue?
   - Are any devices showing randomized MAC addresses (potential probe/rogue device)?
   - What is the IoT device exposure (smart home devices with known vulnerabilities)?

5. **NETWORK HYGIENE**
   - Is the network segmented (separate IoT VLAN)?
   - Are unnecessary services exposed?
   - What is the overall attack surface?

WRITING STYLE:
- Write for a non-technical home user who is worried about being hacked
- Lead with the bottom line: "Your network is clean" or "Threats detected"
- Explain every finding as if talking to a smart friend who doesn't work in IT
- For each risk, explain: what it means in plain language, why it matters, and exactly what to do about it
- Be specific with instructions (e.g., "log into your router at 192.168.1.1, go to System Tools > Firmware Update")
- If the scan is incomplete (0 devices), explain clearly why and what the user should do
- Grade the overall network security: A (excellent), B (good), C (needs attention), D (at risk), F (compromised)

You MUST respond with ONLY valid JSON in this exact format:
{
  "risk_level": "critical|high|medium|low|info",
  "risk_score": 0-100,
  "summary": "3-5 sentence executive summary that a non-technical person can understand. Include the security grade (A-F). Be direct about whether they should be worried or not.",
  "findings": [
    {
      "id": "F1",
      "severity": "critical|high|medium|low|info",
      "category": "dns_hijack|apt28_port|vulnerable_router|suspicious_device|open_port|network_config|scan_incomplete",
      "title": "Clear, non-technical title",
      "description": "2-4 sentence explanation a non-technical person can understand. What did we find? Why does it matter? What's the real-world impact?",
      "evidence": "Technical evidence supporting the finding",
      "affected_device": "IP or device identifier or 'network-wide'"
    }
  ],
  "recommendations": [
    {
      "id": "R1",
      "priority": "immediate|soon|routine",
      "action": "Specific, step-by-step instruction the user can follow",
      "reason": "Why this action matters — connect it to a specific finding",
      "difficulty": "easy|moderate|advanced",
      "related_findings": ["F1"]
    }
  ],
  "network_health_summary": {
    "devices_scanned": 0,
    "critical_issues": 0,
    "warnings": 0,
    "clean_checks": 0,
    "security_grade": "A|B|C|D|F",
    "grade_explanation": "One sentence explaining the grade"
  }
}"""

_ANOMALY_SYSTEM_PROMPT = """You are GATEKEEP AI Analyst, a cybersecurity expert specializing in home network security assessment.

You will be given a traffic anomaly event detected on a home network. Your job is to assess whether it represents a genuine threat or a benign/false-positive event.

Respond with ONLY valid JSON in this format:
{
  "risk_level": "critical|high|medium|low|info",
  "risk_score": 0-100,
  "summary": "1-2 sentence assessment",
  "is_threat": true|false,
  "confidence": "high|medium|low",
  "findings": [],
  "recommendations": [],
  "network_health_summary": {
    "devices_scanned": 0,
    "critical_issues": 0,
    "warnings": 0,
    "clean_checks": 0
  }
}"""

_HARDENING_SYSTEM_PROMPT = """You are GATEKEEP AI Analyst, a cybersecurity and network hardening expert.

Given a full network state, produce specific firewall rules and hardening recommendations.
The rules must be in the requested format: iptables, windows_firewall, or generic.

Respond with ONLY valid JSON:
{
  "rules": [
    {
      "id": "rule-1",
      "description": "Brief description of what this rule does",
      "command": "The exact rule/command string",
      "rationale": "Why this rule is needed"
    }
  ],
  "explanation": "Plain-language summary of the hardening strategy for a home user"
}"""


# ---------------------------------------------------------------------------
# Cache entry
# ---------------------------------------------------------------------------


@dataclass
class _CacheEntry:
    result: AIAnalysisResult
    inserted_at: float = field(default_factory=time.monotonic)

    def is_expired(self) -> bool:
        return (time.monotonic() - self.inserted_at) > _CACHE_TTL_SECONDS


# ---------------------------------------------------------------------------
# AIAnalyzer
# ---------------------------------------------------------------------------


class AIAnalyzer:
    """
    Async AI analysis engine backed by the Claude Agent SDK.

    Uses Claude Code's existing authentication -- no API key needed.
    Handles SHA-256 prompt caching (1-hour TTL), retry logic, and
    safe fallback behaviour when the SDK is not installed.
    """

    SYSTEM_PROMPT = SYSTEM_PROMPT

    def __init__(self, config: AIConfig) -> None:
        """
        Initialise the analyzer.

        Args:
            config: AIConfig section from GatekeepConfig.
        """
        self.config = config
        self._cache: dict[str, _CacheEntry] = {}

        # Check if the Agent SDK is importable
        try:
            import claude_agent_sdk  # noqa: F401
            self.available = True
        except ImportError:
            logger.warning(
                "ai_analyzer.sdk_not_installed",
                message="claude-agent-sdk not installed -- AI analysis unavailable.",
            )
            self.available = False

        logger.info("ai_analyzer_initialized", model=config.model, available=self.available)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def analyze_scan(self, scan_data: dict[str, Any]) -> AIAnalysisResult:
        """
        Analyse structured scan data and return a full security assessment.

        Args:
            scan_data: Dictionary produced by the scan engine containing
                       device list, DNS check results, port scan results,
                       and router fingerprint data.

        Returns:
            AIAnalysisResult populated from Claude's response, or a safe
            fallback result when the engine is unavailable.
        """
        if not self.available:
            return self._unavailable_result()

        user_prompt = self._build_user_prompt(scan_data)
        return await self._call_claude(
            system_prompt=self.SYSTEM_PROMPT,
            user_prompt=user_prompt,
        )

    async def analyze_traffic_anomaly(
        self, anomaly_data: dict[str, Any]
    ) -> AIAnalysisResult:
        """
        Assess a traffic anomaly detected by the network monitor.

        Args:
            anomaly_data: Dictionary describing the anomaly event, including
                          type, source/destination IPs, timestamps, and
                          raw evidence.

        Returns:
            AIAnalysisResult with is_threat assessment and confidence level.
        """
        if not self.available:
            return self._unavailable_result()

        user_prompt = self._build_anomaly_prompt(anomaly_data)
        return await self._call_claude(
            system_prompt=_ANOMALY_SYSTEM_PROMPT,
            user_prompt=user_prompt,
        )

    async def generate_hardening_advice(
        self,
        network_state: dict[str, Any],
        target_format: str = "generic",
    ) -> HardeningResult:
        """
        Generate firewall rules and hardening recommendations.

        Args:
            network_state: Full network state dictionary.
            target_format: Rule format -- "iptables", "windows_firewall", or
                           "generic".

        Returns:
            HardeningResult with structured rules and plain-language explanation.
        """
        if not self.available:
            return HardeningResult(
                rules=[],
                explanation="AI hardening advice unavailable -- Claude Agent SDK not installed.",
                format=target_format,
                model_used="none",
            )

        user_prompt = self._build_hardening_prompt(network_state, target_format)
        prompt_hash = self._hash_prompt(_HARDENING_SYSTEM_PROMPT + user_prompt)

        cached = self._get_cache(prompt_hash)
        if cached is not None:
            # Re-wrap cached analysis result into HardeningResult
            raw = cached.network_health.get("_hardening_raw", {})
            return HardeningResult(
                rules=raw.get("rules", []),
                explanation=raw.get("explanation", cached.summary),
                format=target_format,
                model_used=cached.model_used,
            )

        try:
            raw_text, latency_ms = await self._invoke_agent(
                system_prompt=_HARDENING_SYSTEM_PROMPT,
                user_prompt=user_prompt,
            )
        except Exception as exc:
            logger.error("ai_analyzer.hardening_failed", error=str(exc))
            return HardeningResult(
                rules=[],
                explanation=f"AI hardening advice failed: {exc}",
                format=target_format,
                model_used=self.config.model,
            )

        parsed = self._parse_json(raw_text)
        if parsed is None:
            parsed = {}
        rules: list[dict[str, Any]] = parsed.get("rules", [])
        explanation: str = parsed.get("explanation", raw_text[:500])

        # Store a thin placeholder in the cache
        placeholder = AIAnalysisResult(
            risk_level="info",
            risk_score=0,
            summary=explanation[:200],
            findings=[],
            recommendations=[],
            network_health={"_hardening_raw": {"rules": rules, "explanation": explanation}},
            model_used=self.config.model,
            tokens_used=0,
            latency_ms=latency_ms,
        )
        self._set_cache(prompt_hash, placeholder)

        return HardeningResult(
            rules=rules,
            explanation=explanation,
            format=target_format,
            model_used=self.config.model,
        )

    # ------------------------------------------------------------------
    # Prompt builders
    # ------------------------------------------------------------------

    def _build_user_prompt(self, scan_data: dict[str, Any]) -> str:
        """Format scan data into a readable user prompt for Claude."""
        lines: list[str] = []

        scan_id = scan_data.get("id", "N/A")
        timestamp = scan_data.get("timestamp", "N/A")
        subnet = scan_data.get("subnet", "N/A")
        devices: list[dict[str, Any]] = scan_data.get("devices", [])

        lines.append("## Network Scan Results")
        lines.append(f"Scan ID: {scan_id}")
        lines.append(f"Timestamp: {timestamp}")
        lines.append(f"Subnet: {subnet}")
        lines.append(f"Devices Found: {len(devices)}")
        lines.append("")

        # ---- Discovered devices table ----
        lines.append("### Discovered Devices")
        lines.append("| # | IP Address | MAC Address | Vendor | Type | Gateway |")
        lines.append("|---|------------|-------------|--------|------|---------|")
        for idx, dev in enumerate(devices, start=1):
            ip = dev.get("ip_address", "N/A")
            mac = dev.get("mac_address", "N/A")
            vendor = dev.get("vendor", "Unknown")
            dev_type = dev.get("device_type", "Unknown")
            gateway = "Yes" if dev.get("is_gateway") else "No"
            lines.append(f"| {idx} | {ip} | {mac} | {vendor} | {dev_type} | {gateway} |")
        lines.append("")

        # ---- Device identification details (from SSDP/NetBIOS) ----
        enriched_devices = [
            d for d in devices
            if d.get("netbios_name") or d.get("upnp_name") or d.get("upnp_model") or d.get("ssdp_server")
        ]
        if enriched_devices:
            lines.append("### Device Identification Details")
            for dev in enriched_devices:
                ip = dev.get("ip_address", "N/A")
                lines.append(f"Device {ip}:")
                if dev.get("netbios_name"):
                    lines.append(f"  NetBIOS Name: {dev['netbios_name']}")
                if dev.get("upnp_name") or dev.get("upnp_model") or dev.get("upnp_manufacturer"):
                    upnp_parts = []
                    if dev.get("upnp_name"):
                        upnp_parts.append(dev["upnp_name"])
                    if dev.get("upnp_model"):
                        upnp_parts.append(dev["upnp_model"])
                    mfr = dev.get("upnp_manufacturer", "")
                    if mfr:
                        upnp_parts.append(f"({mfr})")
                    lines.append(f"  UPnP: {' '.join(upnp_parts)}")
                if dev.get("ssdp_server"):
                    lines.append(f"  SSDP Server: {dev['ssdp_server']}")
            lines.append("")

        # ---- DNS integrity ----
        dns_data: dict[str, Any] = scan_data.get("dns_check", {})
        if dns_data:
            lines.append("### DNS Integrity Check")
            servers = dns_data.get("system_dns_servers", [])
            lines.append(f"System DNS Servers: {', '.join(servers) if servers else 'N/A'}")
            status = dns_data.get("status", "unknown")
            lines.append(f"Status: {status}")
            details = dns_data.get("details", "")
            if details:
                lines.append(f"Details: {details}")
            hijacked = dns_data.get("hijacked_domains", [])
            if hijacked:
                lines.append("Hijacked Domains:")
                for entry in hijacked:
                    domain = entry.get("domain", "N/A")
                    expected = entry.get("expected_ips", [])
                    actual = entry.get("actual_ips", [])
                    lines.append(
                        f"  - {domain}: expected {expected}, got {actual}"
                    )
            lines.append("")

        # ---- Port scan results ----
        devices_with_ports = [d for d in devices if d.get("open_ports")]
        if devices_with_ports:
            lines.append("### Port Scan Results")
            for dev in devices_with_ports:
                ip = dev.get("ip_address", "N/A")
                vendor = dev.get("vendor", "Unknown")
                lines.append(f"\nDevice: {ip} ({vendor})")
                lines.append("Open Ports:")
                for port_info in dev.get("open_ports", []):
                    port = port_info.get("port", "?")
                    proto = port_info.get("protocol", "tcp")
                    service = port_info.get("service_name", "")
                    banner = port_info.get("banner", "")
                    suspicious = port_info.get("is_suspicious", False)
                    flag = " [SUSPICIOUS]" if suspicious else ""
                    banner_str = f" -- {banner}" if banner else ""
                    lines.append(
                        f"  - Port {port}/{proto}: {service}{banner_str}{flag}"
                    )
            lines.append("")

        # ---- Router fingerprint ----
        router: dict[str, Any] = scan_data.get("router_fingerprint", {})
        if router:
            lines.append("### Router Identification")
            lines.append(f"Model: {router.get('model', 'Unknown')}")
            lines.append(f"Manufacturer: {router.get('manufacturer', 'Unknown')}")
            lines.append(f"Firmware: {router.get('firmware_version', 'Unknown')}")
            vuln_status = "VULNERABLE" if router.get("is_vulnerable") else "No known vulnerabilities"
            lines.append(f"Vulnerability Status: {vuln_status}")
            cves: list[dict[str, Any]] = router.get("vulnerability_details") or []
            if cves:
                cve_ids = [c.get("cve_id", str(c)) for c in cves]
                lines.append(f"CVEs: {', '.join(cve_ids)}")
            lines.append("")

        # ---- Alerts already raised ----
        alerts: list[dict[str, Any]] = scan_data.get("alerts", [])
        if alerts:
            lines.append("### Pre-Classified Alerts")
            for alert in alerts:
                sev = alert.get("severity", "?").upper()
                title = alert.get("title", "N/A")
                desc = alert.get("description", "")
                lines.append(f"[{sev}] {title}: {desc}")
            lines.append("")

        # Add analysis instructions
        lines.append("### Analysis Instructions")
        lines.append("Perform a comprehensive 5-category assessment as specified in your system prompt.")
        lines.append("Even if some scan data is missing, analyze what IS available thoroughly.")
        lines.append("If the scan is incomplete, still assess DNS results and provide actionable guidance.")
        lines.append(f"The user's local IP is likely in the {scan_data.get('subnet', '192.168.1.0/24')} range.")
        lines.append("Provide a security grade (A-F) and at least 3 recommendations regardless of findings.")

        return "\n".join(lines)

    def _build_anomaly_prompt(self, anomaly_data: dict[str, Any]) -> str:
        """Format anomaly event data into a focused prompt."""
        lines: list[str] = ["## Traffic Anomaly Event"]
        for key, value in anomaly_data.items():
            lines.append(f"{key}: {value}")
        lines.append("\nAssess whether this is a genuine security threat or a benign event.")
        return "\n".join(lines)

    def _build_hardening_prompt(
        self, network_state: dict[str, Any], target_format: str
    ) -> str:
        """Format network state into a hardening advice prompt."""
        lines: list[str] = [
            "## Network Hardening Request",
            f"Target Format: {target_format}",
            "",
            "### Current Network State",
            json.dumps(network_state, indent=2, default=str),
            "",
            f"Generate {target_format} firewall rules and hardening recommendations "
            f"based on the network state above. Focus on blocking APT28 indicators, "
            f"restricting unnecessary exposed services, and protecting DNS integrity.",
        ]
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Core API call with retry
    # ------------------------------------------------------------------

    async def _call_claude(
        self,
        system_prompt: str,
        user_prompt: str,
    ) -> AIAnalysisResult:
        """
        Check cache, invoke the Agent SDK, parse and cache the result.

        Returns:
            Populated AIAnalysisResult.
        """
        prompt_hash = self._hash_prompt(system_prompt + user_prompt)

        cached = self._get_cache(prompt_hash)
        if cached is not None:
            cached.cached = True
            logger.debug("ai_analyzer.cache_hit", prompt_hash=prompt_hash[:16])
            return cached

        try:
            raw_text, latency_ms = await self._invoke_agent(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
            )
        except Exception as exc:
            logger.error("ai_analyzer.query_failed", error=str(exc))
            return AIAnalysisResult(
                risk_level="error",
                risk_score=0,
                summary=f"AI analysis failed: {exc}",
                findings=[],
                recommendations=[],
                network_health={},
                model_used=self.config.model,
                tokens_used=0,
                latency_ms=0,
            )

        result = self._parse_analysis_response(
            raw_text=raw_text,
            latency_ms=latency_ms,
        )
        self._set_cache(prompt_hash, result)
        return result

    async def _invoke_agent(
        self,
        system_prompt: str,
        user_prompt: str,
    ) -> tuple[str, int]:
        """
        Call Claude via the Agent SDK.

        Returns:
            Tuple of (raw_text, latency_ms).

        Raises:
            Exception: If the query fails.
        """
        from claude_agent_sdk import query, ClaudeAgentOptions, ResultMessage

        t_start = time.monotonic()

        result_text = ""
        async for message in query(
            prompt=user_prompt,
            options=ClaudeAgentOptions(
                system_prompt=system_prompt,
                model=self.config.model,
                max_turns=3,
                allowed_tools=[],  # No tools needed -- just analysis
            ),
        ):
            if isinstance(message, ResultMessage):
                result_text = message.result

        latency_ms = int((time.monotonic() - t_start) * 1000)

        logger.info(
            "ai_analyzer.agent_query_success",
            model=self.config.model,
            latency_ms=latency_ms,
            response_length=len(result_text),
        )
        return result_text, latency_ms

    # ------------------------------------------------------------------
    # Response parsing
    # ------------------------------------------------------------------

    def _parse_analysis_response(
        self,
        raw_text: str,
        latency_ms: int,
    ) -> AIAnalysisResult:
        """
        Parse Claude's JSON response into an AIAnalysisResult.

        Handles markdown-wrapped JSON (```json ... ```) gracefully.
        Falls back to an error result on parse failure.
        """
        parsed = self._parse_json(raw_text)

        if parsed is None:
            logger.error(
                "ai_analyzer.json_parse_failure",
                raw_preview=raw_text[:200],
            )
            return AIAnalysisResult(
                risk_level="error",
                risk_score=0,
                summary="AI analysis returned a malformed response.",
                findings=[],
                recommendations=[],
                network_health={"raw_response": raw_text[:2000]},
                model_used=self.config.model,
                tokens_used=0,
                latency_ms=latency_ms,
            )

        return AIAnalysisResult(
            risk_level=parsed.get("risk_level", "unknown"),
            risk_score=int(parsed.get("risk_score", 0)),
            summary=parsed.get("summary", ""),
            findings=parsed.get("findings", []),
            recommendations=parsed.get("recommendations", []),
            network_health=parsed.get("network_health_summary", {}),
            model_used=self.config.model,
            tokens_used=0,  # Agent SDK does not expose token counts
            latency_ms=latency_ms,
        )

    @staticmethod
    def _parse_json(raw_text: str) -> Optional[dict[str, Any]]:
        """
        Extract and parse JSON from Claude's response.

        Strips markdown code fences if present, then attempts JSON parsing.
        Returns None on failure.
        """
        text = raw_text.strip()

        # Strip markdown fences: ```json ... ``` or ``` ... ```
        fence_pattern = re.compile(
            r"```(?:json)?\s*([\s\S]*?)\s*```", re.IGNORECASE
        )
        match = fence_pattern.search(text)
        if match:
            text = match.group(1).strip()

        try:
            return json.loads(text)
        except json.JSONDecodeError:
            # Try to extract a JSON object by finding the first { ... }
            brace_match = re.search(r"\{[\s\S]*\}", text)
            if brace_match:
                try:
                    return json.loads(brace_match.group(0))
                except json.JSONDecodeError:
                    pass
        return None

    # ------------------------------------------------------------------
    # Cache helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _hash_prompt(prompt: str) -> str:
        """Return the SHA-256 hex digest of the combined prompt string."""
        return hashlib.sha256(prompt.encode("utf-8")).hexdigest()

    def _get_cache(self, prompt_hash: str) -> Optional[AIAnalysisResult]:
        """Return a cached result if present and not expired; else None."""
        entry = self._cache.get(prompt_hash)
        if entry is None:
            return None
        if entry.is_expired():
            del self._cache[prompt_hash]
            return None
        return entry.result

    def _set_cache(self, prompt_hash: str, result: AIAnalysisResult) -> None:
        """Store a result in the cache under the given hash key."""
        self._cache[prompt_hash] = _CacheEntry(result=result)
        logger.debug("ai_analyzer.cache_set", prompt_hash=prompt_hash[:16])

    def _evict_expired_cache(self) -> int:
        """Remove all expired entries from the cache. Returns count removed."""
        expired_keys = [k for k, v in self._cache.items() if v.is_expired()]
        for k in expired_keys:
            del self._cache[k]
        return len(expired_keys)

    # ------------------------------------------------------------------
    # Fallback results
    # ------------------------------------------------------------------

    @staticmethod
    def _unavailable_result() -> AIAnalysisResult:
        """Return a safe placeholder result when the Agent SDK is not installed."""
        return AIAnalysisResult(
            risk_level="unknown",
            risk_score=0,
            summary="AI analysis unavailable -- Claude Agent SDK not installed.",
            findings=[],
            recommendations=[
                {
                    "id": "R1",
                    "priority": "routine",
                    "action": "Install claude-agent-sdk to enable AI-powered analysis.",
                    "reason": "AI-powered threat detection requires the Claude Agent SDK.",
                    "difficulty": "easy",
                    "related_findings": [],
                }
            ],
            network_health={},
            model_used="none",
            tokens_used=0,
            latency_ms=0,
        )
