"""
Router fingerprinting engine for GATEKEEP.

Identifies router manufacturer and model via MAC OUI lookup and HTTP
admin-panel probing. Matches fingerprints against the vulnerable router
database (APT28 FrostArmada / Dying Ember campaign targets) and reports
CVEs, remediation guidance, and confidence scores.
"""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import httpx

from gatekeep.config import NetworkConfig
from gatekeep.logging_config import get_logger
from gatekeep.utils.network import mac_to_vendor

log = get_logger(__name__)

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"

# Common admin panel paths probed during fingerprinting
_ADMIN_PATHS = [
    "/",
    "/login",
    "/cgi-bin/luci",
    "/webFig/",
    "/userRpm/LoginRpm.htm",
    "/webpages/login.html",
    "/api/edge/auth.json",
]

# Regex to extract <title>...</title> from HTML
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

# Regex to extract firmware-like version strings from page bodies
_FIRMWARE_RE = re.compile(
    r"(?:firmware|version|fw|ver)[:\s]*"
    r"v?(\d+\.\d+[\.\d]*(?:\s*(?:Build|beta|rc)\s*\w*)?)",
    re.IGNORECASE,
)

# Regex to extract <meta> tags
_META_RE = re.compile(
    r'<meta\s+[^>]*(?:name|property)\s*=\s*["\']([^"\']+)["\']'
    r'[^>]*content\s*=\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)

# Regex to find <form> fields (name attributes)
_FORM_FIELD_RE = re.compile(
    r'<input[^>]+name\s*=\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)


@dataclass
class HTTPProbeResult:
    """Data extracted from an HTTP probe to a router admin page."""

    url: str
    status_code: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    title: Optional[str] = None
    meta_tags: dict[str, str] = field(default_factory=dict)
    form_fields: list[str] = field(default_factory=list)
    body_snippet: str = ""
    server_header: Optional[str] = None
    redirect_url: Optional[str] = None
    error: Optional[str] = None


@dataclass
class VulnerableMatch:
    """A match against the vulnerable router database."""

    manufacturer: str
    model: str
    cves: list[str] = field(default_factory=list)
    campaign: Optional[str] = None
    threat_actor: Optional[str] = None
    attack_vector: Optional[str] = None
    severity: str = "unknown"
    affected_firmware: Optional[str] = None
    remediation: Optional[str] = None
    advisory_url: Optional[str] = None
    confidence: str = "low"  # low | medium | high


@dataclass
class RouterInfo:
    """Complete fingerprint result for a router."""

    manufacturer: Optional[str] = None
    model: Optional[str] = None
    firmware_version: Optional[str] = None
    is_vulnerable: bool = False
    vulnerability_details: list[dict[str, Any]] = field(default_factory=list)
    admin_panel_url: Optional[str] = None
    fingerprint_method: Optional[str] = None
    confidence_score: float = 0.0


class RouterFingerprinter:
    """
    Fingerprints a router by combining MAC OUI lookup with HTTP
    admin-panel probing, then matches against the known-vulnerable
    router database.
    """

    def __init__(self, config: NetworkConfig) -> None:
        self._config = config
        self._vuln_db = self._load_vulnerable_routers()
        self._oui_db = self._load_oui_database()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def fingerprint(self, ip: str, mac: str) -> RouterInfo:
        """
        Fingerprint a router at *ip* with the given *mac* address.

        Steps:
        1. MAC OUI lookup for manufacturer identification
        2. HTTP probe to common admin paths
        3. Match fingerprints against vulnerable router database
        4. Extract firmware version if visible

        Args:
            ip: IPv4 address of the router.
            mac: MAC address of the router.

        Returns:
            A :class:`RouterInfo` with identification, vulnerability
            status, and confidence score.
        """
        info = RouterInfo()
        fingerprint_data: dict[str, Any] = {}

        # Step 1 — OUI manufacturer lookup
        vendor = mac_to_vendor(mac, self._oui_db)
        if vendor:
            info.manufacturer = vendor
            fingerprint_data["oui_vendor"] = vendor
            info.fingerprint_method = "oui"
            info.confidence_score = 0.3
            log.info(
                "router_oui_lookup",
                ip=ip,
                mac=mac,
                vendor=vendor,
            )

        # Step 2 — HTTP probe
        probe_results = await self._http_probe(ip, _ADMIN_PATHS)
        successful_probes = [p for p in probe_results if p.status_code > 0]

        if successful_probes:
            # Use the best probe (prefer one with a title)
            best = self._select_best_probe(successful_probes)
            fingerprint_data["http_title"] = best.title
            fingerprint_data["server_header"] = best.server_header
            fingerprint_data["headers"] = best.headers
            fingerprint_data["meta_tags"] = best.meta_tags
            fingerprint_data["form_fields"] = best.form_fields
            fingerprint_data["body_snippet"] = best.body_snippet
            fingerprint_data["admin_url"] = best.url
            info.admin_panel_url = best.url

            if best.title or best.server_header:
                info.fingerprint_method = "http"
                info.confidence_score = max(info.confidence_score, 0.5)

            # Step 4 — Firmware extraction from HTTP responses
            firmware = self._extract_firmware_version(successful_probes)
            if firmware:
                info.firmware_version = firmware
                fingerprint_data["firmware_version"] = firmware

            log.info(
                "router_http_probe_done",
                ip=ip,
                probes=len(successful_probes),
                title=best.title,
                server=best.server_header,
            )
        else:
            log.info("router_http_probe_no_response", ip=ip)

        # Step 3 — Match against vulnerable router database
        match = self._match_vulnerable_model(fingerprint_data)
        if match:
            info.manufacturer = match.manufacturer
            info.model = match.model
            info.is_vulnerable = True
            info.confidence_score = self._match_confidence_to_score(match.confidence)
            info.fingerprint_method = (
                f"vuln_db_match ({match.confidence} confidence)"
            )
            info.vulnerability_details = [
                {
                    "cves": match.cves,
                    "campaign": match.campaign,
                    "threat_actor": match.threat_actor,
                    "attack_vector": match.attack_vector,
                    "severity": match.severity,
                    "affected_firmware": match.affected_firmware,
                    "remediation": match.remediation,
                    "advisory_url": match.advisory_url,
                }
            ]
            log.warning(
                "vulnerable_router_detected",
                ip=ip,
                manufacturer=match.manufacturer,
                model=match.model,
                cves=match.cves,
                campaign=match.campaign,
                confidence=match.confidence,
            )

        return info

    # ------------------------------------------------------------------
    # HTTP probing
    # ------------------------------------------------------------------

    async def _http_probe(
        self, ip: str, paths: list[str]
    ) -> list[HTTPProbeResult]:
        """
        Probe an IP with HTTP(S) requests on common admin paths.

        Uses httpx with ``verify=False`` since router admin pages
        typically serve self-signed certificates on the local network.

        Args:
            ip: Target IP address.
            paths: URL paths to probe.

        Returns:
            List of :class:`HTTPProbeResult`.
        """
        results: list[HTTPProbeResult] = []
        timeout = httpx.Timeout(5.0, connect=3.0)

        async with httpx.AsyncClient(
            timeout=timeout,
            verify=False,
            follow_redirects=True,
            max_redirects=3,
        ) as client:
            for scheme in ("http", "https"):
                for path in paths:
                    url = f"{scheme}://{ip}{path}"
                    probe = await self._probe_single_url(client, url)
                    results.append(probe)
                    # If we got a good response on HTTP, skip HTTPS for
                    # the same path (and vice versa) to save time
                    if probe.status_code > 0 and probe.status_code < 400:
                        break

        return results

    @staticmethod
    async def _probe_single_url(
        client: httpx.AsyncClient, url: str
    ) -> HTTPProbeResult:
        """Probe a single URL and extract relevant data."""
        result = HTTPProbeResult(url=url)
        try:
            response = await client.get(url)
            result.status_code = response.status_code
            result.headers = dict(response.headers)
            result.server_header = response.headers.get("server")

            body = response.text
            # Limit body to first 8KB for analysis
            body_limited = body[:8192]
            result.body_snippet = body_limited[:2048]

            # Extract title
            title_match = _TITLE_RE.search(body_limited)
            if title_match:
                result.title = title_match.group(1).strip()

            # Extract meta tags
            for name, content in _META_RE.findall(body_limited):
                result.meta_tags[name] = content

            # Extract form field names
            result.form_fields = _FORM_FIELD_RE.findall(body_limited)

            # Track redirects
            if response.history:
                result.redirect_url = str(response.url)

        except httpx.TimeoutException:
            result.error = "timeout"
        except httpx.ConnectError:
            result.error = "connection_refused"
        except httpx.HTTPError as exc:
            result.error = str(exc)
        except Exception as exc:
            result.error = f"unexpected: {type(exc).__name__}: {exc}"

        return result

    # ------------------------------------------------------------------
    # Vulnerability matching
    # ------------------------------------------------------------------

    def _match_vulnerable_model(
        self, fingerprint_data: dict[str, Any]
    ) -> Optional[VulnerableMatch]:
        """
        Compare collected fingerprint data against the vulnerable
        router database.

        Matching levels:
        - **high**: HTTP title AND server header match a known pattern
        - **medium**: HTTP title OR server header matches
        - **low**: OUI vendor matches a known vulnerable manufacturer
        """
        http_title = (fingerprint_data.get("http_title") or "").lower()
        server_header = (fingerprint_data.get("server_header") or "").lower()
        oui_vendor = (fingerprint_data.get("oui_vendor") or "").lower()
        body_snippet = (fingerprint_data.get("body_snippet") or "").lower()

        best_match: Optional[VulnerableMatch] = None
        best_confidence_rank = -1

        confidence_order = {"high": 3, "medium": 2, "low": 1}

        for entry in self._vuln_db:
            patterns = entry.get("fingerprint_patterns", {})
            title_patterns = [t.lower() for t in patterns.get("http_title", [])]
            header_patterns = patterns.get("http_headers", {})
            expected_server = (header_patterns.get("Server") or "").lower()

            title_match = any(tp in http_title for tp in title_patterns) if (http_title and title_patterns) else False
            # Also check the body snippet for title patterns
            body_match = any(tp in body_snippet for tp in title_patterns) if (body_snippet and title_patterns) else False
            server_match = (
                expected_server in server_header
                if (server_header and expected_server)
                else False
            )
            manufacturer_match = (
                entry.get("manufacturer", "").lower() in oui_vendor
                if oui_vendor
                else False
            )

            # Determine confidence level
            if (title_match or body_match) and server_match:
                confidence = "high"
            elif title_match or body_match or server_match:
                confidence = "medium"
            elif manufacturer_match:
                confidence = "low"
            else:
                continue  # No match at all

            rank = confidence_order.get(confidence, 0)
            if rank > best_confidence_rank:
                best_confidence_rank = rank
                best_match = VulnerableMatch(
                    manufacturer=entry.get("manufacturer", "Unknown"),
                    model=entry.get("model", "Unknown"),
                    cves=entry.get("cves", []),
                    campaign=entry.get("campaign"),
                    threat_actor=entry.get("threat_actor"),
                    attack_vector=entry.get("attack_vector"),
                    severity=entry.get("severity", "unknown"),
                    affected_firmware=entry.get("affected_firmware"),
                    remediation=entry.get("remediation"),
                    advisory_url=entry.get("advisory_url"),
                    confidence=confidence,
                )

                # If we found a high-confidence match, stop searching
                if confidence == "high":
                    break

        return best_match

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _select_best_probe(
        probes: list[HTTPProbeResult],
    ) -> HTTPProbeResult:
        """Select the probe result with the most useful information."""
        # Prefer probes with a title
        with_title = [p for p in probes if p.title]
        if with_title:
            # Among those with a title, prefer 200 status
            ok = [p for p in with_title if p.status_code == 200]
            return ok[0] if ok else with_title[0]
        # Otherwise prefer 200 status
        ok = [p for p in probes if p.status_code == 200]
        return ok[0] if ok else probes[0]

    @staticmethod
    def _extract_firmware_version(
        probes: list[HTTPProbeResult],
    ) -> Optional[str]:
        """
        Try to extract a firmware version string from probe results.
        """
        for probe in probes:
            body = probe.body_snippet or ""
            match = _FIRMWARE_RE.search(body)
            if match:
                return match.group(1).strip()
            # Also check meta tags
            for name, content in probe.meta_tags.items():
                if "version" in name.lower() or "firmware" in name.lower():
                    return content
        return None

    @staticmethod
    def _match_confidence_to_score(confidence: str) -> float:
        """Convert a confidence label to a numeric score."""
        return {"high": 0.9, "medium": 0.6, "low": 0.3}.get(confidence, 0.1)

    @staticmethod
    def _load_vulnerable_routers() -> list[dict[str, Any]]:
        """Load the vulnerable routers JSON database."""
        path = _DATA_DIR / "vulnerable_routers.json"
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, list):
                return data
            log.warning("vulnerable_routers_unexpected_format", path=str(path))
            return []
        except (FileNotFoundError, json.JSONDecodeError) as exc:
            log.warning(
                "vulnerable_routers_load_failed",
                path=str(path),
                error=str(exc),
            )
            return []

    @staticmethod
    def _load_oui_database() -> dict[str, str]:
        """Load OUI prefix -> vendor mapping from JSON data file."""
        oui_path = _DATA_DIR / "oui_prefixes.json"
        try:
            with open(oui_path, "r", encoding="utf-8") as fh:
                raw: dict[str, str] = json.load(fh)
            return {k: v for k, v in raw.items() if not k.startswith("_")}
        except (FileNotFoundError, json.JSONDecodeError) as exc:
            log.warning("oui_db_load_failed", path=str(oui_path), error=str(exc))
            return {}
