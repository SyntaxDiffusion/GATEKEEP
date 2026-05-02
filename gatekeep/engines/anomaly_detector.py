"""
Anomaly detection engine for GATEKEEP.

Implements three sliding-window detectors that operate on live packet
streams to identify port scanning, SYN flood attacks, and DNS
tunneling activity.  Each detector maintains its own time-windowed
state and is pruned automatically on every evaluation cycle.
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from gatekeep.config import MonitoringConfig
from gatekeep.logging_config import get_logger
from gatekeep.utils.entropy import shannon_entropy

log = get_logger(__name__)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class Anomaly:
    """A detected network anomaly."""

    type: str
    severity: str
    source_ip: Optional[str]
    destination_ip: Optional[str]
    description: str
    evidence: dict[str, Any]
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    confidence: float = 0.0


# ---------------------------------------------------------------------------
# Individual detectors
# ---------------------------------------------------------------------------


class PortScanDetector:
    """
    Detects horizontal/vertical port scanning.

    Tracks the set of distinct destination ports contacted by each
    source IP within a sliding time window.  When a single source
    touches more ports than the configured threshold, a port-scan
    anomaly is raised.
    """

    def __init__(self, port_threshold: int = 15, time_window: int = 10) -> None:
        self._port_threshold = port_threshold
        self._time_window = time_window
        # src_ip -> list of (timestamp, dst_port)
        self._tracking: dict[str, list[tuple[float, int]]] = defaultdict(list)

    def evaluate(
        self, src_ip: str, dst_port: int, now: float | None = None
    ) -> Anomaly | None:
        """
        Record a connection attempt and check for scanning behavior.

        Args:
            src_ip: Source IP address.
            dst_port: Destination port number.
            now: Current timestamp (defaults to time.monotonic()).

        Returns:
            An Anomaly if the threshold is breached, else None.
        """
        ts = now if now is not None else time.monotonic()
        entries = self._tracking[src_ip]
        entries.append((ts, dst_port))

        # Prune expired entries
        cutoff = ts - self._time_window
        self._tracking[src_ip] = [
            (t, p) for t, p in entries if t > cutoff
        ]

        # Count distinct ports in window
        active_entries = self._tracking[src_ip]
        distinct_ports = {p for _, p in active_entries}

        if len(distinct_ports) >= self._port_threshold:
            anomaly = Anomaly(
                type="port_scan",
                severity="medium",
                source_ip=src_ip,
                destination_ip=None,
                description=(
                    f"Potential port scan detected: {src_ip} contacted "
                    f"{len(distinct_ports)} distinct ports in {self._time_window}s"
                ),
                evidence={
                    "source_ip": src_ip,
                    "port_count": len(distinct_ports),
                    "ports_sample": sorted(distinct_ports)[:20],
                    "time_window": self._time_window,
                },
                confidence=min(1.0, len(distinct_ports) / (self._port_threshold * 2)),
            )
            # Clear tracking for this IP to avoid repeated alerts
            self._tracking[src_ip] = []
            return anomaly

        return None

    def prune(self, now: float | None = None) -> None:
        """Remove all entries older than the time window."""
        ts = now if now is not None else time.monotonic()
        cutoff = ts - self._time_window
        empty_keys: list[str] = []
        for ip, entries in self._tracking.items():
            self._tracking[ip] = [(t, p) for t, p in entries if t > cutoff]
            if not self._tracking[ip]:
                empty_keys.append(ip)
        for ip in empty_keys:
            del self._tracking[ip]


class SYNFloodDetector:
    """
    Detects SYN flood attacks.

    Tracks SYN and ACK packet counts per destination IP within a
    sliding time window.  A flood is flagged when the SYN count
    exceeds the threshold without a proportional number of ACK
    responses (indicating incomplete handshakes).
    """

    def __init__(self, syn_threshold: int = 200, time_window: int = 5) -> None:
        self._syn_threshold = syn_threshold
        self._time_window = time_window
        # dst_ip -> list of (timestamp, is_syn: bool)
        self._tracking: dict[str, list[tuple[float, bool]]] = defaultdict(list)

    def record_syn(self, dst_ip: str, now: float | None = None) -> None:
        """Record an inbound SYN packet to a destination IP."""
        ts = now if now is not None else time.monotonic()
        self._tracking[dst_ip].append((ts, True))

    def record_ack(self, dst_ip: str, now: float | None = None) -> None:
        """Record an ACK packet completing a handshake to a destination IP."""
        ts = now if now is not None else time.monotonic()
        self._tracking[dst_ip].append((ts, False))

    def evaluate(self, dst_ip: str, now: float | None = None) -> Anomaly | None:
        """
        Check whether a destination IP is under SYN flood.

        Args:
            dst_ip: Destination IP to evaluate.
            now: Current timestamp.

        Returns:
            An Anomaly if the SYN flood threshold is breached, else None.
        """
        ts = now if now is not None else time.monotonic()
        cutoff = ts - self._time_window

        entries = self._tracking.get(dst_ip, [])
        # Prune expired
        active = [(t, is_syn) for t, is_syn in entries if t > cutoff]
        self._tracking[dst_ip] = active

        syn_count = sum(1 for _, is_syn in active if is_syn)
        ack_count = sum(1 for _, is_syn in active if not is_syn)

        if syn_count >= self._syn_threshold:
            anomaly = Anomaly(
                type="syn_flood",
                severity="high",
                source_ip=None,
                destination_ip=dst_ip,
                description=(
                    f"Potential SYN flood detected: {dst_ip} received "
                    f"{syn_count} SYN packets with only {ack_count} ACKs "
                    f"in {self._time_window}s"
                ),
                evidence={
                    "target_ip": dst_ip,
                    "syn_count": syn_count,
                    "ack_count": ack_count,
                    "time_window": self._time_window,
                    "syn_ack_ratio": round(
                        syn_count / max(ack_count, 1), 2
                    ),
                },
                confidence=min(1.0, syn_count / (self._syn_threshold * 3)),
            )
            # Reset to avoid repeated alerts within the same window
            self._tracking[dst_ip] = []
            return anomaly

        return None

    def prune(self, now: float | None = None) -> None:
        """Remove all entries older than the time window."""
        ts = now if now is not None else time.monotonic()
        cutoff = ts - self._time_window
        empty_keys: list[str] = []
        for ip, entries in self._tracking.items():
            self._tracking[ip] = [(t, s) for t, s in entries if t > cutoff]
            if not self._tracking[ip]:
                empty_keys.append(ip)
        for ip in empty_keys:
            del self._tracking[ip]


class DNSTunnelDetector:
    """
    Detects DNS tunneling via entropy analysis and query frequency.

    Flags queries that exhibit high Shannon entropy combined with
    excessive label length (indicating encoded payloads), or domains
    receiving an abnormally high query rate (indicating C2 beaconing).
    """

    def __init__(
        self,
        entropy_threshold: float = 4.5,
        min_length: int = 50,
        frequency_threshold: int = 100,
        frequency_window: int = 60,
    ) -> None:
        self._entropy_threshold = entropy_threshold
        self._min_length = min_length
        self._frequency_threshold = frequency_threshold
        self._frequency_window = frequency_window
        # domain -> list of query timestamps
        self._query_times: dict[str, list[float]] = defaultdict(list)

    def evaluate(
        self, query_name: str, now: float | None = None
    ) -> Anomaly | None:
        """
        Evaluate a DNS query for tunneling indicators.

        Two independent checks:
        1. High entropy + long query name (payload encoding)
        2. High query frequency to a single domain (beaconing)

        Args:
            query_name: The queried domain name.
            now: Current timestamp.

        Returns:
            An Anomaly if tunneling is suspected, else None.
        """
        ts = now if now is not None else time.monotonic()
        clean_name = query_name.rstrip(".")

        # --- Check 1: Entropy + length ---
        entropy = shannon_entropy(clean_name)
        if entropy > self._entropy_threshold and len(clean_name) > self._min_length:
            return Anomaly(
                type="dns_tunneling",
                severity="high",
                source_ip=None,
                destination_ip=None,
                description=(
                    f"Suspected DNS tunneling: query '{clean_name[:60]}...' "
                    f"has entropy {entropy:.2f} and length {len(clean_name)}"
                ),
                evidence={
                    "domain": clean_name,
                    "entropy": round(entropy, 4),
                    "query_length": len(clean_name),
                    "query_count": 1,
                    "detection_method": "entropy_length",
                },
                confidence=min(1.0, (entropy / 6.0) * 0.8 + 0.2),
            )

        # --- Check 2: Frequency ---
        # Extract the base domain (last two labels) for frequency tracking
        labels = clean_name.split(".")
        base_domain = ".".join(labels[-2:]) if len(labels) >= 2 else clean_name

        entries = self._query_times[base_domain]
        entries.append(ts)

        # Prune expired
        cutoff = ts - self._frequency_window
        self._query_times[base_domain] = [t for t in entries if t > cutoff]

        query_count = len(self._query_times[base_domain])
        if query_count >= self._frequency_threshold:
            anomaly = Anomaly(
                type="dns_tunneling",
                severity="high",
                source_ip=None,
                destination_ip=None,
                description=(
                    f"Suspected DNS tunneling: domain '{base_domain}' "
                    f"received {query_count} queries in {self._frequency_window}s"
                ),
                evidence={
                    "domain": base_domain,
                    "entropy": round(entropy, 4),
                    "query_length": len(clean_name),
                    "query_count": query_count,
                    "time_window": self._frequency_window,
                    "detection_method": "frequency",
                },
                confidence=min(
                    1.0, query_count / (self._frequency_threshold * 2)
                ),
            )
            # Reset to avoid repeated alerts
            self._query_times[base_domain] = []
            return anomaly

        return None

    def prune(self, now: float | None = None) -> None:
        """Remove all entries older than the frequency window."""
        ts = now if now is not None else time.monotonic()
        cutoff = ts - self._frequency_window
        empty_keys: list[str] = []
        for domain, times in self._query_times.items():
            self._query_times[domain] = [t for t in times if t > cutoff]
            if not self._query_times[domain]:
                empty_keys.append(domain)
        for domain in empty_keys:
            del self._query_times[domain]


# ---------------------------------------------------------------------------
# Main anomaly detection engine
# ---------------------------------------------------------------------------


class AnomalyDetector:
    """
    Composite anomaly detector that evaluates packets against all
    detection strategies.

    Accepts raw scapy packets, extracts the relevant protocol fields,
    and runs each sub-detector.  Returns the first triggered anomaly
    (if any) for each packet.

    Usage::

        detector = AnomalyDetector(config)
        anomaly = await detector.evaluate(packet)
        if anomaly:
            handle_anomaly(anomaly)
    """

    def __init__(self, config: MonitoringConfig) -> None:
        thresholds = config.anomaly_thresholds

        self._port_scan = PortScanDetector(
            port_threshold=thresholds.port_scan.port_count,
            time_window=thresholds.port_scan.time_window,
        )
        self._syn_flood = SYNFloodDetector(
            syn_threshold=thresholds.syn_flood.syn_count,
            time_window=thresholds.syn_flood.time_window,
        )
        self._dns_tunnel = DNSTunnelDetector(
            entropy_threshold=thresholds.dns_tunneling.entropy_threshold,
            min_length=thresholds.dns_tunneling.min_length,
        )

    async def evaluate(self, packet: Any) -> Anomaly | None:
        """
        Evaluate a scapy packet against all anomaly detectors.

        Extracts IP, TCP, UDP, and DNS layers from the packet and
        feeds relevant fields to each sub-detector.  Expired entries
        are pruned on every call.

        Args:
            packet: A scapy Packet object.

        Returns:
            The first Anomaly detected, or None if the packet is clean.
        """
        now = time.monotonic()

        # Prune expired entries from all detectors
        self._port_scan.prune(now)
        self._syn_flood.prune(now)
        self._dns_tunnel.prune(now)

        # Extract fields lazily -- scapy layers are accessed by name
        src_ip: str | None = None
        dst_ip: str | None = None
        src_port: int | None = None
        dst_port: int | None = None
        tcp_flags: int | None = None
        dns_query: str | None = None

        try:
            # Import scapy layer types
            from scapy.layers.inet import IP, TCP, UDP
            from scapy.layers.dns import DNS, DNSQR

            if packet.haslayer(IP):
                ip_layer = packet[IP]
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst

                if packet.haslayer(TCP):
                    tcp_layer = packet[TCP]
                    src_port = tcp_layer.sport
                    dst_port = tcp_layer.dport
                    tcp_flags = tcp_layer.flags

                elif packet.haslayer(UDP):
                    udp_layer = packet[UDP]
                    src_port = udp_layer.sport
                    dst_port = udp_layer.dport

            if packet.haslayer(DNS) and packet.haslayer(DNSQR):
                dns_layer = packet[DNSQR]
                raw_name = dns_layer.qname
                if isinstance(raw_name, bytes):
                    dns_query = raw_name.decode("utf-8", errors="ignore")
                else:
                    dns_query = str(raw_name)

        except Exception as exc:
            log.debug("packet_parse_error", error=str(exc))
            return None

        # --- Port scan detection ---
        if src_ip and dst_port is not None:
            anomaly = self._port_scan.evaluate(src_ip, dst_port, now)
            if anomaly:
                anomaly.destination_ip = dst_ip
                return anomaly

        # --- SYN flood detection ---
        if dst_ip and tcp_flags is not None:
            # SYN flag = 0x02, ACK flag = 0x10
            is_syn = bool(tcp_flags & 0x02) and not bool(tcp_flags & 0x10)
            is_ack = bool(tcp_flags & 0x10)

            if is_syn:
                self._syn_flood.record_syn(dst_ip, now)
                anomaly = self._syn_flood.evaluate(dst_ip, now)
                if anomaly:
                    anomaly.source_ip = src_ip
                    return anomaly
            elif is_ack:
                self._syn_flood.record_ack(dst_ip, now)

        # --- DNS tunneling detection ---
        if dns_query:
            anomaly = self._dns_tunnel.evaluate(dns_query, now)
            if anomaly:
                anomaly.source_ip = src_ip
                anomaly.destination_ip = dst_ip
                return anomaly

        return None
