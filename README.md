# GATEKEEP

**AI-powered home network security scanner and threat dashboard.**

GATEKEEP scans your home network, identifies every connected device, checks for known vulnerabilities and indicators of compromise, and uses Claude to explain what it finds in plain language — no cybersecurity degree required.

![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue)
![License GPL v3](https://img.shields.io/badge/license-GPL%20v3-blue)
![Platform Windows 11](https://img.shields.io/badge/platform-Windows%2011-lightgrey)
![Contributions Welcome](https://img.shields.io/badge/contributions-welcome-brightgreen)

## Features

- **One-click network scan** — discovers all devices, open ports, and services on your network
- **AI-powered threat analysis** — Claude reviews findings and writes a plain-language security report with A–F grade
- **Router integration** — pulls device lists and DNS settings directly from your router's admin panel
- **Device identification** — SSDP/UPnP and NetBIOS discovery names every device on your network
- **DNS integrity verification** — detects if your DNS has been hijacked to redirect your traffic
- **Real-time monitoring** — live packet capture with anomaly detection (port scans, SYN floods, DNS tunneling)
- **Firewall advisor** — AI-generated firewall rules tailored to your network
- **Baseline tracking** — save your network state and get alerted when things change
- **100% local** — all data stays on your machine, no cloud, no telemetry

## Quick Start

```bash
git clone https://github.com/syntaxdiffusion/GATEKEEP.git
cd GATEKEEP
pip install -r requirements.txt
python run.py
```

Open **http://127.0.0.1:8443** in your browser.

### Requirements

- **Python 3.11+**
- **Claude Code** with `claude-agent-sdk` — GATEKEEP uses your existing Claude Code authentication (no separate API key needed)
- **Windows 11** (primary platform — Linux/macOS contributions welcome)
- **Npcap** (optional) — enables ARP scanning and packet capture. Install from [npcap.com](https://npcap.com/) with "WinPcap API-compatible Mode" checked. Without it, GATEKEEP falls back to ping sweep + ARP table parsing.

### Running as Administrator

For full functionality (device discovery via ARP, packet capture, monitoring):

```bash
# Right-click terminal → Run as administrator
cd GATEKEEP
python run.py
```

## Threat Intelligence

GATEKEEP ships with indicators of compromise (IOCs) from publicly disclosed campaigns targeting home routers:

- **FrostArmada** — DNS hijacking campaign targeting TP-Link routers via CVE-2023-50224 (18,000+ devices across 120 countries)
- **Operation Dying Ember** — Moobot malware targeting Ubiquiti EdgeRouters

### IOC Sources

- [FBI IC3 PSA260407](https://www.ic3.gov/PSA/2026/PSA260407) — Operation Masquerade
- [UK NCSC Advisory](https://www.ncsc.gov.uk/news/apt28-exploit-routers-to-enable-dns-hijacking-operations) — APT28 DNS Hijacking
- [NSA/DoD CSA Feb 2024](https://media.defense.gov/2024/Feb/27/2003400753/-1/-1/0/CSA-Russian-Actors-Use-Routers-Facilitate-Cyber_Operations.PDF) — Operation Dying Ember
- [Lumen Black Lotus Labs](https://www.lumen.com/blog-and-news/en-us/frostarmada-forest-blizzard-dns-hijacking) — FrostArmada Analysis

### What It Checks For

**APT28 / FrostArmada indicators:**
- DNS servers redirected to known malicious ranges
- DNS resolution of Microsoft Outlook domains pointing to non-Microsoft IPs
- Open ports associated with SSH tunnel backdoors (TCP 56777, 35681)
- Known-vulnerable router models (TP-Link TL-WR841N, Archer C5/C7, Ubiquiti EdgeRouters, MikroTik RouterBOARD)

**General network hygiene:**
- Unknown or rogue devices
- Randomized MAC addresses
- Unnecessary open ports and services
- Router firmware status

## Architecture

```
Browser Dashboard (localhost:8443)
    ↕ REST API + WebSocket
FastAPI Application
    ├── Scan Engines (network_scanner, dns_checker, port_scanner, router_fingerprint)
    ├── Discovery (SSDP/UPnP, NetBIOS)
    ├── Router Admin (Fios/Sagemcom CGI API integration)
    ├── AI Analyzer (Claude Agent SDK)
    ├── Monitoring (packet capture, anomaly detection, IOC matching)
    ├── Hardening (firewall rules, baseline drift)
    └── SQLite Database (WAL mode)
```

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.11+ / FastAPI / Uvicorn |
| AI | Claude Agent SDK (uses Claude Code auth) |
| Network | scapy (optional) / ping sweep / ARP table |
| Discovery | SSDP/UPnP multicast, NetBIOS queries |
| Database | SQLite with WAL mode (aiosqlite) |
| Frontend | Vanilla HTML/CSS/JS (dark cybersecurity theme) |
| Real-time | WebSocket for live alerts and monitoring |

## API

### Scanning
- `POST /api/v1/scans` — Start a network scan
- `GET /api/v1/scans/{id}` — Get scan results with AI analysis
- `GET /api/v1/devices` — List all discovered devices

### Router Admin
- `POST /api/v1/router/connect` — Authenticate with your router
- `GET /api/v1/router/devices` — Get router's connected device list
- `GET /api/v1/router/info` — Get router model, firmware, DNS settings

### Monitoring
- `POST /api/v1/monitor/start` — Start real-time packet capture
- `GET /api/v1/alerts` — View security alerts
- `WS /ws/events` — WebSocket for live updates

### Hardening
- `GET /api/v1/hardening/recommendations` — Get firewall rules
- `POST /api/v1/baselines` — Save network baseline
- `GET /api/v1/baselines/{id}/drift` — Check for network changes

Full interactive API docs at **http://127.0.0.1:8443/docs** (Swagger UI).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for details. We especially need help with:

- **Router integrations** — Netgear, ASUS, TP-Link, Linksys, Ubiquiti, OpenWrt, MikroTik
- **Linux/macOS support** — currently Windows-only
- **IOC updates** — new threat campaign indicators as they're disclosed
- **UI/UX improvements** — mobile responsiveness, accessibility, themes

## Disclaimer

GATEKEEP is a defensive security tool for scanning your own network. It does not exploit vulnerabilities, attempt unauthorized access, or modify router settings. The AI analysis is advisory — always verify findings independently. This tool is not a replacement for professional security assessment.

## License

[GPL v3](LICENSE) — free to use, modify, and share. Keep it open.
