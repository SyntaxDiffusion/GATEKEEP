# Contributing to GATEKEEP

Thanks for your interest in making home networks safer. Here's how to help.

## Ways to Contribute

### Router Integrations
GATEKEEP currently supports Verizon Fios (Sagemcom/CR1000A) routers. We need integrations for:
- Netgear (Nighthawk, Orbi)
- ASUS (RT, ZenWiFi)
- TP-Link (Archer, Deco)
- Linksys (Velop)
- Ubiquiti (UniFi, EdgeRouter)
- OpenWrt / DD-WRT
- MikroTik RouterOS

### Platform Support
Currently Windows-only. Help wanted for:
- Linux support (replace ipconfig parsing, Npcap → libpcap)
- macOS support

### IOC Updates
As new threat campaigns are disclosed, IOC indicators need updating:
- Add new IP ranges, domains, and port indicators to `gatekeep/ioc/apt28_indicators.json`
- Submit pull requests with source references (government advisories, security vendor reports)

### UI/UX
- The dashboard is vanilla HTML/CSS/JS — no framework lock-in
- Mobile responsiveness improvements
- Accessibility (ARIA, keyboard navigation)
- Dark/light theme toggle

### Documentation
- Setup guides for different environments
- Router-specific configuration guides
- Translation/internationalization

## Development Setup

```bash
git clone https://github.com/syntaxdiffusion/GATEKEEP.git
cd GATEKEEP
pip install -r requirements.txt
python run.py
```

API docs at http://127.0.0.1:8443/docs

## Code Style

- Python: type hints on public functions, structlog for logging, async/await throughout
- JavaScript: vanilla ES2020+, no frameworks, no build step
- Keep it simple — this tool is for home users, not enterprises

## Submitting Changes

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/netgear-support`)
3. Make your changes
4. Test locally (run a scan, check the dashboard)
5. Submit a PR with a clear description of what and why

## Security

If you discover a security vulnerability in GATEKEEP itself, please report it privately via GitHub Security Advisories rather than opening a public issue.
