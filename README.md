# NetHunter Website Monitoring (No-Root TUI)

Interactive Terminal User Interface (TUI) for network diagnostics, sniffing, and defensive operations, specifically designed for Kali NetHunter on Android. This project focuses on monitoring and analyzing network traffic (including website monitoring) without requiring root access.

## Overview

`nethunter-website-monitoring-noroot` provides a unified interface for various networking tools. It operates without requiring root access by leveraging Android's `VpnService` for sniffing and standard CLI tools for diagnostics.

This project is best used in conjunction with [zombiegirlcz/kali_core_emulator](https://github.com/zombiegirlcz/kali_core_emulator.git).

### Key Features
- **Active Scanning:** Nmap Connect Scan (no root needed).
- **VPN Sniffer:** Real-time PCAP streaming via Android `VpnService`.
- **Packet Parser:** Application-layer inspection (HTTP, FTP, Telnet, SMTP) and credential detection.
- **DNS & Recon:** Advanced DNS lookups (dig) and Whois reconnaissance.
- **Honeypot:** Multi-port TCP honeypot with automated Metasploit counter-measures.
- **Background Services:** Managed via PM2 for persistence.
- **No-Root Focus:** All tools are configured to run within standard user permissions.

## Architecture

- **Front-end:** A multi-level TUI menu system built with `InquirerPy`.
- **Background Services:** Managed by PM2, including a honeypot daemon and a VPN logger.
- **VPN Sniffing:** Communicates with the Android backend via Unix sockets or HTTP/TCP streams for non-root packet capture.

## Installation

```bash
chmod +x install.sh
./install.sh
```

The installer supports Kali NetHunter (apt), standard Kali/Debian (apt), Termux (pkg), and Alpine (apk).

## Usage

Launch the interactive interface:
```bash
nethunter-tui
# or
python3 run.py
```

### Background Services (PM2)
Manage persistent daemons:
```bash
pm2 start ecosystem.config.js   # Start all (honeypot, vpn-logger, etc.)
pm2 status                      # Check status
pm2 logs                        # View background logs
```

## Related Projects
- [kali_core_emulator](https://github.com/zombiegirlcz/kali_core_emulator.git) - Core emulator environment for Kali NetHunter.

## License
nethunter-TUI is an open-source tool for security testing. Use only on devices you own or have explicit permission to test.
