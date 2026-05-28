# nethunter-TUI

Interactive Terminal User Interface (TUI) for network diagnostics, sniffing, and defensive operations, specifically designed for Kali NetHunter on Android.

## Project Overview

`nethunter-TUI` is a comprehensive security toolkit that provides a unified interface for various networking tools. It operates without requiring root access by leveraging Android's `VpnService` for sniffing and standard CLI tools for diagnostics.

### Main Technologies
- **Language:** Python 3.8+
- **TUI Framework:** `InquirerPy`, `prompt_toolkit`
- **Process Management:** PM2 (via `ecosystem.config.js`)
- **External Tools:** `nmap`, `dig`, `whois`, `iproute2`, `mtr`, `metasploit-framework`
- **Platform:** Kali NetHunter (Android), also compatible with standard Linux/Debian and Termux.

### Architecture
- **Front-end:** A multi-level TUI menu system (`nethunter_tui/main.py`).
- **Background Services:** Managed by PM2, including a honeypot daemon and a VPN logger.
- **Modules:**
    - `nmap_tools.py`: Active scanning using Nmap.
    - `dns_tools.py`: DNS lookups and Whois reconnaissance.
    - `network_info.py`: Local network configuration and path analysis.
    - `vpn_sniffer.py`: Interactive PCAP streaming via Unix sockets.
    - `honeypot.py`: Multi-port TCP honeypot engine with fake banners and payload capture.
    - `msf_controller.py`: Automated Metasploit counter-measures triggered by honeypot alerts.
    - `pm2_manager.py`: Internal wrapper for controlling background daemons.

## Building and Running

### Installation
Install all system and Python dependencies:
```bash
chmod +x install.sh
./install.sh
```

### Running the TUI
Launch the interactive interface:
```bash
python3 run.py
# Or after installation:
nethunter-tui
```

### Background Services (PM2)
Manage persistent daemons:
```bash
pm2 start ecosystem.config.js   # Start all (honeypot, vpn-logger, etc.)
pm2 status                      # Check status
pm2 logs                        # View background logs
pm2 stop nethunter-tui          # Stop specific service
```

## Development Conventions

- **Subprocess Integration:** The project relies heavily on `subprocess` to invoke external CLI tools. Use `nethunter_tui.utils.run_cmd` (or equivalent helpers) for consistent error handling and output parsing.
- **Non-Root Focus:** Tools are configured to run without root whenever possible (e.g., using Nmap's `-sT -Pn` flags).
- **Socket Communication:** VPN sniffing is handled through Unix sockets (`vpn_control.sock` and `vpn_data.sock`).
- **I18n:** The `install.sh` script provides both English and Czech documentation, though the TUI is primarily in Czech.
- **Logging:** Background services log to the `logs/` directory, managed by PM2.

## Project Structure
- `bin/`: Executable daemon scripts and watchdog tasks.
- `nethunter_tui/`: Core Python package containing module implementations.
- `scripts/`: Supplemental installation scripts (e.g., watchdog setup).
- `ecosystem.config.js`: PM2 configuration for all application components.
- `GEMINI.md`: This file.
