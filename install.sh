#!/usr/bin/env bash
# install.sh — nethunter-TUI: instalace všech závislostí
# Spustit: chmod +x install.sh && ./install.sh
#
# Podporováno: Kali NetHunter (apt), standardní Kali/Debian (apt), Termux (pkg), Alpine (apk)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
APP_NAME="nethunter-TUI"
PYTHON="python3"

# ── Barvy ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC}  $1"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $1"; }
err()   { echo -e "${RED}[ERR]${NC}   $1"; }
header(){ echo -e "${BLUE}${BOLD}$1${NC}"; }

# ── Manuál ─────────────────────────────────────────────────────────────────

show_manual_cz() {
    cat << 'MANUAL_CZ'
╔══════════════════════════════════════════════════════════════╗
║              nethunter-TUI — Uživatelský manuál              ║
║         Interaktivní TUI pro síťové diagnostické nástroje     ║
╚════════════════════════════════════════════════════════════════╝

1. POPIS
   nethunter-TUI je terminálové uživatelské rozhraní (TUI) napsané
   v Pythonu, které poskytuje front-end pro síťové diagnostické
   nástroje. Je navržen speciálně pro Kali NetHunter na Androidu
   a nevyžaduje root oprávnění.

2. ARCHITEKTURA
   ┌──────────────────────────────────────────────┐
   │  run.py  →  main.py (hlavní menu)            │
   │             ├── nmap_tools.py   (nmap)        │
   │             ├── dns_tools.py    (dig/whois)   │
   │             ├── network_info.py (ip/trace)    │
   │             └── vpn_sniffer.py  (VPN)         │
   └──────────────────────────────────────────────┘
   Každý modul je samostatný a volá externí CLI nástroje
   (nmap, dig, ip, atd.) jako subprocessy.

3. POŽADAVKY
   • Python 3.8+ (doporučeno 3.10+)
   • InquirerPy (Python knihovna pro interaktivní CLI)
   • Nástroje: nmap, dig, whois, ip, traceroute, mtr, curl, wget
   • Některé nástroje jsou volitelné (mtr, whois, traceroute)
   • VPN modul vyžaduje Android VpnService (NetHunter)

4. INSTALACE
   chmod +x install.sh && ./install.sh
   Skript automaticky detekuje správce balíčků (apt/pkg/apk),
   nainstaluje všechny závislosti a ověří instalaci.

5. SPUŠTĚNÍ
   Po instalaci spustíš aplikaci příkazem:
     nethunter-tui

   Nebo ručně:
     cd /opt/nethunter-TUI && python3 run.py

6. STRUKTURA MENU
   Hlavní menu nabízí 5 sekcí:
   [1] Aktivní skenování (Nmap Connect Scan)
       - Skenuje otevřené porty na zadaném hostiteli
       - Používá nmap -sT -Pn (bez roota)
       - Podporuje vlastní rozsah portů
       - Volitelně detekuje OS a verze služeb

   [2] Lokální VPN Sniffer / TCP spojení
       - Dual-socket architektura:
         • vpn_control.sock ← JSON z onStateChangeListener
         • vpn_data.sock    ← raw PCAP binární stream
       - Zobrazuje stav VPN (🟢/🔴)
       - Umožňuje spustit / zastavit VPN službu
       - Streamuje data pomocí select() multiplexingu
       - Legacy režim pro zpětnou kompatibilitu

   [3] DNS a Reconnaissance (Dig / Whois)
       - DNS lookup s výběrem typu záznamu (A, AAAA, MX, TXT, NS, CNAME, SOA)
       - Whois lookup domén a IP adres
       - Fallback: host, pokud dig není k dispozici

   [4] Síťová konfigurace (IP / Routování)
       - Výpis IP adres všech rozhraní
       - Směrovací tabulka
       - DNS konfigurace (/etc/resolv.conf)
       - Sledování trasy (preferuje mtr, fallback traceroute)

   [5] Ukončit

7. VPN INTEGRACE (Android VpnService)
   Aplikace komunikuje s Android backendem přes Unix sockety:
   • Control socket: JSON zprávy z onStateChangeListener
     {"state": "started", "timestamp": 1234567890}
     {"state": "stopped", "timestamp": 1234567890}
   • Data socket: raw PCAP packet stream (binární)
   • TerminalActivity.kt registruje listener v onCreate()
     a odregistruje v onDestroy()
   • AndroidManifest.xml vyžaduje:
     <uses-permission android:name="android.permission.FOREGROUND_SERVICE_VPN" />
     <service ... android:foregroundServiceType="vpn" />

8. OŠETŘENÍ CHYB
   • Neexistující příkazy → nápověda s tipem na instalaci
   • Nepřístupný /proc/net/tcp → ošetřeno (chybí CAP_NET_ADMIN)
   • Neexistující VPN socket → nabídne spuštění služby
   • Timeout subprocessů → graceful ukončení s chybovou hláškou

9. SOUBORY
   /usr/bin/nethunter-tui       – spouštěč (symlink)
   /opt/nethunter-TUI/             – instalační adresář
   ├── run.py                      – vstupní bod
   ├── install.sh                  – tento instalační skript
   └── nethunter_tui/
       ├── __init__.py
       ├── main.py                 – hlavní menu + dispatcher
       ├── utils.py                – validace, subprocess helper, formátování
       ├── nmap_tools.py           – Nmap funkce
       ├── dns_tools.py            – DNS / whois funkce
       ├── network_info.py         – IP / routování / trace
       └── vpn_sniffer.py          – VPN socket stream

10. LADĚNÍ
    Problém: "ModuleNotFoundError: InquirerPy"
    → Řešení: pip3 install InquirerPy

    Problém: "nmap: command not found"
    → Řešení: apt install nmap (nebo spusť install.sh)

    Problém: "VPN socket neexistuje"
    → Řešení: Spusť VPN přes menu [2] → "Spustit VPN službu"
               nebo aktivuj VPN ručně v Android nastavení

    Problém: "/proc/net/tcp: Permission denied"
    → Řešení: Toto je normální v Android chrootu bez roota.
              Použij VPN Sniffer mód pro sledování provozu.

11. LICENCE
    nethunter-TUI je open-source nástroj pro bezpečnostní testování.
    Používej pouze na zařízeních, která vlastníš nebo máš
    explicitní povolení testovat.

──────────────────────────────────────────────────────────────────────────
MANUAL_CZ
echo ""
read -r -p "Stiskni Enter pro pokračování v instalaci… "
}

show_manual_en() {
    cat << 'MANUAL_EN'
╔══════════════════════════════════════════════════════════════╗
║              nethunter-TUI — User Manual                     ║
║        Interactive TUI for Network Diagnostic Tools          ║
╚════════════════════════════════════════════════════════════════╝

1. DESCRIPTION
   nethunter-TUI is a Terminal User Interface (TUI) written in
   Python that provides a front-end for network diagnostic tools.
   It is designed specifically for Kali NetHunter on Android
   and does NOT require root access.

2. ARCHITECTURE
   ┌──────────────────────────────────────────────┐
   │  run.py  →  main.py (main menu)              │
   │             ├── nmap_tools.py   (nmap)        │
   │             ├── dns_tools.py    (dig/whois)   │
   │             ├── network_info.py (ip/trace)    │
   │             └── vpn_sniffer.py  (VPN)         │
   └──────────────────────────────────────────────┘
   Each module is independent and invokes external CLI tools
   (nmap, dig, ip, etc.) as subprocesses.

3. REQUIREMENTS
   • Python 3.8+ (recommended 3.10+)
   • InquirerPy (Python library for interactive CLI)
   • Tools: nmap, dig, whois, ip, traceroute, mtr, curl, wget
   • Some tools are optional (mtr, whois, traceroute)
   • VPN module requires Android VpnService (NetHunter)

4. INSTALLATION
   chmod +x install.sh && ./install.sh
   The script auto-detects the package manager (apt/pkg/apk),
   installs all dependencies, and verifies the installation.

5. RUNNING
   After installation, launch the application with:
     nethunter-tui

   Or manually:
     cd /opt/nethunter-TUI && python3 run.py

6. MENU STRUCTURE
   The main menu offers 5 sections:

   [1] Active Scan (Nmap Connect Scan)
       - Scans open ports on a target host
       - Uses nmap -sT -Pn (no root required)
       - Supports custom port ranges
       - Optional OS and service version detection

   [2] Local VPN Sniffer / TCP Connections
       - Dual-socket architecture:
         • vpn_control.sock ← JSON from onStateChangeListener
         • vpn_data.sock    ← raw PCAP binary stream
       - Displays VPN status (🟢/🔴)
       - Start / stop VpnService
       - Data streaming via select() multiplexing
       - Legacy mode for backward compatibility

   [3] DNS & Reconnaissance (Dig / Whois)
       - DNS lookup with record type selection (A, AAAA, MX, TXT, NS, CNAME, SOA)
       - Whois lookup for domains and IP addresses
       - Falls back to host if dig is unavailable

   [4] Network Configuration (IP / Routing)
       - List IP addresses on all interfaces
       - Routing table display
       - DNS configuration (/etc/resolv.conf)
       - Trace route (prefers mtr, falls back to traceroute)

   [5] Exit

7. VPN INTEGRATION (Android VpnService)
   The application communicates with the Android backend via
   Unix sockets:
   • Control socket: JSON messages from onStateChangeListener
     {"state": "started", "timestamp": 1234567890}
     {"state": "stopped", "timestamp": 1234567890}
   • Data socket: raw PCAP packet stream (binary)
   • TerminalActivity.kt registers listener in onCreate()
     and unregisters in onDestroy()
   • AndroidManifest.xml requires:
     <uses-permission android:name="android.permission.FOREGROUND_SERVICE_VPN" />
     <service ... android:foregroundServiceType="vpn" />

8. ERROR HANDLING
   • Missing commands → help text with install hint
   • Inaccessible /proc/net/tcp → gracefully handled (no CAP_NET_ADMIN)
   • Missing VPN socket → prompts to start the service
   • Subprocess timeout → graceful exit with error message

9. FILES
   /usr/bin/nethunter-tui       – launcher (symlink)
   /opt/nethunter-TUI/             – installation directory
   ├── run.py                      – entry point
   ├── install.sh                  – this installer
   └── nethunter_tui/
       ├── __init__.py
       ├── main.py                 – main menu + dispatcher
       ├── utils.py                – validation, subprocess helper, formatting
       ├── nmap_tools.py           – Nmap functions
       ├── dns_tools.py            – DNS / whois functions
       ├── network_info.py         – IP / routing / trace
       └── vpn_sniffer.py          – VPN socket stream

10. TROUBLESHOOTING
    Issue: "ModuleNotFoundError: InquirerPy"
    → Fix: pip3 install InquirerPy

    Issue: "nmap: command not found"
    → Fix: apt install nmap (or run install.sh)

    Issue: "VPN socket does not exist"
    → Fix: Start VPN via menu [2] → "Start VPN service"
           or enable VPN manually in Android settings

    Issue: "/proc/net/tcp: Permission denied"
    → Fix: This is normal in Android chroot without root.
           Use VPN Sniffer mode to monitor traffic instead.

11. LICENSE
    nethunter-TUI is an open-source tool for security testing.
    Use only on devices you own or have explicit permission to test.

──────────────────────────────────────────────────────────────────────────
MANUAL_EN
echo ""
read -r -p "Press Enter to continue with installation… "
}

# ── Výběr jazyka / Language selection ──────────────────────────────────────

select_language() {
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║       nethunter-TUI — Installation Setup       ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "Select language / Vyber jazyk:"
    echo ""
    echo "  [1]  English  (default)"
    echo "  [2]  Čeština"
    echo ""
    read -r -p "Choice [1]: " LANG_CHOICE
    LANG_CHOICE="${LANG_CHOICE:-1}"

    case "$LANG_CHOICE" in
        2|cz|cs|cestina|čeština)
            LANGUAGE="cz"
            echo ""
            echo -e "${GREEN}→ Čeština vybrána${NC}"
            echo ""
            show_manual_cz
            ;;
        *)
            LANGUAGE="en"
            echo ""
            echo -e "${GREEN}→ English selected${NC}"
            echo ""
            show_manual_en
            ;;
    esac
}

# ── Detekce správce balíčků ────────────────────────────────────────────────
detect_pkg_manager() {
    if command -v apt &>/dev/null; then
        PKG_MANAGER="apt"
        INSTALL_CMD="apt install -y"
        UPDATE_CMD="apt update"
    elif command -v pkg &>/dev/null; then
        PKG_MANAGER="pkg"   # Termux
        INSTALL_CMD="pkg install -y"
        UPDATE_CMD="pkg update"
    elif command -v apk &>/dev/null; then
        PKG_MANAGER="apk"   # Alpine / ADB shell
        INSTALL_CMD="apk add"
        UPDATE_CMD="apk update"
    else
        err "Neznámý správce balíčků (apt/pkg/apk). Instaluj závislosti ručně."
        err "Unknown package manager. Install dependencies manually."
        exit 1
    fi
    info "Package manager: $PKG_MANAGER"
}

# ── Systémové balíčky ─────────────────────────────────────────────────────
SYSTEM_PACKAGES=()

install_system_packages() {
    info "Updating package lists..."
    $UPDATE_CMD

    if [[ "$PKG_MANAGER" == "apt" ]]; then
        SYSTEM_PACKAGES=(
            nmap              # Connect scan (-sT -Pn)
            dnsutils          # dig, host, nslookup
            whois             # Whois lookup
            traceroute        # Traceroute (fallback)
            mtr               # MTR (preferred traceroute)
            iproute2          # ip, ss
            curl              # HTTP tests
            wget              # HTTP downloads
            python3           # Python runtime
            python3-pip       # Python package manager
        )
    elif [[ "$PKG_MANAGER" == "pkg" ]]; then
        SYSTEM_PACKAGES=(
            nmap
            dnsutils
            whois
            traceroute
            mtr
            iproute2
            curl
            wget
            python
        )
    elif [[ "$PKG_MANAGER" == "apk" ]]; then
        SYSTEM_PACKAGES=(
            nmap
            bind-tools        # dig, host
            whois
            traceroute
            mtr
            iproute2
            curl
            wget
            python3
            py3-pip
        )
    fi

    info "Installing system packages..."
    $INSTALL_CMD "${SYSTEM_PACKAGES[@]}"
    ok "System packages installed."
}

# ── Python balíčky ────────────────────────────────────────────────────────
install_python_packages() {
    info "Installing Python dependencies (prompt_toolkit, InquirerPy)..."
    pip3 install --upgrade InquirerPy prompt_toolkit --user --break-system-packages 2>&1 | tail -5
    ok "Python dependencies installed."
}

# ── Vytvoření spouštěče / Create launcher ──────────────────────────────────

create_launcher() {
    local LAUNCHER="/usr/bin/nethunter-tui"
    local INSTALL_DIR="$SCRIPT_DIR"

    echo ""
    if [ "$LANGUAGE" = "cz" ]; then
        info "Vytvářím spouštěč: $LAUNCHER"
    else
        info "Creating launcher: $LAUNCHER"
    fi

    # Zajisti, že adresář existuje
    mkdir -p "$(dirname "$LAUNCHER")" 2>/dev/null || true

    # Zkus vytvořit symlink – pokud není oprávnění, zkus s sudo
    if ln -sf "$INSTALL_DIR/run.py" "$LAUNCHER" 2>/dev/null; then
        ok "nethunter-tui → $LAUNCHER"
    else
        if [ "$LANGUAGE" = "cz" ]; then
            warn "Nelze vytvořit symlink bez sudo. Zkouším s sudo..."
        else
            warn "Cannot create symlink without sudo. Trying with sudo..."
        fi
        if sudo ln -sf "$INSTALL_DIR/run.py" "$LAUNCHER" 2>/dev/null; then
            ok "nethunter-tui → $LAUNCHER (sudo)"
        else
            if [ "$LANGUAGE" = "cz" ]; then
                warn "Nepodařilo se vytvořit $LAUNCHER."
                warn "Přidání do PATH selhalo. Můžeš použít:"
                warn "  echo 'alias nethunter-tui=\"$INSTALL_DIR/run.py\"' >> ~/.bashrc"
                warn "  source ~/.bashrc"
            else
                warn "Failed to create $LAUNCHER."
                warn "PATH setup failed. You can use:"
                warn "  echo 'alias nethunter-tui=\"$INSTALL_DIR/run.py\"' >> ~/.bashrc"
                warn "  source ~/.bashrc"
            fi
        fi
    fi

    # Nastavit exec bit na run.py pokud není
    chmod +x "$INSTALL_DIR/run.py" 2>/dev/null || true
}

# ── Ověření ────────────────────────────────────────────────────────────────
verify_installation() {
    echo ""
    if [ "$LANGUAGE" = "cz" ]; then
        echo "──────────────────────────────────────────────"
        info "Ověřování instalace..."
    else
        echo "──────────────────────────────────────────────"
        info "Verifying installation..."
    fi
    echo ""

    local errors=0

    # Python modules
    if [ "$LANGUAGE" = "cz" ]; then
        echo "  Python moduly:"
    else
        echo "  Python modules:"
    fi
    for mod in InquirerPy pfzy prompt_toolkit; do
        if python3 -c "import $mod" 2>/dev/null; then
            ok "    $mod"
        else
            err "    $mod"
            errors=$((errors + 1))
        fi
    done

    # CLI tools
    echo ""
    if [ "$LANGUAGE" = "cz" ]; then
        echo "  CLI nástroje:"
    else
        echo "  CLI tools:"
    fi
    for cmd in nmap dig whois host traceroute mtr ip curl wget; do
        if command -v "$cmd" &>/dev/null; then
            ok "    $cmd ($(command -v "$cmd"))"
        else
            if [ "$LANGUAGE" = "cz" ]; then
                warn "    $cmd (volitelné – chybí)"
            else
                warn "    $cmd (optional – missing)"
            fi
        fi
    done

    echo ""
    if [ "$errors" -eq 0 ]; then
        if [ "$LANGUAGE" = "cz" ]; then
            ok "Všechny povinné závislosti jsou nainstalovány."
        else
            ok "All required dependencies are installed."
        fi
    else
        if [ "$LANGUAGE" = "cz" ]; then
            warn "Některé závislosti chybí – zkontroluj výše."
        else
            warn "Some dependencies are missing – check above."
        fi
    fi
}

# ── Závěrečná zpráva ───────────────────────────────────────────────────────

show_final_message() {
    echo ""
    echo "──────────────────────────────────────────────"
    if [ "$LANGUAGE" = "cz" ]; then
        echo -e "${GREEN} Instalace dokončena!${NC}"
        echo ""
        echo " Spuštění:"
        echo "   nethunter-tui"
        echo ""
        echo " Nebo ručně:"
        echo "   cd $SCRIPT_DIR && python3 run.py"
        echo ""
        echo " Nápověda:"
        echo "   nethunter-tui --help"
        echo ""
    else
        echo -e "${GREEN} Installation complete!${NC}"
        echo ""
        echo " Run:"
        echo "   nethunter-tui"
        echo ""
        echo " Or manually:"
        echo "   cd $SCRIPT_DIR && python3 run.py"
        echo ""
        echo " Help:"
        echo "   nethunter-tui --help"
        echo ""
    fi
}

# ── Hlavní spuštění ────────────────────────────────────────────────────────
main() {
    select_language
    detect_pkg_manager
    echo ""
    install_system_packages
    echo ""
    install_python_packages
    echo ""
    create_launcher
    echo ""
    verify_installation
    echo ""
    show_final_message
}

main "$@"
