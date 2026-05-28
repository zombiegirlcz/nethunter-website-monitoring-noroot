"""VPN Sniffer – hybrid HTTP/TCP + Unix socket fallback.

The Android VpnService (nethunteraioperator) exposes:
  - Port 1337 (HTTP API):  GET /vpn → {"running":bool, "packets":N, "bytes":N}
  - Port 13338 (TCP raw):  PCAP binary stream (24 B global hdr + 16 B record hdr + packet)

When the HTTP API is reachable it is used as the primary status source;
when TCP port 13338 is reachable it is used as the primary data stream.
Unix sockets (vpn_control.sock / vpn_data.sock) are kept as fallback for
older / alternative VPN implementations.

Legacy architecture (Unix socket fallback):
  Android VpnService (foregroundServiceType="vpn", API 34+)
    ├─ onStateChangeListener fires on startVpn()/stopVpn()
    │    └── writes JSON to vpn_control.sock
    ├─ VpnService.Builder establishes tun interface
    │    └── writes raw packets to vpn_data.sock
    └─ TerminalActivity.kt registers listener in onCreate()
         and unregisters in onDestroy()
"""

import json
import socket
import os
import time
import subprocess
import urllib.request
import urllib.error
from typing import Optional, Tuple

from .utils import get_my_ip, check_binary

from InquirerPy import inquirer

from .utils import heading, check_binary, run_cmd
from .packet_parser import process_packet, format_pcap_summary, format_log_line

import ipaddress

# Logovací soubor – kořen projektu (jeden adresář nad nethunter_tui/)
_VPN_LOG = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "vpn_internal.log",
)


# Socket paths – adjustable per your setup
#   vpn_control.sock – JSON state messages from onStateChangeListener
#   vpn_data.sock    – Raw PCAP binary stream
#
# Default Android path (outside chroot): /data/data/com.offensive.security.nethunter/files/
# If not accessible, try:
#   1. Set NETHUNTER_TUI_VPN_DIR env var
#   2. Create a bind-mount: mount --bind /data/data/com.offensive.security.nethunter/files /data/local/nhsystem/kali-arm64/...
#   3. Configure VpnService to write to /tmp/ or another chroot-accessible path
_BASE_CANDIDATES = [
    os.environ.get("NETHUNTER_TUI_VPN_DIR", ""),           # 1. Env var override
    "/data/data/com.offensive.security.nethunter/files",   # 2. Default Android (bind-mount)
    "/data/data/com.offensive.security.kalifs/files",      # 3. Alternative NetHunter
    os.path.expanduser("~/.local/share/nethunter-tui/vpn"),# 4. User-writable (symlink target)
    "/tmp/nethunter-tui/vpn",                              # 5. /tmp (chroot-safe)
]

CTRL_SOCK_NAME = "vpn_control.sock"
DATA_SOCK_NAME = "vpn_data.sock"
LEGACY_SOCK_NAME = "vpn.sock"

# Resolved at runtime on first access
_BASE_DIR = None
CTRL_SOCK = ""
DATA_SOCK = ""


def _resolve_base_dir() -> str:
    """Projde kandidáty a vrátí první existující adresář se socketem."""
    global _BASE_DIR, CTRL_SOCK, DATA_SOCK

    if _BASE_DIR:
        return _BASE_DIR

    for d in _BASE_CANDIDATES:
        if not d:
            continue
        ctrl = os.path.join(d, CTRL_SOCK_NAME)
        data = os.path.join(d, DATA_SOCK_NAME)
        legacy = os.path.join(d, LEGACY_SOCK_NAME)
        if os.path.exists(ctrl) or os.path.exists(data) or os.path.exists(legacy):
            _BASE_DIR = d
            CTRL_SOCK = ctrl
            DATA_SOCK = data
            return _BASE_DIR

    # Fallback: use first non-empty candidate (default Android path)
    fallback = [d for d in _BASE_CANDIDATES if d][0]
    _BASE_DIR = fallback
    CTRL_SOCK = os.path.join(fallback, CTRL_SOCK_NAME)
    DATA_SOCK = os.path.join(fallback, DATA_SOCK_NAME)
    return _BASE_DIR


# Call once at module init
_resolve_base_dir()


# ── Stav VPN služby (HTTP API + Unix socket fallback) ────────────────────────

_VPN_HTTP_URL = "http://127.0.0.1:1337/vpn"
_VPN_TCP_HOST = "127.0.0.1"
_VPN_TCP_PORT = 13338


def _http_get_vpn_status() -> Optional[dict]:
    """
    Zkusí HTTP GET na 127.0.0.1:1337/vpn.
    Vrací dict s klíči running/packets/bytes nebo None při chybě.
    """
    try:
        req = urllib.request.Request(_VPN_HTTP_URL, method="GET")
        with urllib.request.urlopen(req, timeout=2) as resp:
            if resp.status != 200:
                return None
            raw = resp.read().decode("utf-8", errors="replace")
            data = json.loads(raw)
            return {
                "running": bool(data.get("running", False)),
                "packets": int(data.get("packets", 0)),
                "bytes": int(data.get("bytes", 0)),
            }
    except (urllib.error.URLError, urllib.error.HTTPError,
            json.JSONDecodeError, OSError, socket.timeout):
        return None


def get_vpn_status() -> dict:
    """
    Zjistí aktuální stav VPN služby.
    Priorita: 1) HTTP API (127.0.0.1:1337/vpn)  2) Unix socket fallback

    Returns dict s klíči:
      - running (bool):  VPN běží
      - detail   (str):  stavová hláška
      - mode     (str):  "http-api" nebo "unix-socket" / "single"
      - packets  (int):  zachycené pakety (pouze HTTP režim)
      - bytes_   (int):  zachycené bajty (pouze HTTP režim)
      - ctrl_path / data_path / sock_exists (pouze Unix fallback)
    """
    # ── 1. Zkus HTTP API ──────────────────────────────────────────────
    http_status = _http_get_vpn_status()
    if http_status is not None:
        detail = f"HTTP 1337/vpn: "
        if http_status["running"]:
            detail += f"running, {http_status['packets']} paketů, {http_status['bytes']} B"
        else:
            detail += "stopped"
        return {
            "running": http_status["running"],
            "detail": detail,
            "mode": "http-api",
            "packets": http_status["packets"],
            "bytes_": http_status["bytes"],
            "ctrl_path": "",
            "data_path": "",
            "sock_exists": False,
        }

    # ── 2. Fallback: Unix sockety ─────────────────────────────────────
    result = {
        "running": False,
        "ctrl_path": CTRL_SOCK,
        "data_path": DATA_SOCK,
        "detail": "",
        "mode": "single",
        "sock_exists": False,
        "packets": 0,
        "bytes_": 0,
    }

    ctrl_exists = os.path.exists(CTRL_SOCK)
    data_exists = os.path.exists(DATA_SOCK)

    if not ctrl_exists and not data_exists:
        old_sock = os.path.join(_resolve_base_dir(), LEGACY_SOCK_NAME)
        if os.path.exists(old_sock):
            result["running"] = True
            result["mode"] = "single"
            result["sock_exists"] = True
            result["detail"] = "single-socket režim (legacy)"
            return result
        # HTTP API neodpověděl a sockety neexistují → VPN určitě neběží
        result["detail"] = "HTTP 1337/vpn: connection refused; sockety nenalezeny"
        return result

    if ctrl_exists:
        result["mode"] = "dual"
        result["sock_exists"] = True
        result["running"] = True
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect(CTRL_SOCK)
            raw = s.recv(4096)
            s.close()
            if raw:
                decoded = raw.decode("utf-8", errors="replace").strip()
                try:
                    parsed = json.loads(decoded)
                    if isinstance(parsed, dict):
                        state = parsed.get("state", "")
                        timestamp = parsed.get("timestamp", "")
                        if state == "started":
                            result["detail"] = f"onStateChange=started @ {timestamp}"
                        elif state == "stopped":
                            result["running"] = False
                            result["detail"] = f"onStateChange=stopped @ {timestamp}"
                        else:
                            result["detail"] = decoded.strip()
                    else:
                        result["detail"] = decoded
                except json.JSONDecodeError:
                    result["detail"] = decoded
        except (ConnectionRefusedError, socket.timeout, OSError):
            result["detail"] = "socket existuje, ale nelze číst"

    if data_exists and not ctrl_exists:
        result["running"] = True
        result["mode"] = "dual (data only)"
        result["detail"] = "data socket existuje, control chybí"

    return result


def show_vpn_status() -> None:
    """Zobrazí stav VPN služby – HTTP API + Unix socket fallback."""
    status = get_vpn_status()
    mode_icon = {
        "http-api": "🔵 HTTP API",
        "dual": "🔵 Dual-socket",
        "single": "🟡 Legacy single",
    }
    mode_str = mode_icon.get(status["mode"], "⚪ " + status["mode"])

    print(heading("Stav VPN služby"))
    print(f"  Režim:     {mode_str}")
    print(f"  Stav:      {'🟢 BĚŽÍ' if status['running'] else '🔴 NEBĚŽÍ'}")
    if status["detail"]:
        print(f"  Detail:    {status['detail']}")

    if status["mode"] == "http-api":
        print(f"  Pakety:    {status.get('packets', 0)}")
        print(f"  Bajty:     {status.get('bytes_', 0)}")
        print(f"  API:       {_VPN_HTTP_URL}")
        print(f"  PCAP:      tcp://{_VPN_TCP_HOST}:{_VPN_TCP_PORT}")
    else:
        print(f"  Control:   {status['ctrl_path']}")
        print(f"  Data:      {status['data_path']}")
        ex = []
        if os.path.exists(status.get('ctrl_path', '')):
            ex.append("CTRL")
        if os.path.exists(status.get('data_path', '')):
            ex.append("DATA")
        print(f"  Existuje:  {'✅ ' + ' '.join(ex) if ex else '❌'}")

    print()

    if status["running"]:
        print("  Pro stream → zvol 'Stream z VPN data socketu'.")
    else:
        print("  VPN není aktivní nebo API/sockety nejsou dostupné.")
        print()
        print("  👉 Pokud máš ikonu klíče v Android liště, VPN běží –")
        print("     jen sockety/API nejsou z chrootu dostupné.")
        print()
        print("  Možnosti:")
        print("    • Export NETHUNTER_TUI_VPN_DIR=/cesta/k/socketum")
        print("    • Bind-mount: mount --bind /data/data/... <cesta_v_chrootu>")
        print("    • Spusť 'Zobrazit aktivní TCP spojení' pro náhled")
    print()


def _find_am() -> Optional[str]:
    """Najde cestu k 'am' (Android Activity Manager) v NetHunter chrootu."""
    candidates = [
        "am",                       # v PATH (shell wrapper, adb shell)
        "/system/bin/am",           # Android native path (běžně bind-mounted)
    ]
    for path in candidates:
        if check_binary(path) or os.path.exists(path):
            return path
    return None


def _am_cmd(action: str, *args: str) -> Optional[list]:
    """Sestaví seznam příkazů pro 'am' s nalezenou cestou."""
    am = _find_am()
    if not am:
        return None
    return [am, action, *args]


def _run_am(action: str, *args: str, timeout: int = 5) -> Tuple[int, str, str]:
    """Spustí 'am' příkaz a vrátí (ret, out, err)."""
    cmd = _am_cmd(action, *args)
    if not cmd:
        return (127, "", "'am' nebyl nalezen v systému.\n"
                "Zkus:   su -c 'am ...'\n"
                "Nebo aktivuj VPN profil ručně v Androidu.")
    try:
        return run_cmd(cmd, timeout=timeout)
    except (FileNotFoundError, OSError):
        return (127, "", f"Příkaz '{cmd[0]}' selhal – chybí binárka nebo oprávnění.")


def _start_vpn_service() -> bool:
    """
    Spustí Android VpnService přes 'am' příkaz.
    Na Androidu vyvolá systémový dialog s žádostí o povolení VPN (první spuštění).
    """
    # Zkusíme nejdřív běžnou cestu pro NetHunter VpnService
    candidates = [
        # NetHunter AI Operator
        "com.offensive.security.nethunter/.VpnService",
        "com.offensive.security.nethunter/.services.VpnService",
        "com.offensive.security.nethunter/.vpn.VpnService",
        # Obecný fallback
    ]

    for svc in candidates:
        ret, out, err = _run_am("start-foreground-service", "-n", svc)
        if ret == 0:
            print(f"  ✓ VPN služba spuštěna: {svc}")
            return True
        # Ignorujeme "not found" a zkusíme další

    # Pokud nic nefunguje, zkus obecný intent
    ret, out, _ = _run_am(
        "start-foreground-service",
        "-a", "com.offensive.security.nethunter.action.START_VPN",
    )
    if ret == 0:
        print("  ✓ VPN služba spuštěna (action.START_VPN)")
        return True

    print("  [!] Nelze spustit VPN službu – není nainstalovaná nebo nemáš oprávnění.")
    print("      Zkus spustit VPN ručně v Androidu.")
    return False


def _stop_vpn_service() -> bool:
    """Zastaví Android VpnService přes 'am' příkaz."""
    base = _resolve_base_dir()
    pkg = base.replace("/data/data/", "").split("/")[0] if "/data/data/" in base else "com.offensive.security.nethunter"

    ret, out, err = _run_am("stopservice", "-n", f"{pkg}/.VpnService")
    if ret == 0:
        print("  ✓ VPN služba zastavena")
        return True

    # Fallback: zkus action-based stop
    ret, out, _ = _run_am("stopservice", "-a", f"{pkg}.action.STOP_VPN")
    if ret == 0:
        print("  ✓ VPN služba zastavena (action.STOP_VPN)")
        return True

    print("  [!] Nelze zastavit VPN službu.")
    return False


# ── Streamování dat (TCP PCAP + Unix socket fallback) ─────────────────────

def _tcp_pcap_connect() -> Optional[socket.socket]:
    """
    Zkusí TCP connect na 127.0.0.1:13338 (PCAP stream z VpnCaptureService).
    Vrací socket nebo None.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((_VPN_TCP_HOST, _VPN_TCP_PORT))
        print(f"✅ TCP PCAP stream: {_VPN_TCP_HOST}:{_VPN_TCP_PORT}")
        return s
    except (ConnectionRefusedError, socket.timeout, OSError):
        return None


def _stream_tcp_pcap_daemon(sock: socket.socket, log_path: str) -> None:
    """
    Daemonová verze — žádné InquirerPy, žádné ANSI escape kódy.
    Čte binární PCAP data z TCP socketu (port 13338), parsuje je
    a zapisuje POUZE textové log řádky do souboru (žádný JSON,
    žádný binární výstup na tento kanál).
    """
    import struct
    import ipaddress
    import os

    from .logo import C
    from .packet_parser import process_packet, format_pcap_summary, format_log_line

    buf = b""
    parsed_global = False
    link_type = 1
    byte_count = 0
    packet_count = 0
    start = time.monotonic()

    sock.setblocking(False)
    from select import select

    try:
        while True:
            ready, _, _ = select([sock], [], [], 1.0)
            if not ready:
                if not parsed_global:
                    elapsed = time.monotonic() - start
                    print(f"\r  ⏳ Připojuji se... ⏱ {elapsed:.0f}s  ", end="", flush=True)
                continue

            chunk = sock.recv(65536)
            if not chunk:
                print("\n[i] TCP spojení uzavřeno.")
                break

            # PCAP global header
            if not parsed_global:
                need = 24 - len(buf)
                if len(chunk) < need:
                    buf += chunk
                    continue
                hdr_bytes = buf + chunk[:need]
                chunk = chunk[need:]
                buf = b""
                link_type = int.from_bytes(hdr_bytes[20:24], "little")
                print(f"\r  [i] PCAP connected, link_type={link_type}  ")
                parsed_global = True

            # Zpracování PCAP záznamů
            buf += chunk
            while True:
                if len(buf) < 16:
                    break
                incl_len = struct.unpack("<I", buf[8:12])[0]
                record_total = 16 + incl_len
                if len(buf) < record_total:
                    break

                pkt_data = buf[16:record_total]
                buf = buf[record_total:]

                byte_count += incl_len
                packet_count += 1

                parsed = process_packet(pkt_data, link_type)
                ip_hdr = parsed.get("ip_header", {})
                pkt_src = ip_hdr.get("src", "")
                pkt_dst = ip_hdr.get("dst", "")

                # Filtr: jen privátní IP
                try:
                    src_priv = ipaddress.ip_address(pkt_src).is_private or ipaddress.ip_address(pkt_src).is_loopback
                    dst_priv = ipaddress.ip_address(pkt_dst).is_private or ipaddress.ip_address(pkt_dst).is_loopback
                except (ValueError, TypeError):
                    src_priv = dst_priv = False
                if not src_priv and not dst_priv:
                    continue

                # Sestavit log line — využít packet_parser.format_log_line
                log_line = format_log_line(parsed)
                try:
                    with open(log_path, "a") as log_fh:
                        log_fh.write(log_line + "\n")
                except OSError:
                    pass

    except Exception as e:
        print(f"\n[ERROR] {e}")

    sock.close()
    elapsed = time.monotonic() - start
    print(f"[i] Daemon ukončen: {packet_count} paketů, {elapsed:.0f}s")


def _stream_tcp_pcap(sock: socket.socket) -> None:
    """
    Streamuje binární PCAP data z TCP socketu (port 13338).
    Parsuje PCAP záznamy, rozebírá IP/TCP/UDP hlavičky a zobrazuje
    živý přehled paketů + dashboard.
    """
    global _display_height
    _display_height = 0  # reset výšky displaye
    timeout = inquirer.text(
        message="Doba odposlechu (sekund, 0 = vždy do Ctrl+C):",
        default="10",
        validate=lambda t: t.strip().isdigit(),
        invalid_message="Zadej číslo.",
    ).execute()

    duration = int(timeout.strip())
    from select import select
    import struct

    from .logo import C  # barevné konstanty

    duration_str = "∞ (Ctrl+C)" if duration == 0 else f"{duration}s"
    my_ip = get_my_ip()

    print(heading("📡 VPN Sniffer – živý přehled"))
    print(f"{C.CYAN}  Lokální IP:{C.RESET} {my_ip}")
    print(f"{C.CYAN}  Zdroj:{C.RESET}      {_VPN_TCP_HOST}:{_VPN_TCP_PORT} (TCP PCAP)")
    print(f"{C.CYAN}  Délka:{C.RESET}      {duration_str}")
    print()

    start = time.monotonic()
    end_time = start + duration if duration > 0 else None
    byte_count = 0
    packet_count = 0
    parsed_global = False
    link_type = 1  # default Ethernet

    # Buffer pro nedokončené PCAP záznamy
    buf = b""
    # Sledování statistik
    unique_dsts: set = set()
    proto_counts: dict = {}
    interesting_packets = 0
    MAX_LIVE_PKTS = 10  # kolik posledních paketů zobrazit v tabulce
    live_packets: list = []  # cirkulární buffer pro tabulku

    try:
        sock.setblocking(False)
        while True:
            if end_time and time.monotonic() >= end_time:
                break
            remaining = max(end_time - time.monotonic(), 0.5) if end_time else 1.0
            ready, _, _ = select([sock], [], [], remaining)
            if not ready:
                elapsed = time.monotonic() - start
                if packet_count > 0:
                    # Už máme pakety → překreslit celý view
                    _draw_vpn_view(my_ip, link_type, live_packets,
                                   packet_count, byte_count, elapsed,
                                   proto_counts, interesting_packets)
                elif parsed_global:
                    # Globální hlavička načtená, čekáme na pakety
                    print(f"\r  ⏳ Čekám na pakety... ⏱ {elapsed:.0f}s  ", end="", flush=True)
                else:
                    # Čekáme na první data (globální hlavičku)
                    print(f"\r  ⏳ Připojuji se k {_VPN_TCP_HOST}:{_VPN_TCP_PORT}... ⏱ {elapsed:.0f}s  ", end="", flush=True)
                continue

            chunk = sock.recv(65536)
            if not chunk:
                print(f"\n{C.CYAN}[i]{C.RESET} TCP spojení uzavřeno (VpnCaptureService skončil).")
                break

            # ── PCAP global header ──────────────────────────────────────
            if not parsed_global:
                need = 24 - len(buf)
                if len(chunk) < need:
                    buf += chunk
                    continue
                hdr_bytes = buf + chunk[:need]
                chunk = chunk[need:]
                buf = b""

                magic = hdr_bytes[:4].hex()
                linktype_raw = int.from_bytes(hdr_bytes[20:24], "little")
                link_names = {1: "Ethernet", 101: "Raw IP", 0: "Null/Loopback"}
                link_type = linktype_raw
                print()  # odřádkovat po waiting zprávě
                print(f"{C.CYAN}  📋 PCAP Global Header:{C.RESET} magic=0x{magic}, "
                      f"link_type={link_names.get(linktype_raw, linktype_raw)}")
                print()
                parsed_global = True

            # ── Zpracování PCAP záznamů ─────────────────────────────────
            buf += chunk
            while True:
                if len(buf) < 16:
                    break  # potřeba víc dat pro record header

                # Record header: ts_sec(4), ts_usec(4), incl_len(4), orig_len(4)
                incl_len = struct.unpack("<I", buf[8:12])[0]
                record_total = 16 + incl_len

                if len(buf) < record_total:
                    break  # čekáme na zbytek dat

                pkt_data = buf[16:record_total]
                buf = buf[record_total:]

                byte_count += incl_len
                packet_count += 1

                # Parsovat paket přes packet_parser
                parsed = process_packet(pkt_data, link_type)
                summary = format_pcap_summary(parsed)

                # Filtrovat pouze interní IP (10.x, 172.16-31.x, 192.168.x, 127.x)
                ip_hdr = parsed.get("ip_header", {})
                pkt_src = ip_hdr.get("src", "")
                pkt_dst = ip_hdr.get("dst", "")
                try:
                    src_priv = ipaddress.ip_address(pkt_src).is_private or ipaddress.ip_address(pkt_src).is_loopback
                    dst_priv = ipaddress.ip_address(pkt_dst).is_private or ipaddress.ip_address(pkt_dst).is_loopback
                except (ValueError, TypeError):
                    src_priv = dst_priv = False
                if not src_priv and not dst_priv:
                    continue

                # Logovat interní pakety do souboru — využít packet_parser.format_log_line
                log_line = format_log_line(parsed)
                try:
                    with open(_VPN_LOG, "a") as log_fh:
                        log_fh.write(log_line + "\n")
                except OSError:
                    pass

                # Sledovat statistiky
                transport = parsed.get("transport", {})
                proto = transport.get("protocol", "?")
                proto_counts[proto] = proto_counts.get(proto, 0) + 1

                ip_hdr = parsed.get("ip_header", {})
                dst = ip_hdr.get("dst", "")
                if dst:
                    unique_dsts.add(dst)

                app = parsed.get("app_layer", {})
                if app.get("interesting"):
                    interesting_packets += 1

                # Přidat do živé tabulky
                ts = time.strftime("%H:%M:%S", time.localtime())
                flags_tcp = ""
                t_hdr = transport.get("header", {})
                if proto == "tcp":
                    fl = t_hdr.get("flags", {})
                    fl_str = "".join(k[0].upper() for k, v in fl.items() if v)
                    if fl_str:
                        flags_tcp = f" [{fl_str}]"

                entry = {
                    "ts": ts,
                    "summary": summary,
                    "proto": proto.upper(),
                    "len": incl_len,
                    "interesting": app.get("interesting", False),
                    "tags": app.get("tags", []),
                    "creds": app.get("credentials", []),
                    "flags": flags_tcp,
                }
                live_packets.append(entry)
                if len(live_packets) > MAX_LIVE_PKTS:
                    live_packets.pop(0)

                # Vykreslit tabulku
                elapsed = time.monotonic() - start
                _draw_vpn_view(my_ip, link_type, live_packets,
                               packet_count, byte_count, elapsed,
                               proto_counts, interesting_packets)

    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}[i]{C.RESET} Ukončeno uživatelem.")

    sock.close()
    elapsed = time.monotonic() - start
    _print_pkt_summary(my_ip, link_type, packet_count, byte_count, elapsed,
                       unique_dsts, proto_counts, interesting_packets)
    inquirer.select(
        message="Stiskni Enter pro návrat.",
        choices=["OK"]
    ).execute()





_display_height = 0  # počet řádků naposledy vykresleného view


def _draw_vpn_view(my_ip: str, link_type: int, live_packets: list,
                   pkt_count: int, byte_count: int, elapsed: float,
                   proto_counts: dict, interesting: int) -> None:
    """Překreslí celý VPN přehled (hlavičku + pakety + statistiky)."""
    global _display_height
    from .logo import C as _C
    kbps = (byte_count / 1024) / elapsed if elapsed > 0 else 0
    mb = byte_count / (1024 * 1024)
    speed = f"{kbps:.1f} KB/s" if kbps < 1000 else f"{kbps / 1024:.2f} MB/s"
    lt_name = {1: "Eth", 101: "RawIP", 0: "Null"}.get(link_type, f"LT{link_type}")

    lines = []
    # ── Hlavička ───────────────────────────────────────────────────
    lines.append(f"{_C.CYAN}┌{'─' * 68}┐{_C.RESET}")
    lines.append(f"{_C.CYAN}│{_C.RESET} {_C.BOLD}📊 VPN PAKETOVÝ ANALYZÁR{_C.RESET}{' ' * 40}{_C.CYAN}│{_C.RESET}")
    lines.append(f"{_C.CYAN}├{'─' * 68}┤{_C.RESET}")
    lines.append(f"{_C.CYAN}│{_C.RESET} IP: {_C.BOLD}{my_ip:<15}{_C.RESET}  "
                 f"Link: {lt_name:<5}  "
                 f"Zdroj: tcp://{_VPN_TCP_HOST}:{_VPN_TCP_PORT:<4}"
                 f"{'':>6}{_C.CYAN}│{_C.RESET}")
    lines.append(f"{_C.CYAN}├{'─' * 68}┤{_C.RESET}")
    lines.append(f"{_C.CYAN}│{_C.RESET} 📦 {_C.BOLD}{pkt_count:>6}{_C.RESET} pkts  "
                 f"💾 {_C.BOLD}{mb:.2f}{_C.RESET} MB  "
                 f"⚡ {_C.BOLD}{speed:>10}{_C.RESET}  "
                 f"⏱ {_C.BOLD}{elapsed:>5.1f}{_C.RESET}s  "
                 f"{'':>8}{_C.CYAN}│{_C.RESET}")
    lines.append(f"{_C.CYAN}╞{'═' * 68}╡{_C.RESET}")
    lines.append(f"{_C.CYAN}│{_C.RESET} {'ČAS':<9} {'PROTO':<6} {'DÉLKA':<6} "
                 f"{'ZDROJ → CÍL / INFO':<32} {'TAGY / FLAGY'}{'':>9}{_C.CYAN}│{_C.RESET}")
    lines.append(f"{_C.CYAN}├{'─' * 68}┤{_C.RESET}")

    # ── Řádky paketů (max 10) ──────────────────────────────────────
    for p in live_packets[-10:]:
        tags_str = ", ".join(p["tags"][:3])
        if p.get("creds"):
            tags_str = f"{_C.RED}🔑{'/'.join(p['creds'])}{_C.RESET}"
        elif tags_str:
            tags_str = f"{_C.YELLOW}{tags_str}{_C.RESET}"
        if p.get("flags"):
            tags_str += f" {_C.MAGENTA}{p['flags']}{_C.RESET}"
        lines.append(
            f"{_C.CYAN}│{_C.RESET} "
            f"{_C.DIM}{p['ts']:<9}{_C.RESET} "
            f"{p['proto']:<6} "
            f"{p['len']:<6} "
            f"{p['summary'][:40]:<40} "
            f"{tags_str:<20}"
            f"{_C.CYAN}│{_C.RESET}"
        )

    # ── Spodní část ────────────────────────────────────────────────
    lines.append(f"{_C.CYAN}├{'─' * 68}┤{_C.RESET}")
    lines.append(f"{_C.CYAN}│{_C.RESET} 📦 {pkt_count:>6} pkts  "
                 f"💾 {mb:.2f} MB  ⚡ {speed:>10}  "
                 f"⏱ {elapsed:>5.1f}s  "
                 f"{_C.YELLOW}⚠ {interesting} zajímavých{_C.RESET}"
                 f"{'':>2}{_C.CYAN}│{_C.RESET}")
    lines.append(f"{_C.CYAN}└{'─' * 68}┘{_C.RESET}")

    proto_str = " ".join(f"{k}={v}" for k, v in proto_counts.items())
    if proto_str:
        lines.append(f"{_C.DIM}  Protokoly: {proto_str}{_C.RESET}")

    # ── Překreslení ────────────────────────────────────────────────
    new_height = len(lines)
    if _display_height > 0:
        # Cursor nahoru o předchozí výšku a přepsat
        print(f"\033[{_display_height}A", end="")
    for line in lines:
        print(f"\r\033[K{line}")
    _display_height = new_height


def _print_pkt_summary(my_ip: str, link_type: int,
                       packets: int, bytes_: int, elapsed: float,
                       unique_dsts: set, proto_counts: dict,
                       interesting: int) -> None:
    """Závěrečný souhrn po skončení streamu."""
    from .logo import C as _C, info_box
    kbps = (bytes_ / 1024) / elapsed if elapsed > 0 else 0
    mb = bytes_ / (1024 * 1024)
    mbps = kbps / 1024 if kbps >= 1000 else 0

    print()
    dst_list = ", ".join(sorted(unique_dsts)[:5])
    if len(unique_dsts) > 5:
        dst_list += f" a {len(unique_dsts) - 5} dalších"
    proto_str = ", ".join(f"{k}: {v}" for k, v in
                          sorted(proto_counts.items(), key=lambda x: -x[1]))
    items = [
        ("Lokální IP",       f"{my_ip}"),
        ("VPN zdroj",        f"tcp://{_VPN_TCP_HOST}:{_VPN_TCP_PORT}"),
        ("Celkem paketů",    f"{packets:,}"),
        ("Celkem dat",       f"{mb:.2f} MB ({bytes_:,} B)"),
        ("Prům. rychlost",   f"{mbps:.2f} MB/s" if mbps else f"{kbps:.1f} KB/s"),
        ("Doba běhu",        f"{elapsed:.1f}s"),
        ("Unikátní cíle",    f"{len(unique_dsts)} ({dst_list})"),
        ("Zajímavé pakety",  f"{interesting} (🔑 kredenciály / HTTP form / auth)"),
        ("Protokoly",        f"{proto_str}"),
    ]
    print()
    print(info_box(items, _C.CYAN))
    print()


def _resolve_socket_path() -> Optional[str]:
    """
    Vrátí cestu k prvnímu existujícímu socketu (data nebo control).
    Používá stejné kandidátní cesty jako _resolve_base_dir().
    """
    base = _resolve_base_dir()
    # Zkus data socket, pak control, pak legacy
    data = os.path.join(base, DATA_SOCK_NAME)
    ctrl = os.path.join(base, CTRL_SOCK_NAME)
    legacy = os.path.join(base, LEGACY_SOCK_NAME)
    for sock in [data, ctrl, legacy]:
        if os.path.exists(sock):
            return sock
    return None


def stream_vpn_socket() -> None:
    """Streamuje z VPN – TCP PCAP (port 13338) nebo Unix socket fallback.

    Priority:
      1) TCP 127.0.0.1:13338  (PCAP binary stream from VpnCaptureService)
      2) Unix socket vpn_data.sock (legacy dual-socket arch)
      3) Unix socket vpn.sock (legacy single-socket arch)
    """
    # ── 1. Zkus TCP PCAP stream ───────────────────────────────────────
    tcp_sock = _tcp_pcap_connect()
    if tcp_sock is not None:
        _stream_tcp_pcap(tcp_sock)
        return

    # ── 2. Fallback na Unix sockety ─────────────────────────────────
    sock_path = _resolve_socket_path()
    if sock_path is None:
        print("\n[i] VPN socket ani TCP port 13338 nejsou dostupné.")
        choice = inquirer.select(
            message="Chceš spustit VPN službu?",
            choices=["Ano, spustit VPN", "Ne, vrátit se"],
        ).execute()
        if choice == "Ano, spustit VPN":
            _start_vpn_service()
            print("\n  Počkej na vytvoření socketu a zkus to znovu.")
        return

    timeout = inquirer.text(
        message="Doba odposlechu (sekund, 0 = vždy do přerušení Ctrl+C):",
        default="10",
        validate=lambda t: t.strip().isdigit(),
        invalid_message="Zadej číslo.",
    ).execute()

    duration = int(timeout.strip())
    from select import select

    # ─────────────────────────────────────────────────────────────────
    # STRICT CHANNEL SEPARATION (guard proti smíchání datových typů):
    #   data_sock  → pouze binární PCAP stream (raw pakety)
    #   ctrl_sock  → pouze JSON control zprávy (stavy started/stopped)
    #
    # NIKDY nepoužívej jeden socket pro oba typy dat — při vyšší
    # zátěži by došlo k chybnému parsování a narušení PCAP struktury.
    # ─────────────────────────────────────────────────────────────────
    data_sock = None
    ctrl_sock = None

    if os.path.exists(DATA_SOCK):
        try:
            ds = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            ds.connect(DATA_SOCK)
            data_sock = ds
            print(f"✅ Data socket:   {DATA_SOCK}")
        except OSError as e:
            print(f"⚠️  Data socket:   {e}")

    if os.path.exists(CTRL_SOCK):
        try:
            cs = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            cs.connect(CTRL_SOCK)
            ctrl_sock = cs
            print(f"✅ Control socket: {CTRL_SOCK}")
        except OSError as e:
            print(f"⚠️  Control socket: {e}")

    if not data_sock and not ctrl_sock:
        try:
            ds = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            ds.connect(sock_path)
            data_sock = ds
            print(f"✅ Legacy socket:  {sock_path} (single-socket režim)")
        except OSError as e:
            print(f"\n❌ {e}\n")
            inquirer.select(message="Stiskni Enter pro návrat.", choices=["OK"]).execute()
            return

    print(heading(f"VPN Sniffer – {'dual-socket' if ctrl_sock else 'single-socket'}"))
    print(f"Délka:  {'∞ (Ctrl+C pro ukončení)' if duration == 0 else f'{duration}s'}\n")
    print("  ⚡ JSON control zprávy z onStateChangeListener → zobrazeny")
    print("  📦 Binární PCAP data → počítána\n")

    start = time.monotonic()
    end_time = start + duration if duration > 0 else None
    byte_count = 0
    packet_count = 0

    try:
        while True:
            if end_time and time.monotonic() >= end_time:
                break

            read_set = []
            if data_sock:
                read_set.append(data_sock)
            if ctrl_sock:
                read_set.append(ctrl_sock)

            if not read_set:
                break

            remaining = max(end_time - time.monotonic(), 0.1) if end_time else 1.0
            ready, _, _ = select(read_set, [], [], remaining)

            for sock in ready:
                # ── data_sock: POUZE binární PCAP ──
                if data_sock and sock is data_sock:
                    chunk = data_sock.recv(65536)
                    if not chunk:
                        print("\n[i] Data socket uzavřen (VpnService skončil).")
                        data_sock = None
                        continue
                    byte_count += len(chunk)
                    packet_count += 1
                    if packet_count % 50 == 0:
                        elapsed = time.monotonic() - start
                        kbps = (byte_count / 1024) / elapsed if elapsed > 0 else 0
                        print(f"  📦 {packet_count} paketů, {byte_count} B, {kbps:.1f} KB/s")

                # ── ctrl_sock: POUZE JSON control zprávy ──
                elif ctrl_sock and sock is ctrl_sock:
                    raw = ctrl_sock.recv(4096)
                    if raw:
                        try:
                            msg = json.loads(raw.decode("utf-8", errors="replace"))
                            state = msg.get("state", "")
                            ts = msg.get("timestamp", "")
                            if state == "started":
                                print(f"  🔵 onStateChange: STARTED  @ {ts}")
                            elif state == "stopped":
                                print(f"  🔴 onStateChange: STOPPED  @ {ts}")
                                print("[i] VPN služba ukončena.")
                                ctrl_sock.close()
                                ctrl_sock = None
                            else:
                                print(f"  📄 Control: {raw.decode('utf-8', errors='replace').strip()}")
                        except json.JSONDecodeError:
                            pass

            if not data_sock and not ctrl_sock:
                break

    except KeyboardInterrupt:
        print("\n[i] Ukončeno uživatelem.")

    if data_sock:
        data_sock.close()
    if ctrl_sock:
        ctrl_sock.close()

    elapsed = time.monotonic() - start
    kbps = (byte_count / 1024) / elapsed if elapsed > 0 else 0
    print(f"\n{'=' * 45}")
    print(f"  Přijato paketů: {packet_count}")
    print(f"  Celkem bajtů:   {byte_count}")
    print(f"  Průměr:         {kbps:.1f} KB/s")
    print(f"  Doba běhu:      {elapsed:.1f}s")
    print(f"{'=' * 45}")
    inquirer.select(message="Stiskni Enter pro návrat.", choices=["OK"]).execute()


def stream_vpn_legacy() -> None:
    """Legacy single-socket stream pro zpětnou kompatibilitu."""
    sock_path = _resolve_socket_path()
    if sock_path is None:
        return

    timeout = inquirer.text(
        message="Doba odposlechu (sekund, 0 = vždy):",
        default="10",
        validate=lambda t: t.strip().isdigit(),
        invalid_message="Zadej číslo.",
    ).execute()

    duration = int(timeout.strip())

    print(heading(f"VPN Sniffer (legacy single-socket)"))
    print(f"Délka:  {'∞' if duration == 0 else f'{duration}s'}\n")

    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(duration if duration > 0 else None)
        sock.connect(sock_path)

        start = time.monotonic()
        byte_count = 0
        packet_count = 0

        while True:
            if duration > 0 and (time.monotonic() - start) >= duration:
                break
            try:
                data = sock.recv(4096)
                if not data:
                    break
                byte_count += len(data)
                packet_count += 1
                if packet_count % 50 == 0:
                    elapsed = time.monotonic() - start
                    kbps = (byte_count / 1024) / elapsed if elapsed > 0 else 0
                    print(f"  📦 {packet_count} paketů, {byte_count} B, {kbps:.1f} KB/s")
            except socket.timeout:
                break
            except KeyboardInterrupt:
                break

        sock.close()
        elapsed = time.monotonic() - start
        kbps = (byte_count / 1024) / elapsed if elapsed > 0 else 0
        print(f"\n  Paketů: {packet_count}, {byte_count} B, {kbps:.1f} KB/s")
    except (FileNotFoundError, ConnectionRefusedError, OSError) as e:
        print(f"\n[!] {e}")

    inquirer.select(message="Stiskni Enter pro návrat.", choices=["OK"]).execute()


def tap_pcap_stream() -> None:
    """
    Show active TCP connections from /proc/net/tcp or ss.
    Non-root alternative to tcpdump.
    """
    print(heading("Aktivní TCP spojení"))
    header = ["Local", "Remote", "Stav"]
    rows: List[List[str]] = []

    # Try /proc/net/tcp first (works on Android without root)
    try:
        with open("/proc/net/tcp", "r") as f:
            raw = f.read()
    except (FileNotFoundError, PermissionError, OSError):
        raw = ""

    if raw:
        lines = raw.strip().splitlines()
        for line in lines[1:]:  # skip header
            parts = line.strip().split()
            if len(parts) >= 4:
                local = _hex_ip_port(parts[1])
                remote = _hex_ip_port(parts[2])
                state = _tcp_state(int(parts[3], 16))
                rows.append([local, remote, state])
    else:
        # Fallback: /proc/net/tcp permission denied or missing
        # Show a helpful diagnostic instead
        print("[i] /proc/net/tcp není v tomto prostředí čitelný (vyžaduje root nebo Android chroot bez CAP_NET_ADMIN).\n")
        print("    Tipy pro sledování provozu bez roota:")
        print("      • Aktivuj VPN profil v NetHunteru – proud dat se objeví")
        print("        na Unix socketu (volba 'Stream z VPN Unix socketu').")
        print("      • Použij 'ip -br addr' pro výpis aktivních rozhraní.")
        print("      • Pokud máš root, spusť: tcpdump -i any\n")

    if rows:
        from .utils import format_table
        print(format_table(header, rows))
        print(f"\n(Celkem {len(rows)} aktivních TCP spojení)")
    else:
        print("  (žádná aktivní TCP spojení nezachycena)")

    inquirer.select(message="Stiskni Enter pro návrat.", choices=["OK"]).execute()


def _hex_ip_port(hex_str: str) -> str:
    """Convert hex '0100007F:0016' to '127.0.0.1:22'."""
    try:
        ip_hex, port_hex = hex_str.split(":")
        ip_bytes = bytes.fromhex(ip_hex)
        ip = ".".join(str(b) for b in reversed(ip_bytes))
        port = str(int(port_hex, 16))
        return f"{ip}:{port}"
    except Exception:
        return hex_str


def _tcp_state(code: int) -> str:
    states = {
        0x01: "ESTABLISHED",
        0x02: "SYN_SENT",
        0x03: "SYN_RECV",
        0x04: "FIN_WAIT1",
        0x05: "FIN_WAIT2",
        0x06: "TIME_WAIT",
        0x07: "CLOSE",
        0x08: "CLOSE_WAIT",
        0x09: "LAST_ACK",
        0x0A: "LISTEN",
        0x0B: "CLOSING",
    }
    return states.get(code, f"0x{code:02X}")


def run_daemon() -> None:
    """PM2 entry point — runs VPN sniffer in passive logging mode."""
    import os
    import signal
    import time

    # Log do kořene projektu, ne do _resolve_base_dir() (Android cesta)
    _LOG_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.makedirs(_LOG_DIR, exist_ok=True)
    log_path = os.path.join(_LOG_DIR, "vpn_capture.log")

    print(f"[PM2] VPN logger started, logging to {log_path}")
    with open(log_path, "a") as log_f:
        log_f.write(f"\n--- VPN logger started at {time.ctime()} ---\n")

    stop = False
    def _handle_signal(signum, frame):
        nonlocal stop
        stop = True
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    while not stop:
        sock = _tcp_pcap_connect()
        if sock is None:
            print("[PM2] VPN TCP socket (127.0.0.1:13338) not available, retrying in 10s...")
            with open(log_path, "a") as log_fh:
                log_fh.write(f"[{time.ctime()}] Socket not available, retrying in 10s\n")
            for _ in range(10):
                if stop:
                    break
                time.sleep(1)
            continue
        try:
            _stream_tcp_pcap_daemon(sock, log_path)
        except Exception as e:
            print(f"[ERROR] {e}")
            with open(log_path, "a") as log_fh:
                log_fh.write(f"[ERROR] {e}\n")
        time.sleep(2)
    print("[PM2] VPN logger stopped.")


if __name__ == "__main__":
    run_daemon()
