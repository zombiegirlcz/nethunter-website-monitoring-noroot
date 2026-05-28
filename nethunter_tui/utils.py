"""Shared utilities: validation, subprocess helpers, output formatting."""

import subprocess
import re
import shutil
import socket as _socket
from typing import List, Optional, Tuple

# ── Validation ──────────────────────────────────────────────────────────────

IP_RE = re.compile(
    r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$"
)


def validate_ip(text: str) -> bool:
    """Return True if *text* is a valid IPv4 address."""
    m = IP_RE.match(text.strip())
    if not m:
        return False
    return all(0 <= int(g) <= 255 for g in m.groups())


def validate_cidr(text: str) -> bool:
    """Return True for valid CIDR notation, e.g. 192.168.1.0/24."""
    text = text.strip()
    if "/" not in text:
        return False
    ip_part, prefix = text.rsplit("/", 1)
    if not prefix.isdigit():
        return False
    p = int(prefix)
    if p < 0 or p > 32:
        return False
    return validate_ip(ip_part)


def validate_domain(text: str) -> bool:
    """Basic domain validation."""
    text = text.strip()
    # very permissive – catches most obvious typos
    return bool(re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?\.[a-zA-Z]{2,}$", text))


def validate_port_range(text: str) -> bool:
    """Accept a single port (1-65535) or a comma-separated list."""
    text = text.strip()
    for part in text.split(","):
        part = part.strip()
        if not part.isdigit():
            return False
        p = int(part)
        if p < 1 or p > 65535:
            return False
    return True


# ── Subprocess helpers ──────────────────────────────────────────────────────

def run_cmd(cmd: List[str], timeout: int = 30) -> Tuple[int, str, str]:
    """
    Run *cmd* in a subprocess.

    Returns (returncode, stdout, stderr).
    Raises ``FileNotFoundError`` if the binary is missing.
    """
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        raise FileNotFoundError(
            f"Příkaz '{cmd[0]}' nebyl nalezen v systému. "
            f"Nainstaluj ho například přes: pkg install {cmd[0]}"
        )
    except OSError as e:
        return (-1, "", f"Příkaz '{' '.join(cmd)}' selhal (OSError: {e}).")
    except subprocess.TimeoutExpired:
        return (-1, "", f"Příkaz '{' '.join(cmd)}' vypršel (timeout {timeout}s).")

    return (proc.returncode, proc.stdout, proc.stderr)


def nethunter_notify(action: str) -> None:
    """
    Spouští nethunter-... API příkazy pro notifikace (TTS, vibrace, svítilna).
    Provádí se na pozadí (non-blocking).
    """
    print(f"DEBUG: nethunter_notify(action='{action}') called")
    try:
        if action == "block":
            subprocess.Popen(["nethunter-tts-speak", "block!!"])
            subprocess.Popen(["nethunter-vibrate"])
        elif action == "counter":
            subprocess.Popen(["nethunter-tts-speak", "counter attack!11"])
            # Blikání svítilnou: on/off/on/off
            def _torch_blink():
                import time
                for _ in range(2):
                    subprocess.run(["nethunter-torch", "on"])
                    time.sleep(0.2)
                    subprocess.run(["nethunter-torch", "off"])
                    time.sleep(0.2)
                subprocess.run(["nethunter-vibrate"])

            import threading
            threading.Thread(target=_torch_blink, daemon=True).start()
    except Exception:
        # Tichá chyba, pokud API příkazy chybí
        pass


def check_binary(name: str) -> Optional[str]:
    """Return the path to *name* or ``None``."""
    return shutil.which(name)


# ── Output helpers ──────────────────────────────────────────────────────────

def format_table(header: List[str], rows: List[List[str]]) -> str:
    """Render a simple monospace table with a header and rows."""
    col_widths = [len(h) for h in header]
    for row in rows:
        for i, cell in enumerate(row):
            if i < len(col_widths):
                col_widths[i] = max(col_widths[i], len(cell))

    sep = "  ".join("-" * w for w in col_widths)
    fmt = "  ".join(f"{{:<{w}}}" for w in col_widths)

    lines = [fmt.format(*header), sep]
    for row in rows:
        # pad row to match header length
        padded = list(row) + [""] * (len(header) - len(row))
        lines.append(fmt.format(*padded))
    return "\n".join(lines)


def heading(text: str, char: str = "═") -> str:
    """Return a centred heading line, e.g. ``══════ Nmap Scan ══════``."""
    return f" {text} ".center(60, char)


# ── IP detection (multi-method) ────────────────────────────────────────────

def _parse_ifconfig(output: str) -> List[Tuple[str, str, str]]:
    """Parse ``ifconfig`` output into (interface, IP, state) tuples."""
    results: List[Tuple[str, str, str]] = []
    current_iface = ""
    current_ip = "-"
    current_state = "-"
    for line in output.splitlines():
        # Line starting with non-whitespace → new interface
        if line and not line[0].isspace():
            # Save previous
            if current_iface:
                results.append((current_iface, current_ip, current_state))
            parts = line.split()
            current_iface = parts[0].rstrip(":")
            current_ip = "-"
            current_state = "UP" if "UP" in line.upper() else "DOWN"
        else:
            # Look for inet line
            m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", line)
            if m:
                current_ip = m.group(1)
    if current_iface:
        results.append((current_iface, current_ip, current_state))
    return results


def _parse_ip_addr(output: str) -> List[Tuple[str, str, str]]:
    """Parse ``ip -br addr`` output into (interface, IP, state) tuples."""
    results: List[Tuple[str, str, str]] = []
    for line in output.splitlines():
        parts = line.strip().split()
        if len(parts) >= 2:
            iface = parts[0]
            ip_info = parts[1] if len(parts) >= 2 else "-"
            state = parts[2] if len(parts) >= 3 else "-"
            results.append((iface, ip_info, state))
    return results


def get_local_ips() -> List[Tuple[str, str, str]]:
    """
    Vrací seznam (rozhraní, IP, stav) všemi dostupnými metodami.

    Zkouší:
      1. ``ip -br addr`` (nejmodernější)
      2. ``ifconfig`` (fallback pro starší systémy / Android chroot)
      3. Python ``socket.gethostbyname`` (poslední záchrana)
    """
    # Method 1: ip -br addr
    ip_path = shutil.which("ip")
    if ip_path:
        try:
            r = subprocess.run(
                [ip_path, "-br", "addr"],
                capture_output=True, text=True, timeout=5,
            )
            if r.returncode == 0 and r.stdout.strip():
                return _parse_ip_addr(r.stdout)
        except (OSError, subprocess.TimeoutExpired):
            pass

    # Method 2: ifconfig
    ifconfig_path = shutil.which("ifconfig")
    if ifconfig_path:
        try:
            r = subprocess.run(
                [ifconfig_path],
                capture_output=True, text=True, timeout=5,
            )
            if r.returncode == 0 and r.stdout.strip():
                return _parse_ifconfig(r.stdout)
        except (OSError, subprocess.TimeoutExpired):
            pass

    # Method 3: Python socket fallback (just one IP)
    try:
        hostname = _socket.gethostname()
        ip = _socket.gethostbyname(hostname)
        if ip and not ip.startswith("127."):
            return [("(auto)", ip, "-")]
    except OSError:
        pass

    return [("N/A", "žádná IP nenalezena", "")]


def get_my_ip() -> str:
    """
    Vrací první ne-loopback IP adresu tohoto zařízení.

    Vrací ``"N/A"`` pokud žádnou nenajde.
    """
    interfaces = get_local_ips()
    for iface, ip, _state in interfaces:
        if ip and ip != "-" and not ip.startswith("127."):
            # ip could be "192.168.1.100/24" – strip prefix
            if "/" in ip:
                ip = ip.split("/")[0]
            return ip
    return "N/A"
