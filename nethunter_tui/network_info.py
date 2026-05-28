"""Network configuration tools (ip, route)."""

from typing import List

from InquirerPy import inquirer

from .utils import run_cmd, format_table, heading, check_binary, get_local_ips


def show_ip_addr() -> None:
    """Show all network interfaces and their addresses."""
    print(heading("IP adresy zařízení"))
    interfaces = get_local_ips()
    if not interfaces or (len(interfaces) == 1 and interfaces[0][1] == "žádná IP nenalezena"):
        print("\n[!] Nepodařilo se zjistit IP adresy (zkoušeno ip i ifconfig).\n")
        return

    header = ["Rozhraní", "IP / Prefix", "Stav"]
    rows: List[List[str]] = []

    for iface, ip, state in interfaces:
        s = state.upper()
        state_colored = f"\033[92m{s}\033[0m" if s == "UP" else f"\033[91m{s}\033[0m"
        rows.append([iface, ip, state_colored])

    if rows:
        print(format_table(header, rows))
    else:
        print("(žádná data)")


def show_routing_table() -> None:
    """Display the kernel routing table."""
    if not check_binary("ip"):
        print("\n[!] 'ip' není k dispozici.\n")
        return

    print(heading("Směrovací tabulka"))
    ret, out, err = run_cmd(["ip", "route"], timeout=5)

    if ret != 0:
        print(f"[!] Chyba: {err}")
        return

    # Parse structured output
    header = ["Cíl", "Přes bránu", "Rozhraní", "Metrika"]
    rows: List[List[str]] = []

    for line in out.splitlines():
        parts = line.strip().split()
        if not parts:
            continue

        dst = parts[0] if len(parts) > 0 else "-"
        gw = parts[2] if len(parts) > 2 and parts[1] == "via" else "0.0.0.0"
        dev = parts[4] if len(parts) > 4 and parts[3] == "dev" else parts[2] if len(parts) > 2 else "-"
        metric = parts[6] if len(parts) > 6 and parts[5] == "metric" else "-"
        rows.append([dst, gw, dev, metric])

    if rows:
        print(format_table(header, rows))
    else:
        print(out)


def dns_info() -> None:
    """Show DNS configuration from /etc/resolv.conf."""
    print(heading("DNS konfigurace"))
    try:
        with open("/etc/resolv.conf", "r") as f:
            content = f.read()
        print(content)
    except FileNotFoundError:
        print("[!] /etc/resolv.conf nebyl nalezen.")
    except PermissionError:
        print("[!] Nedostatečná oprávnění pro čtení /etc/resolv.conf.")


def trace_route(target: str | None = None) -> None:
    """Run traceroute to a target."""
    # Prefer mtr, fallback to traceroute
    binary = check_binary("mtr") or check_binary("traceroute")

    if not binary:
        print(
            "\n[!] 'mtr' ani 'traceroute' nejsou nainstalovány.\n"
            "    Nainstaluj: pkg install traceroute\n"
        )
        return

    if target is None:
        target = inquirer.text(
            message="Cílová IP nebo doména:",
            validate=lambda t: len(t.strip()) > 0,
        ).execute()

    cmd = [binary]
    if "mtr" in binary:
        cmd += ["--report", "--report-wide", "--no-dns", "-c", "3"]
    else:
        cmd += ["-n", "-m", "15"]
    cmd.append(target)

    print(heading(f"Trasa k {target}"))
    print(f"Spouštím: {' '.join(cmd)}\n")

    ret, out, err = run_cmd(cmd, timeout=60)

    if ret != 0:
        print(f"[!] Chyba (kód {ret}):\n{err}")
    else:
        print(out)
