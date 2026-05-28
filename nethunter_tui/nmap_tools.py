"""Nmap Connect Scan module (no root required)."""

from typing import List

from InquirerPy import inquirer
from InquirerPy.base.control import Choice

from .utils import (
    validate_ip,
    validate_cidr,
    validate_port_range,
    run_cmd,
    format_table,
    heading,
    check_binary,
)


def run_nmap_scan() -> None:
    """Interactive Nmap -sT -Pn scan."""
    if not check_binary("nmap"):
        print("\n[!] 'nmap' není nainstalován. Spusť: pkg install nmap\n")
        return

    target = inquirer.text(
        message="Cílová IP / rozsah (CIDR):",
        validate=lambda t: validate_ip(t) or validate_cidr(t),
        invalid_message="Zadej platnou IP adresu nebo CIDR (např. 192.168.1.0/24).",
    ).execute()

    method = inquirer.select(
        message="Způsob zadání portů:",
        choices=[
            "Rychlé skenování (top 1000 portů)",
            "Vlastní seznam portů",
        ],
    ).execute()

    ports = ""
    if "Vlastní" in method:
        ports = inquirer.text(
            message="Porty (např. 22,80,443):",
            validate=validate_port_range,
            invalid_message="Použij čísla oddělená čárkou, každé 1-65535.",
        ).execute()

    presets = inquirer.checkbox(
        message="Další volby (nepovinné):",
        choices=[
            Choice("--reason", name="Zobrazit důvod stavu portu"),
            Choice("-O", name="Detekce OS (vyžaduje root)"),
            Choice("-sV", name="Detekce verzí služeb"),
        ],
    ).execute()

    print(heading("Nmap Connect Scan"))
    print(f"Cíl: {target}\n")

    # Build command – always -sT -Pn (no root, no ICMP)
    cmd: List[str] = ["nmap", "-sT", "-Pn"]
    if ports:
        cmd.extend(["-p", ports])
    if "--reason" in presets:
        cmd.append("--reason")
    if "-O" in presets:
        cmd.append("-O")
    if "-sV" in presets:
        cmd.append("-sV")
    cmd.append(target)

    print(f"Spouštím: {' '.join(cmd)}\n")

    ret, out, err = run_cmd(cmd, timeout=120)

    if ret == -1 and "timeout" in err:
        print(err)
        return

    if ret != 0:
        print(f"[!] Nmap selhal (kód {ret}):\n{err}")
    else:
        _show_parsed_output(out)


def _show_parsed_output(raw: str) -> None:
    """Parse nmap output and display a summary table."""
    header = ["Port", "State", "Service"]
    rows: List[List[str]] = []

    for line in raw.splitlines():
        # typical: "22/tcp   open  ssh"
        parts = line.strip().split()
        if len(parts) >= 3 and "/tcp" in parts[0] and parts[1] in ("open", "filtered", "closed"):
            rows.append([parts[0], parts[1], parts[2]])

    if rows:
        print(format_table(header, rows))
    else:
        print(raw)
