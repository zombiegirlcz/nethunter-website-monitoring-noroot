"""DNS & Reconnaissance tools: dig, whois (with graceful fallbacks)."""

from typing import Dict, List

from InquirerPy import inquirer

from InquirerPy.base.control import Choice

from .utils import (
    validate_domain,
    run_cmd,
    format_table,
    heading,
    check_binary,
)


RECORD_TYPES: Dict[str, str] = {
    "A": "IPv4 záznam",
    "AAAA": "IPv6 záznam",
    "MX": "Mail server",
    "TXT": "Textové záznamy",
    "NS": "Nameservery",
    "CNAME": "Canonical name",
    "SOA": "Start of Authority",
}


def dns_lookup(domain: str | None = None) -> None:
    """Look up DNS records for a domain (dig / host)."""
    dig_path = check_binary("dig")
    host_path = check_binary("host")

    if not dig_path and not host_path:
        print(
            "\n[!] 'dig' ani 'host' nejsou k dispozici.\n"
            "    Nainstaluj: pkg install dnsutils\n"
        )
        return

    if domain is None:
        domain = inquirer.text(
            message="Zadej doménu:",
            validate=validate_domain,
            invalid_message="Zadej platnou doménu (např. example.com).",
        ).execute()

    selected = inquirer.checkbox(
        message="Typy DNS záznamů:",
        choices=[
            Choice(k, name=f"{k} ({v})")
            for k, v in RECORD_TYPES.items()
        ],
        cycle=False,
    ).execute()

    # Default to A if nothing selected
    if not selected:
        selected = ["A"]

    print(heading("DNS Lookup"))
    print(f"Doména: {domain}\n")

    if dig_path:
        _run_dig(domain, selected)
    else:
        _run_host(domain, selected)


def _run_dig(domain: str, types: List[str]) -> None:
    for rt in types:
        print(f"\n--- {rt} záznamy ---")
        cmd = ["dig", "+short", "+time=10", domain, rt]
        ret, out, err = run_cmd(cmd, timeout=15)

        if ret != 0:
            print(f"  [i] Chyba: {err.strip() or out.strip()}")
        elif out.strip():
            print(out)
        else:
            print("  (žádné záznamy)")


def _run_host(domain: str, types: List[str]) -> None:
    # The `host` command doesn't support type selection natively;
    # we just show the default output.
    print("\n--- host výstup ---")
    cmd = ["host", domain]
    ret, out, err = run_cmd(cmd, timeout=15)
    if ret == 0:
        print(out)
    else:
        print(f"  [i] Chyba: {err.strip() or out.strip()}")


def whois_lookup(target: str | None = None) -> None:
    """Look up Whois registration info for a domain or IP."""
    if not check_binary("whois"):
        print(
            "\n[!] 'whois' není nainstalován.\n"
            "    Nainstaluj: pkg install whois\n"
        )
        return

    if target is None:
        target = inquirer.text(
            message="Zadej doménu nebo IP pro whois lookup:",
            validate=lambda t: len(t.strip()) > 0,
            invalid_message="Vstup nesmí být prázdný.",
        ).execute()

    print(heading("Whois Lookup"))
    print(f"Cíl: {target}\n")

    ret, out, err = run_cmd(["whois", target], timeout=30)

    if ret != 0:
        print(f"[!] Whois selhal (kód {ret}):\n{err}")
    else:
        # Show first 40 lines to keep output manageable
        lines = out.splitlines()
        for line in lines[:40]:
            # Skip blank lines at start
            if line.strip() or True:
                print(line)
        if len(lines) > 40:
            print(f"\n[... zkráceno, celkem {len(lines)} řádků ...]")
