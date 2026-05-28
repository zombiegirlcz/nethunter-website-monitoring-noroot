"""nethunter-TUI: Interactive TUI frontend for network diagnostics.

Entry point — displays the main menu and dispatches to sub-modules.
Uses InquirerPy Alternate Syntax throughout.
"""

import sys
import os
import glob
import time
from InquirerPy import inquirer
from InquirerPy.base.control import Choice

from .nmap_tools import run_nmap_scan
from .dns_tools import dns_lookup, whois_lookup
from .network_info import show_ip_addr, show_routing_table, dns_info, trace_route
from .vpn_sniffer import (
    stream_vpn_socket,
    stream_vpn_legacy,
    tap_pcap_stream,
    get_vpn_status,
    show_vpn_status,
)
from .honeypot import get_engine, show_honeypot_status
from .msf_controller import MsfController
from .logo import print_logo, C
from . import pm2_manager


# ── Helpers ─────────────────────────────────────────────────────────────


def _prompt_enter() -> None:
    """Wait for Enter, then clear screen."""
    input("\nStiskni Enter pro návrat do menu.")
    print("\033[2J\033[H", end="")


def _handle_result(result: str) -> None:
    """Print a one-line result or nothing."""
    if result:
        print(result)


# ── Sub-menus ───────────────────────────────────────────────────────────


def dns_submenu() -> None:
    """DNS submenu loop."""
    while True:
        choice = inquirer.select(
            message="DNS a Reconnaissance:",
            choices=[
                Choice(name="DNS Lookup (dig)",     value="dns_lookup"),
                Choice(name="Whois Lookup",         value="whois"),
                Choice(name="← Zpět do hlavního menu", value="back"),
            ],
        ).execute()

        if choice == "back":
            return
        elif choice == "dns_lookup":
            target = inquirer.text(message="Zadej doménu / IP:").execute()
            if target.strip():
                _handle_result(dns_lookup(target.strip()))
        elif choice == "whois":
            target = inquirer.text(message="Zadej doménu / IP:").execute()
            if target.strip():
                _handle_result(whois_lookup(target.strip()))
        _prompt_enter()


def net_submenu() -> None:
    """Network config submenu loop."""
    while True:
        choice = inquirer.select(
            message="Síťová konfigurace:",
            choices=[
                Choice(name="IP adresy zařízení (ip addr)", value="ip"),
                Choice(name="Směrovací tabulka (ip route)", value="route"),
                Choice(name="DNS konfigurace (resolv.conf)", value="dnsconf"),
                Choice(name="Sledování trasy (trace route)", value="trace"),
                Choice(name="← Zpět do hlavního menu", value="back"),
            ],
        ).execute()

        if choice == "back":
            return
        elif choice == "ip":
            _handle_result(show_ip_addr())
        elif choice == "route":
            _handle_result(show_routing_table())
        elif choice == "dnsconf":
            _handle_result(dns_info())
        elif choice == "trace":
            target = inquirer.text(message="Zadej cíl (IP / doménu):", default="8.8.8.8").execute()
            if target.strip():
                _handle_result(trace_route(target.strip()))
        _prompt_enter()


def vpn_submenu() -> None:
    """VPN / sniffing submenu loop."""
    while True:
        status = get_vpn_status()
        status_str = "🟢 BĚŽÍ" if status["running"] else "🔴 NEBĚŽÍ"
        detail = f" ({status['detail']})" if status["detail"] else ""

        choice = inquirer.select(
            message=f"VPN Sniffer  |  Stav: {status_str}{detail}",
            choices=[
                Choice(name="📊 Zobrazit stav VPN služby", value="status"),
                Choice(name="📡 [Dual] Stream z VPN (data+control socket)", value="stream"),
                Choice(name="📡 [Legacy] Stream z VPN (single socket)", value="legacy"),
                Choice(name="🔌 Aktivní TCP spojení (/proc/net/tcp)", value="pcap"),
                Choice(name="← Zpět do hlavního menu", value="back"),
            ],
        ).execute()

        if choice == "back":
            return
        elif choice == "status":
            show_vpn_status()
        elif choice == "stream":
            stream_vpn_socket()
        elif choice == "legacy":
            stream_vpn_legacy()
        elif choice == "pcap":
            tap_pcap_stream()
        _prompt_enter()


def honeypot_submenu() -> None:
    """Honeypot submenu loop."""
    while True:
        status = get_engine().get_status()
        running = status["running"]
        status_str = "🟢 BĚŽÍ" if running else "🔴 NEBĚŽÍ"
        port_str = f" ({', '.join(str(p) for p in status['ports'])})" if running else ""

        choice = inquirer.select(
            message=f"🛡️ Honeypot  |  Stav: {status_str}{port_str}",
            choices=[
                Choice(name="📊 Zobrazit stav",               value="status"),
                Choice(name="▶️  Spustit (výchozí porty)",     value="start"),
                Choice(name="⏹  Zastavit",                     value="stop"),
                Choice(name="🔧 Nastavit porty a spustit",     value="config"),
                Choice(name="📜 Zobrazit log útoků",          value="log"),
                Choice(name="🎯 Úroveň auto-obrany",          value="defense"),
                Choice(name="📡 Stav MSF",                    value="msf"),
                Choice(name="🔁 Stav shadow instance",        value="shadow"),
                Choice(name="← Zpět do hlavního menu",        value="back"),
            ],
        ).execute()

        if choice == "back":
            return
        elif choice == "status":
            print(show_honeypot_status())
        elif choice == "start":
            res = get_engine().start()
            ok = [str(p) for p, e in res.items() if e is None]
            fail = [f"{p}: {e}" for p, e in res.items() if e is not None]
            if ok:
                print(f"  {C.GREEN}✅ Honeypot spuštěn na portech: {', '.join(ok)}{C.RESET}")
            if fail:
                print(f"  {C.RED}❌ Chyby: {'; '.join(fail)}{C.RESET}")
        elif choice == "stop":
            get_engine().stop()
            print(f"  {C.YELLOW}⏹ Honeypot zastaven{C.RESET}")
        elif choice == "config":
            ports_str = inquirer.text(
                message="Porty (čárkou, např. 2222,2323,2121):",
                default="2222,2323,2121,8443,9090",
            ).execute()
            port_list = [int(p.strip()) for p in ports_str.split(",") if p.strip().isdigit()]
            if port_list:
                res = get_engine().start(port_list)
                ok = [str(p) for p, e in res.items() if e is None]
                fail = [f"{p}: {e}" for p, e in res.items() if e is not None]
                if ok:
                    print(f"  {C.GREEN}✅ Honeypot spuštěn na portech: {', '.join(ok)}{C.RESET}")
                if fail:
                    print(f"  {C.RED}❌ Chyby: {'; '.join(fail)}{C.RESET}")
        elif choice == "log":
            log = get_engine().get_attack_log(20)
            if not log:
                print(f"  {C.DIM}Zatím žádné útoky.{C.RESET}")
            else:
                for i, ev in enumerate(reversed(log), 1):
                    src = ev.src_ip
                    port = ev.dst_port
                    banner = ev.banner_sent
                    alert = f" {C.RED}[SCAN]{C.RESET}" if ev.scan_alert else ""
                    print(f"  {C.DIM}{i}.{C.RESET} {src}:{ev.src_port} → port {port} "
                          f"({banner}){alert}")
                    if ev.credentials:
                        for c in ev.credentials:
                            print(f"     {C.RED}🔑 {c}{C.RESET}")
        elif choice == "defense":
            current = get_engine().config.auto_defense
            new_level = inquirer.select(
                message="Úroveň auto-obrany (MSF counter-measures):",
                choices=[
                    Choice(name="⛔ Žádná", value="none"),
                    Choice(name="🔍 Rekognoskace (auxiliary skeny)", value="recon"),
                    Choice(name="💥 Agresivní (exploit + scan)", value="aggressive"),
                ],
                default=current,
            ).execute()
            if new_level != current:
                get_engine().config.auto_defense = new_level
                print(f"  {C.GREEN}✅ Auto-obrana nastavena na: {new_level}{C.RESET}")
            else:
                print(f"  {C.DIM}Beze změny.{C.RESET}")
        elif choice == "msf":
            msf = MsfController()
            script_dir = os.path.expanduser("~/.nethunter/msf_scripts")
            scripts = list(glob.glob(os.path.join(script_dir, "*.rc")))
            print(f"\n  {C.CYAN}📡 MSF Controller{C.RESET}")
            print(f"  {'─' * 40}")
            print(f"  Skripty: {len(scripts)}")
            if scripts:
                for s in sorted(scripts):
                    sz = os.path.getsize(s)
                    print(f"    • {os.path.basename(s)} ({sz} B)")
            status = msf.get_status()
            print(f"  Běžící procesy: {status.get('running_processes', 0)}")
        elif choice == "shadow":
            try:
                import subprocess, json
                r = subprocess.run(["pm2", "jlist"], capture_output=True, text=True, timeout=10)
                procs = json.loads(r.stdout)
                shadow_info = {}
                for p in procs:
                    nm = p.get("name", "")
                    if nm in ("honeypot", "honeypot-shadow"):
                        env = p.get("pm2_env", {})
                        shadow_info[nm] = {
                            "status": env.get("status", "?"),
                            "pid": env.get("pm_pid", "?"),
                            "uptime": env.get("pm_uptime", 0),
                            "restarts": env.get("restart_time", 0),
                        }
                print(f"\n  {C.CYAN}🔁 Shadow instance status{C.RESET}")
                print(f"  {'─' * 40}")
                for nm, info in sorted(shadow_info.items()):
                    icon = "🟢" if info["status"] == "online" else "🔴"
                    uptime_s = int((time.time()*1000 - info["uptime"])/1000) if info["uptime"] else 0
                    uptime_str = f"{uptime_s//3600}h{(uptime_s%3600)//60}m" if uptime_s > 60 else f"{uptime_s}s"
                    print(f"  {icon} {nm}: {info['status']} (PID={info['pid']}, "
                          f"uptime={uptime_str}, restarts={info['restarts']})")
                # Heartbeat check
                hb_dir = os.path.expanduser("~/.nethunter")
                for hb_name in ["heartbeat-primary.ts", "heartbeat-shadow.ts"]:
                    hb_path = os.path.join(hb_dir, hb_name)
                    if os.path.exists(hb_path):
                        try:
                            with open(hb_path) as f:
                                ts = int(f.read().strip())
                            age = int(time.time() - ts)
                            hb_ok = "✅" if age < 90 else "⚠️"
                            print(f"  {hb_ok} {hb_name}: {age}s old")
                        except Exception:
                            print(f"  ⚠️  {hb_name}: unreadable")
                    else:
                        print(f"  ⚠️  {hb_name}: missing")
            except Exception as exc:
                print(f"  {C.RED}❌ Shadow check failed: {exc}{C.RESET}")
        _prompt_enter()


# ── Main menu ───────────────────────────────────────────────────────────


def _pm2_submenu() -> None:
    """Správa služeb na pozadí (PM2)."""
    from .logo import C as _C

    if not pm2_manager.is_installed():
        print(f"\n  {_C.RED}❌ pm2 není nainstalován.{_C.RESET}")
        print(f"  {_C.YELLOW}Nainstaluj: npm install -g pm2{_C.RESET}")
        _prompt_enter()
        return

    while True:
        svc_status = pm2_manager.status()
        _lines = []
        for s in pm2_manager.available():
            st = svc_status.get(s, "?")
            icon = {"online": "🟢", "stopped": "🔴", "errored": "🔴"}.get(st, "⚪")
            _lines.append(f"  {icon} {_C.BOLD}{s}{_C.RESET}  →  {st}")

        status_block = "\n".join(_lines)

        choice = inquirer.select(
            message=f"⚙️  Správa služeb na pozadí (PM2)\n{status_block}",
            choices=[
                Choice(name="▶️  Spustit vše",                  value="start_all"),
                Choice(name="⏹  Zastavit vše",                  value="stop_all"),
                Choice(name="🔄 Restartovat vše",                value="restart_all"),
                Choice(name="▶️  Spustit Honeypot",              value="start_honeypot"),
                Choice(name="⏹  Zastavit Honeypot",             value="stop_honeypot"),
                Choice(name="▶️  Spustit VPN logger",            value="start_vpn"),
                Choice(name="⏹  Zastavit VPN logger",           value="stop_vpn"),
                Choice(name="📜 Zobrazit logy (honeypot)",       value="logs_honeypot"),
                Choice(name="📜 Zobrazit logy (VPN logger)",     value="logs_vpn"),
                Choice(name="💾 Uložit seznam procesů (pm2 save)", value="save"),
                Choice(name="← Zpět do hlavního menu",           value="back"),
            ],
        ).execute()

        if choice == "back":
            return
        elif choice == "start_all":
            pm2_manager.start()
        elif choice == "stop_all":
            pm2_manager.stop()
        elif choice == "restart_all":
            pm2_manager.restart()
        elif choice == "start_honeypot":
            pm2_manager.start("honeypot")
        elif choice == "stop_honeypot":
            pm2_manager.stop("honeypot")
        elif choice == "start_vpn":
            pm2_manager.start("vpn-logger")
        elif choice == "stop_vpn":
            pm2_manager.stop("vpn-logger")
        elif choice == "logs_honeypot":
            print(pm2_manager.logs("honeypot"))
        elif choice == "logs_vpn":
            print(pm2_manager.logs("vpn-logger"))
        elif choice == "save":
            print(pm2_manager.save())
        _prompt_enter()


def run() -> None:
    """Main loop — InquirerPy menu dispatcher."""
    print("\033[2J\033[H", end="")  # clear screen on start
    print_logo()
    print(f"  {C.DIM}NetHunter TUI — síťové diagnostické nástroje{C.RESET}\n")
    while True:
        choice = inquirer.select(
            message=f"{C.BOLD}nethunter TUI{C.RESET} — Vyber operaci:",
            choices=[
                Choice(name="[1] Aktivní skenování (Nmap Connect Scan)", value="scan"),
                Choice(name="[2] Lokální VPN Sniffer / TCP spojení",     value="vpn"),
                Choice(name="[3] DNS a Reconnaissance (Dig / Whois)",    value="dns"),
                Choice(name="[4] Síťová konfigurace (IP / Routování)",   value="net"),
                Choice(name="[5] 🛡️ Honeypot (past na útočníky)",      value="honeypot"),
                Choice(name="[6] ⚙️  Správa služeb na pozadí (PM2)",    value="pm2"),
                Choice(name="[7] 👋 Ukončit", value="exit"),
            ],
            qmark="▸",
            amark="▸",
        ).execute()

        if choice == "exit":
            print(f"\n{C.GREEN}👋 Nashle!{C.RESET}")
            sys.exit(0)
        elif choice == "scan":
            run_nmap_scan()
            _prompt_enter()
        elif choice == "vpn":
            vpn_submenu()
        elif choice == "dns":
            dns_submenu()
        elif choice == "net":
            net_submenu()
        elif choice == "honeypot":
            honeypot_submenu()
        elif choice == "pm2":
            _pm2_submenu()


if __name__ == "__main__":
    run()
