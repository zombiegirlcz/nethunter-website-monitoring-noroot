"""Mutual watchdog: heartbeat + cross-instance revival for honeypot shadow pair.

Each instance writes its heartbeat to ``~/.nethunter/heartbeat-{instance}.ts``
and monitors the other instance's heartbeat. If the other is stale for > 60 s,
it issues ``pm2 restart <other>``.

Cron provides a third-layer safety net — see ``bin/watchdog-cron.sh``.
"""

import os
import time
import logging
import threading
import subprocess
from typing import Optional

logger = logging.getLogger(__name__)

# ── Constants ───────────────────────────────────────────────────────────────

_HEARTBEAT_DIR = os.path.join(os.path.expanduser("~"), ".nethunter")
_HEARTBEAT_TTL = 60          # seconds — if heartbeat older than this, assume dead
_WATCHDOG_INTERVAL = 30      # seconds between health checks
_PM2_CHECK_INTERVAL = 15     # seconds between "am I even registered in PM2?" checks
_INSTANCES = {               # instance_name → partner_name
    "primary": "honeypot-shadow",
    "shadow": "honeypot",
}
_PM2_NAMES = {
    "primary": "honeypot",
    "shadow": "honeypot-shadow",
}


# ── Helpers ─────────────────────────────────────────────────────────────────


def _heartbeat_path(instance: str) -> str:
    """Return absolute path to heartbeat file for *instance* (e.g. ``primary``)."""
    return os.path.join(_HEARTBEAT_DIR, f"heartbeat-{instance}.ts")


def _write_heartbeat(instance: str) -> None:
    """Write current epoch timestamp to heartbeat file."""
    path = _heartbeat_path(instance)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    try:
        with open(path, "w") as f:
            f.write(f"{time.time():.0f}\n")
    except OSError as exc:
        logger.warning("Cannot write heartbeat %s: %s", path, exc)


def _read_heartbeat(instance: str) -> Optional[float]:
    """Read heartbeat timestamp for *instance*, or ``None``."""
    path = _heartbeat_path(instance)
    try:
        with open(path) as f:
            return float(f.read().strip())
    except (OSError, ValueError):
        return None


def _pm2_restart(pm2_name: str) -> Optional[str]:
    """Run ``pm2 restart <pm2_name>``, return stdout+stderr or ``None`` on fail."""
    try:
        r = subprocess.run(
            ["pm2", "restart", pm2_name],
            capture_output=True, text=True, timeout=15,
        )
        out = (r.stdout or "") + (r.stderr or "")
        logger.info("PM2 restart %s → exit=%d\n%s", pm2_name, r.returncode, out[:512])
        return out
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        logger.warning("PM2 restart %s failed: %s", pm2_name, exc)
        return None


# ── Heartbeat writer thread ────────────────────────────────────────────────


def start_heartbeat_writer(instance: str, stop_ev: threading.Event,
                           interval: float = 15.0) -> threading.Thread:
    """Daemon thread that writes a heartbeat file every *interval* seconds."""
    def _loop() -> None:
        while not stop_ev.is_set():
            _write_heartbeat(instance)
            stop_ev.wait(interval)

    t = threading.Thread(target=_loop, daemon=True,
                         name=f"hb-writer-{instance}")
    t.start()
    return t


# ── Mutual watchdog thread ───────────────────────────────────────────────


def start_mutual_watchdog(instance: str, stop_ev: threading.Event,
                          interval: float = _WATCHDOG_INTERVAL,
                          ttl: float = _HEARTBEAT_TTL) -> threading.Thread:
    """Daemon thread that monitors the partner instance's heartbeat.

    If the partner's heartbeat is older than *ttl* seconds, issues
    ``pm2 restart <partner>``.
    """
    partner = _INSTANCES[instance]
    pm2_name = partner  # _INSTANCES already maps to the PM2 process name

    def _loop() -> None:
        logger.info("Watchdog started: monitoring %s via PM2 name %s",
                     partner, pm2_name)
        while not stop_ev.is_set():
            stop_ev.wait(interval)
            if stop_ev.is_set():
                break

            ts = _read_heartbeat(partner)
            now = time.time()

            if ts is None:
                logger.warning("No heartbeat file for %s — attempting revival",
                               partner)
                _pm2_restart(pm2_name)
                continue

            age = now - ts
            if age > ttl:
                logger.warning(
                    "Heartbeat %s is %.0f s stale (TTL=%.0f) — reviving",
                    partner, age, ttl,
                )
                _pm2_restart(pm2_name)
            else:
                logger.debug("Heartbeat %s is %.0f s old — OK", partner, age)

    t = threading.Thread(target=_loop, daemon=True,
                         name=f"wd-{instance}")
    t.start()
    return t


# ── PM2 integrity checker (background) ────────────────────────────────────


def start_pm2_integrity_check(pm2_name: str, stop_ev: threading.Event,
                               interval: float = 60.0) -> threading.Thread:
    """Daemon thread that periodically verifies this instance is running in
    PM2 and re-registers itself if missing (e.g. PM2 was restarted)."""
    def _loop() -> None:
        while not stop_ev.is_set():
            stop_ev.wait(interval)
            if stop_ev.is_set():
                break
            try:
                r = subprocess.run(
                    ["pm2", "jlist"],
                    capture_output=True, text=True, timeout=10,
                )
                if r.returncode != 0:
                    continue
                import json
                procs = json.loads(r.stdout)
                found = any(p.get("name") == pm2_name
                            for p in procs)
                if not found:
                    logger.warning(
                        "Instance %s not found in PM2 — re-registering", pm2_name
                    )
                    subprocess.run(
                        ["pm2", "start", os.path.join(
                            os.path.dirname(__file__), "..", "ecosystem.config.js"
                        ), "--only", pm2_name],
                        capture_output=True, text=True, timeout=15,
                    )
            except Exception as exc:
                logger.debug("PM2 integrity check failed: %s", exc)

    t = threading.Thread(target=_loop, daemon=True,
                         name=f"pm2-check-{pm2_name}")
    t.start()
    return t


# ── Convenience: start all watchdog services for one instance ────────────


def start_all(instance: str, stop_ev: threading.Event) -> dict:
    """Start heartbeat writer + mutual watchdog.

    Returns ``{"heartbeat": Thread, "watchdog": Thread}``.
    """
    pm2_name = _PM2_NAMES[instance]
    hb = start_heartbeat_writer(instance, stop_ev=stop_ev)
    wd = start_mutual_watchdog(instance, stop_ev=stop_ev)
    pi = start_pm2_integrity_check(pm2_name, stop_ev=stop_ev)
    return {"heartbeat": hb, "watchdog": wd, "pm2_check": pi}


# ── CLI entry ─────────────────────────────────────────────────────────────


def run_watchdog_cli() -> None:
    """Minimal CLI for testing: ``python3 -m nethunter_tui.watchdog primary``."""
    import sys
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(message)s")

    instance = sys.argv[1] if len(sys.argv) > 1 else "primary"
    if instance not in _INSTANCES:
        print(f"Usage: {sys.argv[0]} [primary|shadow]", file=sys.stderr)
        sys.exit(1)

    stop_ev = threading.Event()
    svc = start_all(instance, stop_ev)

    print(f"Watchdog running for instance={instance}")
    print(f"  Heartbeat writer: {svc['heartbeat'].name}")
    print(f"  Mutual watchdog:  {svc['watchdog'].name}")
    print(f"  PM2 integrity:    {svc['pm2_check'].name}")
    print("Press Ctrl+C to stop.")

    try:
        while not stop_ev.is_set():
            stop_ev.wait(1)
    except KeyboardInterrupt:
        print("\nShutting down …")
        stop_ev.set()


if __name__ == "__main__":
    run_watchdog_cli()
