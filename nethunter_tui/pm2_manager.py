"""PM2 service manager wrapper for nethunter-TUI background services.

Provides start/stop/restart/status/log access to services managed by PM2
(e.g. honeypot daemon, VPN logger).

Uses subprocess to shell out to ``pm2``.
"""

import shutil
import subprocess
from typing import Dict, List, Optional


# ── Helpers ─────────────────────────────────────────────────────────────


def _pm2(*args: str, timeout: int = 10) -> subprocess.CompletedProcess:
    """Run a ``pm2`` subprocess."""
    pm2_bin = shutil.which("pm2")
    if pm2_bin is None:
        raise FileNotFoundError("pm2 not found — install it via 'npm install -g pm2'")
    return subprocess.run(
        [pm2_bin, *args],
        capture_output=True,
        text=True,
        timeout=timeout,
    )


_ECOSYSTEM = "/home/kali/nethunter-TUI/ecosystem.config.js"
_AVAILABLE_SERVICES = ["honeypot", "honeypot-shadow", "vpn-logger", "nethunter-tui"]


# ── Public API ─────────────────────────────────────────────────────────


def available() -> List[str]:
    """Return list of service names defined in the ecosystem file."""
    return list(_AVAILABLE_SERVICES)


def status() -> Dict[str, str]:
    """Return {service_name: status_string} for all registered services.

    Status strings: "online", "stopped", "errored", or "unknown".
    """
    result = _pm2("jlist", timeout=5)
    if result.returncode != 0:
        return {s: "unknown" for s in _AVAILABLE_SERVICES}
    try:
        import json
        processes = json.loads(result.stdout)
    except (json.JSONDecodeError, TypeError):
        return {s: "unknown" for s in _AVAILABLE_SERVICES}

    proc_map: Dict[str, str] = {}
    for p in processes:
        name = p.get("name", "")
        pm2_env = p.get("pm2_env", {})
        proc_map[name] = pm2_env.get("status", "unknown")

    return {s: proc_map.get(s, "stopped") for s in _AVAILABLE_SERVICES}


def start(service: Optional[str] = None) -> str:
    """Start a service (or all if *service* is ``None``).

    Returns the stdout from pm2.
    """
    if service:
        args = ["start", _ECOSYSTEM, "--only", service]
    else:
        args = ["start", _ECOSYSTEM]
    result = _pm2(*args)
    return result.stdout or result.stderr


def stop(service: Optional[str] = None) -> str:
    """Stop a service (or all if *service* is ``None``).

    Returns the stdout from pm2.
    """
    if service:
        args = ["stop", service]
    else:
        args = ["stop", _ECOSYSTEM]
    result = _pm2(*args)
    return result.stdout or result.stderr


def restart(service: Optional[str] = None) -> str:
    """Restart a service (or all if *service* is ``None``).

    Returns the stdout from pm2.
    """
    if service:
        args = ["restart", service]
    else:
        args = ["restart", _ECOSYSTEM]
    result = _pm2(*args)
    return result.stdout or result.stderr


def logs(service: Optional[str] = None, lines: int = 20) -> str:
    """Return last *lines* log entries for *service* (or all if ``None``).

    Returns the logs as a single string.
    """
    args = ["logs", "--nostream", "--lines", str(lines)]
    if service:
        args.extend(["--nostream", service])
    else:
        args.append("--nostream")
    result = _pm2(*args)
    return result.stdout or result.stderr


def save() -> str:
    """Save the current PM2 process list (so it survives reboot after
    ``pm2 startup``)."""
    result = _pm2("save")
    return result.stdout or result.stderr


def is_installed() -> bool:
    """Return ``True`` if the ``pm2`` binary is available on ``$PATH``."""
    return shutil.which("pm2") is not None
