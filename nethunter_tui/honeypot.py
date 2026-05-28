"""
Multi-port TCP honeypot engine with fake banners, payload capture,
scan detection, JSON logging, and TUI integration helpers.

Usage::

    engine = get_engine()
    engine.start([2222, 2323, 2121])
    status = engine.get_status()
    engine.stop()
"""

import json
import logging
import os
import socket
import threading
import time
from collections import deque
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from .logo import C, info_box, colorize
from .msf_controller import MsfController
from .utils import nethunter_notify

# ── Logging ───────────────────────────────────────────────────────────────

logger = logging.getLogger(__name__)


# ── Data classes ───────────────────────────────────────────────────────────


@dataclass
class AttackEvent:
    """Recorded attack from a single TCP connection."""
    timestamp: str            # ISO-8601
    src_ip: str
    src_port: int
    dst_port: int
    banner_sent: str          # service name
    payload: str              # first 1024 bytes, sanitised
    payload_hex: str          # hex dump if payload not printable
    scan_alert: bool          # True if same IP connected >= N times in window
    raw_len: int = 0
    credentials: List[str] = field(default_factory=list)
    severity: int = 0         # attack severity 0–10 (0=benign, 10=critical)
    exploit_type: str = ""    # e.g. "sqli", "cmd_inject", "overflow", "traversal"


@dataclass
class HoneypotConfig:
    """Mutable configuration for the honeypot engine."""
    ports: List[int] = field(
        default_factory=lambda: [2222, 2323, 2121, 8443, 9090]
    )
    scan_threshold: int = 5     # connections within window → scan alert
    scan_window: float = 60.0   # seconds
    max_payload: int = 2048
    max_events: int = 100       # circular buffer size
    log_dir: str = ""           # auto-set from XDG / home
    log_file: str = ""          # auto-set from log_dir
    blacklist_duration: int = 300  # auto-block scan IPs for N seconds
    interactive_services: bool = True  # fake auth interaction on SSH/Telnet/FTP
    throttle_enabled: bool = True     # delay suspicious IPs
    throttle_delay: float = 2.0       # seconds delay per connection
    auto_defense: str = "none"        # "none" | "recon" | "aggressive"
    critical_threshold: int = 3       # critical events before auto-defense
    defense_cooldown: int = 600       # seconds between defense actions per IP


# ── Service banners ───────────────────────────────────────────────────────

BANNERS: Dict[int, bytes] = {
    22:   b"SSH-2.0-OpenSSH_9.2p1 Debian-2\r\n",
    2222: b"SSH-2.0-OpenSSH_9.2p1 Debian-2\r\n",
    23:   b"\r\nTelnet (Nethunter)\r\nlogin: ",
    2323: b"\r\nTelnet (Nethunter)\r\nlogin: ",
    21:   b"220 (vsFTPd 3.0.5)\r\n",
    2121: b"220 (vsFTPd 3.0.5)\r\n",
    80:   b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.57\r\n\r\n",
    8080: b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.57\r\n\r\n",
    443:  b"",                        # capture only – no plain banner
    8443: b"",
}


# ── Engine ────────────────────────────────────────────────────────────────


class HoneypotEngine:
    """
    Thread-per-port TCP honeypot.

    Each port runs a daemon listener thread that accepts connections,
    sends a fake banner, captures the first *max_payload* bytes,
    logs the interaction, and attaches metadata (scan detection).
    """

    def __init__(self, config: Optional[HoneypotConfig] = None):
        self.config = config or HoneypotConfig()
        self._setup_logging()

        self._listeners: Dict[int, socket.socket] = {}
        self._threads: Dict[int, threading.Thread] = {}
        self._stop_ev = threading.Event()
        self._lock = threading.Lock()

        # IP tracking for scan detection
        self._ip_counter: Dict[str, List[float]] = {}
        self._conn_semaphore: Dict[str, int] = {}  # concurrent connections/IP

        # Auto-blacklist: IP → unblock timestamp (epoch)
        self._blacklist: Dict[str, float] = {}

        # Circular buffer of recent events
        self._events: deque = deque(maxlen=self.config.max_events)

        # Bind errors reporting
        self._bind_errors: Dict[int, str] = {}

        # Periodic blacklist cleanup timer
        self._cleanup_timer: Optional[threading.Thread] = None

        # Auto-fallback port mapping: {original_port: actual_port}
        self._port_map: Dict[int, int] = {}

        # Auto-defense resources
        self._msf: Optional[MsfController] = None
        self._critical_counter: Dict[str, int] = {}  # IP → critical event count
        self._defense_cooldown: Dict[str, float] = {}  # IP → next allowed defense time

    # ── Setup ─────────────────────────────────────────────────────────

    def _setup_logging(self) -> None:
        log_dir = self.config.log_dir or os.path.join(
            os.path.expanduser("~"), ".nethunter"
        )
        os.makedirs(log_dir, exist_ok=True)
        self.config.log_dir = log_dir
        self.config.log_file = os.path.join(log_dir, "honeypot.log")

    # ── Public API ───────────────────────────────────────────────────

    def start(self, ports: Optional[List[int]] = None) -> Dict[int, Optional[str]]:
        """
        Start honeypot listeners on *ports*.

        Returns a dict ``{port: error_or_None}``.
        If *ports* is omitted, uses ``self.config.ports``.
        """
        if ports is not None:
            self.config.ports = ports

        self._stop_ev.clear()
        self._bind_errors.clear()
        self._port_map.clear()
        results: Dict[int, Optional[str]] = {}

        # Start blacklist cleanup thread
        if self._cleanup_timer is None or not self._cleanup_timer.is_alive():
            self._cleanup_timer = threading.Thread(
                target=self._blacklist_cleanup_loop,
                daemon=True,
                name="honeypot-blacklist-cleanup",
            )
            self._cleanup_timer.start()

        for port in self.config.ports:
            err = self._start_listener(port)
            results[port] = err
            if err:
                self._bind_errors[port] = err

        # Give threads a moment to fail-fast if bind failed
        time.sleep(0.2)
        return results

    def stop(self) -> None:
        """Signal all listeners to stop and close sockets."""
        self._stop_ev.set()
        with self._lock:
            for port, sock in self._listeners.items():
                try:
                    sock.close()
                except OSError:
                    pass
            self._listeners.clear()
            self._threads.clear()
            self._port_map.clear()

    def get_status(self) -> Dict[str, object]:
        """Return a status dict for the dashboard."""
        running_ports = []
        with self._lock:
            for port, t in list(self._threads.items()):
                if t and t.is_alive():
                    running_ports.append(port)

        now = time.time()
        active_blacklist = sum(
            1 for expires in self._blacklist.values() if expires > now
        )

        # Build port display: "2222→10222" when fallback used
        port_display = []
        for p in running_ports:
            orig = next((k for k, v in self._port_map.items() if v == p), p)
            port_display.append(f"{orig}→{p}" if orig != p else str(p))

        return {
            "running": len(running_ports) > 0,
            "ports": port_display,
            "total_attacks": len(self._events),
            "errors": dict(self._bind_errors),
            "blacklisted_ips": active_blacklist,
        }

    def get_attack_log(self, n: int = 20) -> List[AttackEvent]:
        """Return the last *n* attack events."""
        with self._lock:
            return list(self._events)[-n:]

    def get_events_since(self, since: float) -> List[AttackEvent]:
        """Return events whose timestamp (epoch) >= *since*."""
        result = []
        with self._lock:
            for ev in self._events:
                try:
                    ts = datetime.fromisoformat(ev.timestamp).timestamp()
                    if ts >= since:
                        result.append(ev)
                except ValueError:
                    continue
        return result

    # ── Internal ─────────────────────────────────────────────────────

    @staticmethod
    def _find_free_port(start_port: int, max_attempts: int = 200) -> Optional[int]:
        """
        Return the first free port at or above *start_port*.
        Tries up to *max_attempts* consecutive ports.
        """
        for port in range(start_port, start_port + max_attempts):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(("0.0.0.0", port))
                sock.close()
                return port
            except OSError:
                continue
        return None

    def _start_listener(self, port: int, fallback: bool = True) -> Optional[str]:
        """
        Start one listener thread.

        If *fallback* is True and *port* is occupied, automatically finds the
        next free port and binds to it instead.  The mapping is stored in
        ``self._port_map[original_port] = actual_port``.

        Return None on success, error string on failure.
        """
        actual_port = port
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(1.0)

        try:
            sock.bind(("0.0.0.0", port))
            sock.listen(5)
        except OSError:
            sock.close()
            if not fallback:
                return f"port {port}: obsazen"
            free_port = self._find_free_port(port + 1)
            if free_port is None:
                return f"port {port}: obsazen, žádný náhradní port nenalezen"
            actual_port = free_port
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(1.0)
            try:
                sock.bind(("0.0.0.0", free_port))
                sock.listen(5)
            except OSError as e:
                sock.close()
                return f"port {port}: {e}"

        with self._lock:
            self._listeners[actual_port] = sock
            self._port_map[port] = actual_port
            ready_ev = threading.Event()
            t = threading.Thread(
                target=self._listener_loop,
                args=(actual_port, sock, ready_ev),
                daemon=True,
                name=f"honeypot-{actual_port}",
            )
            t.start()
            self._threads[actual_port] = t

        if not ready_ev.wait(timeout=2.0):
            return f"port {port}: vlákno se nespustilo (timeout)"

        # Check if thread died immediately due to bind error
        bind_err = getattr(t, "_bind_error", None)
        if bind_err:
            return f"port {port}: {bind_err}"

        return None

    # ── Blacklist helpers ──────────────────────────────────────────

    def _is_blacklisted(self, ip: str) -> bool:
        """Check if *ip* is currently blacklisted."""
        now = time.time()
        expires = self._blacklist.get(ip)
        if expires is None:
            return False
        if expires <= now:
            with self._lock:
                self._blacklist.pop(ip, None)
            return False
        return True

    def _add_to_blacklist(self, ip: str) -> None:
        """Add *ip* to the auto-blacklist for *blacklist_duration* seconds."""
        expires = time.time() + self.config.blacklist_duration
        with self._lock:
            self._blacklist[ip] = expires
        logger.info("Blacklisted %s for %ds", ip, self.config.blacklist_duration)
        nethunter_notify("block")

    def _blacklist_cleanup_loop(self) -> None:
        """Periodic cleanup of expired blacklist entries."""
        while not self._stop_ev.is_set():
            now = time.time()
            expired = [
                ip for ip, expires in self._blacklist.items()
                if expires <= now
            ]
            if expired:
                with self._lock:
                    for ip in expired:
                        self._blacklist.pop(ip, None)
                        self._ip_counter.pop(ip, None)
            self._stop_ev.wait(30)

    # ── Fake interaction helpers ───────────────────────────────────

    _LOGIN_PROMPTS: Dict[int, bytes] = {
        23:   b"Password: ",
        2323: b"Password: ",
    }

    _FTP_USER_RE = None  # lazy import

    @classmethod
    def _fake_telnet_interact(cls, conn: socket.socket,
                              payload: bytes,
                              dst_port: int) -> Tuple[str, List[str]]:
        """After Telnet banner, parse username from payload, send
        Password: prompt, and capture the password reply.

        Returns (updated_payload_text, captured_credentials).
        """
        import re as _re
        text = payload.decode("utf-8", errors="replace").strip()
        creds: List[str] = []

        # Telnet: user usually sent right after banner
        if text:
            # Many clients send login after banner
            creds.append(f"username={text}")
            pwd_prompt = cls._LOGIN_PROMPTS.get(dst_port, b"Password: ")
            try:
                conn.sendall(pwd_prompt)
                pwd_data = conn.recv(1024)
                pwd = pwd_data.decode("utf-8", errors="replace").strip()
                if pwd:
                    creds.append(f"password={pwd}")
                    text += " | password=" + pwd
            except (socket.timeout, OSError):
                pass

        return text, creds

    @classmethod
    def _fake_ftp_interact(cls, conn: socket.socket,
                           payload: bytes,
                           dst_port: int) -> Tuple[str, List[str]]:
        """After FTP banner, wait for USER command, reply with password
        prompt, and capture the PASS reply.

        Returns (updated_payload_text, captured_credentials).
        """
        text = payload.decode("utf-8", errors="replace").strip()
        creds: List[str] = []

        # FTP: look for USER command
        if text.upper().startswith("USER "):
            username = text[5:].strip()
            creds.append(f"username={username}")
            try:
                conn.sendall(b"331 User OK, need password\r\n")
                pwd_data = conn.recv(1024)
                pwd = pwd_data.decode("utf-8", errors="replace").strip()
                if pwd.upper().startswith("PASS "):
                    password = pwd[5:].strip()
                    creds.append(f"password={password}")
                    text += f" | PASS={password}"
                elif pwd:
                    creds.append(f"reply={pwd}")
                    text += f" | reply={pwd}"
            except (socket.timeout, OSError):
                pass

        return text, creds

    # ── Critical attack detection ─────────────────────────────────

    @staticmethod
    def _score_payload(data: bytes, dst_port: int) -> tuple:
        """Analyze *data* for exploit signatures.

        Returns ``(severity: int, exploit_type: str, details: List[str])``
        where severity is 0–10.
        """
        if not data:
            return 0, "", []

        payload_text = data.decode("utf-8", errors="replace")
        payload_lower = payload_text.lower()
        details: List[str] = []
        severity = 0
        ex_type = ""

        # ── SQL injection patterns ──────────────────────────────────
        sqli_patterns = [
            (r"'(\s*OR|\s*or|\s*Or)", "OR injection"),
            (r"union(\s+all)?\s+select", "UNION SELECT"),
            (r"1=1", "1=1 probe"),
            (r"--(\s|$)", "SQL comment injection"),
            (r"drop\s+table", "DROP TABLE"),
            (r"admin'\s*--", "admin bypass"),
            (r"or\s+1=1", "OR 1=1"),
            (r"'\s*or\s+'\d'\s*=\s*'\d", "tautology"),
            (r"sleep\(\s*\d+\s*\)", "time-based blind"),
        ]
        import re as _re
        for pat, label in sqli_patterns:
            if _re.search(pat, payload_lower):
                details.append(label)
                severity = max(severity, 5)

        # ── Command injection patterns ──────────────────────────────
        cmd_shells = [
            r"/bin/sh", r"/bin/bash", r"/bin/zsh", r"bash\s+-i",
            r"sh\s+-c", r"cmd\.exe", r"powershell",
        ]
        for pat in cmd_shells:
            if _re.search(pat, payload_lower):
                details.append("shell_invoke")
                severity = max(severity, 8)

        cmd_ops = [
            (r"(^|[|;&`])nc\s", "netcat"),
            (r"wget\s+", "wget"),
            (r"curl\s+", "curl"),
            (r"\|.*/bin/sh", "pipe_shell"),
            (r";\s*(rm|mv|dd|mkfs|reboot|halt)", "destructive_cmd"),
            (r"\$\(cat\s+", "subshell_cat"),
            (r"`cat\s+", "backtick_cat"),
            (r"python\s+-c\s*['\"]", "python_exec"),
            (r"perl\s+-e\s*['\"]", "perl_exec"),
        ]
        for pat, label in cmd_ops:
            if _re.search(pat, payload_lower):
                details.append(label)
                severity = max(severity, 7)

        # ── Path traversal ──────────────────────────────────────────
        trav_patterns = [
            (r"\.\./", "traversal"),
            (r"%2e%2e%2f", "encoded_traversal"),
            (r"\.\.\\", "win_traversal"),
            (r"\.\.%5c", "encoded_win_traversal"),
            (r"/etc/passwd", "etc_passwd"),
            (r"/etc/shadow", "etc_shadow"),
        ]
        for pat, label in trav_patterns:
            if _re.search(pat, payload_lower):
                details.append(label)
                severity = max(severity, 4)

        # ── Buffer overflow / DoS patterns ──────────────────────────
        rep_bytes = 0
        for b in data[:512]:
            if b == data[0]:
                rep_bytes += 1
            else:
                break
        if rep_bytes > 500:
            details.append(f"overflow_repeated_byte(0x{data[0]:02x}x{rep_bytes})")
            severity = max(severity, 7)
        # NOP sled
        if b"\x90\x90\x90" in data:
            details.append("nop_sled")
            severity = max(severity, 6)
        # Long string of A
        if b"A" * 200 in data:
            details.append("long_A_padding")
            severity = max(severity, 5)

        # ── HTTP exploitation ───────────────────────────────────────
        if dst_port in (80, 8080) or dst_port in (443, 8443):
            if "<?php" in payload_lower or "system(" in payload_lower:
                details.append("php_code_inject")
                severity = max(severity, 8)
            if "<script>" in payload_lower and "alert" in payload_lower:
                details.append("xss_probe")
                severity = max(severity, 3)

        # ── Known exploit / scanner signatures ──────────────────────
        # Metasploit default payload markers
        msf_patterns = [
            (b"metasploit", "metasploit_agent"),
            (b"meterpreter", "meterpreter"),
            (b"reverse_tcp", "reverse_tcp"),
            (b"\x00" * 20, "null_padding"),
        ]
        for pat, label in msf_patterns:
            if pat in data:
                details.append(label)
                severity = max(severity, 9)

        # HTTP scanner tools
        tool_patterns = [
            ("nikto", "nikto"),
            ("sqlmap", "sqlmap"),
            ("nmap_scan", "nmap"),
            ("acunetix", "acunetix"),
            ("nessus", "nessus"),
            ("openvas", "openvas"),
            ("burpsuite", "burpsuite"),
            ("zap", "zap_proxy"),
            ("gobuster", "gobuster"),
        ]
        for pat, label in tool_patterns:
            if pat in payload_lower:
                if label not in details:
                    details.append(label)
                severity = max(severity, 2)

        ex_type = ",".join(sorted(set(details))) if details else ""
        return severity, ex_type, details

    def _trigger_defense(self, ip: str, ports: List[int],
                         severity: int) -> Optional[str]:
        """Launch MSF counter-measure against *ip* if allowed.

        Respects defense cooldown per IP.
        Returns the MSF output or None.
        """
        now = time.time()

        # Cooldown check
        cooldown_until = self._defense_cooldown.get(ip, 0)
        if now < cooldown_until:
            remaining = int(cooldown_until - now)
            logger.debug("Defense cooldown for %s: %ds remaining", ip, remaining)
            return None

        # Determine level based on config
        level = self.config.auto_defense
        if level == "none":
            return None

        # Lazy-init MSF controller
        if self._msf is None:
            self._msf = MsfController()

        # Escalate to aggressive if severity >= 8
        if severity >= 8 and level == "recon":
            level = "aggressive"
            logger.info("Escalating defense for %s to aggressive (severity=%d)", ip, severity)

        # Run counter-measure in background thread
        def _run() -> None:
            logger.info("Auto-defense %s -> %s (level=%s, sev=%d, ports=%s)",
                        ip, level, severity, ports)
            nethunter_notify("counter")
            output = self._msf.run_countermeasure(ip, level, ports)
            if output:
                # Log output to file
                log_path = os.path.join(self.config.log_dir, "defense.log")
                try:
                    with open(log_path, "a") as f:
                        f.write(f"[{datetime.now(timezone.utc).isoformat()}] "
                                f"{ip} {level} sev={severity}\n{output[:4096]}\n---\n")
                except OSError:
                    pass

        def_t = threading.Thread(target=_run, daemon=True,
                                 name=f"defense-{ip.replace('.','_')}")
        def_t.start()

        # Set cooldown
        with self._lock:
            self._defense_cooldown[ip] = now + self.config.defense_cooldown

        return f"Defense {level} launched against {ip}"

    # ── Listener ───────────────────────────────────────────────────

    def _listener_loop(self, port: int, sock: socket.socket,
                       ready_ev: threading.Event) -> None:
        """Accept loop for a single port."""
        ready_ev.set()

        while not self._stop_ev.is_set():
            try:
                conn, addr = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break  # socket closed

            threading.Thread(
                target=self._handle_connection,
                args=(conn, addr, port),
                daemon=True,
            ).start()

    def _handle_connection(self, conn: socket.socket,
                          addr: Tuple[str, int], dst_port: int) -> None:
        """Handle one TCP connection: check blacklist, send banner,
        capture payload, run fake auth interaction, log event."""
        src_ip, src_port = addr

        # ── Blacklist check ────────────────────────────────────────
        if self._is_blacklisted(src_ip):
            try:
                conn.close()
            except OSError:
                pass
            logger.debug("Dropped blacklisted %s -> port %d", src_ip, dst_port)
            nethunter_notify("block")
            return

        payload = b""
        banner = BANNERS.get(dst_port, b"")
        credentials: List[str] = []

        try:
            conn.settimeout(5.0)

            # ── Connection throttling ──────────────────────────────
            if self.config.throttle_enabled:
                now = time.time()
                with self._lock:
                    timestamps = self._ip_counter.get(src_ip, [])
                    recent = sum(1 for ts in timestamps if now - ts <= self.config.scan_window)
                if recent >= self.config.scan_threshold // 2:
                    logger.debug("Throttling %s (conns=%d)", src_ip, recent)
                    try:
                        conn.sendall(banner)
                    except OSError:
                        pass
                    try:
                        self._stop_ev.wait(self.config.throttle_delay)
                        if self._stop_ev.is_set():
                            return
                    except OSError:
                        pass
                else:
                    if banner:
                        try:
                            conn.sendall(banner)
                        except OSError:
                            pass
            else:
                if banner:
                    try:
                        conn.sendall(banner)
                    except OSError:
                        pass

            # ── Read payload ───────────────────────────────────────
            try:
                payload = conn.recv(self.config.max_payload)
            except socket.timeout:
                pass
            except OSError:
                pass

            # ── Fake auth interaction ──────────────────────────────
            if self.config.interactive_services and payload:
                try:
                    if dst_port in (23, 2323):
                        text, creds = self._fake_telnet_interact(conn, payload, dst_port)
                        credentials.extend(creds)
                    elif dst_port in (21, 2121):
                        text, creds = self._fake_ftp_interact(conn, payload, dst_port)
                        credentials.extend(creds)
                except (socket.timeout, OSError):
                    pass

        finally:
            try:
                conn.close()
            except OSError:
                pass

        # ── Scan detection ─────────────────────────────────────────
        now = time.time()
        with self._lock:
            timestamps = self._ip_counter.setdefault(src_ip, [])
            timestamps.append(now)
            # Prune old entries
            self._ip_counter[src_ip] = [
                ts for ts in timestamps if now - ts <= self.config.scan_window
            ]
            is_scan = len(self._ip_counter[src_ip]) >= self.config.scan_threshold

        # Auto-blacklist scanners
        if is_scan and not self._is_blacklisted(src_ip):
            self._add_to_blacklist(src_ip)

        # ── Build event ───────────────────────────────────────────
        try:
            payload_text = payload.decode("utf-8", errors="replace")
        except Exception:
            payload_text = repr(payload)

        # Score payload for exploit signatures
        severity, ex_type, _ = self._score_payload(payload, dst_port)
        if ex_type:
            logger.info("Exploit detected from %s on port %d: %s (sev=%d)",
                        src_ip, dst_port, ex_type, severity)

        event = AttackEvent(
            timestamp=datetime.now(timezone.utc).isoformat(),
            src_ip=src_ip,
            src_port=src_port,
            dst_port=dst_port,
            banner_sent=banner.split(b"\r\n")[0].decode(errors="replace") or "capture-only",
            payload=payload_text[:512],
            payload_hex=payload.hex()[:1024] if not payload_text.strip() else "",
            scan_alert=is_scan,
            raw_len=len(payload),
            credentials=credentials,
            severity=severity,
            exploit_type=ex_type,
        )

        with self._lock:
            self._events.append(event)

        # ── Auto-defense trigger ───────────────────────────────────
        if severity >= 4 and self.config.auto_defense != "none":
            # OK, severity high enough, notify counter immediately if this is the start of defense
            with self._lock:
                c = self._critical_counter.get(src_ip, 0) + 1
                self._critical_counter[src_ip] = c
            
            logger.info("Auto-defense trigger for %s (%d critical events, sev=%d)",
                        src_ip, c, severity)
            
            if c >= self.config.critical_threshold:
                ports = list(self._threads.keys())
                self._trigger_defense(src_ip, ports, severity)

        # JSON log
        try:
            with open(self.config.log_file, "a") as f:
                f.write(json.dumps(asdict(event), ensure_ascii=False) + "\n")
        except OSError:
            pass

        logger.info(
            "Honeypot attack: %s:%d -> port %d [%s] (scan=%s creds=%d sev=%d)",
            src_ip, src_port, dst_port,
            event.banner_sent, is_scan, len(credentials), severity,
        )


# ── Singleton ─────────────────────────────────────────────────────────────

_engine: Optional[HoneypotEngine] = None


def get_engine() -> HoneypotEngine:
    """Return the module-level singleton."""
    global _engine
    if _engine is None:
        _engine = HoneypotEngine()
    return _engine


# ── TUI helpers ──────────────────────────────────────────────────────────


def show_honeypot_status() -> str:
    """Render a human-readable status string for the TUI."""
    engine = get_engine()
    status = engine.get_status()

    if not status["running"]:
        return colorize("\n  🛡️  Honeypot: 🔴 NEBĚŽÍ\n", C.RED) + \
               colorize("  Pro spuštění použij 'Spustit honeypot' v menu.\n", C.DIM)

    parts = [
        ("Stav", "🟢 BĚŽÍ"),
        ("Porty", ", ".join(str(p) for p in status["ports"])),
        ("Zachycené útoky", str(status["total_attacks"])),
        ("Blacklist", str(status.get("blacklisted_ips", 0))),
    ]

    if status["errors"]:
        err_str = "; ".join(f"{p}: {e}" for p, e in status["errors"].items())
        parts.append(("Chyby", err_str))

    return "\n" + info_box(parts, C.CYAN)


def render_honeypot_dash_panel(engine: Optional['HoneypotEngine'] = None) -> str:
    """Return a short honeypot status line for the dashboard."""
    if engine is None:
        engine = get_engine()
    status = engine.get_status()
    if not status["running"]:
        return f"  {C.RED}🛡️  Honeypot: 🔴 NEBĚŽÍ{C.RESET}"
    bl = status.get("blacklisted_ips", 0)
    bl_str = f"  {C.RED}🚫 Blacklist: {bl}{C.RESET}" if bl else ""
    return (
        f"  {C.GREEN}🛡️  Honeypot: 🟢 BĚŽÍ{C.RESET}\n"
        f"    Porty: {C.BOLD}{', '.join(str(p) for p in status['ports'])}{C.RESET}\n"
        f"    Útoky: {C.YELLOW}{status['total_attacks']}{C.RESET}"
        + (f"\n{bl_str}" if bl else "")
    )


def run_daemon(instance: str = "primary") -> None:
    """PM2 entry point — runs honeypot as a background daemon.

    Args:
        instance: ``"primary"`` or ``"shadow"`` — controls watchdog identity.
    """
    import signal
    import time

    engine = get_engine()
    engine.start()
    print(f"[PM2] Honeypot-{instance} daemon started, ports:",
          list(engine.get_status()["ports"]))

    # ── Start mutual watchdog (heartbeat + cross-revival) ──────────
    from nethunter_tui.watchdog import start_all as start_watchdog
    stop_wd = threading.Event()
    wd_services = start_watchdog(instance, stop_wd)
    print(f"[PM2] Watchdog running: hb={wd_services['heartbeat'].name}, "
          f"wd={wd_services['watchdog'].name}")

    # Keep running until SIGTERM
    stop = False
    def _handle_signal(signum, frame):
        nonlocal stop
        stop = True
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    while not stop:
        time.sleep(1)

    stop_wd.set()
    engine.stop()
    print(f"[PM2] Honeypot-{instance} daemon stopped.")


if __name__ == "__main__":
    run_daemon()
