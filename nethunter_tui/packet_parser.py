"""
Packet dissection module for Nethunter TUI.

Parses raw packet data (PCAP records) into structured dicts with
IP/TCP/UDP/ICMP header fields and application-layer inspection
(HTTP, FTP, Telnet, SMTP). Includes credential detection.

Main entry point::

    result = process_packet(raw_bytes, link_type=1)
    summary = format_pcap_summary(result)
    detailed = format_full_dissection(result)
"""

import struct
import textwrap
from typing import Dict, Optional, Any

from .logo import C


# ── Constants ────────────────────────────────────────────────────────────

IP_PROTOCOLS: Dict[int, str] = {
    1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP",
    41: "IPv6", 47: "GRE", 50: "ESP", 51: "AH",
    89: "OSPF", 132: "SCTP",
}

PORT_SERVICES: Dict[int, str] = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
    143: "IMAP", 389: "LDAP", 443: "HTTPS", 993: "IMAPS",
    995: "POP3S", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    6379: "Redis", 8080: "HTTP-alt", 8443: "HTTPS-alt",
}

LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_NULL = 0

# Application-layer patterns
_AUTH_PATTERNS = [
    b"password", b"passwd", b"PASSWORD", b"secret",
    b"Authorization: Basic", b"login:", b"Login:",
    b"USER ", b"PASS ", b"AUTH LOGIN", b"AUTH PLAIN",
    b"&pass=", b"&password=", b'"pass":', b'"password":',
]

_HTTP_METHODS = {b"GET", b"POST", b"PUT", b"DELETE", b"PATCH", b"HEAD", b"OPTIONS"}


# ── PCAP global header parsing ───────────────────────────────────────────


def parse_pcap_global_header(data: bytes) -> Optional[Dict[str, Any]]:
    """Parse 24-byte PCAP global header. Returns dict or None."""
    if len(data) < 24:
        return None
    magic, ver_major, ver_minor, tz, sigfigs, snaplen, link_type = \
        struct.unpack("<IHHiIII", data[:24])
    return {
        "magic": hex(magic), "version": f"{ver_major}.{ver_minor}",
        "snaplen": snaplen, "link_type": link_type,
    }


# ── Link-layer stripping ─────────────────────────────────────────────────


def strip_link_layer(data: bytes, link_type: int) -> bytes:
    """Strip link-layer header and return IP payload. Returns empty bytes on failure."""
    if link_type == LINKTYPE_ETHERNET:
        if len(data) < 14:
            return b""
        eth_type = struct.unpack("!H", data[12:14])[0]
        # 0x0800 = IPv4, 0x86DD = IPv6
        if eth_type == 0x0800 or eth_type == 0x86DD:
            return data[14:]
        # 802.1Q VLAN (4 more bytes)
        if eth_type == 0x8100 and len(data) >= 18:
            eth_type2 = struct.unpack("!H", data[16:18])[0]
            if eth_type2 == 0x0800 or eth_type2 == 0x86DD:
                return data[18:]
        return b""
    elif link_type == LINKTYPE_RAW:
        return data
    elif link_type == LINKTYPE_NULL:
        # 4-byte header: AF_INET=2, AF_INET6=24 (BSD)
        if len(data) < 4:
            return b""
        return data[4:] if len(data) > 4 else b""
    return data  # unknown – pass through


# ── IP header parsing ────────────────────────────────────────────────────


def parse_ipv4(data: bytes) -> Dict[str, Any]:
    """Parse IPv4 header. Returns dict with at least {version, ihl, ...}."""
    result: Dict[str, Any] = {
        "version": 4, "error": None, "src": "?.?.?.?", "dst": "?.?.?.?",
        "protocol": "?", "total_length": 0, "header_length": 20,
    }
    if len(data) < 20:
        result["error"] = "Truncated IPv4 header"
        return result

    ver_ihl = data[0]
    ihl = (ver_ihl & 0x0F) * 4
    total_len = struct.unpack("!H", data[2:4])[0]
    proto_num = data[9]
    src = ".".join(str(b) for b in data[12:16])
    dst = ".".join(str(b) for b in data[16:20])

    result.update({
        "version": 4, "ihl": ihl, "tos": data[1],
        "total_length": total_len, "id": struct.unpack("!H", data[4:6])[0],
        "flags": data[6] >> 5, "fragment_offset": ((data[6] & 0x1F) << 8) | data[7],
        "ttl": data[8], "protocol": IP_PROTOCOLS.get(proto_num, str(proto_num)),
        "protocol_num": proto_num, "src": src, "dst": dst,
    })

    if ihl > 20:
        result["options"] = data[20:ihl].hex()
    return result


def parse_ipv6(data: bytes) -> Dict[str, Any]:
    """Parse IPv6 header."""
    result: Dict[str, Any] = {
        "version": 6, "error": None,
        "src": "::", "dst": "::", "protocol": "?", "total_length": 40,
    }
    if len(data) < 40:
        result["error"] = "Truncated IPv6 header"
        return result

    # Version (4) + Traffic Class (8) + Flow Label (20)
    v_tc_fl = struct.unpack("!I", data[:4])[0]
    payload_len = struct.unpack("!H", data[4:6])[0]
    next_hdr = data[6]
    hop_limit = data[7]

    src = ":".join(
        f"{data[i]:02x}{data[i+1]:02x}" for i in range(8, 24, 2)
    )
    dst = ":".join(
        f"{data[i]:02x}{data[i+1]:02x}" for i in range(24, 40, 2)
    )

    result.update({
        "version": 6, "payload_length": payload_len,
        "protocol": IP_PROTOCOLS.get(next_hdr, str(next_hdr)),
        "protocol_num": next_hdr, "hop_limit": hop_limit,
        "src": src, "dst": dst, "total_length": 40 + payload_len,
    })
    return result


# ── Transport layer parsing ──────────────────────────────────────────────


def parse_tcp(data: bytes) -> Dict[str, Any]:
    """Parse TCP header. Returns dict with src_port, dst_port, ..."""
    result: Dict[str, Any] = {
        "src_port": 0, "dst_port": 0, "protocol": "tcp",
        "error": None, "header": {},
    }
    if len(data) < 20:
        result["error"] = "Truncated TCP header"
        return result

    src_port, dst_port = struct.unpack("!HH", data[0:4])
    seq, ack = struct.unpack("!II", data[4:12])
    data_offset = (data[12] >> 4) * 4
    flags = {
        "FIN": bool(data[13] & 1), "SYN": bool(data[13] & 2),
        "RST": bool(data[13] & 4), "PSH": bool(data[13] & 8),
        "ACK": bool(data[13] & 16), "URG": bool(data[13] & 32),
    }

    window_val = struct.unpack("!H", data[14:16])[0]

    result.update({
        "src_port": src_port, "dst_port": dst_port, "seq": seq,
        "ack": ack, "data_offset": data_offset, "flags": flags,
        "window": window_val,
        "header": {
            "src_port": src_port, "dst_port": dst_port,
            "seq": seq, "ack": ack, "flags": flags,
            "window": window_val,
        },
    })
    return result


def parse_udp(data: bytes) -> Dict[str, Any]:
    """Parse UDP header."""
    result: Dict[str, Any] = {
        "src_port": 0, "dst_port": 0, "protocol": "udp",
        "error": None, "header": {},
    }
    if len(data) < 8:
        result["error"] = "Truncated UDP header"
        return result
    src_port, dst_port, length, checksum = struct.unpack("!HHHH", data[:8])
    result.update({
        "src_port": src_port, "dst_port": dst_port,
        "length": length, "checksum": checksum,
        "header": {"src_port": src_port, "dst_port": dst_port, "length": length},
    })
    return result


def parse_icmp(data: bytes) -> Dict[str, Any]:
    """Parse ICMP header (minimal)."""
    result: Dict[str, Any] = {
        "src_port": 0, "dst_port": 0, "protocol": "icmp",
        "error": None, "header": {},
    }
    if len(data) < 4:
        result["error"] = "Truncated ICMP header"
        return result
    icmp_type, icmp_code = data[0], data[1]
    type_names = {0: "Echo Reply", 3: "Dest Unreach", 8: "Echo Request", 11: "Time Exceeded"}
    result.update({
        "type": icmp_type, "code": icmp_code,
        "type_name": type_names.get(icmp_type, f"Type-{icmp_type}"),
        "header": {"type": icmp_type, "code": icmp_code},
    })
    return result


TRANSPORT_PARSERS = {
    6: parse_tcp,
    17: parse_udp,
    1: parse_icmp,
}


# ── Application-layer inspection ────────────────────────────────────────


def _sanitize_payload(data: bytes, max_len: int = 256) -> str:
    """Decode payload bytes to printable string, truncated."""
    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        text = repr(data)
    # Remove or replace unprintable chars
    sanitized = "".join(c if c.isprintable() or c in "\r\n\t" else "." for c in text)
    if len(sanitized) > max_len:
        sanitized = sanitized[:max_len] + "..."
    return sanitized


def _extract_credentials(payload: bytes) -> Dict[str, Any]:
    """Search payload for credentials. Returns {credentials: [...], interesting: bool}."""
    creds = []
    interesting = False
    text = payload.decode("utf-8", errors="replace")

    # HTTP Basic Auth
    if b"Authorization: Basic " in payload:
        import base64
        try:
            auth_b64 = payload.split(b"Authorization: Basic ")[1].split(b"\r\n")[0]
            decoded = base64.b64decode(auth_b64).decode(errors="replace")
            creds.append(f"HTTP Basic: {decoded}")
            interesting = True
        except Exception:
            pass

    # HTTP POST form data
    if b"&pass" in payload or b"&password" in payload or b"&pwd" in payload:
        try:
            body = text.split("\r\n\r\n")[-1] if "\r\n\r\n" in text else text
            for param in body.split("&"):
                if any(k in param.lower() for k in ["pass", "pwd", "secret", "token"]):
                    creds.append(f"Form: {param[:128]}")
                    interesting = True
        except Exception:
            pass

    # FTP
    if b"PASS " in payload and (b"USER " in payload or b"user " in payload):
        for kw in [b"USER ", b"user ", b"PASS ", b"pass "]:
            if kw in payload:
                try:
                    val = payload.split(kw)[1].split(b"\r\n")[0]
                    creds.append(f"FTP {kw.decode().strip()}: {val.decode(errors='replace')}")
                    interesting = True
                except Exception:
                    pass

    # Telnet login
    if b"login:" in payload or b"Login:" in payload:
        for kw in [b"login:", b"Login:", b"password:", b"Password:"]:
            if kw in payload:
                try:
                    val = payload.split(kw)[1].split(b"\r\n")[0]
                    creds.append(f"Telnet {kw.decode().strip()}: {val.decode(errors='replace')}")
                    interesting = True
                except Exception:
                    pass

    # SMTP AUTH
    if b"AUTH LOGIN" in payload or b"AUTH PLAIN" in payload:
        creds.append("SMTP AUTH detected")
        interesting = True

    # Generic keyword match
    for pat in _AUTH_PATTERNS:
        if pat in payload and pat not in [b"USER ", b"PASS ", b"login:", b"Login:"]:
            interesting = True
            break

    return {"credentials": creds, "interesting": interesting}


def _inspect_app_layer(payload: bytes, src_port: int, dst_port: int) -> Dict[str, Any]:
    """Inspect payload for known application protocols."""
    result: Dict[str, Any] = {
        "protocol": "?", "payload_snippet": "", "interesting": False,
        "tags": [], "credentials": [],
    }

    if not payload:
        return result

    text = payload.decode("utf-8", errors="replace")
    snippet = _sanitize_payload(payload)

    # HTTP
    first_word = payload.split(b" ")[0] if b" " in payload else b""
    is_http = first_word in _HTTP_METHODS
    is_http_resp = payload.startswith(b"HTTP/")
    if is_http or is_http_resp:
        result["protocol"] = "HTTP"
        result["tags"].append("HTTP")
        result["payload_snippet"] = snippet[:200]
        # Extract credentials
        cred_info = _extract_credentials(payload)
        result["interesting"] = cred_info["interesting"]
        result["credentials"] = cred_info["credentials"]
        return result

    # FTP
    if dst_port in (21, 2121) or src_port in (21, 2121):
        result["protocol"] = "FTP"
        result["tags"].append("FTP")
        cred_info = _extract_credentials(payload)
        result["interesting"] = cred_info["interesting"]
        result["credentials"] = cred_info["credentials"]
        if not result["interesting"]:
            result["interesting"] = b"220 " in payload  # FTP greeting
        return result

    # SMTP
    if dst_port in (25, 587) or src_port in (25, 587):
        result["protocol"] = "SMTP"
        result["tags"].append("SMTP")
        cred_info = _extract_credentials(payload)
        result["interesting"] = cred_info["interesting"]
        result["credentials"] = cred_info["credentials"]
        if not result["interesting"]:
            result["interesting"] = b"220 " in payload or b"250 " in payload
        return result

    # DNS (UDP only - no payload content parsing, just detect via port)
    if dst_port == 53 or src_port == 53:
        result["protocol"] = "DNS"
        result["tags"].append("DNS")
        return result

    # TLS/SSL Client Hello
    if payload[0] == 0x16 and len(payload) > 5:
        tls_type = payload[5] if len(payload) > 5 else 0
        if tls_type == 1:  # Client Hello
            result["protocol"] = "TLS"
            result["tags"].append("TLS")
            result["interesting"] = False
            # Try to extract SNI
            sni = _extract_sni(payload)
            if sni:
                result["tags"].append(f"SNI:{sni}")
            return result

    return result


def _extract_sni(payload: bytes) -> Optional[str]:
    """Extract TLS SNI from Client Hello. Returns None if not found."""
    try:
        # Session ID length at offset 43
        sid_len = payload[43] if len(payload) > 43 else 0
        offset = 44 + sid_len
        # Cipher suites length
        if offset + 1 >= len(payload):
            return None
        cs_len = struct.unpack("!H", payload[offset:offset+2])[0]
        offset += 2 + cs_len
        # Compression methods length
        if offset >= len(payload):
            return None
        cm_len = payload[offset]
        offset += 1 + cm_len
        # Extensions length
        if offset + 1 >= len(payload):
            return None
        ext_len = struct.unpack("!H", payload[offset:offset+2])[0]
        offset += 2
        ext_end = offset + ext_len

        while offset + 4 < ext_end and offset + 4 < len(payload):
            ext_type, ext_data_len = struct.unpack("!HH", payload[offset:offset+4])
            offset += 4
            if ext_type == 0:  # SNI
                if offset + 2 >= len(payload):
                    return None
                sni_list_len = struct.unpack("!H", payload[offset:offset+2])[0]
                offset += 2
                if offset + 1 >= len(payload):
                    return None
                sni_type = payload[offset]
                offset += 1
                if sni_type == 0:  # host_name
                    if offset + 1 >= len(payload):
                        return None
                    name_len = struct.unpack("!H", payload[offset:offset+2])[0]
                    offset += 2
                    name = payload[offset:offset+name_len].decode(errors="replace")
                    return name
            offset += ext_data_len
        return None
    except (struct.error, IndexError, ValueError):
        return None


# ── Main pipeline ────────────────────────────────────────────────────────


def process_packet(data: bytes, link_type: int = LINKTYPE_ETHERNET) -> Dict[str, Any]:
    """
    Process one raw packet. Returns a structured result dict.

    Keys: link_type, ip_family, ip_header, transport, app_layer, error
    """
    result: Dict[str, Any] = {
        "link_type": link_type,
        "ip_family": "?",
        "ip_header": {},
        "transport": {"protocol": "?", "header": {}, "src_port": 0, "dst_port": 0},
        "app_layer": {"protocol": "?", "payload_snippet": "", "interesting": False,
                       "tags": [], "credentials": []},
        "error": None,
    }

    # Strip link layer
    ip_data = strip_link_layer(data, link_type)
    if not ip_data:
        result["error"] = "Failed to strip link layer"
        return result

    # Determine IP version
    if len(ip_data) < 1:
        result["error"] = "Empty IP payload"
        return result

    ip_version = (ip_data[0] >> 4) & 0x0F

    if ip_version == 4:
        ip_hdr = parse_ipv4(ip_data)
        result["ip_family"] = "IPv4"
        result["ip_header"] = ip_hdr
        if ip_hdr.get("error"):
            result["error"] = ip_hdr["error"]
            return result
        ip_hdr_len = ip_hdr.get("ihl", 20)
        proto_num = ip_hdr.get("protocol_num", 0)
        ip_total = ip_hdr.get("total_length", len(ip_data))
        transport_start = ip_hdr_len
        transport_payload_len = ip_total - ip_hdr_len
    elif ip_version == 6:
        ip_hdr = parse_ipv6(ip_data)
        result["ip_family"] = "IPv6"
        result["ip_header"] = ip_hdr
        if ip_hdr.get("error"):
            result["error"] = ip_hdr["error"]
            return result
        proto_num = ip_hdr.get("protocol_num", 0)
        transport_start = 40
        transport_payload_len = ip_hdr.get("payload_length", len(ip_data) - 40)
    else:
        result["error"] = f"Unknown IP version: {ip_version}"
        return result

    # Parse transport
    transport_data = ip_data[transport_start:transport_start + transport_payload_len]
    parser_fn = TRANSPORT_PARSERS.get(proto_num)
    if parser_fn:
        transport = parser_fn(transport_data)
        result["transport"] = transport
    else:
        result["transport"] = {
            "protocol": IP_PROTOCOLS.get(proto_num, f"proto-{proto_num}"),
            "header": {}, "src_port": 0, "dst_port": 0,
        }

    # Compute hex of transport payload (for log output)
    transport_hdr_len = result["transport"].get("data_offset", 0) or 8
    if transport_hdr_len < len(transport_data):
        payload_raw = transport_data[transport_hdr_len:]
        result["transport"]["payload_hex"] = payload_raw.hex()[:1024]
    else:
        result["transport"]["payload_hex"] = ""

    # Inspect application layer
    src_port = result["transport"].get("src_port", 0)
    dst_port = result["transport"].get("dst_port", 0)
    app_offset = transport_start + transport_hdr_len

    if app_offset < len(ip_data):
        app_payload = ip_data[app_offset:]
        app_info = _inspect_app_layer(app_payload, src_port, dst_port)
        result["app_layer"] = app_info

    return result


# ── Formatting ───────────────────────────────────────────────────────────


def format_pcap_summary(result: Dict[str, Any]) -> str:
    """Return a one-line coloured summary of a parsed packet."""
    ip = result.get("ip_header", {})
    transport = result.get("transport", {})
    app = result.get("app_layer", {})

    src_ip = ip.get("src", "?")
    dst_ip = ip.get("dst", "?")

    src_port = transport.get("src_port", 0)
    dst_port = transport.get("dst_port", 0)
    proto = transport.get("protocol", "?").upper()
    app_proto = app.get("protocol", "")

    tags = app.get("tags", [])
    creds = app.get("credentials", [])

    # Build summary
    if src_port and dst_port:
        flow = f"{src_ip}:{src_port} → {dst_ip}:{dst_port}"
    else:
        flow = f"{src_ip} → {dst_ip}"

    proto_str = f"{C.CYAN}[{proto}]{C.RESET}" if proto != "?" else proto

    extra = ""
    if app_proto and app_proto != "?" and app_proto != proto:
        extra += f" {C.GREEN}({app_proto}){C.RESET}"
    if tags:
        tag_str = " ".join(f"{C.YELLOW}[{t}]{C.RESET}" for t in tags)
        extra += f" {tag_str}"
    if "TLS" in tags:
        sni = [t for t in tags if t.startswith("SNI:")]
        if sni:
            extra += f" {C.DIM}{sni[0]}{C.RESET}"

    line = f"{flow} {proto_str}{extra}"
    if app.get("interesting"):
        line = f"{C.RED}⚠{C.RESET} {line}"
    if creds:
        line = f"{C.RED}🔑{C.RESET} {line}  {C.RED}({'; '.join(creds)}){C.RESET}"

    return line


# ── Log formatting ──────────────────────────────────────────────────────────

_LOG_COLUMNS = [
    "timestamp", "src_ip", "src_port", "dst_ip", "dst_port",
    "ip_ver", "protocol", "ttl", "tcp_flags", "payload_len",
    "app_proto", "tags", "credentials", "payload_hex64",
]


def format_log_line(result: Dict[str, Any]) -> str:
    """
    Return a single tab-separated log line with all available packet metadata.

    Suitable for appending to a root-project log file (vpn_capture.log).
    Fields are ordered and pipe-separated for readability::

        ts | src:port → dst:port | IPv4 | TCP | ttl=64 | SYN,ACK | len=74 | HTTP | tag1 tag2 | cred | hex64
    """
    import time as _time

    ip = result.get("ip_header", {})
    transport = result.get("transport", {})
    app = result.get("app_layer", {})

    ts = _time.strftime("%Y-%m-%d %H:%M:%S")
    src_ip = ip.get("src", "?")
    dst_ip = ip.get("dst", "?")
    src_port = transport.get("src_port", 0)
    dst_port = transport.get("dst_port", 0)

    ip_ver = result.get("ip_family", "?")
    proto = transport.get("protocol", "?").upper()

    # TTL / Hop limit
    ttl = ip.get("ttl", ip.get("hop_limit", "?"))

    # TCP flags
    flags = transport.get("header", {}).get("flags", {})
    tcp_flags = ",".join(k for k, v in flags.items() if v) if flags else ""

    # Payload length
    transport_data_offset = transport.get("data_offset", 0) or 8
    ip_total = ip.get("total_length", 0)
    plen = max(0, ip_total - ip.get("ihl", 20) - transport_data_offset) if ip_total else "?"

    # Application layer
    app_proto = app.get("protocol", "")
    tags = app.get("tags", [])
    creds = app.get("credentials", [])

    tag_str = " ".join(tags) if tags else ""
    cred_str = "; ".join(creds) if creds else ""

    # Hex dump (first 64 bytes of payload if available)
    hex64 = ""
    if transport.get("payload_hex"):
        hex64 = transport["payload_hex"][:128]  # 64 bytes = 128 hex chars

    cols = [
        ts,
        f"{src_ip}:{src_port}",
        f"{dst_ip}:{dst_port}",
        ip_ver,
        proto,
        f"ttl={ttl}" if ttl != "?" else "",
        tcp_flags,
        f"len={plen}" if plen != "?" else "",
        app_proto,
        tag_str,
        cred_str,
        hex64,
    ]
    # Strip empty trailing fields
    while cols and not cols[-1]:
        cols.pop()
    return " | ".join(cols)


# ── Full dissection ─────────────────────────────────────────────────────────


def format_full_dissection(result: Dict[str, Any]) -> str:
    """Return a multi-line detailed dissection of a parsed packet."""
    lines = []
    ip = result.get("ip_header", {})
    transport = result.get("transport", {})

    # IP layer
    if result["ip_family"] == "IPv4":
        lines.append(
            f"  {C.CYAN}IP{C.RESET} {ip.get('src','?')} → {ip.get('dst','?')}  "
            f"v{ip.get('version', '?')} len={ip.get('total_length','?')} "
            f"ttl={ip.get('ttl','?')} id={ip.get('id','?')}"
        )
    elif result["ip_family"] == "IPv6":
        lines.append(
            f"  {C.CYAN}IPv6{C.RESET} {ip.get('src','?')} → {ip.get('dst','?')}  "
            f"plen={ip.get('payload_length','?')} hlim={ip.get('hop_limit','?')}"
        )

    # Transport layer
    proto = transport.get("protocol", "?").upper()
    src_port = transport.get("src_port", 0)
    dst_port = transport.get("dst_port", 0)
    if src_port or dst_port:
        svc = PORT_SERVICES.get(src_port, PORT_SERVICES.get(dst_port, ""))
        svc_str = f" ({svc})" if svc else ""
        lines.append(
            f"  {C.CYAN}{proto}{C.RESET} :{src_port} → :{dst_port}{svc_str}"
        )
    else:
        lines.append(f"  {C.CYAN}{proto}{C.RESET}")

    # TCP flags
    flags = transport.get("header", {}).get("flags", {})
    if flags:
        fl_str = " ".join(k for k, v in flags.items() if v)
        if fl_str:
            lines.append(f"  {C.DIM}Flags:{C.RESET} {fl_str}")

    # Application layer
    app = result.get("app_layer", {})
    if app.get("tags"):
        lines.append(f"  {C.YELLOW}App:{C.RESET} {' '.join(app['tags'])}")
    if app.get("credentials"):
        for cred in app["credentials"]:
            lines.append(f"  {C.RED}🔑{C.RESET} {cred}")
    if app.get("payload_snippet"):
        snippet = app["payload_snippet"]
        if len(snippet) > 120:
            snippet = snippet[:120] + "..."
        lines.append(f"  {C.DIM}Payload:{C.RESET} {repr(snippet)}")

    return "\n".join(lines)
