"""Lightweight liveness probe: is a host:port actually responding *right now*?

Shodan data is a snapshot and can be stale, so this answers "is it still up?"
with a single TCP connect (works for any service, not just HTTP). It is the
one place in the app that opens an outbound socket to an operator-chosen
target, so it is fenced in:

* Off unless ``SH_ENABLE_PROBE`` is set — same posture as on-demand scanning.
* Refuses private/loopback/link-local/reserved targets unless
  ``SH_PROBE_ALLOW_PRIVATE`` is set, so it can't be turned into an
  internal-network port scanner.
* Short, bounded timeout; every probe is audit-logged by the route.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import time
from typing import Any

from . import config


class ProbeDisabled(RuntimeError):
    """SH_ENABLE_PROBE is not set."""


class ProbeNotAllowed(PermissionError):
    """Target is a private/reserved address and SH_PROBE_ALLOW_PRIVATE is off."""


def _is_internal(addr: ipaddress._BaseAddress) -> bool:
    return (addr.is_private or addr.is_loopback or addr.is_link_local
            or addr.is_reserved or addr.is_multicast or addr.is_unspecified)


def _check_target(ip: str, port: int) -> str:
    """Shared gate for every outbound socket the app opens: enforce the
    SH_ENABLE_PROBE switch, validate ip/port, and refuse non-public targets
    unless SH_PROBE_ALLOW_PRIVATE is set. Returns the normalized address string.

    Raises ProbeDisabled, ProbeNotAllowed, or ValueError (bad ip/port) — all
    caller errors that never reach the socket layer."""
    if not config.PROBE_ENABLED:
        raise ProbeDisabled("Probing is disabled (set SH_ENABLE_PROBE=1).")

    addr = ipaddress.ip_address(ip.strip())  # raises ValueError on bad input
    if not (isinstance(port, int) and 1 <= port <= 65535):
        raise ValueError(f"port out of range: {port!r}")
    if _is_internal(addr) and not config.PROBE_ALLOW_PRIVATE:
        raise ProbeNotAllowed(
            f"refusing to probe non-public address {addr} "
            "(set SH_PROBE_ALLOW_PRIVATE=1 to override)"
        )
    return str(addr)


def probe(ip: str, port: int, *, timeout: float | None = None) -> dict[str, Any]:
    """TCP-connect to ``ip:port``. Returns ``{status, ms, detail}`` where status
    is one of up / down / timeout / error.

    Raises ProbeDisabled, ProbeNotAllowed, or ValueError (bad ip/port) — these
    are caller errors and never reach the socket layer."""
    addr = _check_target(ip, port)
    timeout = config.PROBE_TIMEOUT if timeout is None else timeout
    start = time.monotonic()
    try:
        with socket.create_connection((addr, port), timeout=timeout):
            ms = round((time.monotonic() - start) * 1000)
            return {"status": "up", "ms": ms, "detail": f"connected in {ms} ms"}
    except socket.timeout:
        return {"status": "timeout", "ms": round(timeout * 1000),
                "detail": f"no response within {timeout:g}s"}
    except ConnectionRefusedError:
        ms = round((time.monotonic() - start) * 1000)
        return {"status": "down", "ms": ms, "detail": "connection refused"}
    except OSError as e:
        return {"status": "error", "ms": None, "detail": str(e)}


# ── Banner grabbing ─────────────────────────────────────────────────────────
# A liveness probe only answers "is the port open?". A *banner* grab answers
# "what is it?" — it reads the bytes a service emits, the way a Shodan-style
# crawler does. Many services speak first (SSH, FTP, SMTP); others stay silent
# until sent a protocol-specific payload, so an optional ``payload`` is sent
# before reading. Same security fence as :func:`probe` via ``_check_target``.


def banner_grab(
    ip: str,
    port: int,
    *,
    payload: bytes = b"",
    connect_timeout: float | None = None,
    read_timeout: float = 2.0,
    overall_timeout: float = 8.0,
    max_bytes: int = 8192,
    terminator: bytes | None = None,
) -> dict[str, Any]:
    """Connect to ``ip:port``, optionally send ``payload``, and read the banner.

    Reads until one of: ``terminator`` is seen, the peer closes, ``max_bytes``
    is reached, ``read_timeout`` elapses with no new data (the normal end for a
    service that sends a burst then holds the socket open), or ``overall_timeout``
    caps total read time. Returns ``{status, ms, bytes, banner, hex, truncated}``
    where status is up / empty / timeout / down / error.

    Raises ProbeDisabled, ProbeNotAllowed, or ValueError before any socket opens."""
    addr = _check_target(ip, port)
    connect_timeout = config.PROBE_TIMEOUT if connect_timeout is None else connect_timeout
    start = time.monotonic()
    chunks = bytearray()
    try:
        with socket.create_connection((addr, port), timeout=connect_timeout) as sock:
            if payload:
                sock.sendall(payload)
            deadline = time.monotonic() + overall_timeout
            while len(chunks) < max_bytes:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                sock.settimeout(min(read_timeout, remaining))
                try:
                    data = sock.recv(4096)
                except socket.timeout:
                    break  # idle: the service finished (or sits silent)
                if not data:
                    break  # peer closed the connection
                chunks.extend(data)
                if terminator and terminator in data:
                    break
        raw = bytes(chunks[:max_bytes])
        ms = round((time.monotonic() - start) * 1000)
        return {
            "status": "up" if raw else "empty",
            "ms": ms,
            "bytes": len(raw),
            "banner": raw.decode("latin-1", "replace"),
            "hex": raw.hex(),
            "truncated": len(chunks) >= max_bytes,
        }
    except socket.timeout:
        return {"status": "timeout", "ms": round(connect_timeout * 1000),
                "detail": f"no connection within {connect_timeout:g}s"}
    except ConnectionRefusedError:
        ms = round((time.monotonic() - start) * 1000)
        return {"status": "down", "ms": ms, "detail": "connection refused"}
    except OSError as e:
        return {"status": "error", "ms": None, "detail": str(e)}


# ── Veeder-Root ATG (Automatic Tank Gauge) ──────────────────────────────────
# Fuel-station tank gauges (Veeder-Root TLS-350/450 and compatibles) are widely
# exposed on TCP 10001, usually via a serial-to-Ethernet bridge. They emit no
# unsolicited banner: the serial protocol frames each command with a leading SOH
# (Control-A) byte followed by a 6-char function code, and only then replies.
#
# We support ONLY the I-series *inventory report* (read-only reconnaissance,
# identical to what Shodan already publishes). The S-series setup/write commands
# change live fuel-safety configuration (alarm limits, relays) and are
# deliberately not implemented here — issuing them to a device you don't own is
# tampering, not scanning.
SOH = b"\x01"           # start-of-command, "display format" (human-readable)
ETX = b"\x03"           # end-of-response marker
ATG_INVENTORY = b"I20100"   # In-Tank Inventory report, all tanks

# A tank row: leading number, a product name that may contain spaces, then six
# numeric columns (volume, TC volume, ullage, height, water, temp). The six
# trailing groups anchor the non-greedy product capture.
_ATG_TANK_RE = re.compile(
    r"^\s*(\d+)\s+(.+?)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s*$"
)
_ATG_DATE_RE = re.compile(
    r"[A-Z]{3}\s+\d{1,2},\s+\d{4}\s+\d{1,2}:\d{2}\s*[AP]M", re.IGNORECASE
)


def _squash(s: str) -> str:
    """Collapse the report's column padding to single spaces."""
    return re.sub(r"\s{2,}", " ", s.strip())


def _parse_atg(banner: str) -> dict[str, Any]:
    """Parse an In-Tank Inventory report into a structured record. Resilient to
    missing sections — returns whatever it can recognize."""
    lines = banner.splitlines()

    tanks: list[dict[str, Any]] = []
    for line in lines:
        m = _ATG_TANK_RE.match(line)
        if not m:
            continue
        num, product, vol, tc, ullage, height, water, temp = m.groups()
        tanks.append({
            "tank": int(num),
            "product": _squash(product),
            "volume": float(vol),
            "tc_volume": float(tc),
            "ullage": float(ullage),
            "height": float(height),
            "water": float(water),
            "temp": float(temp),
        })

    date_match = _ATG_DATE_RE.search(banner)
    report_time = _squash(date_match.group(0)) if date_match else None

    # Station block: the non-empty lines after the date and before the inventory
    # header — first line is the name, the rest are address lines.
    station = None
    seen_date = False
    addr_lines: list[str] = []
    for line in lines:
        if not seen_date:
            if _ATG_DATE_RE.search(line):
                seen_date = True
            continue
        s = line.strip()
        if not s:
            continue
        upper = s.upper()
        if "INVENTORY" in upper or upper.startswith("TANK ") or _ATG_TANK_RE.match(line):
            break
        addr_lines.append(_squash(s))
    if addr_lines:
        station = {"name": addr_lines[0], "address": addr_lines[1:]}

    is_atg = bool(tanks) or "IN-TANK INVENTORY" in banner.upper() or "I20100" in banner
    return {
        "is_atg": is_atg,
        "report_time": report_time,
        "station": station,
        "tanks": tanks,
    }


def veeder_root_atg(ip: str, port: int = 10001, *, timeout: float = 10.0) -> dict[str, Any]:
    """Actively confirm a Veeder-Root ATG: send ``<SOH>I20100`` (read-only
    In-Tank Inventory) and parse the reply. Returns the :func:`banner_grab`
    result enriched with ``command``, ``is_atg``, and a parsed ``atg`` record.

    Read-only by design — no setup/write commands are ever sent. Same gate and
    address fence as :func:`probe`."""
    result = banner_grab(
        ip, port,
        payload=SOH + ATG_INVENTORY,
        read_timeout=timeout,      # ATG streams with gaps; rely on ETX / overall cap
        overall_timeout=timeout,
        terminator=ETX,
        max_bytes=8192,
    )
    result["command"] = ATG_INVENTORY.decode()
    banner = result.get("banner") or ""
    result["atg"] = _parse_atg(banner) if banner else {
        "is_atg": False, "report_time": None, "station": None, "tanks": [],
    }
    result["is_atg"] = result["atg"]["is_atg"]
    return result
