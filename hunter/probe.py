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


def probe(ip: str, port: int, *, timeout: float | None = None) -> dict[str, Any]:
    """TCP-connect to ``ip:port``. Returns ``{status, ms, detail}`` where status
    is one of up / down / timeout / error.

    Raises ProbeDisabled, ProbeNotAllowed, or ValueError (bad ip/port) — these
    are caller errors and never reach the socket layer."""
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

    timeout = config.PROBE_TIMEOUT if timeout is None else timeout
    start = time.monotonic()
    try:
        with socket.create_connection((str(addr), port), timeout=timeout):
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
