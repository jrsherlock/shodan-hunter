"""HTTP basic auth gate. Constant-time comparison; per-user credentials.

Also provides :func:`require_same_origin`, a CSRF guard for state-changing
requests — see its docstring for the threat model.
"""

from __future__ import annotations

import secrets
from urllib.parse import urlsplit

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from . import config

security = HTTPBasic(realm="shodan-hunter")


def current_user(creds: HTTPBasicCredentials = Depends(security)) -> str:
    """FastAPI dependency: returns the authenticated username, or 401."""
    if not config.AUTH_USERS:
        # If no users configured, every request 401s — fail closed so the
        # team can't accidentally expose the API key.
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "No users configured. Set SH_AUTH_USERS in .env (user:password,...).",
            headers={"WWW-Authenticate": 'Basic realm="shodan-hunter"'},
        )

    expected_pw = config.AUTH_USERS.get(creds.username)
    ok_user = expected_pw is not None
    # Always compare to *something* so timing doesn't leak which usernames exist.
    pw_to_compare = expected_pw if ok_user else "x"
    pw_match = secrets.compare_digest(creds.password.encode(), pw_to_compare.encode())

    if not (ok_user and pw_match):
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "Invalid credentials.",
            headers={"WWW-Authenticate": 'Basic realm="shodan-hunter"'},
        )
    return creds.username


def require_same_origin(request: Request) -> None:
    """CSRF guard for state-changing (POST) routes.

    We authenticate with HTTP Basic and hold no session cookie, so the browser
    re-attaches the cached credentials to *any* request to this origin —
    including a cross-site form POST from a page the victim is tricked into
    visiting. A browser cannot forge or suppress the ``Origin`` header on such
    a request, so if ``Origin`` (falling back to ``Referer``) is present and
    its host doesn't match ours, we reject.

    Requests with neither header (curl, server-to-server) carry no ambient
    browser credentials, so they pose no CSRF risk and are allowed through —
    auth still applies to them via :func:`current_user`.
    """
    source = request.headers.get("origin") or request.headers.get("referer")
    if not source:
        return
    host = request.headers.get("host")
    if not host or urlsplit(source).netloc != host:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Cross-origin request blocked (CSRF protection).",
        )
