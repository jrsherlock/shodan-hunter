"""HTTP basic auth gate. Constant-time comparison; per-user credentials."""

from __future__ import annotations

import secrets

from fastapi import Depends, HTTPException, status
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
