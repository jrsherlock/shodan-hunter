"""Shared pytest fixtures for the shodan-hunter test suite.

Two non-negotiable isolation guarantees are enforced here:

1. The real SQLite database is never touched. An autouse fixture points
   ``hunter.config.DB_PATH`` at a per-test temp file and resets the
   ``hunter.db._inited`` guard so the schema is recreated in the fresh file.

2. No test ever performs a real network call to Shodan or InternetDB. Unit
   tests monkeypatch ``hunter.shodan_api._api`` / ``_rest_get`` (and the
   internetdb session is never exercised because callers are stubbed). Route
   tests additionally stub ``hunter.shodan_api.api_info`` because the ``_ctx``
   template helper calls it on every render.
"""

from __future__ import annotations

import types
from unittest.mock import MagicMock

import pytest

from hunter import config, db, shodan_api


@pytest.fixture(autouse=True)
def isolate_db(tmp_path, monkeypatch):
    """Redirect the DB to a fresh temp file per test and recreate the schema.

    ``config.DB_PATH`` is resolved at import and read by ``db._connect()`` on
    every call; ``db._ensure()`` builds the schema once, guarded by the module
    global ``db._inited``. We reset that guard so each temp DB gets its own
    schema, fully isolating audit/cache/counters/alerts/scan_jobs per test.
    """
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "t.db")
    # Reset the one-shot schema guard so _ensure() runs against the new file.
    monkeypatch.setattr(db, "_inited", False)
    yield
    # monkeypatch restores config.DB_PATH and db._inited automatically; force a
    # final reset so any module that cached state can't leak into the next test.
    db._inited = False


@pytest.fixture
def api_info_stub(monkeypatch):
    """Stop the api_info() round-trip (used by _ctx on every page render)."""
    monkeypatch.setattr(shodan_api, "api_info", lambda *a, **k: {})


@pytest.fixture
def fake_client():
    """A MagicMock standing in for ``shodan.Shodan``.

    Nested attributes used by shodan_api (``labs.honeyscore``, ``dns.domain_info``)
    work out of the box because MagicMock autogenerates child mocks.
    """
    return MagicMock(name="shodan.Shodan")


@pytest.fixture
def patch_api(monkeypatch, fake_client):
    """Monkeypatch ``shodan_api._api`` to return the fake client.

    Returns the fake client so a test can program/inspect it.
    """
    monkeypatch.setattr(shodan_api, "_api", lambda: fake_client)
    return fake_client


@pytest.fixture
def client(api_info_stub):
    """TestClient with the auth dependency overridden to a fixed username.

    Depends on ``api_info_stub`` so route renders never call the live Shodan
    account-info endpoint. Cleans up the dependency override on teardown.
    """
    from fastapi.testclient import TestClient

    from hunter.app import app
    from hunter.auth import current_user

    app.dependency_overrides[current_user] = lambda: "tester"
    test_client = TestClient(app)
    try:
        yield test_client
    finally:
        app.dependency_overrides.pop(current_user, None)


def ns(**kwargs):
    """Tiny helper to build a SimpleNamespace fake."""
    return types.SimpleNamespace(**kwargs)
