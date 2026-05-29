"""SQLite: audit log of every prompt → query, plus a short-lived result cache."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from datetime import datetime, timezone
from typing import Any

from . import config

_init_lock = threading.Lock()
_inited = False


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(config.DB_PATH, timeout=30, isolation_level=None)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.row_factory = sqlite3.Row
    return conn


def _ensure() -> None:
    global _inited
    if _inited:
        return
    with _init_lock:
        if _inited:
            return
        with _connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS audit (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts           INTEGER NOT NULL,
                    username     TEXT NOT NULL,
                    prompt       TEXT NOT NULL,
                    query        TEXT,
                    rationale    TEXT,
                    result_total INTEGER,
                    error        TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit(ts);

                CREATE TABLE IF NOT EXISTS cache (
                    ns         TEXT NOT NULL,
                    key        TEXT NOT NULL,
                    value_json TEXT NOT NULL,
                    expires_at INTEGER NOT NULL,
                    PRIMARY KEY (ns, key)
                );

                CREATE TABLE IF NOT EXISTS counters (
                    day   TEXT NOT NULL,
                    name  TEXT NOT NULL,
                    count INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (day, name)
                );

                -- Local mirror of Shodan network alerts. Source of truth is
                -- Shodan; this table adds team attribution (who registered it).
                CREATE TABLE IF NOT EXISTS alerts (
                    id           TEXT PRIMARY KEY,
                    name         TEXT,
                    filters_json TEXT,
                    triggers_json TEXT,
                    created_by   TEXT,
                    created_ts   INTEGER
                );

                -- On-demand scan submissions, for tracking + attribution.
                CREATE TABLE IF NOT EXISTS scan_jobs (
                    scan_id      TEXT PRIMARY KEY,
                    targets      TEXT,
                    host_count   INTEGER,
                    status       TEXT,
                    submitted_by TEXT,
                    submitted_ts INTEGER,
                    checked_ts   INTEGER
                );
                """
            )
            _migrate_audit_columns(conn)
        _inited = True


def _migrate_audit_columns(conn: sqlite3.Connection) -> None:
    """Add columns introduced after v0.2 without dropping existing rows.

    SQLite has no `ADD COLUMN IF NOT EXISTS`, so we inspect the schema first.
    `action` records what kind of operation produced the row (search, domain,
    dns, scan, alert, host…); `credits` records query credits actually spent.
    """
    cols = {row["name"] for row in conn.execute("PRAGMA table_info(audit)")}
    if "action" not in cols:
        conn.execute("ALTER TABLE audit ADD COLUMN action TEXT")
    if "credits" not in cols:
        conn.execute("ALTER TABLE audit ADD COLUMN credits INTEGER")


# ── audit log ─────────────────────────────────────────────────────────────


def log_audit(
    *, username: str, prompt: str, query: str | None,
    rationale: str | None, result_total: int | None, error: str | None,
    action: str = "search", credits: int | None = None,
) -> int:
    _ensure()
    with _connect() as conn:
        cur = conn.execute(
            """INSERT INTO audit
                   (ts, username, prompt, query, rationale, result_total, error, action, credits)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (int(time.time()), username, prompt, query, rationale,
             result_total, error, action, credits),
        )
        return cur.lastrowid or 0


def recent_audit(limit: int = 50, username: str | None = None) -> list[dict]:
    _ensure()
    with _connect() as conn:
        if username:
            rows = conn.execute(
                "SELECT * FROM audit WHERE username=? ORDER BY id DESC LIMIT ?",
                (username, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,),
            ).fetchall()
    return [dict(r) for r in rows]


# ── result cache ──────────────────────────────────────────────────────────


def cache_get(ns: str, key: str) -> Any | None:
    _ensure()
    now = int(time.time())
    with _connect() as conn:
        row = conn.execute(
            "SELECT value_json, expires_at FROM cache WHERE ns=? AND key=?",
            (ns, key),
        ).fetchone()
    if not row or row["expires_at"] <= now:
        return None
    try:
        return json.loads(row["value_json"])
    except json.JSONDecodeError:
        return None


def cache_put(ns: str, key: str, value: Any, ttl: int) -> None:
    if ttl <= 0 or value is None:
        return
    _ensure()
    with _connect() as conn:
        conn.execute(
            """INSERT INTO cache (ns, key, value_json, expires_at)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(ns, key) DO UPDATE SET
                   value_json = excluded.value_json,
                   expires_at = excluded.expires_at""",
            (ns, key, json.dumps(value, default=str), int(time.time()) + ttl),
        )


# ── daily budget ──────────────────────────────────────────────────────────


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def credits_used_today() -> int:
    _ensure()
    with _connect() as conn:
        row = conn.execute(
            "SELECT count FROM counters WHERE day=? AND name='query'", (_today(),),
        ).fetchone()
    return int(row["count"]) if row else 0


class BudgetExceeded(RuntimeError):
    pass


def spend(n: int = 1) -> int:
    _ensure()
    cap = config.DAILY_BUDGET
    if cap > 0 and credits_used_today() >= cap:
        raise BudgetExceeded(
            f"Team daily budget exhausted ({cap}). Raise SH_DAILY_BUDGET or wait for UTC midnight."
        )
    with _connect() as conn:
        conn.execute(
            """INSERT INTO counters (day, name, count) VALUES (?, 'query', ?)
               ON CONFLICT(day, name) DO UPDATE SET count = count + excluded.count""",
            (_today(), n),
        )
    return credits_used_today()


def budget_status() -> dict:
    used = credits_used_today()
    cap = config.DAILY_BUDGET
    return {
        "used": used,
        "cap": cap,
        "enabled": cap > 0,
        "exceeded": cap > 0 and used >= cap,
    }


# ── alert mirror (attribution for Shodan network alerts) ───────────────────


def upsert_alert(*, aid: str, name: str | None, filters: Any, triggers: Any,
                 created_by: str | None) -> None:
    """Record/refresh a registered alert. Preserves the original created_by
    when the row already exists (Shodan is the source of truth for the rest)."""
    _ensure()
    with _connect() as conn:
        existing = conn.execute(
            "SELECT created_by, created_ts FROM alerts WHERE id=?", (aid,),
        ).fetchone()
        if existing:
            conn.execute(
                """UPDATE alerts SET name=?, filters_json=?, triggers_json=?
                   WHERE id=?""",
                (name, json.dumps(filters, default=str),
                 json.dumps(triggers, default=str), aid),
            )
        else:
            conn.execute(
                """INSERT INTO alerts (id, name, filters_json, triggers_json, created_by, created_ts)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (aid, name, json.dumps(filters, default=str),
                 json.dumps(triggers, default=str), created_by, int(time.time())),
            )


def get_alert_meta(aid: str) -> dict | None:
    _ensure()
    with _connect() as conn:
        row = conn.execute("SELECT * FROM alerts WHERE id=?", (aid,)).fetchone()
    return dict(row) if row else None


def delete_alert_row(aid: str) -> None:
    _ensure()
    with _connect() as conn:
        conn.execute("DELETE FROM alerts WHERE id=?", (aid,))


# ── scan job tracking ──────────────────────────────────────────────────────


def record_scan(*, scan_id: str, targets: str, host_count: int | None,
                status: str | None, submitted_by: str) -> None:
    _ensure()
    now = int(time.time())
    with _connect() as conn:
        conn.execute(
            """INSERT INTO scan_jobs
                   (scan_id, targets, host_count, status, submitted_by, submitted_ts, checked_ts)
               VALUES (?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(scan_id) DO UPDATE SET
                   targets=excluded.targets, host_count=excluded.host_count,
                   status=excluded.status, checked_ts=excluded.checked_ts""",
            (scan_id, targets, host_count, status, submitted_by, now, now),
        )


def update_scan_status(scan_id: str, status: str | None) -> None:
    _ensure()
    with _connect() as conn:
        conn.execute(
            "UPDATE scan_jobs SET status=?, checked_ts=? WHERE scan_id=?",
            (status, int(time.time()), scan_id),
        )


def get_scan_row(scan_id: str) -> dict | None:
    _ensure()
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM scan_jobs WHERE scan_id=?", (scan_id,),
        ).fetchone()
    return dict(row) if row else None


def recent_scans(limit: int = 50) -> list[dict]:
    _ensure()
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM scan_jobs ORDER BY submitted_ts DESC LIMIT ?", (limit,),
        ).fetchall()
    return [dict(r) for r in rows]
