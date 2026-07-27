from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path


class ConcurrencyError(RuntimeError):
    """Raised when a record changed after the user loaded it."""


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def connect(
    db_path: str | Path,
    *,
    busy_timeout_ms: int = 30_000,
) -> sqlite3.Connection:
    """Open a consistently configured local SQLite connection."""
    timeout_ms = max(1, int(busy_timeout_ms))
    conn = sqlite3.connect(db_path, timeout=timeout_ms / 1000.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA trusted_schema=OFF")
    conn.execute(f"PRAGMA busy_timeout={timeout_ms}")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn
