from __future__ import annotations

from pathlib import Path
from typing import Any

from app.core.db import connect

def count_findings(db_path: str | Path) -> int:
    with connect(db_path) as conn:
        return int(conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0])


def list_findings(db_path: str | Path) -> list[dict[str, Any]]:
    with connect(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM findings ORDER BY score DESC, kev DESC, epss DESC, cve_id ASC"
        ).fetchall()
        return [dict(row) for row in rows]


def get_finding(db_path: str | Path, finding_id: str) -> dict[str, Any] | None:
    with connect(db_path) as conn:
        row = conn.execute("SELECT * FROM findings WHERE finding_id=?", (finding_id,)).fetchone()
        return dict(row) if row else None
