from __future__ import annotations

"""Database-role and project identity metadata used by restore boundaries."""

from pathlib import Path
from typing import Any

from app.core.db import utc_now
from app.core.transactions import read_connection, write_transaction

CONTROL_DATABASE_ROLE = "control"
PROJECT_DATABASE_ROLE = "project-data"


def set_database_identity(
    db_path: str | Path,
    *,
    database_role: str,
    project_id: str,
    project_name: str = "",
) -> dict[str, str]:
    role = str(database_role or "").strip().lower()
    if role not in {CONTROL_DATABASE_ROLE, PROJECT_DATABASE_ROLE}:
        raise ValueError("지원하지 않는 database role입니다.")
    normalized_id = str(project_id or "").strip().lower()
    if not normalized_id:
        raise ValueError("database identity에는 project_id가 필요합니다.")
    values = {
        "database_role": role,
        "project_id": normalized_id,
        "project_name": str(project_name or "").strip(),
    }
    now = utc_now()
    with write_transaction(db_path, operation="set_database_identity") as conn:
        for key, value in values.items():
            conn.execute(
                """INSERT INTO system_metadata(key,value,updated_at) VALUES(?,?,?)
                   ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at""",
                (key, value, now),
            )
    return values


def get_database_identity(db_path: str | Path) -> dict[str, Any]:
    with read_connection(db_path, operation="get_database_identity") as conn:
        rows = conn.execute(
            "SELECT key,value FROM system_metadata WHERE key IN ('database_role','project_id','project_name')"
        ).fetchall()
    values = {str(row["key"]): str(row["value"] or "") for row in rows}
    return {
        "database_role": values.get("database_role", ""),
        "project_id": values.get("project_id", ""),
        "project_name": values.get("project_name", ""),
    }
