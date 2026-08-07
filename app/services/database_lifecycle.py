from __future__ import annotations

import json
import os
import sqlite3
import tempfile
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.core.database_schema import CURRENT_SCHEMA_VERSION, init_db
from app.core.db import connect
from app.repositories.audit import add_audit_event, verify_audit_integrity
from app.services.database_validation import validate_schema_contents
from app.services.database_identity import PROJECT_DATABASE_ROLE

REQUIRED_RESTORE_TABLES = {"findings", "audit_events"}


def backup_database(db_path: str | Path, destination: str | Path) -> None:
    """Create a validated SQLite snapshot and publish it atomically.

    The backup is written to a private temporary file in the destination
    directory.  A failed source read, interrupted backup, or integrity failure
    therefore cannot replace a previously valid artifact with a partial file.
    """
    source_path = Path(db_path)
    destination_path = Path(destination)
    if not source_path.is_file():
        raise FileNotFoundError(f"백업 원본 데이터베이스가 존재하지 않습니다: {source_path}")
    if source_path.stat().st_size <= 0:
        raise ValueError("백업 원본 데이터베이스가 비어 있습니다.")
    destination_path.parent.mkdir(parents=True, exist_ok=True)
    if source_path.resolve() == destination_path.resolve():
        raise ValueError("백업 원본과 대상 경로는 서로 달라야 합니다.")

    handle = tempfile.NamedTemporaryFile(
        prefix=f".{destination_path.name}.",
        suffix=".partial",
        dir=destination_path.parent,
        delete=False,
    )
    temporary_path = Path(handle.name)
    handle.close()
    try:
        with closing(sqlite3.connect(source_path, timeout=30.0)) as source, closing(
            sqlite3.connect(temporary_path, timeout=30.0)
        ) as target:
            source.execute("PRAGMA trusted_schema=OFF")
            target.execute("PRAGMA trusted_schema=OFF")
            source.backup(target)
            target.commit()
            integrity = target.execute("PRAGMA integrity_check").fetchone()
            if not integrity or str(integrity[0]).lower() != "ok":
                raise sqlite3.DatabaseError(
                    "SQLite 백업 무결성 검사에 실패했습니다: "
                    + (str(integrity[0]) if integrity else "unknown")
                )
        # Windows maps os.fsync() to the CRT _commit() call, which rejects a
        # read-only descriptor with EBADF. Open the completed snapshot for update
        # so the durability barrier has a writable descriptor on every supported
        # platform without changing the file contents.
        with temporary_path.open("r+b") as snapshot:
            os.fsync(snapshot.fileno())
        os.replace(temporary_path, destination_path)
        if os.name == "posix":
            directory_fd = os.open(destination_path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    except Exception:
        temporary_path.unlink(missing_ok=True)
        raise

def validate_database_file(
    source: str | Path,
    *,
    expected_project_id: str = "",
    expected_database_role: str = PROJECT_DATABASE_ROLE,
    allow_unscoped: bool = False,
) -> dict[str, Any]:
    """Validate that a SQLite file is readable and compatible with VulnFlow."""
    source_path = Path(source)
    if not source_path.is_file() or source_path.stat().st_size == 0:
        raise ValueError("복원 파일이 비어 있거나 존재하지 않습니다.")
    try:
        with closing(sqlite3.connect(f"file:{source_path.as_posix()}?mode=ro", uri=True)) as conn:
            conn.execute("PRAGMA trusted_schema=OFF")
            integrity = conn.execute("PRAGMA integrity_check").fetchone()
            if not integrity or str(integrity[0]).lower() != "ok":
                raise ValueError(f"SQLite 무결성 검사 실패: {integrity[0] if integrity else 'unknown'}")
            tables = {
                row[0]
                for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
            }
            missing_tables = REQUIRED_RESTORE_TABLES - tables
            if missing_tables:
                raise ValueError("필수 테이블이 없습니다: " + ", ".join(sorted(missing_tables)))
            schema_version = int(conn.execute("PRAGMA user_version").fetchone()[0])
            if schema_version > CURRENT_SCHEMA_VERSION:
                raise ValueError(
                    f"백업 스키마 버전 {schema_version}은 현재 지원 버전 {CURRENT_SCHEMA_VERSION}보다 새롭습니다."
                )
            finding_count, audit_count, evidence_count = validate_schema_contents(
                conn, tables, schema_version
            )
            identity: dict[str, str] = {}
            if "system_metadata" in tables:
                identity = {
                    str(row[0]): str(row[1] or "")
                    for row in conn.execute(
                        "SELECT key,value FROM system_metadata "
                        "WHERE key IN ('database_role','project_id','project_name')"
                    ).fetchall()
                }
            expected_id = str(expected_project_id or "").strip().lower()
            expected_role = str(expected_database_role or PROJECT_DATABASE_ROLE).strip().lower()
            actual_id = str(identity.get("project_id") or "").strip().lower()
            actual_role = str(identity.get("database_role") or "").strip().lower()
            if expected_id:
                if (not actual_id or not actual_role) and not allow_unscoped:
                    raise ValueError("프로젝트 식별정보가 없는 SQLite 백업은 이 경로에서 복원할 수 없습니다.")
                if actual_role and actual_role != expected_role:
                    raise ValueError(
                        f"백업 database role 불일치: expected={expected_role}, actual={actual_role}"
                    )
                if actual_id and actual_id != expected_id:
                    raise ValueError(
                        f"다른 프로젝트의 SQLite 백업입니다: expected={expected_id}, actual={actual_id}"
                    )
    except sqlite3.DatabaseError as exc:
        raise ValueError(f"유효한 VulnFlow SQLite 백업이 아닙니다: {exc}") from exc
    audit_integrity = None
    if schema_version >= 11:
        audit_integrity = verify_audit_integrity(source_path)
        if not audit_integrity.get("valid"):
            raise ValueError("SQLite 백업의 감사 체인 무결성 검증에 실패했습니다: " + "; ".join(audit_integrity.get("issues") or []))
    return {
        "finding_count": finding_count,
        "audit_count": audit_count,
        "evidence_count": evidence_count,
        "schema_version": schema_version,
        "size_bytes": source_path.stat().st_size,
        "audit_integrity": audit_integrity,
        "database_identity": identity,
    }

def restore_database(
    db_path: str | Path,
    source: str | Path,
    *,
    actor: str = "local-user",
    expected_project_id: str = "",
    expected_database_role: str = PROJECT_DATABASE_ROLE,
    allow_unscoped: bool = False,
) -> dict[str, Any]:
    """Restore a validated SQLite backup after creating a safety backup."""
    db_path = Path(db_path)
    source = Path(source)
    source_summary = validate_database_file(
        source,
        expected_project_id=expected_project_id,
        expected_database_role=expected_database_role,
        allow_unscoped=allow_unscoped,
    )
    db_path.parent.mkdir(parents=True, exist_ok=True)
    backup_dir = db_path.parent / "backups"
    backup_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    safety_backup = backup_dir / f"vulnflow_pre_restore_{timestamp}.sqlite3"
    if db_path.exists():
        backup_database(db_path, safety_backup)
    else:
        init_db(db_path)
        backup_database(db_path, safety_backup)

    # SQLite backup API replaces the live database transactionally without trusting file copy semantics.
    try:
        with closing(sqlite3.connect(source)) as source_conn, closing(sqlite3.connect(db_path)) as target_conn:
            source_conn.backup(target_conn)
            target_conn.commit()
        init_db(db_path)  # Apply backward-compatible schema migrations if required.
        restored_integrity = verify_audit_integrity(db_path)
        if not restored_integrity.get("valid"):
            raise ValueError("복원된 데이터베이스의 감사 체인 무결성 검증에 실패했습니다.")
        add_audit_event(
            db_path,
            finding_id=None,
            event_type="database_restore",
            summary=f"SQLite 백업 복원: 취약점 {source_summary['finding_count']}건",
            details={
                "restored_findings": source_summary["finding_count"],
                "restored_audit_events": source_summary["audit_count"],
                "safety_backup": safety_backup.name,
            },
            actor=actor,
        )
    except Exception:
        # Best effort rollback from the safety backup.
        if safety_backup.exists():
            with closing(sqlite3.connect(safety_backup)) as source_conn, closing(sqlite3.connect(db_path)) as target_conn:
                source_conn.backup(target_conn)
                target_conn.commit()
        raise
    return source_summary | {"safety_backup": str(safety_backup)}

def list_maintenance_runs(db_path: str | Path, *, limit: int = 100) -> list[dict[str, Any]]:
    limit = max(1, min(int(limit), 1000))
    with closing(connect(db_path)) as conn:
        rows = conn.execute(
            "SELECT * FROM maintenance_runs ORDER BY started_at DESC LIMIT ?", (limit,)
        ).fetchall()
        output: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            try:
                item["details"] = json.loads(item.pop("details_json") or "{}")
            except json.JSONDecodeError:
                item["details"] = {}
            output.append(item)
        return output
