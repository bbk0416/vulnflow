from __future__ import annotations

"""Durable control/project database separation and legacy layout migration.

VulnFlow 72.0.24 and earlier stored browser accounts, the project registry, and
all default-project operational data in one SQLite file.  Restoring a default
project backup could therefore roll back users and other project registrations.
This module prepares the split layout before any authentication or project
startup work is performed.
"""

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
from typing import Any, Callable

from app.services.database_identity import (
    CONTROL_DATABASE_ROLE,
    PROJECT_DATABASE_ROLE,
    set_database_identity,
)


@dataclass(frozen=True, slots=True)
class StoragePreparation:
    control_database: str
    default_project_database: str
    legacy_database: str
    migrated_legacy_database: bool
    copied_directories: tuple[str, ...]
    marker_path: str

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _same_path(left: Path, right: Path) -> bool:
    try:
        return left.resolve() == right.resolve()
    except OSError:
        return left.absolute() == right.absolute()


def _private_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        path.parent.chmod(0o700)
    except OSError:
        pass


def _sqlite_backup(source: Path, destination: Path) -> None:
    """Copy a live SQLite database through the backup API and replace atomically."""
    _private_parent(destination)
    temporary = destination.with_name(
        f".{destination.name}.split-migration-{os.getpid()}.partial"
    )
    temporary.unlink(missing_ok=True)
    source_connection = sqlite3.connect(source)
    target_connection = sqlite3.connect(temporary)
    try:
        source_connection.backup(target_connection)
        target_connection.commit()
    finally:
        target_connection.close()
        source_connection.close()
    try:
        temporary.chmod(0o600)
    except OSError:
        pass
    os.replace(temporary, destination)




def _table_exists(connection: sqlite3.Connection, table: str) -> bool:
    return connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone() is not None


def _table_columns(connection: sqlite3.Connection, table: str) -> list[str]:
    if not _table_exists(connection, table):
        return []
    return [str(row[1]) for row in connection.execute(f"PRAGMA table_info({table})").fetchall()]


def _copy_control_table(
    source: sqlite3.Connection, target: sqlite3.Connection, table: str
) -> int:
    source_columns = _table_columns(source, table)
    target_columns = set(_table_columns(target, table))
    columns = [column for column in source_columns if column in target_columns]
    if not columns:
        return 0
    quoted = ",".join(f'"{column}"' for column in columns)
    placeholders = ",".join("?" for _ in columns)
    rows = source.execute(f"SELECT {quoted} FROM {table}").fetchall()
    if rows:
        target.executemany(
            f"INSERT OR REPLACE INTO {table}({quoted}) VALUES({placeholders})", rows
        )
    return len(rows)


def _create_control_database(
    source_path: Path, destination: Path, init_db_fn: Callable[[str | Path], None]
) -> None:
    """Create a control store without copying project findings or credentials into backups."""
    _private_parent(destination)
    temporary = destination.with_name(
        f".{destination.name}.control-migration-{os.getpid()}.partial"
    )
    temporary.unlink(missing_ok=True)
    init_db_fn(temporary)
    source = sqlite3.connect(source_path)
    target = sqlite3.connect(temporary)
    try:
        source.row_factory = sqlite3.Row
        target.execute("PRAGMA foreign_keys=OFF")
        for table in ("auth_sessions", "auth_login_attempts", "project_memberships", "projects", "app_users"):
            if _table_exists(target, table):
                target.execute(f"DELETE FROM {table}")
        _copy_control_table(source, target, "app_users")
        copied_projects = _copy_control_table(source, target, "projects")
        if not copied_projects:
            now = _utc_now()
            target.execute(
                """INSERT INTO projects(
                       project_id,name,slug,status,is_default,created_by,created_at,updated_at
                   ) VALUES('default','기본 프로젝트','default','ACTIVE',1,'storage-migration',?,?)""",
                (now, now),
            )
        copied_memberships = _copy_control_table(source, target, "project_memberships")
        if not copied_memberships:
            target.execute(
                """INSERT OR IGNORE INTO project_memberships(project_id,username,created_by,created_at)
                   SELECT 'default',username,'storage-migration',? FROM app_users""",
                (_utc_now(),),
            )
        target.commit()
        integrity = str(target.execute("PRAGMA integrity_check").fetchone()[0])
        if integrity.lower() != "ok":
            raise RuntimeError(f"제어 DB 마이그레이션 무결성 검사 실패: {integrity}")
    finally:
        target.close()
        source.close()
    try:
        temporary.chmod(0o600)
    except OSError:
        pass
    os.replace(temporary, destination)
    set_database_identity(
        destination, database_role=CONTROL_DATABASE_ROLE, project_id="control", project_name="제어 DB"
    )


def _strip_control_rows_from_project(database: Path) -> None:
    """Remove authoritative account/project registry rows from a project database."""
    connection = sqlite3.connect(database)
    try:
        connection.execute("PRAGMA foreign_keys=OFF")
        for table in ("auth_sessions", "auth_login_attempts", "project_memberships", "app_users"):
            if _table_exists(connection, table):
                connection.execute(f"DELETE FROM {table}")
        if _table_exists(connection, "projects"):
            connection.execute("DELETE FROM projects WHERE project_id<>'default'")
            now = _utc_now()
            connection.execute(
                """INSERT OR IGNORE INTO projects(
                       project_id,name,slug,status,is_default,created_by,created_at,updated_at
                   ) VALUES('default','기본 프로젝트','default','ACTIVE',1,'storage-migration',?,?)""",
                (now, now),
            )
        connection.commit()
    finally:
        connection.close()
    set_database_identity(
        database,
        database_role=PROJECT_DATABASE_ROLE,
        project_id="default",
        project_name="기본 프로젝트",
    )


def _preserve_partial(path: Path) -> str:
    if not path.exists():
        return ""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    backup = path.with_name(f"{path.name}.pre-split-{stamp}.bak")
    os.replace(path, backup)
    return str(backup)


def _copy_directory(source: Path, destination: Path) -> bool:
    if not source.is_dir() or _same_path(source, destination):
        return False
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    shutil.copytree(source, destination, dirs_exist_ok=True, copy_function=shutil.copy2)
    try:
        destination.chmod(0o700)
    except OSError:
        pass
    return True


def prepare_split_storage(
    *,
    control_database: str | Path,
    default_project_database: str | Path,
    legacy_database: str | Path,
    data_directory: str | Path,
    directory_migrations: tuple[tuple[str | Path, str | Path], ...] = (),
    init_db_fn: Callable[[str | Path], None],
) -> StoragePreparation:
    """Prepare independent control and default-project stores.

    The legacy source is intentionally retained.  If a previous split attempt
    produced only one target, both split databases are reconstructed from the
    legacy source after preserving the partial target, preventing an ambiguous
    mixture of generations.
    """

    control = Path(control_database)
    default = Path(default_project_database)
    legacy = Path(legacy_database)
    data = Path(data_directory)
    if _same_path(control, default):
        raise RuntimeError(
            "제어 DB와 기본 프로젝트 DB는 서로 다른 파일이어야 합니다. "
            "VULNFLOW_CONTROL_DB와 VULNFLOW_DEFAULT_PROJECT_DB 설정을 확인하세요."
        )

    data.mkdir(parents=True, exist_ok=True, mode=0o700)
    marker = data / "split-storage-v1.json"
    migrated = False
    preserved: list[str] = []

    split_complete = control.is_file() and default.is_file()
    legacy_available = legacy.is_file() and not (
        _same_path(legacy, control) or _same_path(legacy, default)
    )

    if not split_complete and legacy_available:
        # Reconstruct both sides from one consistent generation.  The source is
        # never removed and can be used for manual rollback after migration.
        preserved.extend(filter(None, (_preserve_partial(control), _preserve_partial(default))))
        _create_control_database(legacy, control, init_db_fn)
        _sqlite_backup(legacy, default)
        migrated = True
    else:
        _private_parent(control)
        _private_parent(default)
        init_db_fn(control)

    init_db_fn(default)
    _strip_control_rows_from_project(default)

    copied: list[str] = []
    if migrated:
        for raw_source, raw_destination in directory_migrations:
            source = Path(raw_source)
            destination = Path(raw_destination)
            if _copy_directory(source, destination):
                copied.append(str(destination))

    payload = {
        "format": "vulnflow-split-storage/1",
        "prepared_at": _utc_now(),
        "control_database": str(control),
        "default_project_database": str(default),
        "legacy_database": str(legacy),
        "legacy_database_retained": bool(legacy_available),
        "legacy_database_sha256": _sha256(legacy) if legacy_available else "",
        "migrated_legacy_database": migrated,
        "preserved_partial_targets": preserved,
        "copied_directories": copied,
    }
    temporary_marker = marker.with_name(f".{marker.name}.{os.getpid()}.partial")
    temporary_marker.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    try:
        temporary_marker.chmod(0o600)
    except OSError:
        pass
    os.replace(temporary_marker, marker)

    return StoragePreparation(
        control_database=str(control),
        default_project_database=str(default),
        legacy_database=str(legacy),
        migrated_legacy_database=migrated,
        copied_directories=tuple(copied),
        marker_path=str(marker),
    )
