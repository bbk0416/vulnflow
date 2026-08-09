from __future__ import annotations

"""Control-plane backup and recovery with session invalidation and project preservation."""

from contextlib import closing
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import sqlite3
import stat
import tempfile
from typing import Any, Mapping
import zipfile

from app.core.database_schema import CURRENT_APP_VERSION, CURRENT_SCHEMA_VERSION, init_db
from app.core.signing import KEY_ID_RE, hmac_sha256, verify_hmac
from app.repositories.audit import add_audit_event, verify_audit_integrity
from app.services.database_identity import (
    CONTROL_DATABASE_ROLE,
    PROJECT_DATABASE_ROLE,
    get_database_identity,
    set_database_identity,
)
from app.services.database_lifecycle import backup_database

CONTROL_RECOVERY_FORMAT = "vulnflow-control-recovery/1"
CONTROL_DATABASE_FILENAME = "control.sqlite3"
REQUIRED_FILES = {"manifest.json", CONTROL_DATABASE_FILENAME, "SHA256SUMS.txt"}
MAX_BUNDLE_FILES = 8
MAX_BUNDLE_UNCOMPRESSED = 512 * 1024 * 1024


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return json.dumps(dict(value), ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _table_exists(conn: sqlite3.Connection, table: str) -> bool:
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone() is not None


def _control_counts(conn: sqlite3.Connection) -> dict[str, int]:
    output: dict[str, int] = {}
    for table in ("app_users", "projects", "project_memberships", "audit_events"):
        output[table] = int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
    output["active_users"] = int(
        conn.execute("SELECT COUNT(*) FROM app_users WHERE is_active=1").fetchone()[0]
    )
    output["active_admins"] = int(
        conn.execute(
            "SELECT COUNT(*) FROM app_users WHERE is_active=1 AND role='admin'"
        ).fetchone()[0]
    )
    return output


def validate_control_database_file(source: str | Path) -> dict[str, Any]:
    path = Path(source)
    if not path.is_file() or path.stat().st_size == 0:
        raise ValueError("제어 DB 백업이 비어 있거나 존재하지 않습니다.")
    required_tables = {
        "app_users",
        "auth_sessions",
        "auth_login_attempts",
        "projects",
        "project_memberships",
        "audit_events",
        "system_metadata",
    }
    try:
        with closing(sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)) as conn:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA trusted_schema=OFF")
            integrity = conn.execute("PRAGMA integrity_check").fetchone()
            if not integrity or str(integrity[0]).lower() != "ok":
                raise ValueError(
                    f"제어 DB SQLite 무결성 검사 실패: {integrity[0] if integrity else 'unknown'}"
                )
            tables = {
                str(row[0])
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
            missing = required_tables - tables
            if missing:
                raise ValueError("제어 DB 필수 테이블이 없습니다: " + ", ".join(sorted(missing)))
            schema_version = int(conn.execute("PRAGMA user_version").fetchone()[0])
            if schema_version > CURRENT_SCHEMA_VERSION:
                raise ValueError(
                    f"제어 DB 백업 스키마 {schema_version}은 현재 지원 버전 {CURRENT_SCHEMA_VERSION}보다 새롭습니다."
                )
            identity = {
                str(row["key"]): str(row["value"] or "")
                for row in conn.execute(
                    "SELECT key,value FROM system_metadata WHERE key IN ('database_role','project_id','project_name')"
                ).fetchall()
            }
            if identity.get("database_role") != CONTROL_DATABASE_ROLE:
                raise ValueError("control 역할의 제어 DB만 이 복구 경로에서 사용할 수 있습니다.")
            if identity.get("project_id") != "control":
                raise ValueError("제어 DB identity의 project_id가 control이 아닙니다.")
            counts = _control_counts(conn)
            default_count = int(
                conn.execute("SELECT COUNT(*) FROM projects WHERE is_default=1").fetchone()[0]
            )
            if default_count != 1:
                raise ValueError("제어 DB에는 정확히 하나의 기본 프로젝트가 있어야 합니다.")
    except sqlite3.DatabaseError as exc:
        raise ValueError(f"유효한 VulnFlow 제어 DB가 아닙니다: {exc}") from exc

    audit = verify_audit_integrity(path)
    if not audit.get("valid"):
        raise ValueError(
            "제어 DB 감사 체인 무결성 검증에 실패했습니다: "
            + "; ".join(audit.get("issues") or [])
        )
    return {
        "schema_version": schema_version,
        "size_bytes": path.stat().st_size,
        "sha256": _sha256_file(path),
        "database_identity": identity,
        "counts": counts,
        "audit_integrity": audit,
    }


def _sanitize_control_snapshot(path: Path) -> None:
    with closing(sqlite3.connect(path)) as conn:
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("DELETE FROM auth_sessions")
        conn.execute("DELETE FROM auth_login_attempts")
        conn.execute("UPDATE app_users SET failed_attempts=0,locked_until='' ")
        conn.commit()
        conn.execute("VACUUM")


def create_control_recovery_bundle(
    control_db_path: str | Path,
    destination: str | Path,
    *,
    created_by: str,
    signing_key: str = "",
    signing_key_id: str | None = None,
) -> dict[str, Any]:
    if signing_key_id and not signing_key:
        raise ValueError("제어 DB 복구 번들 key_id에는 서명 키가 필요합니다.")
    if signing_key_id and not KEY_ID_RE.fullmatch(signing_key_id):
        raise ValueError("제어 DB 복구 번들 서명 키 ID 형식이 올바르지 않습니다.")
    source_identity = get_database_identity(control_db_path)
    if source_identity.get("database_role") != CONTROL_DATABASE_ROLE:
        raise ValueError("control 역할의 데이터베이스만 제어 DB 복구 번들로 만들 수 있습니다.")

    destination_path = Path(destination)
    destination_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="vulnflow_control_recovery_") as temp_name:
        temp = Path(temp_name)
        database = temp / CONTROL_DATABASE_FILENAME
        backup_database(control_db_path, database)
        _sanitize_control_snapshot(database)
        summary = validate_control_database_file(database)
        manifest: dict[str, Any] = {
            "format": CONTROL_RECOVERY_FORMAT,
            "created_at": _utc_now(),
            "created_by": str(created_by or "system"),
            "app_version": CURRENT_APP_VERSION,
            "database_role": CONTROL_DATABASE_ROLE,
            "schema_version": summary["schema_version"],
            "database": {
                "filename": CONTROL_DATABASE_FILENAME,
                "sha256": summary["sha256"],
                "size_bytes": summary["size_bytes"],
                "counts": summary["counts"],
                "sessions_included": False,
                "login_attempts_included": False,
            },
            "signed": bool(signing_key),
            "signature": (
                {"algorithm": "HMAC-SHA256", "key_id": signing_key_id}
                if signing_key
                else None
            ),
        }
        manifest_bytes = _canonical_json(manifest)
        manifest_path = temp / "manifest.json"
        manifest_path.write_bytes(manifest_bytes)
        sums_bytes = (
            f"{_sha256_file(database)}  {CONTROL_DATABASE_FILENAME}\n"
            f"{_sha256_file(manifest_path)}  manifest.json\n"
        ).encode("utf-8")
        sums_path = temp / "SHA256SUMS.txt"
        sums_path.write_bytes(sums_bytes)
        files = [
            (database, CONTROL_DATABASE_FILENAME),
            (manifest_path, "manifest.json"),
            (sums_path, "SHA256SUMS.txt"),
        ]
        if signing_key:
            signature = hmac_sha256(signing_key, manifest_bytes + b"\n" + sums_bytes)
            signature_path = temp / "manifest.hmac"
            signature_path.write_text(signature + "\n", encoding="ascii")
            files.append((signature_path, "manifest.hmac"))
        with zipfile.ZipFile(
            destination_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
        ) as archive:
            for path, arcname in sorted(files, key=lambda item: item[1]):
                archive.write(path, arcname=arcname)
    return manifest | {
        "bundle_path": str(destination_path),
        "bundle_sha256": _sha256_file(destination_path),
    }


def _safe_members(archive: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
    infos = archive.infolist()
    if len(infos) > MAX_BUNDLE_FILES:
        raise ValueError("제어 DB 복구 번들 파일 수가 허용 범위를 초과합니다.")
    seen: set[str] = set()
    total = 0
    for info in infos:
        name = PurePosixPath(info.filename)
        if info.filename in seen:
            raise ValueError("제어 DB 복구 번들에 중복 파일명이 있습니다.")
        seen.add(info.filename)
        if name.is_absolute() or ".." in name.parts or len(name.parts) != 1:
            raise ValueError("제어 DB 복구 번들에 안전하지 않은 경로가 있습니다.")
        mode = (int(info.external_attr) >> 16) & 0o170000
        if mode and stat.S_ISLNK(mode):
            raise ValueError("제어 DB 복구 번들에 심볼릭 링크를 포함할 수 없습니다.")
        if not info.is_dir():
            total += int(info.file_size)
        if total > MAX_BUNDLE_UNCOMPRESSED:
            raise ValueError("제어 DB 복구 번들의 압축 해제 크기가 허용 범위를 초과합니다.")
    return infos


def _read_sums(value: str) -> dict[str, str]:
    output: dict[str, str] = {}
    for line in value.splitlines():
        if not line.strip():
            continue
        digest, separator, filename = line.partition("  ")
        if (
            not separator
            or len(digest) != 64
            or any(char not in "0123456789abcdefABCDEF" for char in digest)
            or not filename
        ):
            raise ValueError("제어 DB SHA256SUMS.txt 형식이 올바르지 않습니다.")
        output[filename] = digest.lower()
    return output


def validate_control_recovery_bundle(
    bundle_path: str | Path,
    *,
    signing_key: str = "",
    signing_keys: Mapping[str, str] | None = None,
    require_signature: bool = False,
) -> dict[str, Any]:
    bundle = Path(bundle_path)
    try:
        with zipfile.ZipFile(bundle) as archive:
            infos = _safe_members(archive)
            names = {info.filename for info in infos if not info.is_dir()}
            if not REQUIRED_FILES <= names:
                raise ValueError("제어 DB 복구 번들 필수 파일이 없습니다.")
            allowed = REQUIRED_FILES | {"manifest.hmac"}
            if names - allowed:
                raise ValueError("제어 DB 복구 번들에 정의되지 않은 파일이 있습니다.")
            with tempfile.TemporaryDirectory(prefix="vulnflow_control_validate_") as temp_name:
                temp = Path(temp_name)
                for info in infos:
                    if not info.is_dir():
                        archive.extract(info, temp)
                manifest_bytes = (temp / "manifest.json").read_bytes()
                sums_bytes = (temp / "SHA256SUMS.txt").read_bytes()
                try:
                    manifest = json.loads(manifest_bytes)
                except json.JSONDecodeError as exc:
                    raise ValueError("제어 DB manifest.json 형식이 올바르지 않습니다.") from exc
                if not isinstance(manifest, dict) or manifest.get("format") != CONTROL_RECOVERY_FORMAT:
                    raise ValueError("지원하지 않는 제어 DB 복구 번들 형식입니다.")
                if manifest.get("database_role") != CONTROL_DATABASE_ROLE:
                    raise ValueError("제어 DB 복구 번들의 database role이 control이 아닙니다.")
                sums = _read_sums(sums_bytes.decode("utf-8"))
                expected_sums = {"manifest.json", CONTROL_DATABASE_FILENAME}
                if set(sums) != expected_sums:
                    raise ValueError("제어 DB 복구 번들의 체크섬 파일 목록이 일치하지 않습니다.")
                for filename, digest in sums.items():
                    if _sha256_file(temp / filename) != digest:
                        raise ValueError(f"제어 DB 복구 번들 체크섬이 일치하지 않습니다: {filename}")
                database = temp / CONTROL_DATABASE_FILENAME
                summary = validate_control_database_file(database)
                database_meta = manifest.get("database") if isinstance(manifest.get("database"), dict) else {}
                if database_meta.get("sha256") != summary["sha256"]:
                    raise ValueError("제어 DB manifest 데이터베이스 해시가 일치하지 않습니다.")
                if int(manifest.get("schema_version") or 0) != int(summary["schema_version"]):
                    raise ValueError("제어 DB manifest 스키마 버전이 데이터베이스와 일치하지 않습니다.")
                signed = bool(manifest.get("signed"))
                signature_path = temp / "manifest.hmac"
                if require_signature and not signed:
                    raise ValueError("서명되지 않은 제어 DB 복구 번들은 허용되지 않습니다.")
                resolved_key_id: str | None = None
                if signed:
                    if not signature_path.is_file():
                        raise ValueError("제어 DB 복구 번들 서명 파일이 없습니다.")
                    signature_meta = manifest.get("signature") if isinstance(manifest.get("signature"), dict) else {}
                    declared_key_id = str(signature_meta.get("key_id") or "") or None
                    available_keys = dict(signing_keys or {})
                    if declared_key_id and signing_key:
                        available_keys.setdefault(declared_key_id, signing_key)
                    verified = verify_hmac(
                        signature=signature_path.read_text(encoding="ascii").strip(),
                        payload=manifest_bytes + b"\n" + sums_bytes,
                        signing_keys=available_keys,
                        key_id=declared_key_id,
                        legacy_key=signing_key,
                    )
                    if not verified.get("valid"):
                        raise ValueError("제어 DB 복구 번들 HMAC 서명이 일치하지 않습니다.")
                    resolved_key_id = verified.get("resolved_key_id")
                elif signature_path.exists():
                    raise ValueError("제어 DB 복구 번들 서명 상태와 파일이 일치하지 않습니다.")
                return {
                    "valid": True,
                    "bundle_sha256": _sha256_file(bundle),
                    "manifest": manifest,
                    "database": summary,
                    "signed": signed,
                    "signing_key_id": resolved_key_id,
                }
    except zipfile.BadZipFile as exc:
        raise ValueError("유효한 ZIP 제어 DB 복구 번들이 아닙니다.") from exc


def _registry_snapshot(control_db_path: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if not control_db_path.is_file():
        return [], []
    with closing(sqlite3.connect(control_db_path)) as conn:
        conn.row_factory = sqlite3.Row
        if not _table_exists(conn, "projects"):
            return [], []
        projects = [dict(row) for row in conn.execute("SELECT * FROM projects").fetchall()]
        memberships = (
            [dict(row) for row in conn.execute("SELECT * FROM project_memberships").fetchall()]
            if _table_exists(conn, "project_memberships")
            else []
        )
    return projects, memberships


def _discover_project_rows(projects_dir: Path) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    if not projects_dir.is_dir():
        return output
    now = _utc_now()
    for database in sorted(projects_dir.glob("*/vulnflow.db")):
        try:
            identity = get_database_identity(database)
        except Exception:
            continue
        project_id = str(identity.get("project_id") or "").strip().lower()
        if identity.get("database_role") != PROJECT_DATABASE_ROLE or not project_id or project_id == "default":
            continue
        output.append(
            {
                "project_id": project_id,
                "name": str(identity.get("project_name") or project_id),
                "slug": project_id[:64],
                "status": "ACTIVE",
                "is_default": 0,
                "created_by": "control-recovery-discovery",
                "created_at": now,
                "updated_at": now,
            }
        )
    return output


def _merge_preserved_registry(
    control_db_path: Path,
    *,
    projects: list[dict[str, Any]],
    memberships: list[dict[str, Any]],
    discovered: list[dict[str, Any]],
    projects_dir: Path,
) -> dict[str, int]:
    merged_projects = 0
    merged_memberships = 0
    candidates: dict[str, dict[str, Any]] = {}
    for row in projects + discovered:
        project_id = str(row.get("project_id") or "").strip().lower()
        if not project_id or int(row.get("is_default") or 0):
            continue
        database = projects_dir / project_id / "vulnflow.db"
        if database.is_file():
            candidates.setdefault(project_id, row)
    with closing(sqlite3.connect(control_db_path)) as conn:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        existing = {
            str(row[0]) for row in conn.execute("SELECT project_id FROM projects").fetchall()
        }
        slugs = {str(row[0]) for row in conn.execute("SELECT slug FROM projects").fetchall()}
        for project_id, row in candidates.items():
            if project_id in existing:
                continue
            base_slug = str(row.get("slug") or project_id)[:64]
            slug = base_slug
            suffix = 1
            while slug in slugs:
                suffix += 1
                slug = f"{base_slug[:58]}-{suffix}"
            conn.execute(
                """INSERT INTO projects(project_id,name,slug,status,is_default,created_by,created_at,updated_at)
                   VALUES(?,?,?,?,0,?,?,?)""",
                (
                    project_id,
                    str(row.get("name") or project_id),
                    slug,
                    str(row.get("status") or "ACTIVE"),
                    str(row.get("created_by") or "control-recovery-preserve"),
                    str(row.get("created_at") or _utc_now()),
                    _utc_now(),
                ),
            )
            existing.add(project_id)
            slugs.add(slug)
            merged_projects += 1
        users = {str(row[0]) for row in conn.execute("SELECT username FROM app_users").fetchall()}
        for row in memberships:
            project_id = str(row.get("project_id") or "").strip().lower()
            username = str(row.get("username") or "").strip().lower()
            if project_id not in existing or username not in users:
                continue
            result = conn.execute(
                """INSERT OR IGNORE INTO project_memberships(project_id,username,created_by,created_at)
                   VALUES(?,?,?,?)""",
                (
                    project_id,
                    username,
                    str(row.get("created_by") or "control-recovery-preserve"),
                    str(row.get("created_at") or _utc_now()),
                ),
            )
            merged_memberships += int(result.rowcount or 0)
        conn.commit()
    return {"projects": merged_projects, "memberships": merged_memberships}


def restore_control_recovery_bundle(
    control_db_path: str | Path,
    bundle_path: str | Path,
    *,
    actor: str,
    projects_dir: str | Path,
    signing_key: str = "",
    signing_keys: Mapping[str, str] | None = None,
    require_signature: bool = False,
) -> dict[str, Any]:
    validation = validate_control_recovery_bundle(
        bundle_path,
        signing_key=signing_key,
        signing_keys=signing_keys,
        require_signature=require_signature,
    )
    target = Path(control_db_path)
    project_root = Path(projects_dir)
    preserved_projects, preserved_memberships = _registry_snapshot(target)
    discovered = _discover_project_rows(project_root)
    target.parent.mkdir(parents=True, exist_ok=True)
    backup_root = target.parent / "backups" / "control"
    backup_root.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    safety_backup = backup_root / f"control_pre_restore_{timestamp}.sqlite3"
    if target.is_file():
        backup_database(target, safety_backup)
    else:
        init_db(target)
        set_database_identity(
            target,
            database_role=CONTROL_DATABASE_ROLE,
            project_id="control",
            project_name="제어 DB",
        )
        backup_database(target, safety_backup)

    try:
        with tempfile.TemporaryDirectory(prefix="vulnflow_control_restore_") as temp_name:
            temp = Path(temp_name)
            with zipfile.ZipFile(bundle_path) as archive:
                archive.extract(CONTROL_DATABASE_FILENAME, temp)
            source = temp / CONTROL_DATABASE_FILENAME
            with closing(sqlite3.connect(source)) as source_conn, closing(
                sqlite3.connect(target)
            ) as target_conn:
                source_conn.backup(target_conn)
                target_conn.commit()
        init_db(target)
        set_database_identity(
            target,
            database_role=CONTROL_DATABASE_ROLE,
            project_id="control",
            project_name="제어 DB",
        )
        with closing(sqlite3.connect(target)) as conn:
            conn.execute("DELETE FROM auth_sessions")
            conn.execute("DELETE FROM auth_login_attempts")
            conn.execute("UPDATE app_users SET failed_attempts=0,locked_until='' ")
            conn.commit()
        merged = _merge_preserved_registry(
            target,
            projects=preserved_projects,
            memberships=preserved_memberships,
            discovered=discovered,
            projects_dir=project_root,
        )
        add_audit_event(
            target,
            finding_id=None,
            event_type="CONTROL_DATABASE_RESTORED",
            summary="제어 DB 복구 번들 복원",
            details={
                "bundle_sha256": validation["bundle_sha256"],
                "safety_backup": safety_backup.name,
                "restored_users": validation["database"]["counts"]["app_users"],
                "restored_projects": validation["database"]["counts"]["projects"],
                "preserved_projects": merged["projects"],
                "preserved_memberships": merged["memberships"],
                "sessions_revoked": True,
            },
            actor=str(actor or "system"),
        )
        final_summary = validate_control_database_file(target)
    except Exception:
        if safety_backup.is_file():
            with closing(sqlite3.connect(safety_backup)) as source_conn, closing(
                sqlite3.connect(target)
            ) as target_conn:
                source_conn.backup(target_conn)
                target_conn.commit()
        raise
    return {
        "validation": validation,
        "restore": {
            "safety_backup": str(safety_backup),
            "preserved": merged,
            "sessions_revoked": True,
            "database": final_summary,
        },
    }
