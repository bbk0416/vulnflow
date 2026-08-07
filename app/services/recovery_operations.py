from __future__ import annotations

"""Operational recovery drills and mounted external backup replication.

Recovery bundles are first written to each project's local recovery directory.
When an external root is configured, the completed bundle is copied atomically
into a project-specific folder and verified by SHA-256.  Recovery drills restore
one stored bundle into a temporary isolated store, then re-run database, audit,
and evidence integrity checks without modifying live project data.
"""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import tempfile
import time
from typing import Any, Mapping

from app.repositories.audit import verify_audit_integrity
from app.services.database_lifecycle import validate_database_file
from app.services.evidence import verify_evidence_store
from app.services.recovery import (
    list_recovery_bundles,
    restore_recovery_bundle,
    sha256_file,
)

_PROJECT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{2,63}$")
_BUNDLE_NAME_RE = re.compile(r"^vulnflow_recovery_[0-9]{8}T[0-9]{12,20}Z\.zip$")
_DRILL_REPORT_RE = re.compile(r"^recovery_drill_[0-9]{8}T[0-9]{12,20}Z\.json$")


def _utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _safe_project_id(project_id: str) -> str:
    value = str(project_id or "").strip().lower()
    if not _PROJECT_ID_RE.fullmatch(value):
        raise ValueError("외부 백업 프로젝트 ID 형식이 올바르지 않습니다.")
    return value


def _safe_bundle_name(filename: str) -> str:
    value = str(filename or "").strip()
    if Path(value).name != value or not _BUNDLE_NAME_RE.fullmatch(value):
        raise ValueError("복구 번들 파일명이 올바르지 않습니다.")
    return value


def external_project_backup_dir(
    external_root: str | Path | None,
    project_id: str,
) -> Path | None:
    if external_root is None or not str(external_root).strip():
        return None
    return Path(external_root).expanduser() / _safe_project_id(project_id)


def _ensure_private_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        path.chmod(0o700)
    except OSError:
        pass


def _write_private_text(path: Path, value: str, *, encoding: str) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding=encoding) as handle:
        handle.write(value)
        handle.flush()
        os.fsync(handle.fileno())


def _fsync_file(path: Path) -> None:
    with path.open("rb") as handle:
        os.fsync(handle.fileno())


def _fsync_directory(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def mirror_recovery_bundle(
    bundle_path: str | Path,
    *,
    external_root: str | Path | None,
    project_id: str,
    retention_count: int,
) -> dict[str, Any]:
    """Atomically replicate a completed bundle to a mounted external volume."""
    source = Path(bundle_path)
    if not source.is_file() or source.stat().st_size <= 0:
        raise ValueError("외부 보관할 복구 번들이 존재하지 않습니다.")
    destination_root = external_project_backup_dir(external_root, project_id)
    if destination_root is None:
        return {"configured": False, "copied": False, "project_id": project_id}
    _ensure_private_directory(destination_root)
    filename = _safe_bundle_name(source.name)
    destination = destination_root / filename
    try:
        if source.resolve() == destination.resolve():
            raise ValueError("외부 백업 디렉터리는 로컬 복구 디렉터리와 달라야 합니다.")
    except FileNotFoundError:
        pass
    expected = sha256_file(source)
    nonce = secrets.token_hex(6)
    temporary = destination_root / f".{filename}.{os.getpid()}.{nonce}.partial"
    sidecar = destination.with_suffix(destination.suffix + ".sha256")
    sidecar_temp = destination_root / f".{sidecar.name}.{os.getpid()}.{nonce}.partial"
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with source.open("rb") as input_handle, os.fdopen(descriptor, "wb") as output_handle:
            shutil.copyfileobj(input_handle, output_handle, length=1024 * 1024)
            output_handle.flush()
            os.fsync(output_handle.fileno())
        actual = sha256_file(temporary)
        if actual != expected:
            raise ValueError("외부 백업 복사본의 SHA-256 검증에 실패했습니다.")
        os.replace(temporary, destination)
        _write_private_text(sidecar_temp, f"{expected}  {filename}\n", encoding="ascii")
        os.replace(sidecar_temp, sidecar)
        _fsync_directory(destination_root)
    finally:
        temporary.unlink(missing_ok=True)
        sidecar_temp.unlink(missing_ok=True)

    kept = max(1, int(retention_count))
    bundles = sorted(
        destination_root.glob("vulnflow_recovery_*.zip"),
        key=lambda item: item.stat().st_mtime,
        reverse=True,
    )
    removed = 0
    for old in bundles[kept:]:
        old.unlink(missing_ok=True)
        old.with_suffix(old.suffix + ".sha256").unlink(missing_ok=True)
        removed += 1
    return {
        "configured": True,
        "copied": True,
        "project_id": _safe_project_id(project_id),
        "bundle_path": str(destination),
        "filename": filename,
        "sha256": expected,
        "size_bytes": destination.stat().st_size,
        "pruned": removed,
    }


def list_external_recovery_bundles(
    external_root: str | Path | None,
    *,
    project_id: str,
    limit: int = 100,
) -> list[dict[str, Any]]:
    root = external_project_backup_dir(external_root, project_id)
    if root is None:
        return []
    items = list_recovery_bundles(root, limit=limit)
    for item in items:
        item["location"] = "external"
        path = root / str(item["filename"])
        sidecar = path.with_suffix(path.suffix + ".sha256")
        expected = ""
        try:
            line = sidecar.read_text(encoding="ascii").strip()
            expected, separator, recorded_name = line.partition("  ")
            item["copy_verified"] = bool(
                separator
                and recorded_name == path.name
                and expected == item["sha256"]
            )
        except OSError:
            item["copy_verified"] = False
    return items


def list_local_recovery_bundles(
    recovery_dir: str | Path,
    *,
    limit: int = 100,
) -> list[dict[str, Any]]:
    items = list_recovery_bundles(recovery_dir, limit=limit)
    for item in items:
        item["location"] = "local"
    return items


def resolve_stored_recovery_bundle(
    *,
    recovery_dir: str | Path,
    external_root: str | Path | None,
    project_id: str,
    location: str,
    filename: str,
) -> Path:
    safe_name = _safe_bundle_name(filename)
    normalized_location = str(location or "local").strip().lower()
    if normalized_location == "local":
        root = Path(recovery_dir)
    elif normalized_location == "external":
        root = external_project_backup_dir(external_root, project_id)
        if root is None:
            raise ValueError("외부 백업 보관소가 설정되지 않았습니다.")
    else:
        raise ValueError("지원하지 않는 복구 번들 위치입니다.")
    root = root.resolve()
    candidate = (root / safe_name).resolve()
    if candidate.parent != root or not candidate.is_file():
        raise ValueError("선택한 복구 번들을 찾을 수 없습니다.")
    if normalized_location == "external":
        sidecar = candidate.with_suffix(candidate.suffix + ".sha256")
        try:
            line = sidecar.read_text(encoding="ascii").strip()
        except OSError as exc:
            raise ValueError("외부 복구 번들의 SHA-256 확인 파일이 없습니다.") from exc
        expected, separator, recorded_name = line.partition("  ")
        if (
            not separator
            or recorded_name != candidate.name
            or expected != sha256_file(candidate)
        ):
            raise ValueError("외부 복구 번들의 SHA-256 검증에 실패했습니다.")
    return candidate


def _write_drill_report(report_dir: Path, report: Mapping[str, Any]) -> Path:
    _ensure_private_directory(report_dir)
    destination = report_dir / f"recovery_drill_{_utc_stamp()}.json"
    temporary = report_dir / f".{destination.name}.{os.getpid()}.partial"
    _write_private_text(
        temporary,
        json.dumps(dict(report), ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, destination)
    _fsync_directory(report_dir)
    return destination


def run_recovery_drill(
    bundle_path: str | Path,
    *,
    report_dir: str | Path,
    actor: str,
    project_id: str,
    signing_key: str = "",
    signing_keys: Mapping[str, str] | None = None,
    audit_signing_key: str = "",
    audit_signing_keys: Mapping[str, str] | None = None,
    require_signature: bool = False,
    current_schema_version: int | None = None,
) -> dict[str, Any]:
    """Restore and verify a bundle in an isolated temporary store."""
    source = Path(bundle_path)
    started = time.monotonic()
    base_report: dict[str, Any] = {
        "format": "vulnflow-recovery-drill/1",
        "project_id": _safe_project_id(project_id),
        "actor": str(actor or "system"),
        "bundle_filename": _safe_bundle_name(source.name),
        "bundle_sha256": sha256_file(source) if source.is_file() else "",
        "started_at": _utc_now(),
    }
    try:
        with tempfile.TemporaryDirectory(prefix="vulnflow_recovery_drill_") as temporary_name:
            temporary_root = Path(temporary_name)
            restored_db = temporary_root / "restored.sqlite3"
            restored_evidence = temporary_root / "evidence"
            restore_result = restore_recovery_bundle(
                restored_db,
                source,
                actor=f"recovery-drill:{actor}",
                signing_key=signing_key,
                signing_keys=signing_keys,
                audit_signing_key=audit_signing_key,
                audit_signing_keys=audit_signing_keys,
                require_signature=require_signature,
                current_schema_version=current_schema_version,
                evidence_dir=restored_evidence,
                expected_project_id=_safe_project_id(project_id),
            )
            database = validate_database_file(restored_db)
            audit = verify_audit_integrity(
                restored_db,
                signing_key=audit_signing_key,
                signing_keys=dict(audit_signing_keys or {}),
            )
            evidence = verify_evidence_store(restored_db, restored_evidence)
            if not audit.get("valid"):
                raise ValueError("복구 리허설의 감사 체인 재검사에 실패했습니다.")
            if not evidence.get("valid"):
                raise ValueError("복구 리허설의 증거 저장소 재검사에 실패했습니다.")
            report = base_report | {
                "status": "PASSED",
                "completed_at": _utc_now(),
                "duration_ms": int((time.monotonic() - started) * 1000),
                "database": database,
                "audit_integrity": {
                    "valid": True,
                    "checked_events": int(audit.get("checked_events") or 0),
                    "last_seq": int(audit.get("last_seq") or 0),
                    "last_hash": str(audit.get("last_hash") or ""),
                },
                "evidence_integrity": {
                    "valid": True,
                    "artifact_count": int(evidence.get("artifact_count") or 0),
                    "total_size_bytes": int(evidence.get("total_size_bytes") or 0),
                },
                "restored_bundle": {
                    "signed": bool((restore_result.get("validation") or {}).get("signed")),
                    "signing_key_id": (restore_result.get("validation") or {}).get("signing_key_id"),
                },
            }
    except Exception as exc:
        report = base_report | {
            "status": "FAILED",
            "completed_at": _utc_now(),
            "duration_ms": int((time.monotonic() - started) * 1000),
            "error_type": type(exc).__name__,
            "error": str(exc),
        }
        report_path = _write_drill_report(Path(report_dir), report)
        raise ValueError(f"복구 리허설 실패: {exc} (보고서: {report_path.name})") from exc
    report_path = _write_drill_report(Path(report_dir), report)
    return report | {"report_path": str(report_path), "report_filename": report_path.name}


def list_recovery_drills(report_dir: str | Path, *, limit: int = 50) -> list[dict[str, Any]]:
    root = Path(report_dir)
    if not root.exists():
        return []
    output: list[dict[str, Any]] = []
    paths = sorted(
        (path for path in root.glob("recovery_drill_*.json") if path.is_file()),
        key=lambda item: item.stat().st_mtime,
        reverse=True,
    )[: max(1, min(int(limit), 500))]
    for path in paths:
        if not _DRILL_REPORT_RE.fullmatch(path.name):
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            payload = {"status": "UNREADABLE", "error": "보고서를 읽을 수 없습니다."}
        if not isinstance(payload, dict):
            payload = {"status": "UNREADABLE", "error": "보고서 형식이 올바르지 않습니다."}
        payload = dict(payload)
        payload["report_filename"] = path.name
        output.append(payload)
    return output
