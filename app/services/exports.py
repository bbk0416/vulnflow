from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import shutil
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator

from app.core.db import connect, utc_now
from app.repositories.audit import add_audit_event
from app.repositories.reconciliation import FIELDS
from app.services.database_lifecycle import backup_database
from app.services.finding_query import query_findings

EXPORT_TYPES = {"FINDINGS_CSV", "INTEGRITY_PROOF_ZIP"}
ARTIFACT_STATUSES = {"READY", "EXPIRED", "CORRUPT", "EVICTED"}


def _csv_safe(value: Any) -> Any:
    if value is None:
        return ""
    text = str(value)
    if text.startswith(("=", "+", "-", "@")):
        return "'" + text
    return text


def _canonical_filters(filters: dict[str, Any] | None) -> dict[str, Any]:
    raw = dict(filters or {})
    allowed = {
        "decision", "status", "query", "overdue", "exception",
        "record_state", "scanner_source",
    }
    result: dict[str, Any] = {}
    for key in sorted(allowed):
        value = raw.get(key)
        if key == "overdue":
            result[key] = bool(value)
        elif value not in {None, ""}:
            result[key] = str(value)
    result.setdefault("record_state", "ALL")
    return result


def _artifact_row(row: Any) -> dict[str, Any]:
    item = dict(row)
    try:
        item["filters"] = json.loads(item.pop("filters_json") or "{}")
    except (TypeError, json.JSONDecodeError):
        item["filters"] = {}
    item["downloaded_count"] = int(item.get("downloaded_count") or 0)
    item["row_count"] = int(item.get("row_count") or 0)
    item["size_bytes"] = int(item.get("size_bytes") or 0)
    item["pinned"] = bool(item.get("pinned"))
    return item


def register_export_artifact(
    db_path: str | Path,
    *,
    job_id: str | None,
    export_type: str,
    stored_filename: str,
    download_filename: str,
    content_type: str,
    row_count: int,
    size_bytes: int,
    sha256: str,
    filters: dict[str, Any],
    snapshot_at: str,
    created_by: str,
    expires_at: str | None,
    max_storage_bytes: int = 0,
) -> dict[str, Any]:
    if export_type not in EXPORT_TYPES:
        raise ValueError("지원하지 않는 내보내기 유형입니다.")
    artifact_id = f"EXP-{uuid.uuid4().hex[:20].upper()}"
    now = utc_now()
    with connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        if int(max_storage_bytes) > 0:
            used = int(conn.execute(
                "SELECT COALESCE(SUM(size_bytes),0) FROM export_artifacts WHERE status IN ('READY','CORRUPT')"
            ).fetchone()[0])
            if used + int(size_bytes) > int(max_storage_bytes):
                raise RuntimeError("내보내기 저장소 quota를 초과합니다.")
        conn.execute(
            """
            INSERT INTO export_artifacts(
                artifact_id,job_id,export_type,status,stored_filename,download_filename,
                content_type,row_count,size_bytes,sha256,filters_json,snapshot_at,
                created_by,created_at,expires_at
            ) VALUES(?,?,?,'READY',?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                artifact_id, job_id, export_type, stored_filename, download_filename,
                content_type, int(row_count), int(size_bytes), str(sha256),
                json.dumps(_canonical_filters(filters), ensure_ascii=False, separators=(",", ":")),
                snapshot_at, created_by, now, expires_at,
            ),
        )
        add_audit_event(
            db_path,
            finding_id=None,
            event_type="export_artifact_created",
            summary=f"내보내기 산출물 생성: {export_type}",
            details={
                "artifact_id": artifact_id,
                "job_id": job_id,
                "row_count": int(row_count),
                "size_bytes": int(size_bytes),
                "sha256": sha256,
                "expires_at": expires_at,
            },
            actor=created_by,
            conn=conn,
        )
        conn.commit()
    return get_export_artifact(db_path, artifact_id) or {}


def get_export_artifact(db_path: str | Path, artifact_id: str) -> dict[str, Any] | None:
    with connect(db_path) as conn:
        row = conn.execute("SELECT * FROM export_artifacts WHERE artifact_id=?", (artifact_id,)).fetchone()
    return _artifact_row(row) if row else None


def get_export_artifact_by_job(db_path: str | Path, job_id: str) -> dict[str, Any] | None:
    with connect(db_path) as conn:
        row = conn.execute("SELECT * FROM export_artifacts WHERE job_id=?", (job_id,)).fetchone()
    return _artifact_row(row) if row else None


def list_export_artifacts(
    db_path: str | Path,
    *,
    status: str = "",
    limit: int = 200,
) -> list[dict[str, Any]]:
    normalized = str(status or "").strip().upper()
    if normalized and normalized not in ARTIFACT_STATUSES:
        raise ValueError("지원하지 않는 내보내기 상태입니다.")
    limit = max(1, min(1000, int(limit)))
    where = " WHERE status=?" if normalized else ""
    params: list[Any] = [normalized] if normalized else []
    with connect(db_path) as conn:
        rows = conn.execute(
            f"SELECT * FROM export_artifacts{where} ORDER BY created_at DESC,artifact_id DESC LIMIT ?",
            [*params, limit],
        ).fetchall()
    return [_artifact_row(row) for row in rows]


def resolve_export_artifact_path(export_dir: str | Path, artifact: dict[str, Any]) -> Path:
    base = Path(export_dir).resolve()
    filename = Path(str(artifact.get("stored_filename") or "")).name
    if not filename or filename != str(artifact.get("stored_filename") or ""):
        raise ValueError("내보내기 파일명이 올바르지 않습니다.")
    candidate = (base / filename).resolve()
    if candidate.parent != base:
        raise ValueError("내보내기 파일 경로가 올바르지 않습니다.")
    return candidate


def mark_export_artifact_corrupt(db_path: str | Path, artifact_id: str, *, actor: str, reason: str) -> dict[str, Any]:
    now = utc_now()
    with connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM export_artifacts WHERE artifact_id=?", (artifact_id,)).fetchone()
        if row is None:
            raise KeyError(artifact_id)
        conn.execute("UPDATE export_artifacts SET status='CORRUPT',expired_by=?,expired_at=? WHERE artifact_id=?", (actor, now, artifact_id))
        add_audit_event(
            db_path, finding_id=None, event_type="export_artifact_corrupt",
            summary="내보내기 산출물 무결성 오류", details={"artifact_id": artifact_id, "reason": str(reason)[:500]},
            actor=actor, conn=conn,
        )
        conn.commit()
    return get_export_artifact(db_path, artifact_id) or {}


def verify_export_artifact(export_dir: str | Path, artifact: dict[str, Any]) -> dict[str, Any]:
    path = resolve_export_artifact_path(export_dir, artifact)
    if not path.is_file():
        return {"valid": False, "reason": "missing", "path": str(path)}
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
    actual = digest.hexdigest()
    valid = actual == str(artifact.get("sha256") or "") and size == int(artifact.get("size_bytes") or 0)
    return {
        "valid": valid,
        "reason": "ok" if valid else "digest_or_size_mismatch",
        "actual_sha256": actual,
        "actual_size_bytes": size,
        "path": str(path),
    }


def record_export_download(db_path: str | Path, artifact_id: str, *, actor: str) -> dict[str, Any]:
    now = utc_now()
    with connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM export_artifacts WHERE artifact_id=?", (artifact_id,)).fetchone()
        if row is None:
            raise KeyError(artifact_id)
        if str(row["status"]) != "READY":
            raise ValueError("다운로드 가능한 내보내기 산출물이 아닙니다.")
        expires_at = str(row["expires_at"] or "")
        if expires_at and expires_at <= now and not int(row["pinned"] or 0):
            conn.execute(
                "UPDATE export_artifacts SET status='EXPIRED',expired_by=?,expired_at=? WHERE artifact_id=?",
                ("system-expiry", now, artifact_id),
            )
            conn.commit()
            raise ValueError("내보내기 산출물이 만료되었습니다.")
        conn.execute(
            "UPDATE export_artifacts SET downloaded_count=downloaded_count+1,last_downloaded_at=? WHERE artifact_id=?",
            (now, artifact_id),
        )
        add_audit_event(
            db_path,
            finding_id=None,
            event_type="export_artifact_downloaded",
            summary="내보내기 산출물 다운로드",
            details={"artifact_id": artifact_id},
            actor=actor,
            conn=conn,
        )
        conn.commit()
    return get_export_artifact(db_path, artifact_id) or {}


def expire_export_artifact(
    db_path: str | Path,
    export_dir: str | Path,
    artifact_id: str,
    *,
    actor: str,
) -> dict[str, Any]:
    now = utc_now()
    with connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM export_artifacts WHERE artifact_id=?", (artifact_id,)).fetchone()
        if row is None:
            raise KeyError(artifact_id)
        artifact = _artifact_row(row)
        conn.execute(
            "UPDATE export_artifacts SET status='EXPIRED',expired_by=?,expired_at=? WHERE artifact_id=?",
            (actor, now, artifact_id),
        )
        add_audit_event(
            db_path,
            finding_id=None,
            event_type="export_artifact_expired",
            summary="내보내기 산출물 만료 처리",
            details={"artifact_id": artifact_id},
            actor=actor,
            conn=conn,
        )
        conn.commit()
    path = resolve_export_artifact_path(export_dir, artifact)
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass
    return get_export_artifact(db_path, artifact_id) or {}


def purge_expired_export_artifacts(
    db_path: str | Path,
    export_dir: str | Path,
    *,
    actor: str = "system-maintenance",
) -> dict[str, int]:
    now = utc_now()
    with connect(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM export_artifacts WHERE status='READY' AND pinned=0 AND NULLIF(expires_at,'') IS NOT NULL AND expires_at<=?",
            (now,),
        ).fetchall()
    expired = 0
    removed = 0
    for row in rows:
        artifact = _artifact_row(row)
        try:
            path = resolve_export_artifact_path(export_dir, artifact)
            if path.exists():
                path.unlink()
                removed += 1
        except (OSError, ValueError):
            pass
        with connect(db_path) as conn:
            conn.execute(
                "UPDATE export_artifacts SET status='EXPIRED',expired_by=?,expired_at=? WHERE artifact_id=? AND status='READY'",
                (actor, now, artifact["artifact_id"]),
            )
            conn.commit()
        expired += 1
    return {"exports_expired": expired, "export_files_removed": removed}


def reconcile_export_artifacts(
    db_path: str | Path,
    export_dir: str | Path,
    *,
    actor: str = "system-startup",
) -> dict[str, int]:
    checked = 0
    corrupt = 0
    for artifact in list_export_artifacts(db_path, status="READY", limit=1000):
        checked += 1
        verification = verify_export_artifact(export_dir, artifact)
        if not verification.get("valid"):
            mark_export_artifact_corrupt(
                db_path, str(artifact["artifact_id"]), actor=actor,
                reason=str(verification.get("reason") or "invalid"),
            )
            corrupt += 1
    return {"exports_checked": checked, "exports_marked_corrupt": corrupt}



def export_storage_status(
    db_path: str | Path,
    export_dir: str | Path,
    *,
    quota_bytes: int = 0,
    reserve_bytes: int = 0,
) -> dict[str, Any]:
    root = Path(export_dir)
    root.mkdir(parents=True, exist_ok=True)
    with connect(db_path) as conn:
        row = conn.execute(
            """SELECT
                   COALESCE(SUM(CASE WHEN status IN ('READY','CORRUPT') THEN size_bytes ELSE 0 END),0) AS managed_bytes,
                   SUM(CASE WHEN status='READY' THEN 1 ELSE 0 END) AS ready_count,
                   SUM(CASE WHEN status='CORRUPT' THEN 1 ELSE 0 END) AS corrupt_count,
                   SUM(CASE WHEN status='EVICTED' THEN 1 ELSE 0 END) AS evicted_count,
                   SUM(CASE WHEN status='READY' AND pinned=1 THEN 1 ELSE 0 END) AS pinned_count,
                   COALESCE(SUM(CASE WHEN status='READY' AND pinned=1 THEN size_bytes ELSE 0 END),0) AS pinned_bytes
                 FROM export_artifacts"""
        ).fetchone()
    disk = shutil.disk_usage(root)
    quota = max(0, int(quota_bytes))
    reserve = max(0, int(reserve_bytes))
    managed = int(row["managed_bytes"] or 0)
    over_quota = bool(quota and managed > quota)
    below_reserve = disk.free < reserve
    return {
        "managed_bytes": managed,
        "ready_count": int(row["ready_count"] or 0),
        "corrupt_count": int(row["corrupt_count"] or 0),
        "evicted_count": int(row["evicted_count"] or 0),
        "pinned_count": int(row["pinned_count"] or 0),
        "pinned_bytes": int(row["pinned_bytes"] or 0),
        "quota_bytes": quota,
        "quota_remaining_bytes": max(0, quota - managed) if quota else None,
        "reserve_bytes": reserve,
        "disk_total_bytes": int(disk.total),
        "disk_used_bytes": int(disk.used),
        "disk_free_bytes": int(disk.free),
        "over_quota": over_quota,
        "below_reserve": below_reserve,
        "pressure": over_quota or below_reserve,
    }


def set_export_artifact_pinned(
    db_path: str | Path,
    artifact_id: str,
    *,
    pinned: bool,
    actor: str,
) -> dict[str, Any]:
    now = utc_now()
    with connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM export_artifacts WHERE artifact_id=?", (artifact_id,)).fetchone()
        if row is None:
            raise KeyError(artifact_id)
        if str(row["status"]) != "READY":
            raise ValueError("READY 산출물만 보호 설정을 변경할 수 있습니다.")
        conn.execute(
            "UPDATE export_artifacts SET pinned=?,pinned_by=?,pinned_at=? WHERE artifact_id=?",
            (1 if pinned else 0, actor if pinned else None, now if pinned else None, artifact_id),
        )
        add_audit_event(
            db_path, finding_id=None,
            event_type="export_artifact_pinned" if pinned else "export_artifact_unpinned",
            summary="내보내기 산출물 보호 설정 변경",
            details={"artifact_id": artifact_id, "pinned": bool(pinned)},
            actor=actor, conn=conn,
        )
        conn.commit()
    return get_export_artifact(db_path, artifact_id) or {}


def evict_export_artifact(
    db_path: str | Path,
    export_dir: str | Path,
    artifact_id: str,
    *,
    actor: str,
    reason: str,
) -> dict[str, Any]:
    now = utc_now()
    with connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM export_artifacts WHERE artifact_id=?", (artifact_id,)).fetchone()
        if row is None:
            raise KeyError(artifact_id)
        artifact = _artifact_row(row)
        if artifact.get("pinned"):
            raise ValueError("보호된 내보내기 산출물은 자동 퇴거할 수 없습니다.")
        if str(artifact.get("status") or "") not in {"READY", "CORRUPT"}:
            conn.rollback()
            return artifact
        path = resolve_export_artifact_path(export_dir, artifact)
        try:
            path.unlink(missing_ok=True)
        except OSError as exc:
            conn.rollback()
            raise RuntimeError(f"내보내기 파일 삭제 실패: {exc}") from exc
        conn.execute(
            """UPDATE export_artifacts
                  SET status='EVICTED',evicted_by=?,evicted_at=?,eviction_reason=?
                WHERE artifact_id=?""",
            (actor, now, str(reason)[:500], artifact_id),
        )
        add_audit_event(
            db_path, finding_id=None, event_type="export_artifact_evicted",
            summary="내보내기 산출물 저장공간 퇴거",
            details={"artifact_id": artifact_id, "size_bytes": int(artifact.get("size_bytes") or 0), "reason": str(reason)[:500]},
            actor=actor, conn=conn,
        )
        conn.commit()
    return get_export_artifact(db_path, artifact_id) or {}


def enforce_export_storage_budget(
    db_path: str | Path,
    export_dir: str | Path,
    *,
    quota_bytes: int = 0,
    reserve_bytes: int = 0,
    required_bytes: int = 0,
    actor: str = "system-storage-governor",
) -> dict[str, Any]:
    quota = max(0, int(quota_bytes))
    reserve = max(0, int(reserve_bytes))
    required = max(0, int(required_bytes))
    evicted = 0
    evicted_bytes = 0
    while True:
        status = export_storage_status(db_path, export_dir, quota_bytes=quota, reserve_bytes=reserve)
        quota_ok = not quota or status["managed_bytes"] + required <= quota
        reserve_ok = status["disk_free_bytes"] >= reserve
        if quota_ok and reserve_ok:
            return status | {"evicted": evicted, "evicted_bytes": evicted_bytes}
        with connect(db_path) as conn:
            row = conn.execute(
                """SELECT * FROM export_artifacts
                     WHERE status IN ('CORRUPT','READY') AND pinned=0
                     ORDER BY CASE status WHEN 'CORRUPT' THEN 0 ELSE 1 END,
                              COALESCE(last_downloaded_at,created_at) ASC,created_at ASC,artifact_id ASC
                     LIMIT 1"""
            ).fetchone()
        if row is None:
            raise RuntimeError("보호되지 않은 산출물이 없어 내보내기 저장공간을 확보할 수 없습니다.")
        artifact = _artifact_row(row)
        evict_export_artifact(
            db_path, export_dir, str(artifact["artifact_id"]), actor=actor,
            reason="quota" if not quota_ok else "disk_reserve",
        )
        evicted += 1
        evicted_bytes += int(artifact.get("size_bytes") or 0)


def _iter_snapshot_rows(
    snapshot_db: str | Path,
    *,
    filters: dict[str, Any],
    page_size: int = 1000,
) -> Iterator[dict[str, Any]]:
    cursor = ""
    secret = "snapshot-export-cursor-key-26"
    while True:
        result = query_findings(
            snapshot_db,
            decision=str(filters.get("decision") or ""),
            status=str(filters.get("status") or ""),
            query=str(filters.get("query") or ""),
            overdue=bool(filters.get("overdue")),
            exception=str(filters.get("exception") or ""),
            record_state=str(filters.get("record_state") or "ALL"),
            scanner_source=str(filters.get("scanner_source") or ""),
            page_size=page_size,
            pagination_mode="cursor",
            cursor=cursor,
            cursor_secret=secret,
            include_count=False,
        )
        for row in result["items"]:
            yield row
        cursor = str(result.get("next_cursor") or "")
        if not cursor:
            break


def create_findings_csv_export(
    db_path: str | Path,
    export_dir: str | Path,
    *,
    filters: dict[str, Any] | None,
    actor: str,
    job_id: str | None = None,
    retention_days: int = 7,
    quota_bytes: int = 0,
    reserve_bytes: int = 0,
    heartbeat: Callable[[int, int, str], None] | None = None,
    cancel_check: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    canonical_filters = _canonical_filters(filters)
    if job_id:
        existing = get_export_artifact_by_job(db_path, job_id)
        if existing:
            verification = verify_export_artifact(export_dir, existing)
            if existing.get("status") == "READY" and verification.get("valid"):
                return existing | {"idempotent_replay": True}
            raise RuntimeError("기존 작업 산출물의 무결성이 유효하지 않습니다.")
    export_root = Path(export_dir)
    export_root.mkdir(parents=True, exist_ok=True)
    snapshot_at = utc_now()
    artifact_token = (str(job_id).replace("-", "").lower() if job_id else uuid.uuid4().hex)
    stored_filename = f"findings_{artifact_token}.csv"
    download_filename = f"vulnflow_findings_{snapshot_at[:10].replace('-', '')}.csv"
    final_path = export_root / stored_filename
    partial_path = export_root / f".{stored_filename}.part"

    snapshot_handle = tempfile.NamedTemporaryFile(prefix="vulnflow_export_snapshot_", suffix=".sqlite3", delete=False)
    snapshot_handle.close()
    snapshot_path = Path(snapshot_handle.name)
    try:
        backup_database(db_path, snapshot_path)
        count_result = query_findings(
            snapshot_path,
            decision=str(canonical_filters.get("decision") or ""),
            status=str(canonical_filters.get("status") or ""),
            query=str(canonical_filters.get("query") or ""),
            overdue=bool(canonical_filters.get("overdue")),
            exception=str(canonical_filters.get("exception") or ""),
            record_state=str(canonical_filters.get("record_state") or "ALL"),
            scanner_source=str(canonical_filters.get("scanner_source") or ""),
            page_size=1,
            pagination_mode="offset",
            include_count=True,
        )
        total = int(count_result.get("count") or 0)
        digest = hashlib.sha256()
        row_count = 0
        with partial_path.open("wb") as raw:
            bom = b"\xef\xbb\xbf"
            raw.write(bom)
            digest.update(bom)
            text = io.TextIOWrapper(raw, encoding="utf-8", newline="", write_through=True)
            writer = csv.DictWriter(text, fieldnames=FIELDS, extrasaction="ignore")
            writer.writeheader()
            text.flush()
            # Include the header bytes in the digest after TextIOWrapper flushed them.
            raw.flush()
            # Recompute at the end to avoid coupling to text buffering internals.
            for row in _iter_snapshot_rows(snapshot_path, filters=canonical_filters):
                if cancel_check and cancel_check():
                    raise RuntimeError("내보내기 작업 취소가 요청되었습니다.")
                writer.writerow({field: _csv_safe(row.get(field)) for field in FIELDS})
                row_count += 1
                if row_count % 500 == 0:
                    text.flush()
                    if int(reserve_bytes) > 0 and shutil.disk_usage(export_root).free < int(reserve_bytes):
                        raise RuntimeError("내보내기 저장소의 최소 여유 공간이 부족합니다.")
                    if heartbeat:
                        heartbeat(row_count, max(total, row_count), f"CSV {row_count:,}행 작성")
            text.flush()
            os.fsync(raw.fileno())
            text.detach()
        os.replace(partial_path, final_path)
        digest = hashlib.sha256()
        size_bytes = 0
        with final_path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                digest.update(chunk)
                size_bytes += len(chunk)
        expires_at = None
        if int(retention_days) > 0:
            expires_at = (
                datetime.now(timezone.utc) + timedelta(days=int(retention_days))
            ).replace(microsecond=0).isoformat()
        enforce_export_storage_budget(
            db_path, export_root, quota_bytes=quota_bytes, reserve_bytes=reserve_bytes,
            required_bytes=size_bytes, actor="system-export-admission",
        )
        artifact = register_export_artifact(
            db_path,
            job_id=job_id,
            export_type="FINDINGS_CSV",
            stored_filename=stored_filename,
            download_filename=download_filename,
            content_type="text/csv; charset=utf-8",
            row_count=row_count,
            size_bytes=size_bytes,
            sha256=digest.hexdigest(),
            filters=canonical_filters,
            snapshot_at=snapshot_at,
            created_by=actor,
            expires_at=expires_at,
            max_storage_bytes=quota_bytes,
        )
        return artifact
    except Exception:
        partial_path.unlink(missing_ok=True)
        final_path.unlink(missing_ok=True)
        raise
    finally:
        snapshot_path.unlink(missing_ok=True)
        for suffix in ("-wal", "-shm"):
            Path(str(snapshot_path) + suffix).unlink(missing_ok=True)


def stream_findings_csv(
    db_path: str | Path,
    *,
    filters: dict[str, Any] | None = None,
    batch_size: int = 500,
) -> Iterable[bytes]:
    """Stream a transactionally consistent read snapshot without loading all rows."""
    canonical_filters = _canonical_filters(filters)
    conn = connect(db_path)
    conn.execute("BEGIN")
    try:
        yield b"\xef\xbb\xbf"
        header = io.StringIO()
        csv.writer(header).writerow(FIELDS)
        yield header.getvalue().encode("utf-8")
        # The live read transaction is intentionally held for the response duration.
        # Async exports use a backup snapshot and are preferred for large datasets.
        where = ["1=1"]
        params: list[Any] = []
        if canonical_filters.get("record_state") not in {"", "ALL"}:
            state = canonical_filters["record_state"]
            if state == "CURRENT":
                where.append("record_state!='ARCHIVED'")
            else:
                where.append("record_state=?")
                params.append(state)
        if canonical_filters.get("status"):
            where.append("status=?")
            params.append(canonical_filters["status"])
        if canonical_filters.get("decision"):
            where.append("decision=?")
            params.append(canonical_filters["decision"])
        if canonical_filters.get("scanner_source"):
            where.append("scanner_source=?")
            params.append(canonical_filters["scanner_source"])
        # Complex FTS/exception/overdue filters use the snapshot export job path.
        unsupported = [key for key in ("query", "exception") if canonical_filters.get(key)]
        if canonical_filters.get("overdue"):
            unsupported.append("overdue")
        if unsupported:
            raise ValueError("동기 스트리밍은 query/exception/overdue 필터를 지원하지 않습니다. 비동기 내보내기를 사용하세요.")
        cursor = conn.execute(
            f"SELECT {','.join(FIELDS)} FROM findings WHERE {' AND '.join(where)} "
            "ORDER BY score DESC,kev DESC,epss DESC,cve_id ASC,finding_id ASC",
            params,
        )
        while True:
            rows = cursor.fetchmany(max(1, min(5000, int(batch_size))))
            if not rows:
                break
            buffer = io.StringIO()
            writer = csv.DictWriter(buffer, fieldnames=FIELDS, extrasaction="ignore")
            for row in rows:
                item = dict(row)
                writer.writerow({field: _csv_safe(item.get(field)) for field in FIELDS})
            yield buffer.getvalue().encode("utf-8")
    finally:
        conn.rollback()
        conn.close()
