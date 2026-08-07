from __future__ import annotations

"""Background-job registration, queries, cancellation and retention."""

import json
import sqlite3
import uuid
from pathlib import Path
from typing import Any

from app.core.db import utc_now
from app.core.transactions import read_connection, write_transaction
from app.repositories.audit import add_audit_event
from app.repositories.idempotency import replay_result, request_sha256, store_result
from app.repositories.execution_receipts import record_execution_receipt

JOB_TYPES = {"CSV_IMPORT", "INTEL_REFRESH", "RESCORE_ALL", "MAINTENANCE", "WEBHOOK_DELIVERY", "RECOVERY_BACKUP", "EVIDENCE_SCAN", "OSV_SCAN", "FINDINGS_EXPORT", "DATABASE_MAINTENANCE", "COLLABORATION_DELIVERY"}

def create_background_job(
    db_path: str | Path,
    *,
    job_type: str,
    payload: dict[str, Any] | None = None,
    requested_by: str,
    priority: int = 0,
    max_attempts: int = 3,
    dedupe_key: str | None = None,
    idempotency_key: str | None = None,
    idempotency_request: dict[str, Any] | None = None,
    idempotency_retention_days: int = 30,
) -> dict[str, Any]:
    job_type = str(job_type or "").strip().upper()
    if job_type not in JOB_TYPES:
        raise ValueError(f"지원하지 않는 작업 유형입니다: {job_type}")
    actor = str(requested_by or "system")
    normalized_payload = payload or {}
    request_document = idempotency_request or {
        "job_type": job_type,
        "payload": normalized_payload,
        "priority": int(priority),
        "max_attempts": max(1, int(max_attempts)),
        "dedupe_key": str(dedupe_key) if dedupe_key else None,
    }
    request_digest = request_sha256(request_document) if idempotency_key else ""
    now = utc_now()
    job_id = f"JOB-{uuid.uuid4().hex[:20].upper()}"
    payload_json = json.dumps(normalized_payload, ensure_ascii=False, separators=(",", ":"))
    with write_transaction(db_path, operation="create_background_job") as conn:
        if idempotency_key:
            replay = replay_result(
                conn, scope="background_job", idempotency_key=idempotency_key,
                principal=actor, request_digest=request_digest,
            )
            if replay is not None:
                current = conn.execute(
                    "SELECT * FROM background_jobs WHERE job_id=?", (replay["resource_id"],)
                ).fetchone()
                result = _job_row(current) if current is not None else dict(replay["response"])
                result["idempotent_replay"] = True
                return result
        selected_existing = False
        row = None
        if dedupe_key:
            row = conn.execute(
                """
                SELECT * FROM background_jobs
                 WHERE dedupe_key=? AND status IN ('PENDING','RETRY','RUNNING')
                 ORDER BY created_at DESC LIMIT 1
                """,
                (str(dedupe_key),),
            ).fetchone()
            selected_existing = row is not None
        if row is None:
            conn.execute(
                """
                INSERT INTO background_jobs(
                    job_id,job_type,status,payload_json,requested_by,priority,max_attempts,
                    next_attempt_at,created_at,dedupe_key
                ) VALUES(?,?, 'PENDING', ?,?,?,?,?,?,?)
                """,
                (
                    job_id, job_type, payload_json, actor, int(priority),
                    max(1, int(max_attempts)), now, now, str(dedupe_key) if dedupe_key else None,
                ),
            )
            add_audit_event(
                db_path,
                finding_id=None,
                event_type="background_job_created",
                summary=f"백그라운드 작업 등록: {job_type}",
                details={"job_id": job_id, "job_type": job_type, "dedupe_key": dedupe_key},
                actor=actor,
                conn=conn,
            )
            row = conn.execute("SELECT * FROM background_jobs WHERE job_id=?", (job_id,)).fetchone()
        result = _job_row(row)
        if idempotency_key:
            result["idempotent_replay"] = False
            result["deduplicated"] = selected_existing
            store_result(
                conn, scope="background_job", idempotency_key=idempotency_key, principal=actor,
                request_digest=request_digest, resource_type="background_job",
                resource_id=str(result.get("job_id") or job_id), response=result,
                retention_days=idempotency_retention_days,
            )
    return result

def _job_row(row: sqlite3.Row | None) -> dict[str, Any]:
    if row is None:
        return {}
    item = dict(row)
    for source, target in (("payload_json", "payload"), ("result_json", "result")):
        raw = item.pop(source, None)
        if not raw:
            item[target] = {}
            continue
        try:
            item[target] = json.loads(raw)
        except json.JSONDecodeError:
            item[target] = {}
    item["cancel_requested"] = bool(item.get("cancel_requested"))
    return item

def get_background_job(db_path: str | Path, job_id: str) -> dict[str, Any] | None:
    with read_connection(db_path, operation="get_background_job") as conn:
        row = conn.execute("SELECT * FROM background_jobs WHERE job_id=?", (job_id,)).fetchone()
    return _job_row(row) if row else None

def list_background_jobs(
    db_path: str | Path, *, status: str = "", job_type: str = "", limit: int = 200
) -> list[dict[str, Any]]:
    limit = max(1, min(int(limit), 2000))
    clauses: list[str] = []
    values: list[Any] = []
    if status:
        clauses.append("status=?")
        values.append(str(status).upper())
    if job_type:
        clauses.append("job_type=?")
        values.append(str(job_type).upper())
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    with read_connection(db_path, operation="list_background_jobs") as conn:
        rows = conn.execute(
            f"SELECT * FROM background_jobs{where} ORDER BY created_at DESC LIMIT ?",
            values + [limit],
        ).fetchall()
    return [_job_row(row) for row in rows]

def count_active_background_jobs(db_path: str | Path) -> int:
    with read_connection(db_path, operation="count_active_background_jobs") as conn:
        return int(
            conn.execute(
                "SELECT COUNT(*) FROM background_jobs WHERE status IN ('PENDING','RETRY','RUNNING')"
            ).fetchone()[0]
        )

def request_background_job_cancel(db_path: str | Path, job_id: str, *, actor: str) -> dict[str, Any]:
    now = utc_now()
    with write_transaction(db_path, operation="request_background_job_cancel") as conn:
        row = conn.execute("SELECT * FROM background_jobs WHERE job_id=?", (job_id,)).fetchone()
        if row is None:
            raise KeyError(job_id)
        if str(row["status"]) in {"SUCCEEDED", "FAILED", "CANCELLED"}:
            raise ValueError("완료된 작업은 취소할 수 없습니다.")
        status = "CANCELLED" if str(row["status"]) in {"PENDING", "RETRY"} else str(row["status"])
        conn.execute(
            """
            UPDATE background_jobs SET cancel_requested=1,status=?,
                   completed_at=CASE WHEN ?='CANCELLED' THEN ? ELSE completed_at END,
                   progress_message='취소 요청됨'
             WHERE job_id=?
            """,
            (status, status, now, job_id),
        )
        if status == "CANCELLED":
            record_execution_receipt(
                conn, operation_type="BACKGROUND_JOB", resource_id=job_id,
                resource_subtype=str(row["job_type"]), attempt_no=int(row["attempts"] or 0), outcome="CANCELLED",
                request_document={"job_type": row["job_type"], "payload": json.loads(row["payload_json"] or "{}")},
                actor=str(actor), metadata={"cancelled_before_execution": True},
            )
        add_audit_event(
            db_path, finding_id=None, event_type="background_job_cancel_requested",
            summary=f"백그라운드 작업 취소 요청: {row['job_type']}",
            details={"job_id": job_id}, actor=actor, conn=conn,
        )
    return get_background_job(db_path, job_id) or {}

def retry_background_job(db_path: str | Path, job_id: str, *, actor: str) -> dict[str, Any]:
    now = utc_now()
    with write_transaction(db_path, operation="retry_background_job") as conn:
        row = conn.execute("SELECT * FROM background_jobs WHERE job_id=?", (job_id,)).fetchone()
        if row is None:
            raise KeyError(job_id)
        if str(row["status"]) not in {"FAILED", "CANCELLED"}:
            raise ValueError("FAILED 또는 CANCELLED 작업만 재시도할 수 있습니다.")
        conn.execute(
            """
            UPDATE background_jobs
               SET status='PENDING',attempts=0,cancel_requested=0,lease_owner=NULL,lease_expires_at=NULL,
                   next_attempt_at=?,started_at=NULL,completed_at=NULL,last_error='',result_json=NULL,
                   progress_current=0,progress_message='재시도 대기'
             WHERE job_id=?
            """,
            (now, job_id),
        )
        add_audit_event(
            db_path, finding_id=None, event_type="background_job_retry_requested",
            summary=f"백그라운드 작업 재시도: {row['job_type']}",
            details={"job_id": job_id}, actor=actor, conn=conn,
        )
    return get_background_job(db_path, job_id) or {}

def purge_background_jobs(db_path: str | Path, *, completed_before: str) -> int:
    with write_transaction(db_path, operation="purge_background_jobs") as conn:
        cursor = conn.execute(
            """
            DELETE FROM background_jobs
             WHERE COALESCE(completed_at,created_at)<?
               AND (
                    status='SUCCEEDED'
                 OR (
                      status IN ('FAILED','CANCELLED')
                      AND NOT EXISTS (
                          SELECT 1
                            FROM execution_receipts r
                            LEFT JOIN execution_replays p ON p.receipt_id=r.receipt_id
                           WHERE r.operation_type='BACKGROUND_JOB'
                             AND r.resource_id=background_jobs.job_id
                             AND r.outcome IN ('FAILED','CANCELLED')
                             AND p.receipt_id IS NULL
                      )
                 )
               )
            """,
            (completed_before,),
        )
    return int(cursor.rowcount or 0)
