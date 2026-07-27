from __future__ import annotations

"""Worker claim, lease, progress and execution-result persistence."""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from app.core.db import ConcurrencyError, utc_now
from app.core.retry import RetryPolicy
from app.core.transactions import write_transaction
from app.repositories.audit import add_audit_event
from app.repositories.execution_receipts import record_execution_receipt
from app.repositories.job_records import _job_row, get_background_job

def claim_background_job(
    db_path: str | Path,
    *,
    worker_id: str,
    lease_seconds: int = 120,
    allowed_types: Iterable[str] | None = None,
) -> dict[str, Any] | None:
    from datetime import timedelta

    now_dt = datetime.now(timezone.utc).replace(microsecond=0)
    now = now_dt.isoformat()
    lease_expiry = (now_dt + timedelta(seconds=max(5, int(lease_seconds)))).isoformat()
    allowed = [str(item).upper() for item in (allowed_types or []) if str(item).strip()]
    with write_transaction(db_path, operation="claim_background_job") as conn:
        conn.execute(
            """
            UPDATE background_jobs
               SET status=CASE
                       WHEN cancel_requested=1 THEN 'CANCELLED'
                       WHEN attempts>=max_attempts THEN 'FAILED'
                       ELSE 'RETRY'
                   END,
                   lease_owner=NULL, lease_expires_at=NULL,
                   next_attempt_at=?,
                   completed_at=CASE
                       WHEN cancel_requested=1 OR attempts>=max_attempts THEN ?
                       ELSE completed_at
                   END,
                   last_error=CASE
                       WHEN cancel_requested=1 THEN 'cancelled after lease expiry'
                       WHEN attempts>=max_attempts THEN 'worker lease expired; maximum attempts reached'
                       ELSE 'worker lease expired'
                   END
             WHERE status='RUNNING' AND COALESCE(lease_expires_at,'')<>'' AND lease_expires_at<?
            """,
            (now, now, now),
        )
        conn.execute(
            """
            UPDATE background_jobs
               SET status='CANCELLED',completed_at=?,last_error='cancelled before execution'
             WHERE status IN ('PENDING','RETRY') AND cancel_requested=1
            """,
            (now,),
        )
        type_sql = ""
        params: list[Any] = [now]
        if allowed:
            type_sql = f" AND job_type IN ({','.join('?' for _ in allowed)})"
            params.extend(allowed)
        row = conn.execute(
            f"""
            SELECT * FROM background_jobs
             WHERE status IN ('PENDING','RETRY') AND cancel_requested=0
                   AND attempts<max_attempts AND next_attempt_at<=?
                   {type_sql}
             ORDER BY priority DESC, created_at ASC LIMIT 1
            """,
            params,
        ).fetchone()
        if row is None:
            return None
        job_id = str(row["job_id"])
        cursor = conn.execute(
            """
            UPDATE background_jobs
               SET status='RUNNING', attempts=attempts+1, lease_owner=?, lease_expires_at=?,
                   started_at=COALESCE(started_at,?), progress_message='작업 시작'
             WHERE job_id=? AND status IN ('PENDING','RETRY') AND cancel_requested=0
            """,
            (str(worker_id), lease_expiry, now, job_id),
        )
        if cursor.rowcount != 1:
            conn.rollback()
            return None
        claimed = conn.execute("SELECT * FROM background_jobs WHERE job_id=?", (job_id,)).fetchone()
    return _job_row(claimed)

def heartbeat_background_job(
    db_path: str | Path,
    *,
    job_id: str,
    worker_id: str,
    lease_seconds: int = 120,
    progress_current: int | None = None,
    progress_total: int | None = None,
    progress_message: str | None = None,
) -> dict[str, Any]:
    from datetime import timedelta

    lease_expiry = (
        datetime.now(timezone.utc).replace(microsecond=0) + timedelta(seconds=max(5, int(lease_seconds)))
    ).isoformat()
    assignments = ["lease_expires_at=?"]
    values: list[Any] = [lease_expiry]
    if progress_current is not None:
        assignments.append("progress_current=?")
        values.append(max(0, int(progress_current)))
    if progress_total is not None:
        assignments.append("progress_total=?")
        values.append(max(0, int(progress_total)))
    if progress_message is not None:
        assignments.append("progress_message=?")
        values.append(str(progress_message)[:500])
    values.extend([job_id, str(worker_id)])
    with write_transaction(db_path, operation="heartbeat_background_job") as conn:
        cursor = conn.execute(
            f"UPDATE background_jobs SET {', '.join(assignments)} WHERE job_id=? AND status='RUNNING' AND lease_owner=?",
            values,
        )
    if cursor.rowcount != 1:
        raise ConcurrencyError("작업 임대가 만료되었거나 다른 워커가 소유하고 있습니다.")
    return get_background_job(db_path, job_id) or {}

def complete_background_job(
    db_path: str | Path,
    *,
    job_id: str,
    worker_id: str,
    result: dict[str, Any] | None = None,
    progress_message: str = "작업 완료",
) -> dict[str, Any]:
    now = utc_now()
    result_json = json.dumps(result or {}, ensure_ascii=False, separators=(",", ":"))
    with write_transaction(db_path, operation="complete_background_job") as conn:
        row = conn.execute("SELECT * FROM background_jobs WHERE job_id=?", (job_id,)).fetchone()
        if row is None:
            raise KeyError(job_id)
        if str(row["status"]) != "RUNNING" or str(row["lease_owner"] or "") != str(worker_id):
            raise ConcurrencyError("작업 임대가 만료되었거나 다른 워커가 소유하고 있습니다.")
        status = "CANCELLED" if int(row["cancel_requested"] or 0) else "SUCCEEDED"
        conn.execute(
            """
            UPDATE background_jobs
               SET status=?,result_json=?,completed_at=?,lease_owner=NULL,lease_expires_at=NULL,
                   progress_current=CASE WHEN progress_total>0 THEN progress_total ELSE progress_current END,
                   progress_message=?,last_error=''
             WHERE job_id=?
            """,
            (status, result_json, now, "취소 요청 반영" if status == "CANCELLED" else str(progress_message)[:500], job_id),
        )
        record_execution_receipt(
            conn, operation_type="BACKGROUND_JOB", resource_id=job_id,
            resource_subtype=str(row["job_type"]), attempt_no=int(row["attempts"] or 0), outcome=status,
            request_document={"job_type": row["job_type"], "payload": json.loads(row["payload_json"] or "{}")},
            result_document=result or {}, actor=str(worker_id),
            metadata={"max_attempts": int(row["max_attempts"] or 0)},
        )
        add_audit_event(
            db_path, finding_id=None,
            event_type="background_job_cancelled" if status == "CANCELLED" else "background_job_succeeded",
            summary=f"백그라운드 작업 {status}: {row['job_type']}",
            details={"job_id": job_id, "job_type": row["job_type"]}, actor=str(worker_id), conn=conn,
        )
    return get_background_job(db_path, job_id) or {}

def fail_background_job(
    db_path: str | Path,
    *,
    job_id: str,
    worker_id: str,
    error: str,
    retryable: bool = True,
    retry_after_seconds: float | None = None,
    failure_kind: str = "runtime",
) -> dict[str, Any]:
    from datetime import timedelta

    now_dt = datetime.now(timezone.utc).replace(microsecond=0)
    now = now_dt.isoformat()
    with write_transaction(db_path, operation="fail_background_job") as conn:
        row = conn.execute("SELECT * FROM background_jobs WHERE job_id=?", (job_id,)).fetchone()
        if row is None:
            raise KeyError(job_id)
        if str(row["status"]) != "RUNNING" or str(row["lease_owner"] or "") != str(worker_id):
            raise ConcurrencyError("작업 임대가 만료되었거나 다른 워커가 소유하고 있습니다.")
        attempts = int(row["attempts"] or 0)
        max_attempts = max(1, int(row["max_attempts"] or 1))
        policy = RetryPolicy(
            max_attempts=max_attempts,
            base_delay_seconds=15,
            max_delay_seconds=3600,
            jitter_ratio=0.10,
        )
        decision = policy.decide(
            attempts=attempts,
            retryable=bool(retryable),
            operation_key=job_id,
            retry_after_seconds=retry_after_seconds,
            cancelled=bool(row["cancel_requested"] or 0),
        )
        status = decision.status
        next_attempt_at = (now_dt + timedelta(seconds=decision.delay_seconds)).isoformat() if status == "RETRY" else now
        completed_at = None if status == "RETRY" else now
        conn.execute(
            """
            UPDATE background_jobs
               SET status=?,next_attempt_at=?,completed_at=?,lease_owner=NULL,lease_expires_at=NULL,
                   last_error=?,progress_message=?
             WHERE job_id=?
            """,
            (status, next_attempt_at, completed_at, str(error)[:2000], f"작업 실패: {status}", job_id),
        )
        record_execution_receipt(
            conn, operation_type="BACKGROUND_JOB", resource_id=job_id,
            resource_subtype=str(row["job_type"]), attempt_no=attempts, outcome=status,
            request_document={"job_type": row["job_type"], "payload": json.loads(row["payload_json"] or "{}")},
            error=str(error), error_class=str(failure_kind), actor=str(worker_id),
            metadata={"max_attempts": max_attempts, "retryable": decision.retryable,
                      "retry_delay_seconds": decision.delay_seconds, "retry_reason": decision.reason},
        )
        add_audit_event(
            db_path, finding_id=None, event_type="background_job_failed",
            summary=f"백그라운드 작업 실패: {row['job_type']} ({status})",
            details={
                "job_id": job_id, "attempts": attempts, "max_attempts": max_attempts,
                "retryable": decision.retryable, "retry_delay_seconds": decision.delay_seconds,
                "retry_reason": decision.reason, "failure_kind": str(failure_kind)[:100],
                "error": str(error)[:500],
            },
            actor=str(worker_id), conn=conn,
        )
    result = get_background_job(db_path, job_id) or {}
    result["retryable"] = decision.retryable
    result["retry_delay_seconds"] = decision.delay_seconds
    result["retry_reason"] = decision.reason
    return result
