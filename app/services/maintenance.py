from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any
import uuid

from app.core.db import connect, utc_now
from app.repositories.audit import add_audit_event, prune_audit_prefix
from app.repositories.execution_receipt_retention import archive_execution_receipts


def _cutoff(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=max(0, int(days)))).replace(microsecond=0).isoformat()


def run_maintenance(
    db_path: str | Path,
    *,
    actor: str = "system-maintenance",
    audit_retention_days: int = 0,
    import_retention_days: int = 0,
    auto_archive_stale_days: int = 0,
    webhook_retention_days: int = 0,
    execution_receipt_retention_days: int = 0,
    audit_signing_key: str = "",
    audit_signing_key_id: str | None = None,
) -> dict[str, Any]:
    run_id = f"MNT-{uuid.uuid4().hex[:16].upper()}"
    started_at = utc_now()
    summary: dict[str, Any] = {
        "run_id": run_id,
        "expired_reopened": 0,
        "approval_cancelled": 0,
        "stale_archived": 0,
        "audit_deleted": 0,
        "imports_deleted": 0,
        "webhooks_deleted": 0,
        "idempotency_deleted": 0,
        "execution_receipts_archived": 0,
        "execution_receipt_archive_id": None,
    }
    with connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        expired = conn.execute(
            """
            SELECT finding_id, exception_expiry, risk_acceptance_reason, risk_acceptance_approver
              FROM findings
             WHERE status='RISK_ACCEPTED' AND exception_expiry<>'' AND date(exception_expiry) < date(?)
            """,
            (date.today().isoformat(),),
        ).fetchall()
        for row in expired:
            conn.execute(
                """
                UPDATE findings
                   SET status='OPEN', exception_expiry='', risk_acceptance_reason='',
                       risk_acceptance_approver='', resolved_at='',
                       row_version=COALESCE(row_version,0)+1, updated_at=CURRENT_TIMESTAMP
                 WHERE finding_id=?
                """,
                (row["finding_id"],),
            )
            add_audit_event(
                db_path,
                finding_id=row["finding_id"],
                event_type="risk_acceptance_expired",
                summary="위험수용 만료로 OPEN 자동 재개방",
                details={
                    "expired_on": row["exception_expiry"],
                    "previous_reason": row["risk_acceptance_reason"],
                    "previous_approver": row["risk_acceptance_approver"],
                    "maintenance_run_id": run_id,
                },
                actor=actor,
                conn=conn,
            )
        summary["expired_reopened"] = len(expired)

        obsolete_requests = conn.execute(
            """
            SELECT r.request_id, r.finding_id, r.finding_row_version, r.exception_expiry,
                   f.row_version AS current_row_version, f.record_state
              FROM risk_approval_requests r
              JOIN findings f ON f.finding_id=r.finding_id
             WHERE r.status='PENDING'
               AND (r.finding_row_version<>f.row_version OR f.record_state='ARCHIVED'
                    OR date(r.exception_expiry) < date(?))
            """
            , (date.today().isoformat(),)
        ).fetchall()
        for row in obsolete_requests:
            if str(row["exception_expiry"] or "") < date.today().isoformat():
                reason = "요청 만료"
            elif row["record_state"] == "ARCHIVED":
                reason = "항목 보관"
            else:
                reason = "요청 이후 항목 변경"
            conn.execute(
                """UPDATE risk_approval_requests SET status='CANCELLED', decided_by=?,
                   decision_note=?, decided_at=? WHERE request_id=?""",
                (actor, reason, started_at, row["request_id"]),
            )
            add_audit_event(
                db_path, finding_id=row["finding_id"], event_type="risk_acceptance_cancelled",
                summary="오래된 위험수용 요청 자동 취소",
                details={"request_id": row["request_id"], "reason": reason, "maintenance_run_id": run_id},
                actor=actor, conn=conn,
            )
        summary["approval_cancelled"] = len(obsolete_requests)

        if int(auto_archive_stale_days) > 0:
            cutoff = _cutoff(int(auto_archive_stale_days))
            stale = conn.execute(
                "SELECT finding_id FROM findings WHERE record_state='STALE' AND stale_since<>'' AND stale_since < ?",
                (cutoff,),
            ).fetchall()
            for row in stale:
                conn.execute(
                    """
                    UPDATE findings SET record_state='ARCHIVED', archived_at=?,
                        row_version=COALESCE(row_version,0)+1, updated_at=CURRENT_TIMESTAMP
                    WHERE finding_id=?
                    """,
                    (started_at, row["finding_id"]),
                )
                add_audit_event(
                    db_path,
                    finding_id=row["finding_id"],
                    event_type="auto_archive_stale",
                    summary="보존정책에 따라 STALE 항목 자동 보관",
                    details={"stale_days": int(auto_archive_stale_days), "maintenance_run_id": run_id},
                    actor=actor,
                    conn=conn,
                )
            summary["stale_archived"] = len(stale)

        if int(audit_retention_days) > 0:
            # Audit entries form a hash chain. Retention therefore prunes only a
            # contiguous prefix and advances the signed/verifiable anchor instead
            # of deleting arbitrary rows that would leave holes in the chain.
            conn.commit()
            prune_result = prune_audit_prefix(
                db_path, cutoff_at=_cutoff(int(audit_retention_days)), actor=actor,
                signing_key=audit_signing_key, signing_key_id=audit_signing_key_id,
            )
            summary["audit_deleted"] = int(prune_result.get("deleted_count") or 0)
            conn.execute("BEGIN IMMEDIATE")
        if int(import_retention_days) > 0:
            cutoff = _cutoff(int(import_retention_days))
            cursor = conn.execute("DELETE FROM import_batches WHERE created_at < ?", (cutoff,))
            summary["imports_deleted"] = max(0, cursor.rowcount)
        if int(webhook_retention_days) > 0:
            cutoff = _cutoff(int(webhook_retention_days))
            cursor = conn.execute(
                """DELETE FROM webhook_events
                   WHERE COALESCE(delivered_at,last_attempt_at,created_at) < ?
                     AND (
                          status='DELIVERED'
                       OR (
                            status='FAILED'
                            AND NOT EXISTS (
                                SELECT 1
                                  FROM execution_receipts r
                                  LEFT JOIN execution_replays p ON p.receipt_id=r.receipt_id
                                 WHERE r.operation_type='WEBHOOK_DELIVERY'
                                   AND r.resource_id=webhook_events.event_id
                                   AND r.outcome='FAILED'
                                   AND p.receipt_id IS NULL
                            )
                       )
                     )""",
                (cutoff,),
            )
            summary["webhooks_deleted"] = max(0, cursor.rowcount)

        cursor = conn.execute("DELETE FROM idempotency_records WHERE expires_at<=?", (utc_now(),))
        summary["idempotency_deleted"] = max(0, cursor.rowcount)

        if int(execution_receipt_retention_days) > 0:
            # Receipt archiving owns a short EXCLUSIVE transaction because the
            # immutable delete trigger is temporarily replaced in that same
            # transaction. Finish this maintenance transaction first.
            conn.commit()
            archive = archive_execution_receipts(
                db_path,
                cutoff_at=_cutoff(int(execution_receipt_retention_days)),
                actor=actor,
            )
            summary["execution_receipts_archived"] = int(archive.get("receipt_count") or 0)
            summary["execution_receipt_archive_id"] = archive.get("archive_id")
            conn.execute("BEGIN IMMEDIATE")

        completed_at = utc_now()
        conn.execute(
            """
            INSERT INTO maintenance_runs(
                run_id, actor, started_at, completed_at, status, details_json
            ) VALUES(?,?,?,?,?,?)
            """,
            (run_id, actor, started_at, completed_at, "SUCCESS", __import__("json").dumps(summary, ensure_ascii=False)),
        )
        add_audit_event(
            db_path,
            finding_id=None,
            event_type="maintenance_run",
            summary=(
                f"유지관리 완료: 만료 재개방 {summary['expired_reopened']}건, "
                f"오래된 승인 취소 {summary['approval_cancelled']}건, 자동 보관 {summary['stale_archived']}건"
            ),
            details=summary,
            actor=actor,
            conn=conn,
        )
        conn.commit()
    return summary


def record_maintenance_failure(db_path: str | Path, *, actor: str, error: Exception) -> dict[str, Any]:
    import json
    run_id = f"MNT-{uuid.uuid4().hex[:16].upper()}"
    now = utc_now()
    details = {"run_id": run_id, "error_type": type(error).__name__, "error": str(error)[:1000]}
    with connect(db_path) as conn:
        conn.execute(
            """INSERT INTO maintenance_runs(run_id,actor,started_at,completed_at,status,details_json)
               VALUES(?,?,?,?,?,?)""",
            (run_id, actor, now, now, "FAILED", json.dumps(details, ensure_ascii=False)),
        )
        add_audit_event(
            db_path,
            finding_id=None,
            event_type="maintenance_failed",
            summary="예약 유지관리 실패",
            details=details,
            actor=actor,
            conn=conn,
        )
        conn.commit()
    return details
