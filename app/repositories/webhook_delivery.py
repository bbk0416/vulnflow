from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from app.core.db import utc_now
from app.core.retry import RetryPolicy
from app.core.transactions import write_transaction
from app.repositories.audit import add_audit_event
from app.repositories.execution_receipts import record_execution_receipt
from app.repositories.webhook_queue import _decode_webhook_rows, list_webhook_events


def list_due_webhook_events(
    db_path: str | Path, *, limit: int = 50, lease_seconds: int = 120
) -> list[dict[str, Any]]:
    """Atomically claim due events for one delivery worker.

    SENDING rows whose lease expired are returned to RETRY, allowing recovery after
    a process crash without delivering the same row concurrently in normal operation.
    """
    limit = max(1, min(int(limit), 500))
    now = utc_now()
    lease_cutoff = (
        datetime.now(timezone.utc) - timedelta(seconds=max(1, int(lease_seconds)))
    ).replace(microsecond=0).isoformat()
    claimed: list[sqlite3.Row] = []
    with write_transaction(db_path, operation="list_due_webhook_events") as conn:
        conn.execute(
            """
            UPDATE webhook_events
               SET status='RETRY', next_attempt_at=?, last_error='delivery lease expired'
             WHERE status='SENDING' AND COALESCE(last_attempt_at,'')<>'' AND last_attempt_at<?
            """,
            (now, lease_cutoff),
        )
        rows = conn.execute(
            """
            SELECT * FROM webhook_events
             WHERE status IN ('PENDING','RETRY') AND next_attempt_at<=?
             ORDER BY created_at ASC LIMIT ?
            """,
            (now, limit),
        ).fetchall()
        ids = [str(row["event_id"]) for row in rows]
        if ids:
            conn.executemany(
                "UPDATE webhook_events SET status='SENDING', last_attempt_at=? WHERE event_id=?",
                [(now, event_id) for event_id in ids],
            )
            claimed = conn.execute(
                f"SELECT * FROM webhook_events WHERE event_id IN ({','.join('?' for _ in ids)}) ORDER BY created_at ASC",
                ids,
            ).fetchall()
    return _decode_webhook_rows(claimed)


def record_webhook_delivery(
    db_path: str | Path,
    *,
    event_id: str,
    delivered: bool,
    response_status: int | None,
    error: str,
    max_attempts: int = 5,
    retryable: bool = True,
    retry_after_seconds: float | None = None,
    failure_kind: str = "delivery",
) -> dict[str, Any]:
    now_dt = datetime.now(timezone.utc).replace(microsecond=0)
    now = now_dt.isoformat()
    with write_transaction(db_path, operation="record_webhook_delivery") as conn:
        row = conn.execute(
            "SELECT * FROM webhook_events WHERE event_id=?", (event_id,)
        ).fetchone()
        if row is None:
            raise KeyError(event_id)
        attempts = int(row["attempts"] or 0) + 1
        if delivered:
            status = "DELIVERED"
            delivered_at = now
            next_attempt_at = now
            decision_reason = "delivered"
            retry_delay_seconds = 0
            effective_retryable = False
        else:
            policy = RetryPolicy(
                max_attempts=max_attempts,
                base_delay_seconds=60,
                max_delay_seconds=3600,
                jitter_ratio=0.10,
            )
            decision = policy.decide(
                attempts=attempts,
                retryable=bool(retryable),
                operation_key=event_id,
                retry_after_seconds=retry_after_seconds,
            )
            status = decision.status
            delivered_at = None
            retry_delay_seconds = decision.delay_seconds
            next_attempt_at = (
                now_dt + timedelta(seconds=retry_delay_seconds)
            ).isoformat() if status == "RETRY" else now
            decision_reason = decision.reason
            effective_retryable = decision.retryable
        conn.execute(
            """
            UPDATE webhook_events
               SET status=?, attempts=?, next_attempt_at=?, last_attempt_at=?, delivered_at=?,
                   response_status=?, last_error=?
             WHERE event_id=?
            """,
            (
                status,
                attempts,
                next_attempt_at,
                now,
                delivered_at,
                response_status,
                str(error or "")[:1000],
                event_id,
            ),
        )
        record_execution_receipt(
            conn,
            operation_type="WEBHOOK_DELIVERY",
            resource_id=event_id,
            resource_subtype=str(row["event_type"]),
            attempt_no=attempts,
            outcome=status,
            request_document={
                "endpoint_name": row["endpoint_name"],
                "event_type": row["event_type"],
                "payload": json.loads(row["payload_json"] or "{}"),
            },
            result_document={"response_status": response_status} if delivered else None,
            error=str(error or ""),
            error_class=str(failure_kind),
            actor="system-webhook",
            metadata={
                "response_status": response_status,
                "retryable": effective_retryable,
                "retry_delay_seconds": retry_delay_seconds,
                "retry_reason": decision_reason,
            },
        )
        add_audit_event(
            db_path,
            finding_id=None,
            event_type="webhook_delivered" if delivered else "webhook_delivery_failed",
            summary=("웹훅 전송 성공" if delivered else f"웹훅 전송 실패: {status}"),
            details={
                "event_id": event_id,
                "attempts": attempts,
                "response_status": response_status,
                "retryable": effective_retryable,
                "retry_delay_seconds": retry_delay_seconds,
                "retry_reason": decision_reason,
                "failure_kind": str(failure_kind)[:100],
                "error": str(error or "")[:300],
            },
            actor="system-webhook",
            conn=conn,
        )
    items = list_webhook_events(db_path, limit=2000)
    result = next(item for item in items if item["event_id"] == event_id)
    result["retryable"] = effective_retryable
    result["retry_delay_seconds"] = retry_delay_seconds
    result["retry_reason"] = decision_reason
    return result
