from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any, Iterable, Sequence

from app.core.db import utc_now
from app.core.transactions import read_connection, write_transaction
from app.repositories.audit import add_audit_event
from app.repositories.idempotency import replay_result, request_sha256, store_result

WEBHOOK_STATUSES = {"PENDING", "RETRY", "SENDING", "DELIVERED", "FAILED"}


def _decode_webhook_rows(rows: Sequence[Any]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        try:
            item["payload"] = json.loads(item.pop("payload_json") or "{}")
        except json.JSONDecodeError:
            item["payload"] = {}
        output.append(item)
    return output


def enqueue_webhook_events(
    db_path: str | Path,
    *,
    endpoint_names: Iterable[str],
    event_type: str,
    payload: dict[str, Any],
    actor: str = "system",
    idempotency_key: str | None = None,
    idempotency_request: dict[str, Any] | None = None,
    idempotency_retention_days: int = 30,
) -> list[str]:
    now = utc_now()
    names = [str(name) for name in endpoint_names]
    principal = str(actor or "system")
    request_document = idempotency_request or {
        "endpoint_names": sorted(names),
        "event_type": str(event_type),
        "payload": payload,
    }
    request_digest = request_sha256(request_document) if idempotency_key else ""
    event_ids: list[str] = []
    with write_transaction(db_path, operation="enqueue_webhook_events") as conn:
        if idempotency_key:
            replay = replay_result(
                conn,
                scope="webhook_enqueue",
                idempotency_key=idempotency_key,
                principal=principal,
                request_digest=request_digest,
            )
            if replay is not None:
                saved = replay["response"].get("event_ids", [])
                return [str(item) for item in saved if str(item)]
        for endpoint_name in names:
            event_id = f"WHK-{uuid.uuid4().hex[:20].upper()}"
            conn.execute(
                """
                INSERT INTO webhook_events(
                    event_id,endpoint_name,event_type,payload_json,status,attempts,
                    next_attempt_at,created_at
                ) VALUES(?,?,?,?, 'PENDING', 0, ?, ?)
                """,
                (
                    event_id,
                    endpoint_name,
                    str(event_type),
                    json.dumps(payload, ensure_ascii=False),
                    now,
                    now,
                ),
            )
            event_ids.append(event_id)
        if event_ids:
            add_audit_event(
                db_path,
                finding_id=None,
                event_type="webhook_queued",
                summary=f"웹훅 {len(event_ids)}건 큐 등록: {event_type}",
                details={"event_ids": event_ids, "event_type": event_type},
                actor=principal,
                conn=conn,
            )
        if idempotency_key:
            store_result(
                conn,
                scope="webhook_enqueue",
                idempotency_key=idempotency_key,
                principal=principal,
                request_digest=request_digest,
                resource_type="webhook_batch",
                resource_id=event_ids[0] if event_ids else "none",
                response={"event_ids": event_ids},
                retention_days=idempotency_retention_days,
            )
    return event_ids


def list_webhook_events(
    db_path: str | Path, *, status: str = "", limit: int = 200
) -> list[dict[str, Any]]:
    limit = max(1, min(int(limit), 2000))
    with read_connection(db_path, operation="list_webhook_events") as conn:
        if status:
            rows = conn.execute(
                "SELECT * FROM webhook_events WHERE status=? ORDER BY created_at DESC LIMIT ?",
                (str(status).upper(), limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM webhook_events ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
    return _decode_webhook_rows(rows)


def count_pending_webhooks(db_path: str | Path) -> int:
    with read_connection(db_path, operation="count_pending_webhooks") as conn:
        return int(
            conn.execute(
                "SELECT COUNT(*) FROM webhook_events WHERE status IN ('PENDING','RETRY','SENDING')"
            ).fetchone()[0]
        )


def retry_webhook_event(db_path: str | Path, event_id: str, *, actor: str) -> dict[str, Any]:
    now = utc_now()
    with write_transaction(db_path, operation="retry_webhook_event") as conn:
        existing = conn.execute(
            "SELECT status FROM webhook_events WHERE event_id=?", (event_id,)
        ).fetchone()
        if existing is None:
            raise KeyError(event_id)
        if str(existing["status"]) not in {"FAILED", "RETRY"}:
            raise ValueError("FAILED 또는 RETRY 상태의 웹훅만 수동 재시도할 수 있습니다.")
        conn.execute(
            """
            UPDATE webhook_events
               SET status='PENDING', attempts=0, next_attempt_at=?, last_attempt_at=NULL,
                   delivered_at=NULL, last_error='', response_status=NULL
             WHERE event_id=?
            """,
            (now, event_id),
        )
        add_audit_event(
            db_path,
            finding_id=None,
            event_type="webhook_retry_requested",
            summary="웹훅 수동 재시도 요청",
            details={"event_id": event_id},
            actor=actor,
            conn=conn,
        )
    return next(
        item for item in list_webhook_events(db_path, limit=2000)
        if item["event_id"] == event_id
    )
