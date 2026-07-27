from __future__ import annotations

"""Immutable, redacted execution receipts and explicit dead-letter replay.

Receipts contain only hashes and bounded structural metadata. Job payloads,
webhook payloads, response bodies, raw errors, credentials, and worker IDs are
never persisted in this table.
"""

import hashlib
import json
import sqlite3
import uuid
from pathlib import Path
from typing import Any

from app.core.db import utc_now
from app.core.transactions import read_connection, write_transaction
from app.repositories.audit import add_audit_event
from app.repositories.idempotency import canonical_json

TERMINAL_REPLAY_OUTCOMES = {"FAILED", "CANCELLED"}


def _sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _actor_sha256(actor: str) -> str:
    return hashlib.sha256(str(actor or "system").encode("utf-8")).hexdigest()


def _receipt_row(row: sqlite3.Row | None) -> dict[str, Any]:
    if row is None:
        return {}
    item = dict(row)
    try:
        item["metadata"] = json.loads(item.pop("metadata_json") or "{}")
    except json.JSONDecodeError:
        item["metadata"] = {}
    item["replay"] = None
    return item


def record_execution_receipt(
    conn: sqlite3.Connection,
    *,
    operation_type: str,
    resource_id: str,
    resource_subtype: str,
    attempt_no: int,
    outcome: str,
    request_document: Any,
    result_document: Any | None = None,
    error: str = "",
    error_class: str = "",
    actor: str = "system",
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    operation = str(operation_type or "").strip().upper()
    resource = str(resource_id or "").strip()
    if operation not in {"BACKGROUND_JOB", "WEBHOOK_DELIVERY"}:
        raise ValueError("지원하지 않는 실행 영수증 유형입니다.")
    if not resource:
        raise ValueError("resource_id가 필요합니다.")
    sequence = int(
        conn.execute(
            "SELECT COALESCE(MAX(receipt_sequence),0)+1 FROM execution_receipts WHERE operation_type=? AND resource_id=?",
            (operation, resource),
        ).fetchone()[0]
    )
    receipt_id = f"RCT-{uuid.uuid4().hex[:20].upper()}"
    now = utc_now()
    safe_metadata = {
        str(key)[:80]: value
        for key, value in (metadata or {}).items()
        if key not in {"payload", "result", "error", "secret", "token", "authorization"}
    }
    conn.execute(
        """
        INSERT INTO execution_receipts(
            receipt_id,operation_type,resource_id,resource_subtype,receipt_sequence,
            attempt_no,outcome,request_sha256,result_sha256,error_sha256,error_class,
            actor_sha256,metadata_json,created_at
        ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            receipt_id, operation, resource, str(resource_subtype or "")[:120], sequence,
            max(0, int(attempt_no)), str(outcome or "UNKNOWN").upper(), _sha256(request_document),
            _sha256(result_document) if result_document is not None else "",
            hashlib.sha256(str(error).encode("utf-8")).hexdigest() if error else "",
            str(error_class or "")[:120], _actor_sha256(actor),
            json.dumps(safe_metadata, ensure_ascii=False, separators=(",", ":"), sort_keys=True), now,
        ),
    )
    row = conn.execute("SELECT * FROM execution_receipts WHERE receipt_id=?", (receipt_id,)).fetchone()
    return _receipt_row(row)


def get_execution_receipt(db_path: str | Path, receipt_id: str) -> dict[str, Any] | None:
    with read_connection(db_path, operation="get_execution_receipt") as conn:
        row = conn.execute("SELECT * FROM execution_receipts WHERE receipt_id=?", (receipt_id,)).fetchone()
        if row is None:
            return None
        item = _receipt_row(row)
        replay = conn.execute("SELECT * FROM execution_replays WHERE receipt_id=?", (receipt_id,)).fetchone()
        item["replay"] = dict(replay) if replay else None
        current_status = None
        if item["operation_type"] == "BACKGROUND_JOB":
            current = conn.execute("SELECT status FROM background_jobs WHERE job_id=?", (item["resource_id"],)).fetchone()
            current_status = str(current[0]) if current else None
            item["replayable"] = bool(not replay and item["outcome"] in TERMINAL_REPLAY_OUTCOMES and current_status in TERMINAL_REPLAY_OUTCOMES)
        else:
            current = conn.execute("SELECT status FROM webhook_events WHERE event_id=?", (item["resource_id"],)).fetchone()
            current_status = str(current[0]) if current else None
            item["replayable"] = bool(not replay and item["outcome"] == "FAILED" and current_status == "FAILED")
        item["current_status"] = current_status
        return item


def list_execution_receipts(
    db_path: str | Path, *, operation_type: str = "", outcome: str = "", limit: int = 200
) -> list[dict[str, Any]]:
    clauses: list[str] = []
    values: list[Any] = []
    if operation_type:
        clauses.append("r.operation_type=?")
        values.append(str(operation_type).upper())
    if outcome:
        clauses.append("r.outcome=?")
        values.append(str(outcome).upper())
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    limit = max(1, min(int(limit), 2000))
    with read_connection(db_path, operation="list_execution_receipts") as conn:
        rows = conn.execute(
            f"""SELECT r.*,p.replay_id,p.new_resource_id,p.requested_by,p.reason,p.created_at AS replayed_at,
                       CASE WHEN r.operation_type='BACKGROUND_JOB' THEN bj.status ELSE wh.status END AS current_status
                  FROM execution_receipts r
                  LEFT JOIN execution_replays p ON p.receipt_id=r.receipt_id
                  LEFT JOIN background_jobs bj ON r.operation_type='BACKGROUND_JOB' AND bj.job_id=r.resource_id
                  LEFT JOIN webhook_events wh ON r.operation_type='WEBHOOK_DELIVERY' AND wh.event_id=r.resource_id
                  {where} ORDER BY r.created_at DESC,r.operation_type,r.resource_id,r.receipt_sequence DESC LIMIT ?""",
            values + [limit],
        ).fetchall()
    output: list[dict[str, Any]] = []
    for row in rows:
        raw = dict(row)
        replay = None
        if raw.pop("replay_id", None):
            replay = {
                "new_resource_id": raw.pop("new_resource_id", None),
                "requested_by": raw.pop("requested_by", None),
                "reason": raw.pop("reason", None),
                "created_at": raw.pop("replayed_at", None),
            }
        else:
            for key in ("new_resource_id", "requested_by", "reason", "replayed_at"):
                raw.pop(key, None)
        item = raw
        try:
            item["metadata"] = json.loads(item.pop("metadata_json") or "{}")
        except json.JSONDecodeError:
            item["metadata"] = {}
        item["replay"] = replay
        current_status = item.get("current_status")
        item["replayable"] = bool(
            not replay and (
                item["operation_type"] == "BACKGROUND_JOB"
                and item["outcome"] in TERMINAL_REPLAY_OUTCOMES
                and current_status in TERMINAL_REPLAY_OUTCOMES
                or item["operation_type"] == "WEBHOOK_DELIVERY"
                and item["outcome"] == "FAILED"
                and current_status == "FAILED"
            )
        )
        output.append(item)
    return output


def count_execution_receipts(db_path: str | Path) -> dict[str, int]:
    with read_connection(db_path, operation="count_execution_receipts") as conn:
        total = int(conn.execute("SELECT COUNT(*) FROM execution_receipts").fetchone()[0])
        archived = int(conn.execute("SELECT COALESCE(SUM(receipt_count),0) FROM execution_receipt_archives").fetchone()[0])
        archive_batches = int(conn.execute("SELECT COUNT(*) FROM execution_receipt_archives").fetchone()[0])
        dead = int(
            conn.execute(
                """SELECT COUNT(*) FROM execution_receipts r
                     LEFT JOIN execution_replays p ON p.receipt_id=r.receipt_id
                     LEFT JOIN background_jobs bj ON r.operation_type='BACKGROUND_JOB' AND bj.job_id=r.resource_id
                     LEFT JOIN webhook_events wh ON r.operation_type='WEBHOOK_DELIVERY' AND wh.event_id=r.resource_id
                    WHERE p.receipt_id IS NULL AND (
                          (r.operation_type='BACKGROUND_JOB' AND r.outcome IN ('FAILED','CANCELLED') AND bj.status IN ('FAILED','CANCELLED'))
                       OR (r.operation_type='WEBHOOK_DELIVERY' AND r.outcome='FAILED' AND wh.status='FAILED')
                    )"""
            ).fetchone()[0]
        )
    return {
        "total": total,
        "dead_letters": dead,
        "archived": archived,
        "archive_batches": archive_batches,
    }


def replay_execution_receipt(
    db_path: str | Path, receipt_id: str, *, actor: str, reason: str
) -> dict[str, Any]:
    reason = str(reason or "").strip()
    if len(reason) < 3 or len(reason) > 1500:
        raise ValueError("재처리 사유는 3~1500자여야 합니다.")
    now = utc_now()
    with write_transaction(db_path, operation="replay_execution_receipt") as conn:
        receipt = conn.execute("SELECT * FROM execution_receipts WHERE receipt_id=?", (receipt_id,)).fetchone()
        if receipt is None:
            raise KeyError(receipt_id)
        if str(receipt["outcome"]) not in TERMINAL_REPLAY_OUTCOMES:
            raise ValueError("최종 실패 또는 취소 영수증만 재처리할 수 있습니다.")
        if conn.execute("SELECT 1 FROM execution_replays WHERE receipt_id=?", (receipt_id,)).fetchone():
            raise ValueError("이미 재처리된 실행 영수증입니다.")
        operation = str(receipt["operation_type"])
        source_id = str(receipt["resource_id"])
        if operation == "BACKGROUND_JOB":
            source = conn.execute("SELECT * FROM background_jobs WHERE job_id=?", (source_id,)).fetchone()
            if source is None or str(source["status"]) not in {"FAILED", "CANCELLED"}:
                raise ValueError("원본 background job이 최종 실패 상태가 아닙니다.")
            new_id = f"JOB-{uuid.uuid4().hex[:20].upper()}"
            conn.execute(
                """INSERT INTO background_jobs(
                       job_id,job_type,status,payload_json,requested_by,priority,max_attempts,
                       next_attempt_at,created_at,dedupe_key,progress_message
                   ) VALUES(?,?, 'PENDING', ?,?,?,?,?,?,?,?)""",
                (
                    new_id, source["job_type"], source["payload_json"], str(actor or "admin"),
                    int(source["priority"] or 0), max(1, int(source["max_attempts"] or 1)), now, now,
                    None, f"영수증 {receipt_id} 재처리 대기",
                ),
            )
            new_type = "background_job"
        elif operation == "WEBHOOK_DELIVERY":
            source = conn.execute("SELECT * FROM webhook_events WHERE event_id=?", (source_id,)).fetchone()
            if source is None or str(source["status"]) != "FAILED":
                raise ValueError("원본 webhook event가 최종 실패 상태가 아닙니다.")
            new_id = f"WHK-{uuid.uuid4().hex[:20].upper()}"
            conn.execute(
                """INSERT INTO webhook_events(
                       event_id,endpoint_name,event_type,payload_json,status,attempts,next_attempt_at,created_at
                   ) VALUES(?,?,?,?, 'PENDING',0,?,?)""",
                (new_id, source["endpoint_name"], source["event_type"], source["payload_json"], now, now),
            )
            new_type = "webhook_event"
        else:
            raise ValueError("지원하지 않는 실행 영수증 유형입니다.")
        replay_id = f"RPL-{uuid.uuid4().hex[:20].upper()}"
        conn.execute(
            """INSERT INTO execution_replays(
                   replay_id,receipt_id,source_resource_id,new_resource_type,new_resource_id,
                   requested_by,reason,created_at
               ) VALUES(?,?,?,?,?,?,?,?)""",
            (replay_id, receipt_id, source_id, new_type, new_id, str(actor or "admin"), reason, now),
        )
        add_audit_event(
            db_path, finding_id=None, event_type="execution_receipt_replayed",
            summary=f"실행 영수증 재처리: {operation}",
            details={"receipt_id": receipt_id, "source_resource_id": source_id, "new_resource_id": new_id},
            actor=str(actor or "admin"), conn=conn,
        )
    return {"replay_id": replay_id, "receipt_id": receipt_id, "source_resource_id": source_id,
            "new_resource_type": new_type, "new_resource_id": new_id, "created_at": now}
