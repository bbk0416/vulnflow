from __future__ import annotations

"""Bounded retention for immutable, redacted execution receipts."""

import hashlib
import json
import uuid
from collections import Counter
from pathlib import Path
from typing import Any

from app.core.db import connect, utc_now
from app.core.transactions import read_connection
from app.repositories.audit import add_audit_event
from app.repositories.idempotency import canonical_json

_RECEIPT_DELETE_TRIGGER = """
CREATE TRIGGER execution_receipts_no_delete BEFORE DELETE ON execution_receipts
BEGIN SELECT RAISE(ABORT, 'execution receipts cannot be deleted'); END
"""


def _actor_sha256(actor: str) -> str:
    return hashlib.sha256(str(actor or "system").encode("utf-8")).hexdigest()


def list_execution_receipt_archives(db_path: str | Path, *, limit: int = 100) -> list[dict[str, Any]]:
    limit = max(1, min(int(limit), 1000))
    with read_connection(db_path, operation="list_execution_receipt_archives") as conn:
        rows = conn.execute(
            "SELECT * FROM execution_receipt_archives ORDER BY created_at DESC,archive_id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    output: list[dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        for source, target in (
            ("operation_summary_json", "operation_summary"),
            ("outcome_summary_json", "outcome_summary"),
            ("subtype_summary_json", "subtype_summary"),
        ):
            try:
                item[target] = json.loads(item.pop(source) or "{}")
            except json.JSONDecodeError:
                item[target] = {}
        output.append(item)
    return output


def archive_execution_receipts(
    db_path: str | Path,
    *,
    cutoff_at: str,
    actor: str = "system-maintenance",
    max_rows: int = 5000,
) -> dict[str, Any]:
    """Seal and prune old receipt detail while preserving dead letters/replays."""
    cutoff = str(cutoff_at or "").strip()
    if not cutoff:
        raise ValueError("cutoff_at이 필요합니다.")
    row_limit = max(1, min(int(max_rows), 50_000))
    conn = connect(db_path)
    try:
        conn.execute("BEGIN EXCLUSIVE")
        rows = conn.execute(
            """
            SELECT r.*
              FROM execution_receipts r
              LEFT JOIN execution_replays p ON p.receipt_id=r.receipt_id
              LEFT JOIN background_jobs bj
                ON r.operation_type='BACKGROUND_JOB' AND bj.job_id=r.resource_id
              LEFT JOIN webhook_events wh
                ON r.operation_type='WEBHOOK_DELIVERY' AND wh.event_id=r.resource_id
             WHERE r.created_at < ? AND p.receipt_id IS NULL
               AND (
                    (r.operation_type='BACKGROUND_JOB' AND (bj.status='SUCCEEDED' OR bj.job_id IS NULL))
                 OR (r.operation_type='WEBHOOK_DELIVERY' AND (wh.status='DELIVERED' OR wh.event_id IS NULL))
               )
             ORDER BY r.created_at,r.operation_type,r.resource_id,r.receipt_sequence,r.receipt_id
             LIMIT ?
            """,
            (cutoff, row_limit),
        ).fetchall()
        if not rows:
            conn.rollback()
            return {
                "archive_id": None, "cutoff_at": cutoff, "receipt_count": 0,
                "first_created_at": "", "last_created_at": "", "receipt_digest_sha256": "",
            }

        keys = (
            "receipt_id", "operation_type", "resource_id", "resource_subtype",
            "receipt_sequence", "attempt_no", "outcome", "request_sha256",
            "result_sha256", "error_sha256", "error_class", "actor_sha256",
            "metadata_json", "created_at",
        )
        canonical_rows = [{key: row[key] for key in keys} for row in rows]
        operation_counts = Counter(str(row["operation_type"]) for row in rows)
        outcome_counts = Counter(str(row["outcome"]) for row in rows)
        subtype_counts = Counter(str(row["resource_subtype"] or "unspecified") for row in rows)
        archive_id = f"RCA-{uuid.uuid4().hex[:20].upper()}"
        now = utc_now()
        digest = hashlib.sha256(canonical_json(canonical_rows).encode("utf-8")).hexdigest()
        conn.execute(
            """
            INSERT INTO execution_receipt_archives(
                archive_id,cutoff_at,receipt_count,first_created_at,last_created_at,
                receipt_digest_sha256,operation_summary_json,outcome_summary_json,
                subtype_summary_json,actor_sha256,created_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                archive_id, cutoff, len(rows), str(rows[0]["created_at"]), str(rows[-1]["created_at"]), digest,
                json.dumps(dict(sorted(operation_counts.items())), ensure_ascii=False, separators=(",", ":")),
                json.dumps(dict(sorted(outcome_counts.items())), ensure_ascii=False, separators=(",", ":")),
                json.dumps(dict(sorted(subtype_counts.items())), ensure_ascii=False, separators=(",", ":")),
                _actor_sha256(actor), now,
            ),
        )
        conn.execute("DROP TRIGGER execution_receipts_no_delete")
        receipt_ids = [str(row["receipt_id"]) for row in rows]
        for offset in range(0, len(receipt_ids), 500):
            chunk = receipt_ids[offset:offset + 500]
            placeholders = ",".join("?" for _ in chunk)
            conn.execute(f"DELETE FROM execution_receipts WHERE receipt_id IN ({placeholders})", chunk)
        conn.execute(_RECEIPT_DELETE_TRIGGER)
        add_audit_event(
            db_path,
            finding_id=None,
            event_type="execution_receipts_archived",
            summary=f"상세 실행 영수증 {len(rows)}건 보존 archive 봉인",
            details={
                "archive_id": archive_id,
                "cutoff_at": cutoff,
                "receipt_count": len(rows),
                "receipt_digest_sha256": digest,
            },
            actor=str(actor or "system-maintenance"),
            conn=conn,
        )
        conn.commit()
        return {
            "archive_id": archive_id, "cutoff_at": cutoff, "receipt_count": len(rows),
            "first_created_at": str(rows[0]["created_at"]), "last_created_at": str(rows[-1]["created_at"]),
            "receipt_digest_sha256": digest,
            "operation_summary": dict(sorted(operation_counts.items())),
            "outcome_summary": dict(sorted(outcome_counts.items())),
            "subtype_summary": dict(sorted(subtype_counts.items())), "created_at": now,
        }
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
