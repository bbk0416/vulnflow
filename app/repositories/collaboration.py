from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

from app.core.db import utc_now
from app.core.retry import RetryPolicy
from app.core.transactions import read_connection, write_transaction
from app.repositories.audit import add_audit_event

CHANNELS = {"EMAIL", "JIRA"}
EVENT_STATUSES = {"PENDING", "RETRY", "SENDING", "DELIVERED", "FAILED", "SKIPPED"}


def _json_object(value: str | None) -> dict[str, Any]:
    try:
        decoded = json.loads(value or "{}")
    except json.JSONDecodeError:
        return {}
    return decoded if isinstance(decoded, dict) else {}


def _integration_item(row: sqlite3.Row, *, include_secret: bool) -> dict[str, Any]:
    item = dict(row)
    item["config"] = _json_object(item.pop("config_json", "{}"))
    item["enabled"] = bool(item.get("enabled"))
    ciphertext = str(item.pop("secret_ciphertext", "") or "")
    item["secret_configured"] = bool(ciphertext)
    if include_secret:
        item["secret_ciphertext"] = ciphertext
    return item


def get_integration(
    db_path: str | Path, channel: str, *, include_secret: bool = False
) -> dict[str, Any] | None:
    normalized = str(channel or "").strip().upper()
    with read_connection(db_path, operation="get_collaboration_integration") as conn:
        row = conn.execute(
            "SELECT * FROM collaboration_integrations WHERE channel=?", (normalized,)
        ).fetchone()
    return _integration_item(row, include_secret=include_secret) if row is not None else None


def list_integrations(db_path: str | Path) -> list[dict[str, Any]]:
    with read_connection(db_path, operation="list_collaboration_integrations") as conn:
        rows = conn.execute(
            "SELECT * FROM collaboration_integrations ORDER BY channel"
        ).fetchall()
    return [_integration_item(row, include_secret=False) for row in rows]


def save_integration(
    db_path: str | Path,
    *,
    channel: str,
    enabled: bool,
    config: dict[str, Any],
    secret_ciphertext: str | None,
    actor: str,
) -> dict[str, Any]:
    normalized = str(channel or "").strip().upper()
    if normalized not in CHANNELS:
        raise ValueError("지원하지 않는 연동 채널입니다.")
    now = utc_now()
    with write_transaction(db_path, operation="save_collaboration_integration") as conn:
        existing = conn.execute(
            "SELECT secret_ciphertext FROM collaboration_integrations WHERE channel=?",
            (normalized,),
        ).fetchone()
        secret = (
            str(secret_ciphertext)
            if secret_ciphertext is not None
            else str(existing["secret_ciphertext"] if existing else "")
        )
        conn.execute(
            """
            INSERT INTO collaboration_integrations(
                channel,enabled,config_json,secret_ciphertext,updated_by,updated_at
            ) VALUES(?,?,?,?,?,?)
            ON CONFLICT(channel) DO UPDATE SET
                enabled=excluded.enabled,
                config_json=excluded.config_json,
                secret_ciphertext=excluded.secret_ciphertext,
                updated_by=excluded.updated_by,
                updated_at=excluded.updated_at
            """,
            (
                normalized,
                1 if enabled else 0,
                json.dumps(config, ensure_ascii=False, sort_keys=True),
                secret,
                actor,
                now,
            ),
        )
        add_audit_event(
            db_path,
            finding_id=None,
            event_type="collaboration_integration_updated",
            summary=f"{normalized} 연동 설정 변경",
            details={"channel": normalized, "enabled": bool(enabled), "secret_configured": bool(secret)},
            actor=actor,
            conn=conn,
        )
    return get_integration(db_path, normalized) or {}


def queue_collaboration_event(
    db_path: str | Path,
    *,
    channel: str,
    event_type: str,
    payload: dict[str, Any],
    actor: str,
    finding_id: str = "",
    dedupe_key: str = "",
    requeue_failed: bool = False,
) -> str:
    normalized = str(channel or "").strip().upper()
    if normalized not in CHANNELS:
        raise ValueError("지원하지 않는 연동 채널입니다.")
    event_id = f"COL-{uuid.uuid4().hex[:20].upper()}"
    now = utc_now()
    with write_transaction(db_path, operation="queue_collaboration_event") as conn:
        if dedupe_key:
            existing = conn.execute(
                "SELECT event_id,status FROM collaboration_events WHERE dedupe_key=?",
                (str(dedupe_key),),
            ).fetchone()
            if existing is not None:
                if requeue_failed and str(existing["status"]) in {"FAILED", "SKIPPED"}:
                    conn.execute(
                        """UPDATE collaboration_events
                              SET status='PENDING',attempts=0,next_attempt_at=?,last_attempt_at=NULL,
                                  delivered_at=NULL,response_status=NULL,last_error='',external_key='',external_url=''
                            WHERE event_id=?""",
                        (now, str(existing["event_id"])),
                    )
                return str(existing["event_id"])
        conn.execute(
            """
            INSERT INTO collaboration_events(
                event_id,channel,event_type,finding_id,payload_json,status,attempts,
                next_attempt_at,dedupe_key,created_by,created_at
            ) VALUES(?,?,?,?,?,'PENDING',0,?,?,?,?)
            """,
            (
                event_id,
                normalized,
                str(event_type),
                str(finding_id or ""),
                json.dumps(payload, ensure_ascii=False, sort_keys=True),
                now,
                str(dedupe_key or ""),
                str(actor or "system"),
                now,
            ),
        )
        add_audit_event(
            db_path,
            finding_id=str(finding_id or "") or None,
            event_type="collaboration_event_queued",
            summary=f"{normalized} 협업 알림 큐 등록: {event_type}",
            details={"event_id": event_id, "channel": normalized, "event_type": str(event_type)},
            actor=str(actor or "system"),
            conn=conn,
        )
    return event_id


def get_collaboration_event(
    db_path: str | Path, event_id: str
) -> dict[str, Any] | None:
    with read_connection(db_path, operation="get_collaboration_event") as conn:
        row = conn.execute(
            "SELECT * FROM collaboration_events WHERE event_id=?", (str(event_id),)
        ).fetchone()
    if row is None:
        return None
    item = dict(row)
    item["payload"] = _json_object(item.pop("payload_json", "{}"))
    return item


def list_collaboration_events(
    db_path: str | Path, *, status: str = "", limit: int = 200
) -> list[dict[str, Any]]:
    limit = max(1, min(int(limit), 2000))
    with read_connection(db_path, operation="list_collaboration_events") as conn:
        if status:
            rows = conn.execute(
                "SELECT * FROM collaboration_events WHERE status=? ORDER BY created_at DESC LIMIT ?",
                (str(status).upper(), limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM collaboration_events ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
    output: list[dict[str, Any]] = []
    for raw in rows:
        item = dict(raw)
        item["payload"] = _json_object(item.pop("payload_json", "{}"))
        output.append(item)
    return output


def count_pending_collaboration_events(db_path: str | Path) -> int:
    with read_connection(db_path, operation="count_pending_collaboration_events") as conn:
        return int(
            conn.execute(
                "SELECT COUNT(*) FROM collaboration_events WHERE status IN ('PENDING','RETRY','SENDING')"
            ).fetchone()[0]
        )


def claim_due_collaboration_events(
    db_path: str | Path, *, limit: int = 50, lease_seconds: int = 120
) -> list[dict[str, Any]]:
    now = utc_now()
    cutoff = (
        datetime.now(timezone.utc) - timedelta(seconds=max(1, int(lease_seconds)))
    ).replace(microsecond=0).isoformat()
    with write_transaction(db_path, operation="claim_due_collaboration_events") as conn:
        conn.execute(
            """
            UPDATE collaboration_events
               SET status='RETRY',next_attempt_at=?,last_error='delivery lease expired'
             WHERE status='SENDING' AND COALESCE(last_attempt_at,'')<>'' AND last_attempt_at<?
            """,
            (now, cutoff),
        )
        rows = conn.execute(
            """
            SELECT * FROM collaboration_events
             WHERE status IN ('PENDING','RETRY') AND next_attempt_at<=?
             ORDER BY created_at ASC LIMIT ?
            """,
            (now, max(1, min(int(limit), 500))),
        ).fetchall()
        ids = [str(row["event_id"]) for row in rows]
        if not ids:
            return []
        conn.executemany(
            "UPDATE collaboration_events SET status='SENDING',last_attempt_at=? WHERE event_id=?",
            [(now, event_id) for event_id in ids],
        )
        claimed = conn.execute(
            f"SELECT * FROM collaboration_events WHERE event_id IN ({','.join('?' for _ in ids)}) ORDER BY created_at",
            ids,
        ).fetchall()
    output: list[dict[str, Any]] = []
    for raw in claimed:
        item = dict(raw)
        item["payload"] = _json_object(item.pop("payload_json", "{}"))
        output.append(item)
    return output


def record_collaboration_delivery(
    db_path: str | Path,
    *,
    event_id: str,
    delivered: bool,
    response_status: int | None = None,
    error: str = "",
    external_key: str = "",
    external_url: str = "",
    max_attempts: int = 5,
    retryable: bool = True,
    retry_after_seconds: float | None = None,
) -> dict[str, Any]:
    now_dt = datetime.now(timezone.utc).replace(microsecond=0)
    now = now_dt.isoformat()
    with write_transaction(db_path, operation="record_collaboration_delivery") as conn:
        row = conn.execute(
            "SELECT * FROM collaboration_events WHERE event_id=?", (event_id,)
        ).fetchone()
        if row is None:
            raise KeyError(event_id)
        attempts = int(row["attempts"] or 0) + 1
        if delivered:
            status = "DELIVERED"
            next_attempt_at = now
            delivered_at = now
        else:
            decision = RetryPolicy(
                max_attempts=max_attempts,
                base_delay_seconds=60,
                max_delay_seconds=3600,
                jitter_ratio=0.10,
            ).decide(
                attempts=attempts,
                retryable=retryable,
                operation_key=event_id,
                retry_after_seconds=retry_after_seconds,
            )
            status = decision.status
            next_attempt_at = (
                now_dt + timedelta(seconds=decision.delay_seconds)
            ).isoformat() if status == "RETRY" else now
            delivered_at = None
        conn.execute(
            """
            UPDATE collaboration_events SET status=?,attempts=?,next_attempt_at=?,delivered_at=?,
                   response_status=?,last_error=?,external_key=?,external_url=?
             WHERE event_id=?
            """,
            (
                status,
                attempts,
                next_attempt_at,
                delivered_at,
                response_status,
                str(error or "")[:1000],
                str(external_key or "")[:200],
                str(external_url or "")[:1000],
                event_id,
            ),
        )
        add_audit_event(
            db_path,
            finding_id=str(row["finding_id"] or "") or None,
            event_type="collaboration_event_delivered" if delivered else "collaboration_event_failed",
            summary=("협업 알림 전송 성공" if delivered else f"협업 알림 전송 실패: {status}"),
            details={
                "event_id": event_id,
                "channel": row["channel"],
                "event_type": row["event_type"],
                "attempts": attempts,
                "response_status": response_status,
                "error": str(error or "")[:300],
            },
            actor="system-collaboration",
            conn=conn,
        )
    updated = get_collaboration_event(db_path, event_id)
    if updated is None:
        raise KeyError(event_id)
    return updated


def get_finding_external_link(
    db_path: str | Path, finding_id: str, *, provider: str = "JIRA"
) -> dict[str, Any] | None:
    with read_connection(db_path, operation="get_finding_external_link") as conn:
        row = conn.execute(
            "SELECT * FROM finding_external_links WHERE finding_id=? AND provider=?",
            (str(finding_id), str(provider).upper()),
        ).fetchone()
    return dict(row) if row else None


def upsert_finding_external_link(
    db_path: str | Path,
    *,
    finding_id: str,
    provider: str,
    external_key: str,
    external_url: str,
    actor: str,
) -> dict[str, Any]:
    now = utc_now()
    with write_transaction(db_path, operation="upsert_finding_external_link") as conn:
        conn.execute(
            """
            INSERT INTO finding_external_links(
                finding_id,provider,external_key,external_url,status,created_by,created_at,updated_at
            ) VALUES(?,?,?,?,'ACTIVE',?,?,?)
            ON CONFLICT(finding_id,provider) DO UPDATE SET
                external_key=excluded.external_key,external_url=excluded.external_url,
                status='ACTIVE',updated_at=excluded.updated_at
            """,
            (finding_id, provider.upper(), external_key, external_url, actor, now, now),
        )
        add_audit_event(
            db_path,
            finding_id=finding_id,
            event_type="finding_external_link_updated",
            summary=f"{provider.upper()} 티켓 연결: {external_key}",
            details={"provider": provider.upper(), "external_key": external_key, "external_url": external_url},
            actor=actor,
            conn=conn,
        )
    return get_finding_external_link(db_path, finding_id, provider=provider) or {}
