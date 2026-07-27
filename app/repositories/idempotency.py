from __future__ import annotations

"""Durable idempotency ledger for short transactional commands.

The raw client key is never persisted.  A principal-bound SHA-256 digest and a
canonical request digest are stored in the same SQLite transaction as the
created resource, so rollback cannot leave a completed ledger entry behind.
"""

import hashlib
import json
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from app.core.db import utc_now
from app.core.transactions import read_connection

IDEMPOTENCY_KEY_RE = re.compile(r"^[A-Za-z0-9._:-]{8,200}$")


class IdempotencyConflict(ValueError):
    """The same principal/key pair was reused for a different request."""


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def request_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def key_sha256(key: str, *, principal: str) -> str:
    normalized = str(key or "").strip()
    if not IDEMPOTENCY_KEY_RE.fullmatch(normalized):
        raise ValueError("Idempotency-Key는 8~200자의 영문·숫자·._:- 조합이어야 합니다.")
    material = f"{str(principal or 'anonymous')}\0{normalized}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def replay_result(
    conn: sqlite3.Connection,
    *,
    scope: str,
    idempotency_key: str,
    principal: str,
    request_digest: str,
) -> dict[str, Any] | None:
    digest = key_sha256(idempotency_key, principal=principal)
    row = conn.execute(
        """SELECT * FROM idempotency_records
             WHERE scope=? AND key_sha256=?""",
        (str(scope), digest),
    ).fetchone()
    if row is None:
        return None
    now = utc_now()
    if str(row["expires_at"] or "") <= now:
        conn.execute(
            "DELETE FROM idempotency_records WHERE scope=? AND key_sha256=?",
            (str(scope), digest),
        )
        return None
    if str(row["request_sha256"] or "") != str(request_digest):
        raise IdempotencyConflict("동일한 Idempotency-Key가 다른 요청 내용에 사용되었습니다.")
    try:
        response = json.loads(str(row["response_json"] or "{}"))
    except json.JSONDecodeError:
        response = {}
    return {
        "resource_type": str(row["resource_type"] or ""),
        "resource_id": str(row["resource_id"] or ""),
        "response": response if isinstance(response, dict) else {},
        "created_at": str(row["created_at"] or ""),
        "expires_at": str(row["expires_at"] or ""),
    }


def store_result(
    conn: sqlite3.Connection,
    *,
    scope: str,
    idempotency_key: str,
    principal: str,
    request_digest: str,
    resource_type: str,
    resource_id: str,
    response: dict[str, Any],
    retention_days: int = 30,
) -> None:
    now_dt = datetime.now(timezone.utc).replace(microsecond=0)
    now = now_dt.isoformat()
    expires_at = (now_dt + timedelta(days=max(1, min(int(retention_days), 365)))).isoformat()
    conn.execute(
        """INSERT INTO idempotency_records(
               scope,key_sha256,request_sha256,resource_type,resource_id,response_json,
               created_at,expires_at
           ) VALUES(?,?,?,?,?,?,?,?)""",
        (
            str(scope),
            key_sha256(idempotency_key, principal=principal),
            str(request_digest),
            str(resource_type),
            str(resource_id),
            canonical_json(response),
            now,
            expires_at,
        ),
    )


def purge_expired_idempotency_records(conn: sqlite3.Connection, *, now: str | None = None) -> int:
    cursor = conn.execute(
        "DELETE FROM idempotency_records WHERE expires_at<=?",
        (str(now or utc_now()),),
    )
    return int(cursor.rowcount or 0)


def count_idempotency_records(db_path: str | Path) -> int:
    with read_connection(db_path, operation="count_idempotency_records") as conn:
        return int(conn.execute("SELECT COUNT(*) FROM idempotency_records WHERE expires_at>?", (utc_now(),)).fetchone()[0])
