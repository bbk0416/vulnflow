from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import uuid
from pathlib import Path
from typing import Any

from app.core.db import utc_now
from app.core.signing import KEY_ID_RE, hmac_sha256, verify_hmac
from app.core.transactions import borrowed_or_write_transaction, read_connection, write_transaction

AUDIT_GENESIS_HASH = "0" * 64


def _canonical_audit_details(details: dict[str, Any] | None = None, raw: str | None = None) -> str:
    value: Any = details if details is not None else {}
    if raw is not None:
        try:
            parsed = json.loads(raw or "{}")
            value = parsed if isinstance(parsed, dict) else {"value": parsed}
        except json.JSONDecodeError:
            value = {"unparsed": str(raw)}
    return json.dumps(value or {}, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _audit_event_digest(*, chain_seq: int, finding_id: str | None, event_type: str, actor: str,
                        summary: str, details_json: str, created_at: str, prev_hash: str) -> str:
    payload = {
        "chain_seq": int(chain_seq),
        "finding_id": finding_id,
        "event_type": str(event_type),
        "actor": str(actor),
        "summary": str(summary),
        "details_json": str(details_json),
        "created_at": str(created_at),
        "prev_hash": str(prev_hash),
    }
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def add_audit_event(
    db_path: str | Path,
    *,
    finding_id: str | None,
    event_type: str,
    summary: str,
    details: dict[str, Any] | None = None,
    actor: str = "local-user",
    created_at: str | None = None,
    conn: sqlite3.Connection | None = None,
) -> None:
    with borrowed_or_write_transaction(
        db_path, conn=conn, operation="add_audit_event"
    ) as connection:
        state = connection.execute(
            "SELECT anchor_seq,anchor_hash,last_seq,last_hash FROM audit_chain_state WHERE singleton_id=1"
        ).fetchone()
        if state is None:
            raise RuntimeError("audit chain state is missing")
        chain_seq = int(state["last_seq"]) + 1
        prev_hash = str(state["last_hash"] or AUDIT_GENESIS_HASH)
        created_at = created_at or utc_now()
        details_json = _canonical_audit_details(details=details)
        event_hash = _audit_event_digest(
            chain_seq=chain_seq, finding_id=finding_id, event_type=event_type, actor=actor,
            summary=summary, details_json=details_json, created_at=created_at, prev_hash=prev_hash,
        )
        connection.execute(
            """INSERT INTO audit_events(
                   finding_id,event_type,actor,summary,details_json,created_at,chain_seq,prev_hash,event_hash
               ) VALUES(?,?,?,?,?,?,?,?,?)""",
            (finding_id, event_type, actor, summary, details_json, created_at, chain_seq, prev_hash, event_hash),
        )
        connection.execute(
            "UPDATE audit_chain_state SET last_seq=?,last_hash=?,updated_at=? WHERE singleton_id=1",
            (chain_seq, event_hash, created_at),
        )


def list_audit_events(db_path: str | Path, finding_id: str | None = None, *, limit: int = 100) -> list[dict[str, Any]]:
    limit = max(1, min(int(limit), 10000))
    with read_connection(db_path, operation="list_audit_events") as conn:
        if finding_id:
            rows = conn.execute(
                "SELECT * FROM audit_events WHERE finding_id=? ORDER BY chain_seq DESC LIMIT ?",
                (finding_id, limit),
            ).fetchall()
        else:
            rows = conn.execute("SELECT * FROM audit_events ORDER BY chain_seq DESC LIMIT ?", (limit,)).fetchall()
        output = []
        for row in rows:
            item = dict(row)
            try:
                item["details"] = json.loads(item.pop("details_json") or "{}")
            except json.JSONDecodeError:
                item["details"] = {}
            output.append(item)
        return output


def list_audit_checkpoints(db_path: str | Path, *, limit: int = 100) -> list[dict[str, Any]]:
    limit = max(1, min(int(limit), 1000))
    with read_connection(db_path, operation="list_audit_checkpoints") as conn:
        return [dict(row) for row in conn.execute(
            "SELECT * FROM audit_checkpoints ORDER BY chain_seq DESC,created_at DESC LIMIT ?", (limit,)
        ).fetchall()]


def list_audit_prune_history(db_path: str | Path, *, limit: int = 100) -> list[dict[str, Any]]:
    limit = max(1, min(int(limit), 1000))
    with read_connection(db_path, operation="list_audit_prune_history") as conn:
        return [dict(row) for row in conn.execute(
            "SELECT * FROM audit_prune_history ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()]


def _checkpoint_payload(*, chain_seq: int, event_hash: str, created_at: str, key_id: str | None = None) -> bytes:
    payload = {
        "format": "vulnflow-audit-checkpoint/2" if key_id else "vulnflow-audit-checkpoint/1",
        "chain_seq": int(chain_seq),
        "event_hash": str(event_hash),
        "created_at": str(created_at),
    }
    if key_id:
        payload["key_id"] = str(key_id)
    return json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")


def create_audit_checkpoint(
    db_path: str | Path,
    *,
    signing_key: str = "",
    signing_key_id: str | None = None,
    actor: str = "system",
    chain_seq: int | None = None,
    event_hash: str | None = None,
    conn: sqlite3.Connection | None = None,
) -> dict[str, Any]:
    if signing_key and len(signing_key) < 16:
        raise ValueError("감사 체크포인트 서명 키는 최소 16자 이상이어야 합니다.")
    if signing_key_id and not signing_key:
        raise ValueError("감사 체크포인트 key_id에는 서명 키가 필요합니다.")
    if signing_key_id and not KEY_ID_RE.fullmatch(signing_key_id):
        raise ValueError("감사 체크포인트 서명 키 ID 형식이 올바르지 않습니다.")
    with borrowed_or_write_transaction(
        db_path, conn=conn, operation="create_audit_checkpoint"
    ) as connection:
        state = connection.execute(
            "SELECT anchor_seq,anchor_hash,last_seq,last_hash FROM audit_chain_state WHERE singleton_id=1"
        ).fetchone()
        if state is None:
            raise RuntimeError("audit chain state is missing")
        seq = int(chain_seq if chain_seq is not None else state["last_seq"])
        digest = str(event_hash if event_hash is not None else state["last_hash"])
        if seq < int(state["anchor_seq"]) or seq > int(state["last_seq"]):
            raise ValueError("체크포인트 체인 순번이 현재 감사 체인 범위를 벗어납니다.")
        if chain_seq is not None and event_hash is None:
            row = connection.execute("SELECT event_hash FROM audit_events WHERE chain_seq=?", (seq,)).fetchone()
            if row is None and seq == int(state["anchor_seq"]):
                digest = str(state["anchor_hash"])
            elif row is None:
                raise ValueError("체크포인트 대상 감사 이벤트를 찾을 수 없습니다.")
            else:
                digest = str(row["event_hash"])
        created_at = utc_now()
        signature = hmac_sha256(
            signing_key,
            _checkpoint_payload(chain_seq=seq, event_hash=digest, created_at=created_at, key_id=signing_key_id),
        ) if signing_key else None
        checkpoint_id = f"ACP-{uuid.uuid4().hex[:16].upper()}"
        connection.execute(
            """INSERT INTO audit_checkpoints(
                   checkpoint_id,chain_seq,event_hash,signature,key_id,algorithm,created_by,created_at
               ) VALUES(?,?,?,?,?,?,?,?)""",
            (checkpoint_id, seq, digest, signature, signing_key_id, "HMAC-SHA256", actor, created_at),
        )
        return {
            "checkpoint_id": checkpoint_id, "chain_seq": seq, "event_hash": digest,
            "signature": signature, "signed": bool(signature), "key_id": signing_key_id,
            "created_by": actor, "created_at": created_at,
        }


def verify_audit_integrity(
    db_path: str | Path,
    *,
    signing_key: str = "",
    signing_keys: dict[str, str] | None = None,
) -> dict[str, Any]:
    issues: list[str] = []
    checkpoint_results: list[dict[str, Any]] = []
    with read_connection(db_path, operation="verify_audit_integrity") as conn:
        state_row = conn.execute(
            "SELECT anchor_seq,anchor_hash,last_seq,last_hash,updated_at FROM audit_chain_state WHERE singleton_id=1"
        ).fetchone()
        if state_row is None:
            return {"valid": False, "issues": ["audit chain state is missing"], "checked_events": 0, "checkpoints": []}
        state = dict(state_row)
        rows = conn.execute("SELECT * FROM audit_events ORDER BY chain_seq").fetchall()
        expected_seq = int(state["anchor_seq"]) + 1
        previous_hash = str(state["anchor_hash"])
        for row in rows:
            if row["chain_seq"] is None or row["prev_hash"] is None or row["event_hash"] is None:
                issues.append(f"unchained audit event id={row['id']}")
                continue
            seq = int(row["chain_seq"])
            if seq != expected_seq:
                issues.append(f"audit sequence gap: expected {expected_seq}, got {seq}")
            if str(row["prev_hash"]) != previous_hash:
                issues.append(f"previous hash mismatch at chain_seq={seq}")
            details_json = _canonical_audit_details(raw=row["details_json"])
            expected_hash = _audit_event_digest(
                chain_seq=seq, finding_id=row["finding_id"], event_type=row["event_type"],
                actor=row["actor"], summary=row["summary"], details_json=details_json,
                created_at=row["created_at"], prev_hash=str(row["prev_hash"]),
            )
            if not hmac.compare_digest(str(row["event_hash"]), expected_hash):
                issues.append(f"event hash mismatch at chain_seq={seq}")
            previous_hash = str(row["event_hash"])
            expected_seq = seq + 1
        calculated_last_seq = expected_seq - 1
        calculated_last_hash = previous_hash
        if calculated_last_seq != int(state["last_seq"]):
            issues.append(
                f"chain state last_seq mismatch: state={state['last_seq']}, calculated={calculated_last_seq}"
            )
        if not hmac.compare_digest(str(state["last_hash"]), calculated_last_hash):
            issues.append("chain state last_hash mismatch")

        retained = {int(row["chain_seq"]): str(row["event_hash"]) for row in rows if row["chain_seq"] is not None}
        checkpoints = conn.execute("SELECT * FROM audit_checkpoints ORDER BY chain_seq,created_at").fetchall()
        for row in checkpoints:
            item = dict(row)
            seq = int(item["chain_seq"])
            expected_event_hash = str(state["anchor_hash"]) if seq == int(state["anchor_seq"]) else retained.get(seq)
            hash_matches = expected_event_hash is None or hmac.compare_digest(str(item["event_hash"]), expected_event_hash)
            signature_status = "unsigned"
            signature_valid: bool | None = None
            resolved_key_id: str | None = None
            if item.get("signature"):
                if not signing_key and not dict(signing_keys or {}):
                    signature_status = "unverified-no-key"
                else:
                    result = verify_hmac(
                        signature=str(item["signature"]),
                        payload=_checkpoint_payload(
                            chain_seq=seq, event_hash=item["event_hash"], created_at=item["created_at"],
                            key_id=item.get("key_id"),
                        ),
                        signing_keys=signing_keys, key_id=item.get("key_id"), legacy_key=signing_key,
                    )
                    signature_valid = bool(result["valid"])
                    signature_status = str(result["status"])
                    resolved_key_id = result.get("resolved_key_id")
                    if not signature_valid:
                        issues.append(f"checkpoint signature mismatch or key unavailable: {item['checkpoint_id']}")
            if not hash_matches:
                issues.append(f"checkpoint event hash mismatch: {item['checkpoint_id']}")
            checkpoint_results.append(item | {
                "hash_matches": hash_matches, "signature_status": signature_status,
                "signature_valid": signature_valid, "resolved_key_id": resolved_key_id,
            })
    return {
        "valid": not issues,
        "issues": issues,
        "checked_events": len(rows),
        "anchor_seq": int(state["anchor_seq"]),
        "anchor_hash": str(state["anchor_hash"]),
        "last_seq": int(state["last_seq"]),
        "last_hash": str(state["last_hash"]),
        "checkpoints": checkpoint_results,
        "checkpoint_count": len(checkpoint_results),
        "verified_at": utc_now(),
    }


def prune_audit_prefix(
    db_path: str | Path,
    *,
    cutoff_at: str,
    actor: str,
    signing_key: str = "",
    signing_key_id: str | None = None,
) -> dict[str, Any]:
    with write_transaction(db_path, operation="prune_audit_prefix") as conn:
        state = conn.execute(
            "SELECT anchor_seq,anchor_hash,last_seq,last_hash FROM audit_chain_state WHERE singleton_id=1"
        ).fetchone()
        if state is None:
            raise RuntimeError("audit chain state is missing")
        candidates = conn.execute(
            "SELECT chain_seq,event_hash,created_at FROM audit_events ORDER BY chain_seq"
        ).fetchall()
        prefix: list[sqlite3.Row] = []
        for row in candidates:
            if str(row["created_at"]) < str(cutoff_at):
                prefix.append(row)
            else:
                break
        if not prefix:
            conn.rollback()
            return {"deleted_count": 0, "anchor_seq": int(state["anchor_seq"]), "anchor_hash": state["anchor_hash"]}
        from_seq = int(prefix[0]["chain_seq"])
        to_seq = int(prefix[-1]["chain_seq"])
        anchor_hash = str(prefix[-1]["event_hash"])
        checkpoint = create_audit_checkpoint(
            db_path, signing_key=signing_key, signing_key_id=signing_key_id, actor=actor,
            chain_seq=to_seq, event_hash=anchor_hash, conn=conn
        )
        prune_id = f"APR-{uuid.uuid4().hex[:16].upper()}"
        now = utc_now()
        conn.execute(
            """INSERT INTO audit_prune_history(
                   prune_id,from_seq,to_seq,anchor_hash,deleted_count,cutoff_at,actor,created_at
               ) VALUES(?,?,?,?,?,?,?,?)""",
            (prune_id, from_seq, to_seq, anchor_hash, len(prefix), cutoff_at, actor, now),
        )
        conn.execute(
            "UPDATE audit_chain_state SET anchor_seq=?,anchor_hash=?,updated_at=? WHERE singleton_id=1",
            (to_seq, anchor_hash, now),
        )
        conn.execute("DELETE FROM audit_events WHERE chain_seq BETWEEN ? AND ?", (from_seq, to_seq))
        add_audit_event(
            db_path, finding_id=None, event_type="audit_chain_pruned",
            summary=f"감사 체인 선두 {len(prefix)}건을 보존정책에 따라 정리",
            details={
                "prune_id": prune_id, "from_seq": from_seq, "to_seq": to_seq,
                "deleted_count": len(prefix), "cutoff_at": cutoff_at,
                "checkpoint_id": checkpoint["checkpoint_id"], "checkpoint_signed": checkpoint["signed"],
            },
            actor=actor, conn=conn,
        )
        return {
            "prune_id": prune_id, "from_seq": from_seq, "to_seq": to_seq,
            "deleted_count": len(prefix), "anchor_seq": to_seq, "anchor_hash": anchor_hash,
            "checkpoint": checkpoint,
        }
