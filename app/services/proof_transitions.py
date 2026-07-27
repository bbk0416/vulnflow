from __future__ import annotations

"""Cross-signed Ed25519 proof-key transition records.

This module owns transition creation, persistence, export, and document
validation.  Trust-path resolution is intentionally separated into
``proof_trust_resolver`` so write-side key rotation changes cannot silently
affect proof verification traversal.
"""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping
import uuid

from app.core.db import utc_now
from app.core.public_signing import (
    ED25519_ALGORITHM,
    public_key_fingerprint,
    sign_ed25519,
    verify_ed25519,
)
from app.core.signing import KEY_ID_RE
from app.core.transactions import read_connection, write_transaction
from app.repositories.audit import add_audit_event

TRANSITION_FORMAT = "vulnflow-integrity-proof-key-transition/1"
MAX_TRANSITIONS_PER_PROOF = 64
MAX_TRUST_CHAIN_DEPTH = 8

def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256_text(value: str) -> str:
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()


def _transition_payload(statement: Mapping[str, Any]) -> bytes:
    return b"vulnflow-integrity-proof-key-transition/1\n" + _canonical_json_bytes(dict(statement))


def _normalize_timestamp(value: str, *, field: str) -> str:
    text = str(value or "").strip() or utc_now()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field}는 ISO-8601 시각이어야 합니다.") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{field}에는 시간대가 포함되어야 합니다.")
    return parsed.astimezone(timezone.utc).replace(microsecond=0).isoformat()


def create_integrity_proof_key_transition(
    db_path: str | Path,
    *,
    from_key_id: str,
    to_key_id: str,
    private_keys: Mapping[str, str],
    public_keys: Mapping[str, str],
    actor: str,
    reason: str,
    effective_at: str = "",
) -> dict[str, Any]:
    source_id = str(from_key_id or "").strip()
    target_id = str(to_key_id or "").strip()
    if not KEY_ID_RE.fullmatch(source_id) or not KEY_ID_RE.fullmatch(target_id):
        raise ValueError("전환 키 ID 형식이 올바르지 않습니다.")
    if source_id == target_id:
        raise ValueError("이전 키와 신규 키는 달라야 합니다.")
    source_private = str(dict(private_keys).get(source_id, ""))
    target_private = str(dict(private_keys).get(target_id, ""))
    source_public = str(dict(public_keys).get(source_id, ""))
    target_public = str(dict(public_keys).get(target_id, ""))
    if not source_private or not target_private:
        raise ValueError("교차서명 전환에는 이전 키와 신규 키의 private key가 모두 필요합니다.")
    if not source_public or not target_public:
        raise ValueError("교차서명 전환에는 이전 키와 신규 키의 public key가 모두 필요합니다.")
    reason_text = str(reason or "").strip()
    if len(reason_text) < 3 or len(reason_text) > 1500:
        raise ValueError("키 전환 사유는 3자 이상 1500자 이하여야 합니다.")

    created_at = utc_now()
    effective = _normalize_timestamp(effective_at, field="effective_at")
    transition_id = f"IPKT-{uuid.uuid4().hex[:20].upper()}"
    statement = {
        "format": TRANSITION_FORMAT,
        "transition_id": transition_id,
        "from": {
            "algorithm": ED25519_ALGORITHM,
            "key_id": source_id,
            "public_key_base64": source_public,
            "public_key_sha256": public_key_fingerprint(source_public),
        },
        "to": {
            "algorithm": ED25519_ALGORITHM,
            "key_id": target_id,
            "public_key_base64": target_public,
            "public_key_sha256": public_key_fingerprint(target_public),
        },
        "effective_at": effective,
        "reason_sha256": _sha256_text(reason_text),
        "created_at": created_at,
    }
    payload = _transition_payload(statement)
    source_signature = sign_ed25519(source_private, payload)
    target_signature = sign_ed25519(target_private, payload)
    statement_json = _canonical_json_bytes(statement).decode("utf-8")

    with write_transaction(db_path, operation="create_integrity_proof_key_transition") as conn:
        existing = conn.execute(
            "SELECT transition_id FROM integrity_proof_key_transitions "
            "WHERE from_public_key_sha256=? AND to_public_key_sha256=?",
            (statement["from"]["public_key_sha256"], statement["to"]["public_key_sha256"]),
        ).fetchone()
        if existing:
            raise ValueError(f"동일한 키 전환이 이미 존재합니다: {existing['transition_id']}")
        conn.execute(
            """INSERT INTO integrity_proof_key_transitions(
                   transition_id,from_key_id,from_public_key_base64,from_public_key_sha256,
                   to_key_id,to_public_key_base64,to_public_key_sha256,effective_at,
                   reason_sha256,statement_json,from_signature,to_signature,created_by,created_at
               ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                transition_id,
                source_id,
                source_public,
                statement["from"]["public_key_sha256"],
                target_id,
                target_public,
                statement["to"]["public_key_sha256"],
                effective,
                statement["reason_sha256"],
                statement_json,
                source_signature,
                target_signature,
                str(actor or "local-user"),
                created_at,
            ),
        )
        add_audit_event(
            db_path,
            finding_id=None,
            event_type="integrity_proof.key_transition_created",
            summary=f"Ed25519 proof key transition {source_id} → {target_id}",
            details={
                "transition_id": transition_id,
                "from_key_id": source_id,
                "from_public_key_sha256": statement["from"]["public_key_sha256"],
                "to_key_id": target_id,
                "to_public_key_sha256": statement["to"]["public_key_sha256"],
                "effective_at": effective,
                "reason_sha256": statement["reason_sha256"],
            },
            actor=str(actor or "local-user"),
            conn=conn,
        )
    return transition_document_from_values(statement, source_signature, target_signature)


def transition_document_from_values(
    statement: Mapping[str, Any], from_signature: str, to_signature: str
) -> dict[str, Any]:
    return {
        "statement": dict(statement),
        "signatures": {
            "from": {"algorithm": ED25519_ALGORITHM, "signature_base64": str(from_signature)},
            "to": {"algorithm": ED25519_ALGORITHM, "signature_base64": str(to_signature)},
        },
    }


def _row_to_document(row: Mapping[str, Any]) -> dict[str, Any]:
    statement = json.loads(str(row["statement_json"]))
    return transition_document_from_values(statement, str(row["from_signature"]), str(row["to_signature"]))


def list_integrity_proof_key_transitions(
    db_path: str | Path, *, limit: int = 100
) -> list[dict[str, Any]]:
    safe_limit = max(1, min(int(limit), 1000))
    with read_connection(db_path, operation="list_integrity_proof_key_transitions") as conn:
        rows = conn.execute(
            "SELECT transition_id,from_key_id,from_public_key_sha256,to_key_id,to_public_key_sha256,"
            "effective_at,reason_sha256,created_by,created_at,statement_json,from_signature,to_signature "
            "FROM integrity_proof_key_transitions ORDER BY created_at,transition_id LIMIT ?",
            (safe_limit,),
        ).fetchall()
    return [dict(row) | {"document": _row_to_document(row)} for row in rows]


def export_integrity_proof_key_transitions(db_path: str | Path) -> list[dict[str, Any]]:
    rows = list_integrity_proof_key_transitions(db_path, limit=MAX_TRANSITIONS_PER_PROOF + 1)
    if len(rows) > MAX_TRANSITIONS_PER_PROOF:
        raise RuntimeError(
            f"무결성 proof에 포함할 키 전환 수가 제한({MAX_TRANSITIONS_PER_PROOF})을 초과했습니다."
        )
    return [dict(row["document"]) for row in rows]


def validate_transition_document(document: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(document, Mapping):
        raise ValueError("키 전환 문서는 JSON 객체여야 합니다.")
    statement = document.get("statement")
    signatures = document.get("signatures")
    if not isinstance(statement, Mapping) or not isinstance(signatures, Mapping):
        raise ValueError("키 전환 statement 또는 signatures가 없습니다.")
    if str(statement.get("format") or "") != TRANSITION_FORMAT:
        raise ValueError("지원하지 않는 키 전환 형식입니다.")
    source = statement.get("from")
    target = statement.get("to")
    if not isinstance(source, Mapping) or not isinstance(target, Mapping):
        raise ValueError("키 전환의 from/to 공개키 정보가 없습니다.")
    source_id = str(source.get("key_id") or "")
    target_id = str(target.get("key_id") or "")
    if not KEY_ID_RE.fullmatch(source_id) or not KEY_ID_RE.fullmatch(target_id) or source_id == target_id:
        raise ValueError("키 전환의 key ID가 올바르지 않습니다.")
    source_key = str(source.get("public_key_base64") or "")
    target_key = str(target.get("public_key_base64") or "")
    source_fp = public_key_fingerprint(source_key)
    target_fp = public_key_fingerprint(target_key)
    if source_fp != str(source.get("public_key_sha256") or ""):
        raise ValueError("키 전환 이전 공개키 fingerprint가 일치하지 않습니다.")
    if target_fp != str(target.get("public_key_sha256") or ""):
        raise ValueError("키 전환 신규 공개키 fingerprint가 일치하지 않습니다.")
    effective = _normalize_timestamp(str(statement.get("effective_at") or ""), field="effective_at")
    created = _normalize_timestamp(str(statement.get("created_at") or ""), field="created_at")
    if len(str(statement.get("reason_sha256") or "")) != 64:
        raise ValueError("키 전환 사유 digest가 올바르지 않습니다.")
    payload = _transition_payload(statement)
    source_sig = signatures.get("from") if isinstance(signatures.get("from"), Mapping) else {}
    target_sig = signatures.get("to") if isinstance(signatures.get("to"), Mapping) else {}
    if not verify_ed25519(
        signature_base64=str(source_sig.get("signature_base64") or ""),
        public_key_base64=source_key,
        payload=payload,
    ):
        raise ValueError("키 전환의 이전 키 서명이 일치하지 않습니다.")
    if not verify_ed25519(
        signature_base64=str(target_sig.get("signature_base64") or ""),
        public_key_base64=target_key,
        payload=payload,
    ):
        raise ValueError("키 전환의 신규 키 서명이 일치하지 않습니다.")
    return {
        "transition_id": str(statement.get("transition_id") or ""),
        "from_key_id": source_id,
        "from_public_key": source_key,
        "from_public_key_sha256": source_fp,
        "to_key_id": target_id,
        "to_public_key": target_key,
        "to_public_key_sha256": target_fp,
        "effective_at": effective,
        "created_at": created,
    }
