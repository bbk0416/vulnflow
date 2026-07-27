from __future__ import annotations

"""Emergency Ed25519 proof-key revocation and recovery statements.

Unlike planned key transitions, a revocation does not require the compromised
private key.  It is authorized by a separately pinned recovery root and the
replacement key, then preserved as an immutable public statement.
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

REVOCATION_FORMAT = "vulnflow-integrity-proof-key-revocation/1"
MAX_REVOCATIONS_PER_PROOF = 64


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256_text(value: str) -> str:
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()


def _payload(statement: Mapping[str, Any]) -> bytes:
    return b"vulnflow-integrity-proof-key-revocation/1\n" + _canonical_json_bytes(dict(statement))


def _normalize_timestamp(value: str, *, field: str) -> str:
    text = str(value or "").strip() or utc_now()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field}는 ISO-8601 시각이어야 합니다.") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{field}에는 시간대가 포함되어야 합니다.")
    return parsed.astimezone(timezone.utc).replace(microsecond=0).isoformat()


def create_integrity_proof_key_revocation(
    db_path: str | Path,
    *,
    revoked_key_id: str,
    replacement_key_id: str,
    recovery_key_id: str,
    private_keys: Mapping[str, str],
    public_keys: Mapping[str, str],
    actor: str,
    reason: str,
    invalid_after: str,
    effective_at: str = "",
) -> dict[str, Any]:
    revoked_id = str(revoked_key_id or "").strip()
    replacement_id = str(replacement_key_id or "").strip()
    recovery_id = str(recovery_key_id or "").strip()
    ids = (revoked_id, replacement_id, recovery_id)
    if any(not KEY_ID_RE.fullmatch(item) for item in ids):
        raise ValueError("폐기·대체·recovery 키 ID 형식이 올바르지 않습니다.")
    if len(set(ids)) != 3:
        raise ValueError("폐기 키, 대체 키, recovery root는 서로 달라야 합니다.")

    public = dict(public_keys)
    private = dict(private_keys)
    revoked_public = str(public.get(revoked_id, ""))
    replacement_public = str(public.get(replacement_id, ""))
    recovery_public = str(public.get(recovery_id, ""))
    replacement_private = str(private.get(replacement_id, ""))
    recovery_private = str(private.get(recovery_id, ""))
    if not revoked_public or not replacement_public or not recovery_public:
        raise ValueError("폐기·대체·recovery 공개키가 모두 필요합니다.")
    if not replacement_private or not recovery_private:
        raise ValueError("비상 폐기에는 대체 키와 recovery root의 private key가 필요합니다.")

    reason_text = str(reason or "").strip()
    if len(reason_text) < 3 or len(reason_text) > 1500:
        raise ValueError("키 폐기 사유는 3자 이상 1500자 이하여야 합니다.")
    invalid = _normalize_timestamp(invalid_after, field="invalid_after")
    effective = _normalize_timestamp(effective_at, field="effective_at")
    if datetime.fromisoformat(effective) < datetime.fromisoformat(invalid):
        raise ValueError("effective_at은 invalid_after보다 빠를 수 없습니다.")

    created_at = utc_now()
    revocation_id = f"IPKR-{uuid.uuid4().hex[:20].upper()}"
    statement = {
        "format": REVOCATION_FORMAT,
        "revocation_id": revocation_id,
        "revoked": {
            "algorithm": ED25519_ALGORITHM,
            "key_id": revoked_id,
            "public_key_base64": revoked_public,
            "public_key_sha256": public_key_fingerprint(revoked_public),
        },
        "replacement": {
            "algorithm": ED25519_ALGORITHM,
            "key_id": replacement_id,
            "public_key_base64": replacement_public,
            "public_key_sha256": public_key_fingerprint(replacement_public),
        },
        "recovery": {
            "algorithm": ED25519_ALGORITHM,
            "key_id": recovery_id,
            "public_key_base64": recovery_public,
            "public_key_sha256": public_key_fingerprint(recovery_public),
        },
        "invalid_after": invalid,
        "effective_at": effective,
        "reason_sha256": _sha256_text(reason_text),
        "created_at": created_at,
    }
    payload = _payload(statement)
    recovery_signature = sign_ed25519(recovery_private, payload)
    replacement_signature = sign_ed25519(replacement_private, payload)
    statement_json = _canonical_json_bytes(statement).decode("utf-8")

    with write_transaction(db_path, operation="create_integrity_proof_key_revocation") as conn:
        existing = conn.execute(
            "SELECT revocation_id FROM integrity_proof_key_revocations WHERE revoked_public_key_sha256=?",
            (statement["revoked"]["public_key_sha256"],),
        ).fetchone()
        if existing:
            raise ValueError(f"해당 공개키의 폐기 기록이 이미 존재합니다: {existing['revocation_id']}")
        conn.execute(
            """INSERT INTO integrity_proof_key_revocations(
                   revocation_id,revoked_key_id,revoked_public_key_base64,revoked_public_key_sha256,
                   replacement_key_id,replacement_public_key_base64,replacement_public_key_sha256,
                   recovery_key_id,recovery_public_key_base64,recovery_public_key_sha256,
                   invalid_after,effective_at,reason_sha256,statement_json,
                   recovery_signature,replacement_signature,created_by,created_at
               ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                revocation_id,
                revoked_id,
                revoked_public,
                statement["revoked"]["public_key_sha256"],
                replacement_id,
                replacement_public,
                statement["replacement"]["public_key_sha256"],
                recovery_id,
                recovery_public,
                statement["recovery"]["public_key_sha256"],
                invalid,
                effective,
                statement["reason_sha256"],
                statement_json,
                recovery_signature,
                replacement_signature,
                str(actor or "local-user"),
                created_at,
            ),
        )
        add_audit_event(
            db_path,
            finding_id=None,
            event_type="integrity_proof.key_revocation_created",
            summary=f"Ed25519 proof key revoked {revoked_id} → {replacement_id}",
            details={
                "revocation_id": revocation_id,
                "revoked_key_id": revoked_id,
                "revoked_public_key_sha256": statement["revoked"]["public_key_sha256"],
                "replacement_key_id": replacement_id,
                "replacement_public_key_sha256": statement["replacement"]["public_key_sha256"],
                "recovery_key_id": recovery_id,
                "recovery_public_key_sha256": statement["recovery"]["public_key_sha256"],
                "invalid_after": invalid,
                "effective_at": effective,
                "reason_sha256": statement["reason_sha256"],
            },
            actor=str(actor or "local-user"),
            conn=conn,
        )
    return revocation_document_from_values(statement, recovery_signature, replacement_signature)


def revocation_document_from_values(
    statement: Mapping[str, Any], recovery_signature: str, replacement_signature: str
) -> dict[str, Any]:
    return {
        "statement": dict(statement),
        "signatures": {
            "recovery": {"algorithm": ED25519_ALGORITHM, "signature_base64": str(recovery_signature)},
            "replacement": {"algorithm": ED25519_ALGORITHM, "signature_base64": str(replacement_signature)},
        },
    }


def _row_to_document(row: Mapping[str, Any]) -> dict[str, Any]:
    return revocation_document_from_values(
        json.loads(str(row["statement_json"])),
        str(row["recovery_signature"]),
        str(row["replacement_signature"]),
    )


def list_integrity_proof_key_revocations(
    db_path: str | Path, *, limit: int = 100
) -> list[dict[str, Any]]:
    safe_limit = max(1, min(int(limit), 1000))
    with read_connection(db_path, operation="list_integrity_proof_key_revocations") as conn:
        rows = conn.execute(
            "SELECT revocation_id,revoked_key_id,revoked_public_key_sha256,replacement_key_id,"
            "replacement_public_key_sha256,recovery_key_id,recovery_public_key_sha256,invalid_after,"
            "effective_at,reason_sha256,created_by,created_at,statement_json,recovery_signature,"
            "replacement_signature FROM integrity_proof_key_revocations "
            "ORDER BY created_at,revocation_id LIMIT ?",
            (safe_limit,),
        ).fetchall()
    return [dict(row) | {"document": _row_to_document(row)} for row in rows]


def export_integrity_proof_key_revocations(db_path: str | Path) -> list[dict[str, Any]]:
    rows = list_integrity_proof_key_revocations(db_path, limit=MAX_REVOCATIONS_PER_PROOF + 1)
    if len(rows) > MAX_REVOCATIONS_PER_PROOF:
        raise RuntimeError(
            f"무결성 proof에 포함할 키 폐기 수가 제한({MAX_REVOCATIONS_PER_PROOF})을 초과했습니다."
        )
    return [dict(row["document"]) for row in rows]


def validate_revocation_document(document: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(document, Mapping):
        raise ValueError("키 폐기 문서는 JSON 객체여야 합니다.")
    statement = document.get("statement")
    signatures = document.get("signatures")
    if not isinstance(statement, Mapping) or not isinstance(signatures, Mapping):
        raise ValueError("키 폐기 statement 또는 signatures가 없습니다.")
    if str(statement.get("format") or "") != REVOCATION_FORMAT:
        raise ValueError("지원하지 않는 키 폐기 형식입니다.")
    sections: dict[str, Mapping[str, Any]] = {}
    for name in ("revoked", "replacement", "recovery"):
        value = statement.get(name)
        if not isinstance(value, Mapping):
            raise ValueError(f"키 폐기 문서의 {name} 공개키 정보가 없습니다.")
        sections[name] = value
    ids = [str(sections[name].get("key_id") or "") for name in sections]
    if any(not KEY_ID_RE.fullmatch(item) for item in ids) or len(set(ids)) != 3:
        raise ValueError("키 폐기 문서의 key ID가 올바르지 않습니다.")
    normalized: dict[str, dict[str, str]] = {}
    for name, value in sections.items():
        public_key = str(value.get("public_key_base64") or "")
        fingerprint = public_key_fingerprint(public_key)
        if fingerprint != str(value.get("public_key_sha256") or ""):
            raise ValueError(f"키 폐기 {name} 공개키 fingerprint가 일치하지 않습니다.")
        normalized[name] = {
            "key_id": str(value.get("key_id")),
            "public_key": public_key,
            "public_key_sha256": fingerprint,
        }
    invalid = _normalize_timestamp(str(statement.get("invalid_after") or ""), field="invalid_after")
    effective = _normalize_timestamp(str(statement.get("effective_at") or ""), field="effective_at")
    created = _normalize_timestamp(str(statement.get("created_at") or ""), field="created_at")
    if datetime.fromisoformat(effective) < datetime.fromisoformat(invalid):
        raise ValueError("키 폐기 effective_at이 invalid_after보다 빠릅니다.")
    if len(str(statement.get("reason_sha256") or "")) != 64:
        raise ValueError("키 폐기 사유 digest가 올바르지 않습니다.")
    payload = _payload(statement)
    recovery_sig = signatures.get("recovery") if isinstance(signatures.get("recovery"), Mapping) else {}
    replacement_sig = signatures.get("replacement") if isinstance(signatures.get("replacement"), Mapping) else {}
    if not verify_ed25519(
        signature_base64=str(recovery_sig.get("signature_base64") or ""),
        public_key_base64=normalized["recovery"]["public_key"],
        payload=payload,
    ):
        raise ValueError("키 폐기 recovery root 서명이 일치하지 않습니다.")
    if not verify_ed25519(
        signature_base64=str(replacement_sig.get("signature_base64") or ""),
        public_key_base64=normalized["replacement"]["public_key"],
        payload=payload,
    ):
        raise ValueError("키 폐기 대체 키 서명이 일치하지 않습니다.")
    return {
        "revocation_id": str(statement.get("revocation_id") or ""),
        "invalid_after": invalid,
        "effective_at": effective,
        "created_at": created,
        **{f"{name}_key_id": value["key_id"] for name, value in normalized.items()},
        **{f"{name}_public_key": value["public_key"] for name, value in normalized.items()},
        **{f"{name}_public_key_sha256": value["public_key_sha256"] for name, value in normalized.items()},
    }


def trusted_revocation_state(
    documents: list[Mapping[str, Any]] | tuple[Mapping[str, Any], ...],
    *,
    pinned_public_keys: Mapping[str, str],
    verification_time: str,
) -> tuple[list[dict[str, Any]], dict[tuple[str, str], datetime]]:
    checked_at = datetime.fromisoformat(_normalize_timestamp(verification_time, field="verification_time"))
    trusted: list[dict[str, Any]] = []
    cutoffs: dict[tuple[str, str], datetime] = {}
    for document in documents:
        item = validate_revocation_document(document)
        recovery_pinned = str(dict(pinned_public_keys).get(item["recovery_key_id"], ""))
        if not recovery_pinned:
            continue
        if public_key_fingerprint(recovery_pinned) != item["recovery_public_key_sha256"]:
            raise ValueError("고정된 emergency recovery 공개키가 폐기 문서와 일치하지 않습니다.")
        if datetime.fromisoformat(item["effective_at"]) > checked_at:
            continue
        trusted.append(item)
        node = (item["revoked_key_id"], item["revoked_public_key_sha256"])
        invalid = datetime.fromisoformat(item["invalid_after"])
        if node not in cutoffs or invalid < cutoffs[node]:
            cutoffs[node] = invalid
    return trusted, cutoffs


def emergency_recovery_edges(
    revocations: list[dict[str, Any]], *, proof_time: datetime
) -> dict[tuple[str, str], list[dict[str, Any]]]:
    edges: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for item in revocations:
        if datetime.fromisoformat(item["effective_at"]) > proof_time:
            continue
        node = (item["recovery_key_id"], item["recovery_public_key_sha256"])
        edges.setdefault(node, []).append({
            "edge_kind": "revocation",
            "transition_id": item["revocation_id"],
            "to_key_id": item["replacement_key_id"],
            "to_public_key_sha256": item["replacement_public_key_sha256"],
        })
    return edges
