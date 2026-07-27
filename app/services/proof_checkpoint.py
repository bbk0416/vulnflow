from __future__ import annotations

"""Signed monotonic checkpoints for integrity-proof trust registries.

A checkpoint binds the complete public key-transition and emergency-revocation
registries to a monotonically increasing sequence.  The recovery root signs the
checkpoint; verifiers must pin that public root independently and may enforce a
minimum accepted sequence or exact checkpoint digest to detect stale or rolled
back registries.
"""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping, Sequence
import uuid

from app.core.db import utc_now
from app.core.public_signing import ED25519_ALGORITHM, public_key_fingerprint, sign_ed25519, verify_ed25519
from app.core.signing import KEY_ID_RE
from app.core.transactions import read_connection, write_transaction
from app.repositories.audit import add_audit_event
from app.services.proof_revocation import export_integrity_proof_key_revocations
from app.services.proof_transitions import export_integrity_proof_key_transitions

CHECKPOINT_FORMAT = "vulnflow-integrity-proof-revocation-checkpoint/1"
MAX_CHECKPOINTS_PER_PROOF = 64
ZERO_SHA256 = "0" * 64


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _registry_digest(rows: Sequence[Mapping[str, Any]]) -> str:
    return _sha256_bytes(_canonical_json_bytes([dict(row) for row in rows]))


def _payload(statement: Mapping[str, Any]) -> bytes:
    return b"vulnflow-integrity-proof-revocation-checkpoint/1\n" + _canonical_json_bytes(dict(statement))


def checkpoint_document_sha256(document: Mapping[str, Any]) -> str:
    canonical = {"statement": document.get("statement"), "signature": document.get("signature")}
    return _sha256_bytes(_canonical_json_bytes(canonical))


def checkpoint_document_from_values(statement: Mapping[str, Any], signature: str) -> dict[str, Any]:
    return {
        "statement": dict(statement),
        "signature": {"algorithm": ED25519_ALGORITHM, "signature_base64": str(signature)},
    }


def create_integrity_proof_revocation_checkpoint(
    db_path: str | Path,
    *,
    recovery_key_id: str,
    private_keys: Mapping[str, str],
    public_keys: Mapping[str, str],
    actor: str,
) -> dict[str, Any]:
    key_id = str(recovery_key_id or "").strip()
    if not KEY_ID_RE.fullmatch(key_id):
        raise ValueError("recovery key ID 형식이 올바르지 않습니다.")
    private_key = str(dict(private_keys).get(key_id, ""))
    public_key = str(dict(public_keys).get(key_id, ""))
    if not private_key or not public_key:
        raise ValueError("checkpoint 생성에는 recovery private/public key가 모두 필요합니다.")

    transitions = export_integrity_proof_key_transitions(db_path)
    revocations = export_integrity_proof_key_revocations(db_path)
    transition_digest = _registry_digest(transitions)
    revocation_digest = _registry_digest(revocations)
    created_at = utc_now()

    with write_transaction(db_path, operation="create_integrity_proof_revocation_checkpoint") as conn:
        previous = conn.execute(
            "SELECT sequence,document_sha256 FROM integrity_proof_revocation_checkpoints "
            "ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        sequence = int(previous["sequence"]) + 1 if previous else 1
        previous_digest = str(previous["document_sha256"]) if previous else ZERO_SHA256
        latest_same = conn.execute(
            "SELECT checkpoint_id,revocation_registry_sha256,transition_registry_sha256 "
            "FROM integrity_proof_revocation_checkpoints ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        if latest_same and str(latest_same["revocation_registry_sha256"]) == revocation_digest \
                and str(latest_same["transition_registry_sha256"]) == transition_digest:
            raise ValueError(f"현재 registry는 이미 checkpoint에 고정되어 있습니다: {latest_same['checkpoint_id']}")

        checkpoint_id = f"IPRC-{uuid.uuid4().hex[:20].upper()}"
        statement = {
            "format": CHECKPOINT_FORMAT,
            "checkpoint_id": checkpoint_id,
            "sequence": sequence,
            "previous_checkpoint_sha256": previous_digest,
            "revocation_count": len(revocations),
            "revocation_registry_sha256": revocation_digest,
            "transition_count": len(transitions),
            "transition_registry_sha256": transition_digest,
            "recovery": {
                "algorithm": ED25519_ALGORITHM,
                "key_id": key_id,
                "public_key_base64": public_key,
                "public_key_sha256": public_key_fingerprint(public_key),
            },
            "created_at": created_at,
        }
        signature = sign_ed25519(private_key, _payload(statement))
        document = checkpoint_document_from_values(statement, signature)
        document_sha256 = checkpoint_document_sha256(document)
        conn.execute(
            """INSERT INTO integrity_proof_revocation_checkpoints(
                   checkpoint_id,sequence,previous_checkpoint_sha256,
                   revocation_count,revocation_registry_sha256,
                   transition_count,transition_registry_sha256,
                   recovery_key_id,recovery_public_key_base64,recovery_public_key_sha256,
                   statement_json,signature,document_sha256,created_by,created_at
               ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                checkpoint_id, sequence, previous_digest,
                len(revocations), revocation_digest,
                len(transitions), transition_digest,
                key_id, public_key, public_key_fingerprint(public_key),
                _canonical_json_bytes(statement).decode("utf-8"), signature,
                document_sha256, str(actor or "local-user"), created_at,
            ),
        )
        add_audit_event(
            db_path,
            finding_id=None,
            event_type="integrity_proof.revocation_checkpoint_created",
            summary=f"Revocation registry checkpoint #{sequence} created",
            details={
                "checkpoint_id": checkpoint_id,
                "sequence": sequence,
                "document_sha256": document_sha256,
                "revocation_count": len(revocations),
                "transition_count": len(transitions),
                "recovery_key_id": key_id,
            },
            actor=str(actor or "local-user"),
            conn=conn,
        )
    return document | {"document_sha256": document_sha256}


def _row_to_document(row: Mapping[str, Any]) -> dict[str, Any]:
    return checkpoint_document_from_values(json.loads(str(row["statement_json"])), str(row["signature"]))


def list_integrity_proof_revocation_checkpoints(
    db_path: str | Path, *, limit: int = 100
) -> list[dict[str, Any]]:
    safe_limit = max(1, min(int(limit), 1000))
    with read_connection(db_path, operation="list_integrity_proof_revocation_checkpoints") as conn:
        rows = conn.execute(
            "SELECT checkpoint_id,sequence,previous_checkpoint_sha256,revocation_count,"
            "revocation_registry_sha256,transition_count,transition_registry_sha256,"
            "recovery_key_id,recovery_public_key_sha256,document_sha256,created_by,created_at,"
            "statement_json,signature FROM integrity_proof_revocation_checkpoints "
            "ORDER BY sequence DESC LIMIT ?",
            (safe_limit,),
        ).fetchall()
    return [dict(row) | {"document": _row_to_document(row)} for row in rows]


def export_integrity_proof_revocation_checkpoints(db_path: str | Path) -> list[dict[str, Any]]:
    rows = list_integrity_proof_revocation_checkpoints(db_path, limit=MAX_CHECKPOINTS_PER_PROOF + 1)
    if len(rows) > MAX_CHECKPOINTS_PER_PROOF:
        raise RuntimeError(
            f"무결성 proof에 포함할 registry checkpoint 수가 제한({MAX_CHECKPOINTS_PER_PROOF})을 초과했습니다."
        )
    return [dict(row["document"]) for row in reversed(rows)]


def validate_revocation_checkpoint_document(document: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(document, Mapping):
        raise ValueError("registry checkpoint는 JSON 객체여야 합니다.")
    statement = document.get("statement")
    signature = document.get("signature")
    if not isinstance(statement, Mapping) or not isinstance(signature, Mapping):
        raise ValueError("registry checkpoint statement 또는 signature가 없습니다.")
    if str(statement.get("format") or "") != CHECKPOINT_FORMAT:
        raise ValueError("지원하지 않는 registry checkpoint 형식입니다.")
    checkpoint_id = str(statement.get("checkpoint_id") or "")
    if not checkpoint_id.startswith("IPRC-"):
        raise ValueError("registry checkpoint ID가 올바르지 않습니다.")
    sequence = int(statement.get("sequence") or 0)
    if sequence < 1:
        raise ValueError("registry checkpoint sequence가 올바르지 않습니다.")
    previous = str(statement.get("previous_checkpoint_sha256") or "")
    if len(previous) != 64 or any(ch not in "0123456789abcdef" for ch in previous.lower()):
        raise ValueError("이전 registry checkpoint digest가 올바르지 않습니다.")
    for field in ("revocation_registry_sha256", "transition_registry_sha256"):
        digest = str(statement.get(field) or "")
        if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest.lower()):
            raise ValueError(f"{field}가 올바르지 않습니다.")
    if int(statement.get("revocation_count") or 0) < 0 or int(statement.get("transition_count") or 0) < 0:
        raise ValueError("registry checkpoint count가 올바르지 않습니다.")
    recovery = statement.get("recovery")
    if not isinstance(recovery, Mapping):
        raise ValueError("registry checkpoint recovery 공개키 정보가 없습니다.")
    key_id = str(recovery.get("key_id") or "")
    public_key = str(recovery.get("public_key_base64") or "")
    fingerprint = public_key_fingerprint(public_key)
    if not KEY_ID_RE.fullmatch(key_id) or fingerprint != str(recovery.get("public_key_sha256") or ""):
        raise ValueError("registry checkpoint recovery 공개키 정보가 올바르지 않습니다.")
    created_at = str(statement.get("created_at") or "")
    try:
        parsed = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("registry checkpoint created_at이 올바르지 않습니다.") from exc
    if parsed.tzinfo is None:
        raise ValueError("registry checkpoint created_at에는 시간대가 필요합니다.")
    if str(signature.get("algorithm") or "") != ED25519_ALGORITHM or not verify_ed25519(
        signature_base64=str(signature.get("signature_base64") or ""),
        public_key_base64=public_key,
        payload=_payload(statement),
    ):
        raise ValueError("registry checkpoint recovery 서명이 일치하지 않습니다.")
    return {
        "checkpoint_id": checkpoint_id,
        "sequence": sequence,
        "previous_checkpoint_sha256": previous,
        "revocation_count": int(statement.get("revocation_count") or 0),
        "revocation_registry_sha256": str(statement.get("revocation_registry_sha256")),
        "transition_count": int(statement.get("transition_count") or 0),
        "transition_registry_sha256": str(statement.get("transition_registry_sha256")),
        "recovery_key_id": key_id,
        "recovery_public_key": public_key,
        "recovery_public_key_sha256": fingerprint,
        "created_at": parsed.astimezone(timezone.utc).replace(microsecond=0).isoformat(),
        "document_sha256": checkpoint_document_sha256(document),
    }


def verify_revocation_checkpoint_chain(
    documents: Sequence[Mapping[str, Any]],
    *,
    pinned_public_keys: Mapping[str, str] | None,
    revocations: Sequence[Mapping[str, Any]],
    transitions: Sequence[Mapping[str, Any]],
    minimum_sequence: int = 0,
    trusted_checkpoint_sha256: str = "",
) -> dict[str, Any]:
    if not documents:
        if int(minimum_sequence) > 0 or str(trusted_checkpoint_sha256 or "").strip():
            raise ValueError("요구된 registry checkpoint가 제공되지 않았습니다.")
        return {"status": "revocation-freshness-unverified", "sequence": 0, "document_sha256": ""}

    validated = [validate_revocation_checkpoint_document(item) for item in documents]
    validated.sort(key=lambda item: item["sequence"])
    expected_previous = ZERO_SHA256
    expected_sequence = validated[0]["sequence"]
    if expected_sequence != 1:
        raise ValueError("registry checkpoint 체인은 sequence 1부터 시작해야 합니다.")
    seen_sequences: set[int] = set()
    for item in validated:
        if item["sequence"] in seen_sequences or item["sequence"] != expected_sequence:
            raise ValueError("registry checkpoint sequence가 중복되거나 연속적이지 않습니다.")
        if item["previous_checkpoint_sha256"] != expected_previous:
            raise ValueError("registry checkpoint 이전 digest 연결이 일치하지 않습니다.")
        pinned = str(dict(pinned_public_keys or {}).get(item["recovery_key_id"], ""))
        if not pinned or public_key_fingerprint(pinned) != item["recovery_public_key_sha256"]:
            raise ValueError("registry checkpoint recovery root가 외부에서 고정되지 않았거나 일치하지 않습니다.")
        seen_sequences.add(item["sequence"])
        expected_previous = item["document_sha256"]
        expected_sequence += 1

    latest = validated[-1]
    if latest["sequence"] < max(0, int(minimum_sequence)):
        raise ValueError("registry checkpoint sequence가 검증자가 요구한 최소값보다 오래되었습니다.")
    trusted_digest = str(trusted_checkpoint_sha256 or "").strip().lower()
    if trusted_digest and latest["document_sha256"] != trusted_digest:
        raise ValueError("최신 registry checkpoint digest가 외부 고정값과 일치하지 않습니다.")
    revocation_rows = [dict(row) for row in revocations]
    transition_rows = [dict(row) for row in transitions]
    if latest["revocation_count"] != len(revocation_rows) or latest["revocation_registry_sha256"] != _registry_digest(revocation_rows):
        raise ValueError("revocation registry가 최신 checkpoint에 고정된 내용과 일치하지 않습니다.")
    if latest["transition_count"] != len(transition_rows) or latest["transition_registry_sha256"] != _registry_digest(transition_rows):
        raise ValueError("transition registry가 최신 checkpoint에 고정된 내용과 일치하지 않습니다.")
    return {
        "status": "revocation-freshness-verified",
        "sequence": latest["sequence"],
        "checkpoint_id": latest["checkpoint_id"],
        "document_sha256": latest["document_sha256"],
        "recovery_key_id": latest["recovery_key_id"],
    }
