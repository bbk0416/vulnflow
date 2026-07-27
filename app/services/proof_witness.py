from __future__ import annotations

"""Independent witness attestations for revocation-registry checkpoints.

A witness signs the digest and registry state of an already recovery-root-signed
checkpoint. Witness private keys are supplied only for the signing operation and
are never persisted. Offline verifiers establish witness trust by pinning public
keys independently and may require a distinct-key quorum.
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
from app.services.proof_checkpoint import (
    checkpoint_document_from_values,
    checkpoint_document_sha256,
    validate_revocation_checkpoint_document,
)

WITNESS_FORMAT = "vulnflow-integrity-proof-checkpoint-witness/1"
MAX_WITNESSES_PER_PROOF = 64


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _payload(statement: Mapping[str, Any]) -> bytes:
    return b"vulnflow-integrity-proof-checkpoint-witness/1\n" + _canonical_json_bytes(dict(statement))


def witness_document_sha256(document: Mapping[str, Any]) -> str:
    canonical = {"statement": document.get("statement"), "signature": document.get("signature")}
    return _sha256_bytes(_canonical_json_bytes(canonical))


def witness_document_from_values(statement: Mapping[str, Any], signature: str) -> dict[str, Any]:
    return {
        "statement": dict(statement),
        "signature": {"algorithm": ED25519_ALGORITHM, "signature_base64": str(signature)},
    }


def _checkpoint_document_from_row(row: Mapping[str, Any]) -> dict[str, Any]:
    return checkpoint_document_from_values(json.loads(str(row["statement_json"])), str(row["signature"]))


def create_integrity_proof_checkpoint_witness(
    db_path: str | Path,
    *,
    witness_key_id: str,
    private_keys: Mapping[str, str],
    public_keys: Mapping[str, str],
    actor: str,
    checkpoint_id: str = "",
) -> dict[str, Any]:
    key_id = str(witness_key_id or "").strip()
    if not KEY_ID_RE.fullmatch(key_id):
        raise ValueError("witness key ID 형식이 올바르지 않습니다.")
    private_key = str(dict(private_keys).get(key_id, ""))
    public_key = str(dict(public_keys).get(key_id, ""))
    if not private_key or not public_key:
        raise ValueError("witness attestation 생성에는 witness private/public key가 모두 필요합니다.")

    with write_transaction(db_path, operation="create_integrity_proof_checkpoint_witness") as conn:
        if str(checkpoint_id or "").strip():
            row = conn.execute(
                "SELECT checkpoint_id,sequence,statement_json,signature,document_sha256 "
                "FROM integrity_proof_revocation_checkpoints WHERE checkpoint_id=?",
                (str(checkpoint_id).strip(),),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT checkpoint_id,sequence,statement_json,signature,document_sha256 "
                "FROM integrity_proof_revocation_checkpoints ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
        if row is None:
            raise ValueError("witness가 확인할 registry checkpoint가 없습니다.")
        checkpoint_document = _checkpoint_document_from_row(row)
        checkpoint = validate_revocation_checkpoint_document(checkpoint_document)
        checkpoint_digest = checkpoint_document_sha256(checkpoint_document)
        if checkpoint_digest != str(row["document_sha256"]):
            raise ValueError("registry checkpoint 저장 digest가 문서와 일치하지 않습니다.")
        witness_fingerprint = public_key_fingerprint(public_key)
        if witness_fingerprint == checkpoint["recovery_public_key_sha256"]:
            raise ValueError("witness 키는 checkpoint recovery root와 독립된 키여야 합니다.")

        existing = conn.execute(
            "SELECT attestation_id,checkpoint_document_sha256 FROM integrity_proof_checkpoint_witnesses "
            "WHERE witness_public_key_sha256=? AND checkpoint_sequence=?",
            (witness_fingerprint, int(checkpoint["sequence"])),
        ).fetchone()
        if existing:
            if str(existing["checkpoint_document_sha256"]) == checkpoint_digest:
                raise ValueError(f"해당 witness는 이미 checkpoint를 확인했습니다: {existing['attestation_id']}")
            raise ValueError("동일 witness가 같은 sequence의 상충 checkpoint를 확인할 수 없습니다.")

        observed_at = utc_now()
        attestation_id = f"IPWA-{uuid.uuid4().hex[:20].upper()}"
        statement = {
            "format": WITNESS_FORMAT,
            "attestation_id": attestation_id,
            "checkpoint": {
                "checkpoint_id": checkpoint["checkpoint_id"],
                "sequence": int(checkpoint["sequence"]),
                "document_sha256": checkpoint_digest,
                "revocation_registry_sha256": checkpoint["revocation_registry_sha256"],
                "transition_registry_sha256": checkpoint["transition_registry_sha256"],
            },
            "witness": {
                "algorithm": ED25519_ALGORITHM,
                "key_id": key_id,
                "public_key_base64": public_key,
                "public_key_sha256": witness_fingerprint,
            },
            "observed_at": observed_at,
        }
        signature = sign_ed25519(private_key, _payload(statement))
        document = witness_document_from_values(statement, signature)
        document_sha256 = witness_document_sha256(document)
        conn.execute(
            """INSERT INTO integrity_proof_checkpoint_witnesses(
                   attestation_id,checkpoint_id,checkpoint_sequence,checkpoint_document_sha256,
                   revocation_registry_sha256,transition_registry_sha256,
                   witness_key_id,witness_public_key_base64,witness_public_key_sha256,
                   observed_at,statement_json,signature,document_sha256,created_by,created_at
               ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                attestation_id, checkpoint["checkpoint_id"], int(checkpoint["sequence"]), checkpoint_digest,
                checkpoint["revocation_registry_sha256"], checkpoint["transition_registry_sha256"],
                key_id, public_key, witness_fingerprint, observed_at,
                _canonical_json_bytes(statement).decode("utf-8"), signature, document_sha256,
                str(actor or "local-user"), observed_at,
            ),
        )
        add_audit_event(
            db_path,
            finding_id=None,
            event_type="integrity_proof.checkpoint_witnessed",
            summary=f"Checkpoint #{checkpoint['sequence']} witnessed by {key_id}",
            details={
                "attestation_id": attestation_id,
                "checkpoint_id": checkpoint["checkpoint_id"],
                "checkpoint_sequence": int(checkpoint["sequence"]),
                "checkpoint_document_sha256": checkpoint_digest,
                "witness_key_id": key_id,
                "witness_public_key_sha256": witness_fingerprint,
            },
            actor=str(actor or "local-user"),
            conn=conn,
        )
    return document | {"document_sha256": document_sha256}


def _row_to_document(row: Mapping[str, Any]) -> dict[str, Any]:
    return witness_document_from_values(json.loads(str(row["statement_json"])), str(row["signature"]))


def list_integrity_proof_checkpoint_witnesses(
    db_path: str | Path, *, checkpoint_id: str = "", limit: int = 100
) -> list[dict[str, Any]]:
    safe_limit = max(1, min(int(limit), 1000))
    where = " WHERE checkpoint_id=?" if str(checkpoint_id or "").strip() else ""
    params: tuple[Any, ...] = (str(checkpoint_id).strip(), safe_limit) if where else (safe_limit,)
    with read_connection(db_path, operation="list_integrity_proof_checkpoint_witnesses") as conn:
        rows = conn.execute(
            "SELECT attestation_id,checkpoint_id,checkpoint_sequence,checkpoint_document_sha256,"
            "revocation_registry_sha256,transition_registry_sha256,witness_key_id,"
            "witness_public_key_sha256,observed_at,document_sha256,created_by,created_at,"
            "statement_json,signature FROM integrity_proof_checkpoint_witnesses" + where +
            " ORDER BY checkpoint_sequence DESC,observed_at,witness_key_id LIMIT ?",
            params,
        ).fetchall()
    return [dict(row) | {"document": _row_to_document(row)} for row in rows]


def export_integrity_proof_checkpoint_witnesses(db_path: str | Path) -> list[dict[str, Any]]:
    with read_connection(db_path, operation="export_integrity_proof_checkpoint_witnesses") as conn:
        latest = conn.execute(
            "SELECT checkpoint_id FROM integrity_proof_revocation_checkpoints ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
    if latest is None:
        return []
    rows = list_integrity_proof_checkpoint_witnesses(
        db_path, checkpoint_id=str(latest["checkpoint_id"]), limit=MAX_WITNESSES_PER_PROOF + 1
    )
    if len(rows) > MAX_WITNESSES_PER_PROOF:
        raise RuntimeError(f"proof에 포함할 witness 수가 제한({MAX_WITNESSES_PER_PROOF})을 초과했습니다.")
    return [dict(row["document"]) for row in reversed(rows)]


def validate_checkpoint_witness_document(document: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(document, Mapping):
        raise ValueError("checkpoint witness는 JSON 객체여야 합니다.")
    statement = document.get("statement")
    signature = document.get("signature")
    if not isinstance(statement, Mapping) or not isinstance(signature, Mapping):
        raise ValueError("checkpoint witness statement 또는 signature가 없습니다.")
    if str(statement.get("format") or "") != WITNESS_FORMAT:
        raise ValueError("지원하지 않는 checkpoint witness 형식입니다.")
    attestation_id = str(statement.get("attestation_id") or "")
    if not attestation_id.startswith("IPWA-"):
        raise ValueError("checkpoint witness ID가 올바르지 않습니다.")
    checkpoint = statement.get("checkpoint")
    witness = statement.get("witness")
    if not isinstance(checkpoint, Mapping) or not isinstance(witness, Mapping):
        raise ValueError("checkpoint witness의 checkpoint 또는 witness 정보가 없습니다.")
    checkpoint_id = str(checkpoint.get("checkpoint_id") or "")
    sequence = int(checkpoint.get("sequence") or 0)
    if not checkpoint_id.startswith("IPRC-") or sequence < 1:
        raise ValueError("checkpoint witness 참조가 올바르지 않습니다.")
    for field in ("document_sha256", "revocation_registry_sha256", "transition_registry_sha256"):
        digest = str(checkpoint.get(field) or "").lower()
        if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
            raise ValueError(f"checkpoint witness {field}가 올바르지 않습니다.")
    key_id = str(witness.get("key_id") or "")
    public_key = str(witness.get("public_key_base64") or "")
    fingerprint = public_key_fingerprint(public_key)
    if not KEY_ID_RE.fullmatch(key_id) or fingerprint != str(witness.get("public_key_sha256") or ""):
        raise ValueError("checkpoint witness 공개키 정보가 올바르지 않습니다.")
    observed_at = str(statement.get("observed_at") or "")
    try:
        parsed = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("checkpoint witness observed_at이 올바르지 않습니다.") from exc
    if parsed.tzinfo is None:
        raise ValueError("checkpoint witness observed_at에는 시간대가 필요합니다.")
    normalized_observed_at = parsed.astimezone(timezone.utc).replace(microsecond=0).isoformat()
    if str(signature.get("algorithm") or "") != ED25519_ALGORITHM or not verify_ed25519(
        signature_base64=str(signature.get("signature_base64") or ""),
        public_key_base64=public_key,
        payload=_payload(statement),
    ):
        raise ValueError("checkpoint witness 서명이 일치하지 않습니다.")
    return {
        "attestation_id": attestation_id,
        "checkpoint_id": checkpoint_id,
        "checkpoint_sequence": sequence,
        "checkpoint_document_sha256": str(checkpoint.get("document_sha256")),
        "revocation_registry_sha256": str(checkpoint.get("revocation_registry_sha256")),
        "transition_registry_sha256": str(checkpoint.get("transition_registry_sha256")),
        "witness_key_id": key_id,
        "witness_public_key": public_key,
        "witness_public_key_sha256": fingerprint,
        "observed_at": normalized_observed_at,
        "document_sha256": witness_document_sha256(document),
    }


def verify_checkpoint_witness_quorum(
    documents: Sequence[Mapping[str, Any]],
    *,
    checkpoints: Sequence[Mapping[str, Any]],
    pinned_public_keys: Mapping[str, str] | None,
    minimum_quorum: int = 0,
) -> dict[str, Any]:
    required = max(0, int(minimum_quorum))
    if not checkpoints:
        if documents or required:
            raise ValueError("witness가 참조할 registry checkpoint가 없습니다.")
        return {"status": "witness-quorum-unavailable", "quorum": 0, "required_quorum": required}
    validated_checkpoints = [validate_revocation_checkpoint_document(item) for item in checkpoints]
    latest = max(validated_checkpoints, key=lambda item: item["sequence"])
    if not documents:
        if required:
            raise ValueError("요구된 checkpoint witness quorum이 제공되지 않았습니다.")
        return {
            "status": "witness-quorum-unverified",
            "quorum": 0,
            "required_quorum": required,
            "checkpoint_sequence": latest["sequence"],
            "checkpoint_document_sha256": latest["document_sha256"],
        }

    validated = [validate_checkpoint_witness_document(item) for item in documents]
    seen_fingerprints: set[str] = set()
    seen_sequence_by_fingerprint: dict[tuple[str, int], str] = {}
    trusted: list[dict[str, Any]] = []
    for item in validated:
        key = (item["witness_public_key_sha256"], item["checkpoint_sequence"])
        previous_digest = seen_sequence_by_fingerprint.get(key)
        if previous_digest and previous_digest != item["checkpoint_document_sha256"]:
            raise ValueError("동일 witness가 같은 sequence의 상충 checkpoint를 서명했습니다.")
        seen_sequence_by_fingerprint[key] = item["checkpoint_document_sha256"]
        if item["checkpoint_sequence"] != latest["sequence"] or item["checkpoint_id"] != latest["checkpoint_id"]:
            continue
        if item["checkpoint_document_sha256"] != latest["document_sha256"]:
            raise ValueError("checkpoint witness가 최신 checkpoint digest와 일치하지 않습니다.")
        if item["revocation_registry_sha256"] != latest["revocation_registry_sha256"] or \
                item["transition_registry_sha256"] != latest["transition_registry_sha256"]:
            raise ValueError("checkpoint witness registry digest가 최신 checkpoint와 일치하지 않습니다.")
        if item["witness_public_key_sha256"] == latest["recovery_public_key_sha256"]:
            raise ValueError("checkpoint recovery root는 독립 witness quorum에 포함될 수 없습니다.")
        pinned = str(dict(pinned_public_keys or {}).get(item["witness_key_id"], ""))
        if not pinned or public_key_fingerprint(pinned) != item["witness_public_key_sha256"]:
            continue
        if item["witness_public_key_sha256"] in seen_fingerprints:
            continue
        seen_fingerprints.add(item["witness_public_key_sha256"])
        trusted.append(item)

    quorum = len(trusted)
    if quorum < required:
        raise ValueError(f"checkpoint witness quorum이 부족합니다: {quorum}/{required}")
    return {
        "status": "witness-quorum-verified" if required and quorum >= required else "witness-quorum-unverified",
        "quorum": quorum,
        "required_quorum": required,
        "checkpoint_id": latest["checkpoint_id"],
        "checkpoint_sequence": latest["sequence"],
        "checkpoint_document_sha256": latest["document_sha256"],
        "witness_key_ids": sorted(item["witness_key_id"] for item in trusted),
        "latest_observed_at": max((item["observed_at"] for item in trusted), default=""),
    }
