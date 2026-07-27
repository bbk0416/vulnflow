from __future__ import annotations

"""Append-only transparency log for witnessed revocation checkpoints.

The log is intentionally separate from the recovery root and checkpoint
witnesses. Each entry binds one recovery-root-signed checkpoint and the exact
witness set observed for that checkpoint into a linear SHA-256 chain. An
independent Ed25519 log key signs immutable heads. Offline verifiers pin that
public log key and may require a minimum tree size or a previously trusted head
digest to detect stale or rolled-back views.
"""

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
from app.services.proof_witness import (
    list_integrity_proof_checkpoint_witnesses,
    validate_checkpoint_witness_document,
    verify_checkpoint_witness_quorum,
)

ENTRY_FORMAT = "vulnflow-integrity-proof-transparency-entry/1"
HEAD_FORMAT = "vulnflow-integrity-proof-transparency-head/1"
ZERO_SHA256 = "0" * 64
MAX_TRANSPARENCY_ENTRIES_PER_PROOF = 64
MAX_TRANSPARENCY_HEADS_PER_PROOF = 64


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _valid_sha256(value: str) -> bool:
    return len(value) == 64 and all(ch in "0123456789abcdef" for ch in value.lower())


def _head_payload(statement: Mapping[str, Any]) -> bytes:
    return b"vulnflow-integrity-proof-transparency-head/1\n" + _canonical_json_bytes(dict(statement))


def transparency_entry_document(statement: Mapping[str, Any]) -> dict[str, Any]:
    return {"statement": dict(statement)}


def transparency_entry_document_sha256(document: Mapping[str, Any]) -> str:
    return _sha256_bytes(_canonical_json_bytes({"statement": document.get("statement")}))


def transparency_head_document(statement: Mapping[str, Any], signature: str) -> dict[str, Any]:
    return {
        "statement": dict(statement),
        "signature": {"algorithm": ED25519_ALGORITHM, "signature_base64": str(signature)},
    }


def transparency_head_document_sha256(document: Mapping[str, Any]) -> str:
    return _sha256_bytes(_canonical_json_bytes({
        "statement": document.get("statement"),
        "signature": document.get("signature"),
    }))


def _checkpoint_document_from_row(row: Mapping[str, Any]) -> dict[str, Any]:
    return checkpoint_document_from_values(json.loads(str(row["statement_json"])), str(row["signature"]))


def _witness_documents_for_checkpoint(db_path: str | Path, checkpoint_id: str) -> list[dict[str, Any]]:
    rows = list_integrity_proof_checkpoint_witnesses(db_path, checkpoint_id=checkpoint_id, limit=1000)
    return [dict(row["document"]) for row in reversed(rows)]


def publish_integrity_proof_transparency_head(
    db_path: str | Path,
    *,
    log_key_id: str,
    private_keys: Mapping[str, str],
    public_keys: Mapping[str, str],
    actor: str,
    checkpoint_id: str = "",
    minimum_witness_quorum: int = 1,
) -> dict[str, Any]:
    key_id = str(log_key_id or "").strip()
    if not KEY_ID_RE.fullmatch(key_id):
        raise ValueError("transparency log key ID 형식이 올바르지 않습니다.")
    private_key = str(dict(private_keys).get(key_id, ""))
    public_key = str(dict(public_keys).get(key_id, ""))
    if not private_key or not public_key:
        raise ValueError("transparency head 생성에는 log private/public key가 모두 필요합니다.")

    with read_connection(db_path, operation="load_integrity_proof_transparency_checkpoint") as conn:
        if str(checkpoint_id or "").strip():
            checkpoint_row = conn.execute(
                "SELECT checkpoint_id,sequence,statement_json,signature,document_sha256 "
                "FROM integrity_proof_revocation_checkpoints WHERE checkpoint_id=?",
                (str(checkpoint_id).strip(),),
            ).fetchone()
        else:
            checkpoint_row = conn.execute(
                "SELECT checkpoint_id,sequence,statement_json,signature,document_sha256 "
                "FROM integrity_proof_revocation_checkpoints ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
    if checkpoint_row is None:
        raise ValueError("transparency log에 게시할 registry checkpoint가 없습니다.")

    checkpoint_document = _checkpoint_document_from_row(checkpoint_row)
    checkpoint = validate_revocation_checkpoint_document(checkpoint_document)
    checkpoint_digest = checkpoint_document_sha256(checkpoint_document)
    if checkpoint_digest != str(checkpoint_row["document_sha256"]):
        raise ValueError("registry checkpoint 저장 digest가 문서와 일치하지 않습니다.")

    witness_documents = _witness_documents_for_checkpoint(db_path, str(checkpoint["checkpoint_id"]))
    witness_pins = {
        str((item.get("statement") or {}).get("witness", {}).get("key_id") or ""):
        str((item.get("statement") or {}).get("witness", {}).get("public_key_base64") or "")
        for item in witness_documents
    }
    witness_result = verify_checkpoint_witness_quorum(
        witness_documents,
        checkpoints=[checkpoint_document],
        pinned_public_keys=witness_pins,
        minimum_quorum=max(1, int(minimum_witness_quorum)),
    )
    log_fingerprint = public_key_fingerprint(public_key)
    if log_fingerprint == str(checkpoint["recovery_public_key_sha256"]):
        raise ValueError("transparency log key는 checkpoint recovery root와 독립된 키여야 합니다.")
    witness_fingerprints = {
        str((item.get("statement") or {}).get("witness", {}).get("public_key_sha256") or "")
        for item in witness_documents
    }
    if log_fingerprint in witness_fingerprints:
        raise ValueError("transparency log key는 checkpoint witness와 독립된 키여야 합니다.")
    witness_digest = _sha256_bytes(_canonical_json_bytes(witness_documents))
    published_at = utc_now()

    with write_transaction(db_path, operation="publish_integrity_proof_transparency_head") as conn:
        duplicate = conn.execute(
            "SELECT entry_id,sequence FROM integrity_proof_transparency_entries "
            "WHERE checkpoint_document_sha256=?",
            (checkpoint_digest,),
        ).fetchone()
        if duplicate:
            raise ValueError(f"해당 checkpoint는 이미 transparency log에 게시되었습니다: {duplicate['entry_id']}")

        previous_entry = conn.execute(
            "SELECT sequence,document_sha256 FROM integrity_proof_transparency_entries "
            "ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        sequence = int(previous_entry["sequence"]) + 1 if previous_entry else 1
        previous_entry_digest = str(previous_entry["document_sha256"]) if previous_entry else ZERO_SHA256
        entry_id = f"IPTE-{uuid.uuid4().hex[:20].upper()}"
        entry_statement = {
            "format": ENTRY_FORMAT,
            "entry_id": entry_id,
            "sequence": sequence,
            "previous_entry_sha256": previous_entry_digest,
            "checkpoint": {
                "checkpoint_id": str(checkpoint["checkpoint_id"]),
                "sequence": int(checkpoint["sequence"]),
                "document_sha256": checkpoint_digest,
                "revocation_registry_sha256": str(checkpoint["revocation_registry_sha256"]),
                "transition_registry_sha256": str(checkpoint["transition_registry_sha256"]),
            },
            "witnesses": {
                "count": len(witness_documents),
                "minimum_quorum": max(1, int(minimum_witness_quorum)),
                "documents_sha256": witness_digest,
                "verified_witness_key_ids": list(witness_result.get("witness_key_ids") or []),
            },
            "published_at": published_at,
        }
        entry_document = transparency_entry_document(entry_statement)
        entry_digest = transparency_entry_document_sha256(entry_document)
        conn.execute(
            """INSERT INTO integrity_proof_transparency_entries(
                   entry_id,sequence,previous_entry_sha256,checkpoint_id,checkpoint_sequence,
                   checkpoint_document_sha256,witness_count,witness_registry_sha256,
                   statement_json,document_sha256,created_by,created_at
               ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                entry_id, sequence, previous_entry_digest, str(checkpoint["checkpoint_id"]),
                int(checkpoint["sequence"]), checkpoint_digest, len(witness_documents), witness_digest,
                _canonical_json_bytes(entry_statement).decode("utf-8"), entry_digest,
                str(actor or "local-user"), published_at,
            ),
        )

        previous_head = conn.execute(
            "SELECT tree_size,document_sha256 FROM integrity_proof_transparency_heads "
            "ORDER BY tree_size DESC LIMIT 1"
        ).fetchone()
        if previous_head and int(previous_head["tree_size"]) != sequence - 1:
            raise ValueError("transparency head와 entry chain의 크기가 일치하지 않습니다.")
        previous_head_digest = str(previous_head["document_sha256"]) if previous_head else ZERO_SHA256
        head_id = f"IPTH-{uuid.uuid4().hex[:20].upper()}"
        head_statement = {
            "format": HEAD_FORMAT,
            "head_id": head_id,
            "tree_size": sequence,
            "latest_entry_sha256": entry_digest,
            "previous_head_sha256": previous_head_digest,
            "log": {
                "algorithm": ED25519_ALGORITHM,
                "key_id": key_id,
                "public_key_base64": public_key,
                "public_key_sha256": log_fingerprint,
            },
            "created_at": published_at,
        }
        signature = sign_ed25519(private_key, _head_payload(head_statement))
        head_document = transparency_head_document(head_statement, signature)
        head_digest = transparency_head_document_sha256(head_document)
        conn.execute(
            """INSERT INTO integrity_proof_transparency_heads(
                   head_id,tree_size,latest_entry_sha256,previous_head_sha256,
                   log_key_id,log_public_key_base64,log_public_key_sha256,
                   statement_json,signature,document_sha256,created_by,created_at
               ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                head_id, sequence, entry_digest, previous_head_digest,
                key_id, public_key, log_fingerprint,
                _canonical_json_bytes(head_statement).decode("utf-8"), signature, head_digest,
                str(actor or "local-user"), published_at,
            ),
        )
        add_audit_event(
            db_path,
            finding_id=None,
            event_type="integrity_proof.transparency_head_published",
            summary=f"Transparency log head #{sequence} published",
            details={
                "entry_id": entry_id,
                "head_id": head_id,
                "tree_size": sequence,
                "checkpoint_id": str(checkpoint["checkpoint_id"]),
                "checkpoint_sequence": int(checkpoint["sequence"]),
                "checkpoint_document_sha256": checkpoint_digest,
                "witness_count": len(witness_documents),
                "entry_document_sha256": entry_digest,
                "head_document_sha256": head_digest,
                "log_key_id": key_id,
            },
            actor=str(actor or "local-user"),
            conn=conn,
        )
    return {
        "entry": entry_document | {"document_sha256": entry_digest},
        "head": head_document | {"document_sha256": head_digest},
        "witness_quorum": witness_result,
    }


def validate_transparency_entry_document(document: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(document, Mapping):
        raise ValueError("transparency entry는 JSON 객체여야 합니다.")
    statement = document.get("statement")
    if not isinstance(statement, Mapping) or str(statement.get("format") or "") != ENTRY_FORMAT:
        raise ValueError("지원하지 않는 transparency entry 형식입니다.")
    entry_id = str(statement.get("entry_id") or "")
    if not entry_id.startswith("IPTE-"):
        raise ValueError("transparency entry ID가 올바르지 않습니다.")
    sequence = int(statement.get("sequence") or 0)
    if sequence < 1:
        raise ValueError("transparency entry sequence가 올바르지 않습니다.")
    previous = str(statement.get("previous_entry_sha256") or "")
    if not _valid_sha256(previous):
        raise ValueError("이전 transparency entry digest가 올바르지 않습니다.")
    checkpoint = statement.get("checkpoint")
    witnesses = statement.get("witnesses")
    if not isinstance(checkpoint, Mapping) or not isinstance(witnesses, Mapping):
        raise ValueError("transparency entry checkpoint 또는 witness 정보가 없습니다.")
    checkpoint_digest = str(checkpoint.get("document_sha256") or "")
    if not _valid_sha256(checkpoint_digest):
        raise ValueError("transparency entry checkpoint digest가 올바르지 않습니다.")
    if int(checkpoint.get("sequence") or 0) < 1:
        raise ValueError("transparency entry checkpoint sequence가 올바르지 않습니다.")
    witness_digest = str(witnesses.get("documents_sha256") or "")
    if not _valid_sha256(witness_digest):
        raise ValueError("transparency entry witness digest가 올바르지 않습니다.")
    if int(witnesses.get("count") or 0) < 1 or int(witnesses.get("minimum_quorum") or 0) < 1:
        raise ValueError("transparency entry witness count 또는 quorum이 올바르지 않습니다.")
    return {
        "entry_id": entry_id,
        "sequence": sequence,
        "previous_entry_sha256": previous.lower(),
        "checkpoint_id": str(checkpoint.get("checkpoint_id") or ""),
        "checkpoint_sequence": int(checkpoint.get("sequence") or 0),
        "checkpoint_document_sha256": checkpoint_digest.lower(),
        "witness_count": int(witnesses.get("count") or 0),
        "minimum_witness_quorum": int(witnesses.get("minimum_quorum") or 0),
        "witness_registry_sha256": witness_digest.lower(),
        "document_sha256": transparency_entry_document_sha256(document),
        "document": dict(document),
    }


def validate_transparency_head_document(document: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(document, Mapping):
        raise ValueError("transparency head는 JSON 객체여야 합니다.")
    statement = document.get("statement")
    signature = document.get("signature")
    if not isinstance(statement, Mapping) or not isinstance(signature, Mapping):
        raise ValueError("transparency head statement 또는 signature가 없습니다.")
    if str(statement.get("format") or "") != HEAD_FORMAT:
        raise ValueError("지원하지 않는 transparency head 형식입니다.")
    head_id = str(statement.get("head_id") or "")
    if not head_id.startswith("IPTH-"):
        raise ValueError("transparency head ID가 올바르지 않습니다.")
    tree_size = int(statement.get("tree_size") or 0)
    if tree_size < 1:
        raise ValueError("transparency head tree size가 올바르지 않습니다.")
    latest = str(statement.get("latest_entry_sha256") or "")
    previous = str(statement.get("previous_head_sha256") or "")
    if not _valid_sha256(latest) or not _valid_sha256(previous):
        raise ValueError("transparency head digest가 올바르지 않습니다.")
    log = statement.get("log")
    if not isinstance(log, Mapping):
        raise ValueError("transparency head log 공개키 정보가 없습니다.")
    key_id = str(log.get("key_id") or "")
    public_key = str(log.get("public_key_base64") or "")
    fingerprint = public_key_fingerprint(public_key)
    if not KEY_ID_RE.fullmatch(key_id) or str(log.get("algorithm") or "") != ED25519_ALGORITHM:
        raise ValueError("transparency head log key metadata가 올바르지 않습니다.")
    if fingerprint != str(log.get("public_key_sha256") or ""):
        raise ValueError("transparency head log public key fingerprint가 올바르지 않습니다.")
    signature_value = str(signature.get("signature_base64") or "")
    if str(signature.get("algorithm") or "") != ED25519_ALGORITHM or not signature_value:
        raise ValueError("transparency head 서명 metadata가 올바르지 않습니다.")
    return {
        "head_id": head_id,
        "tree_size": tree_size,
        "latest_entry_sha256": latest.lower(),
        "previous_head_sha256": previous.lower(),
        "log_key_id": key_id,
        "log_public_key_base64": public_key,
        "log_public_key_sha256": fingerprint,
        "signature": signature_value,
        "document_sha256": transparency_head_document_sha256(document),
        "document": dict(document),
    }


def verify_integrity_proof_transparency_log(
    entries: Sequence[Mapping[str, Any]],
    heads: Sequence[Mapping[str, Any]],
    *,
    pinned_public_keys: Mapping[str, str] | None,
    checkpoints: Sequence[Mapping[str, Any]] | None = None,
    witnesses: Sequence[Mapping[str, Any]] | None = None,
    minimum_tree_size: int = 0,
    trusted_head_sha256: str = "",
) -> dict[str, Any]:
    entry_rows = [validate_transparency_entry_document(item) for item in entries]
    head_rows = [validate_transparency_head_document(item) for item in heads]
    if not entry_rows and not head_rows:
        if int(minimum_tree_size) > 0 or str(trusted_head_sha256 or "").strip():
            raise ValueError("요구된 transparency log가 없습니다.")
        return {"status": "transparency-log-unverified", "tree_size": 0, "head_document_sha256": ""}
    if not entry_rows or not head_rows:
        raise ValueError("transparency log entry와 head가 모두 필요합니다.")
    entry_rows.sort(key=lambda row: int(row["sequence"]))
    head_rows.sort(key=lambda row: int(row["tree_size"]))
    if len(entry_rows) > MAX_TRANSPARENCY_ENTRIES_PER_PROOF or len(head_rows) > MAX_TRANSPARENCY_HEADS_PER_PROOF:
        raise ValueError("transparency log 검증 제한을 초과했습니다.")

    expected_previous = ZERO_SHA256
    entries_by_sequence: dict[int, dict[str, Any]] = {}
    checkpoint_digests = {
        checkpoint_document_sha256(item): validate_revocation_checkpoint_document(item)
        for item in (checkpoints or [])
    }
    witness_documents = [dict(item) for item in (witnesses or [])]
    for expected_sequence, row in enumerate(entry_rows, start=1):
        if int(row["sequence"]) != expected_sequence:
            raise ValueError("transparency entry sequence가 연속적이지 않습니다.")
        if str(row["previous_entry_sha256"]) != expected_previous:
            raise ValueError("transparency entry 이전 digest가 일치하지 않습니다.")
        if checkpoint_digests and str(row["checkpoint_document_sha256"]) not in checkpoint_digests:
            raise ValueError("transparency entry가 proof의 registry checkpoint를 참조하지 않습니다.")
        entries_by_sequence[expected_sequence] = row
        expected_previous = str(row["document_sha256"])

    if witness_documents:
        latest_entry = entry_rows[-1]
        relevant = []
        for document in witness_documents:
            checked = validate_checkpoint_witness_document(document)
            if checked["checkpoint_document_sha256"] == str(latest_entry["checkpoint_document_sha256"]):
                relevant.append(dict(document))
        if len(relevant) != int(latest_entry["witness_count"]):
            raise ValueError("최신 transparency entry witness 수가 proof 문서와 일치하지 않습니다.")
        if _sha256_bytes(_canonical_json_bytes(relevant)) != str(latest_entry["witness_registry_sha256"]):
            raise ValueError("최신 transparency entry witness registry digest가 일치하지 않습니다.")

    pins = {str(key): str(value) for key, value in dict(pinned_public_keys or {}).items()}
    expected_previous_head = ZERO_SHA256
    seen_head_digests: set[str] = set()
    for expected_tree_size, row in enumerate(head_rows, start=1):
        if int(row["tree_size"]) != expected_tree_size:
            raise ValueError("transparency head tree size가 연속적이지 않습니다.")
        if str(row["previous_head_sha256"]) != expected_previous_head:
            raise ValueError("transparency head 이전 digest가 일치하지 않습니다.")
        entry = entries_by_sequence.get(expected_tree_size)
        if entry is None or str(entry["document_sha256"]) != str(row["latest_entry_sha256"]):
            raise ValueError("transparency head가 해당 tree size의 최신 entry를 가리키지 않습니다.")
        pinned = str(pins.get(str(row["log_key_id"]), ""))
        if not pinned or public_key_fingerprint(pinned) != str(row["log_public_key_sha256"]):
            raise ValueError("transparency head 검증에 외부에서 고정한 log 공개키가 필요합니다.")
        if pinned != str(row["log_public_key_base64"]):
            raise ValueError("transparency head embedded log 공개키가 고정 공개키와 일치하지 않습니다.")
        statement = dict(row["document"].get("statement") or {})
        if not verify_ed25519(
            signature_base64=str(row["signature"]),
            public_key_base64=pinned,
            payload=_head_payload(statement),
        ):
            raise ValueError("transparency head Ed25519 서명이 유효하지 않습니다.")
        expected_previous_head = str(row["document_sha256"])
        seen_head_digests.add(expected_previous_head)

    latest = head_rows[-1]
    required_size = max(0, int(minimum_tree_size))
    if int(latest["tree_size"]) < required_size:
        raise ValueError(
            f"transparency log tree size가 외부 최소값보다 작습니다: required={required_size}, actual={latest['tree_size']}"
        )
    trusted_digest = str(trusted_head_sha256 or "").strip().lower()
    if trusted_digest:
        if not _valid_sha256(trusted_digest):
            raise ValueError("신뢰 transparency head SHA-256 형식이 올바르지 않습니다.")
        if trusted_digest not in seen_head_digests:
            raise ValueError("외부에서 고정한 transparency head가 현재 append-only chain에 없습니다.")
    return {
        "status": "transparency-log-verified",
        "tree_size": int(latest["tree_size"]),
        "head_id": str(latest["head_id"]),
        "head_document_sha256": str(latest["document_sha256"]),
        "log_key_id": str(latest["log_key_id"]),
        "log_public_key_sha256": str(latest["log_public_key_sha256"]),
        "trusted_head_observed": bool(trusted_digest),
    }


def _entry_row_to_document(row: Mapping[str, Any]) -> dict[str, Any]:
    return transparency_entry_document(json.loads(str(row["statement_json"])))


def _head_row_to_document(row: Mapping[str, Any]) -> dict[str, Any]:
    return transparency_head_document(json.loads(str(row["statement_json"])), str(row["signature"]))


def list_integrity_proof_transparency_entries(db_path: str | Path, *, limit: int = 100) -> list[dict[str, Any]]:
    safe_limit = max(1, min(int(limit), 1000))
    with read_connection(db_path, operation="list_integrity_proof_transparency_entries") as conn:
        rows = conn.execute(
            "SELECT entry_id,sequence,previous_entry_sha256,checkpoint_id,checkpoint_sequence,"
            "checkpoint_document_sha256,witness_count,witness_registry_sha256,document_sha256,"
            "created_by,created_at,statement_json FROM integrity_proof_transparency_entries "
            "ORDER BY sequence DESC LIMIT ?",
            (safe_limit,),
        ).fetchall()
    return [dict(row) | {"document": _entry_row_to_document(row)} for row in rows]


def list_integrity_proof_transparency_heads(db_path: str | Path, *, limit: int = 100) -> list[dict[str, Any]]:
    safe_limit = max(1, min(int(limit), 1000))
    with read_connection(db_path, operation="list_integrity_proof_transparency_heads") as conn:
        rows = conn.execute(
            "SELECT head_id,tree_size,latest_entry_sha256,previous_head_sha256,log_key_id,"
            "log_public_key_sha256,document_sha256,created_by,created_at,statement_json,signature "
            "FROM integrity_proof_transparency_heads ORDER BY tree_size DESC LIMIT ?",
            (safe_limit,),
        ).fetchall()
    return [dict(row) | {"document": _head_row_to_document(row)} for row in rows]


def export_integrity_proof_transparency_entries(db_path: str | Path) -> list[dict[str, Any]]:
    rows = list_integrity_proof_transparency_entries(db_path, limit=MAX_TRANSPARENCY_ENTRIES_PER_PROOF + 1)
    if len(rows) > MAX_TRANSPARENCY_ENTRIES_PER_PROOF:
        raise RuntimeError(
            f"proof에 포함할 transparency entry 수가 제한({MAX_TRANSPARENCY_ENTRIES_PER_PROOF})을 초과했습니다."
        )
    return [dict(row["document"]) for row in reversed(rows)]


def export_integrity_proof_transparency_heads(db_path: str | Path) -> list[dict[str, Any]]:
    rows = list_integrity_proof_transparency_heads(db_path, limit=MAX_TRANSPARENCY_HEADS_PER_PROOF + 1)
    if len(rows) > MAX_TRANSPARENCY_HEADS_PER_PROOF:
        raise RuntimeError(
            f"proof에 포함할 transparency head 수가 제한({MAX_TRANSPARENCY_HEADS_PER_PROOF})을 초과했습니다."
        )
    return [dict(row["document"]) for row in reversed(rows)]
