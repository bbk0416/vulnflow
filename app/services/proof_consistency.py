from __future__ import annotations

"""Cross-mirror consistency checkpoints for transparency gossip.

A consistency checkpoint binds a signed transparency head to a deterministic
set of mirror receipts. The same mirror keys that produced the receipts sign a
single shared statement, which is linked to the previous consistency
checkpoint. Private keys are supplied only for signing and are never stored.
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
from app.services.proof_mirror import (
    mirror_receipt_document,
    mirror_receipt_document_sha256,
    validate_transparency_mirror_receipt_document,
)
from app.services.proof_transparency import (
    ZERO_SHA256,
    transparency_head_document,
    transparency_head_document_sha256,
    validate_transparency_head_document,
)

CONSISTENCY_FORMAT = "vulnflow-integrity-proof-mirror-consistency-checkpoint/1"
MAX_CONSISTENCY_CHECKPOINTS_PER_PROOF = 64
MAX_MIRRORS_PER_CHECKPOINT = 32


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _valid_sha256(value: str) -> bool:
    text = str(value or "").lower()
    return len(text) == 64 and all(ch in "0123456789abcdef" for ch in text)


def _payload(statement: Mapping[str, Any]) -> bytes:
    return b"vulnflow-integrity-proof-mirror-consistency-checkpoint/1\n" + _canonical_json_bytes(dict(statement))


def consistency_document(statement: Mapping[str, Any], signatures: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    return {"statement": dict(statement), "signatures": [dict(item) for item in signatures]}


def consistency_document_sha256(document: Mapping[str, Any]) -> str:
    return _sha256_bytes(_canonical_json_bytes({
        "statement": document.get("statement"),
        "signatures": document.get("signatures"),
    }))


def _head_document_from_row(row: Mapping[str, Any]) -> dict[str, Any]:
    return transparency_head_document(json.loads(str(row["statement_json"])), str(row["signature"]))


def _receipt_document_from_row(row: Mapping[str, Any]) -> dict[str, Any]:
    return mirror_receipt_document(json.loads(str(row["statement_json"])), str(row["signature"]))


def create_integrity_proof_mirror_consistency_checkpoint(
    db_path: str | Path,
    *,
    mirror_key_ids: Sequence[str],
    minimum_quorum: int,
    private_keys: Mapping[str, str],
    public_keys: Mapping[str, str],
    actor: str,
    head_id: str = "",
) -> dict[str, Any]:
    key_ids = sorted({str(item or "").strip() for item in mirror_key_ids if str(item or "").strip()})
    if not key_ids or len(key_ids) > MAX_MIRRORS_PER_CHECKPOINT:
        raise ValueError("mirror consistency checkpoint의 mirror key 수가 올바르지 않습니다.")
    if any(not KEY_ID_RE.fullmatch(item) for item in key_ids):
        raise ValueError("mirror consistency checkpoint key ID 형식이 올바르지 않습니다.")
    quorum = int(minimum_quorum)
    if quorum < 1 or quorum > len(key_ids):
        raise ValueError("mirror consistency checkpoint quorum이 올바르지 않습니다.")

    with write_transaction(db_path, operation="create_integrity_proof_mirror_consistency_checkpoint") as conn:
        if str(head_id or "").strip():
            head_row = conn.execute(
                "SELECT head_id,tree_size,latest_entry_sha256,log_key_id,log_public_key_sha256,"
                "statement_json,signature,document_sha256 FROM integrity_proof_transparency_heads WHERE head_id=?",
                (str(head_id).strip(),),
            ).fetchone()
        else:
            head_row = conn.execute(
                "SELECT head_id,tree_size,latest_entry_sha256,log_key_id,log_public_key_sha256,"
                "statement_json,signature,document_sha256 FROM integrity_proof_transparency_heads "
                "ORDER BY tree_size DESC LIMIT 1"
            ).fetchone()
        if head_row is None:
            raise ValueError("consistency checkpoint가 참조할 transparency head가 없습니다.")
        head_document = _head_document_from_row(head_row)
        head = validate_transparency_head_document(head_document)
        head_digest = transparency_head_document_sha256(head_document)
        if head_digest != str(head_row["document_sha256"]):
            raise ValueError("transparency head 저장 digest가 문서와 일치하지 않습니다.")

        receipt_rows = conn.execute(
            "SELECT receipt_id,mirror_key_id,mirror_public_key_base64,mirror_public_key_sha256,"
            "statement_json,signature,document_sha256 FROM integrity_proof_transparency_mirror_receipts "
            "WHERE head_id=? ORDER BY mirror_key_id",
            (str(head["head_id"]),),
        ).fetchall()
        receipts = {str(row["mirror_key_id"]): row for row in receipt_rows}
        mirror_entries: list[dict[str, Any]] = []
        signatures: list[dict[str, Any]] = []
        for key_id in key_ids:
            row = receipts.get(key_id)
            if row is None:
                raise ValueError(f"선택한 mirror receipt가 최신 head에 없습니다: {key_id}")
            receipt_document = _receipt_document_from_row(row)
            receipt = validate_transparency_mirror_receipt_document(receipt_document)
            if str(receipt["head_document_sha256"]) != head_digest:
                raise ValueError("mirror receipt가 consistency checkpoint head와 일치하지 않습니다.")
            private_key = str(dict(private_keys).get(key_id, ""))
            public_key = str(dict(public_keys).get(key_id, ""))
            if not private_key or not public_key:
                raise ValueError(f"consistency checkpoint 서명키가 없습니다: {key_id}")
            fingerprint = public_key_fingerprint(public_key)
            if fingerprint != str(receipt["mirror_public_key_sha256"]):
                raise ValueError("consistency checkpoint 공개키가 mirror receipt 공개키와 일치하지 않습니다.")
            mirror_entries.append({
                "key_id": key_id,
                "public_key_sha256": fingerprint,
                "receipt_id": str(receipt["receipt_id"]),
                "receipt_document_sha256": str(receipt["document_sha256"]),
            })

        previous = conn.execute(
            "SELECT sequence,document_sha256,head_document_sha256 FROM integrity_proof_mirror_consistency_checkpoints "
            "ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        sequence = int(previous["sequence"]) + 1 if previous else 1
        previous_digest = str(previous["document_sha256"]) if previous else ZERO_SHA256
        if previous and str(previous["head_document_sha256"]) == head_digest:
            raise ValueError("동일 transparency head의 consistency checkpoint가 이미 존재합니다.")

        checkpoint_id = f"IPMC-{uuid.uuid4().hex[:20].upper()}"
        created_at = utc_now()
        statement = {
            "format": CONSISTENCY_FORMAT,
            "checkpoint_id": checkpoint_id,
            "sequence": sequence,
            "previous_checkpoint_sha256": previous_digest,
            "head": {
                "head_id": str(head["head_id"]),
                "tree_size": int(head["tree_size"]),
                "document_sha256": head_digest,
                "latest_entry_sha256": str(head["latest_entry_sha256"]),
                "log_key_id": str(head["log_key_id"]),
                "log_public_key_sha256": str(head["log_public_key_sha256"]),
            },
            "mirror_quorum": quorum,
            "mirrors": mirror_entries,
            "created_at": created_at,
        }
        for item in mirror_entries:
            key_id = str(item["key_id"])
            public_key = str(dict(public_keys)[key_id])
            signatures.append({
                "algorithm": ED25519_ALGORITHM,
                "key_id": key_id,
                "public_key_base64": public_key,
                "public_key_sha256": public_key_fingerprint(public_key),
                "signature_base64": sign_ed25519(str(dict(private_keys)[key_id]), _payload(statement)),
            })
        document = consistency_document(statement, signatures)
        document_sha256 = consistency_document_sha256(document)
        mirror_set_sha256 = _sha256_bytes(_canonical_json_bytes(mirror_entries))
        conn.execute(
            """INSERT INTO integrity_proof_mirror_consistency_checkpoints(
                   checkpoint_id,sequence,previous_checkpoint_sha256,head_id,tree_size,
                   head_document_sha256,mirror_quorum,mirror_count,mirror_set_sha256,
                   statement_json,signatures_json,document_sha256,created_by,created_at
               ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                checkpoint_id, sequence, previous_digest, str(head["head_id"]), int(head["tree_size"]),
                head_digest, quorum, len(mirror_entries), mirror_set_sha256,
                _canonical_json_bytes(statement).decode("utf-8"),
                _canonical_json_bytes(signatures).decode("utf-8"), document_sha256,
                str(actor or "local-user"), created_at,
            ),
        )
        add_audit_event(
            db_path, finding_id=None, event_type="integrity_proof.mirror_consistency_checkpoint_created",
            summary=f"Mirror consistency checkpoint #{sequence}",
            details={"checkpoint_id": checkpoint_id, "sequence": sequence, "tree_size": int(head["tree_size"]),
                     "mirror_quorum": quorum, "mirror_key_ids": key_ids, "document_sha256": document_sha256},
            actor=str(actor or "local-user"), conn=conn,
        )
    return document | {"document_sha256": document_sha256}


def validate_mirror_consistency_checkpoint_document(document: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(document, Mapping):
        raise ValueError("mirror consistency checkpoint는 JSON 객체여야 합니다.")
    statement = document.get("statement")
    signatures = document.get("signatures")
    if not isinstance(statement, Mapping) or not isinstance(signatures, list):
        raise ValueError("mirror consistency checkpoint 필수 필드가 없습니다.")
    if str(statement.get("format") or "") != CONSISTENCY_FORMAT:
        raise ValueError("지원하지 않는 mirror consistency checkpoint 형식입니다.")
    checkpoint_id = str(statement.get("checkpoint_id") or "")
    sequence = int(statement.get("sequence") or 0)
    previous_digest = str(statement.get("previous_checkpoint_sha256") or "").lower()
    head = statement.get("head")
    mirrors = statement.get("mirrors")
    quorum = int(statement.get("mirror_quorum") or 0)
    if not checkpoint_id.startswith("IPMC-") or sequence < 1 or not _valid_sha256(previous_digest):
        raise ValueError("mirror consistency checkpoint identity가 올바르지 않습니다.")
    if sequence == 1 and previous_digest != ZERO_SHA256:
        raise ValueError("첫 mirror consistency checkpoint 이전 digest는 zero hash여야 합니다.")
    if not isinstance(head, Mapping) or not isinstance(mirrors, list) or not mirrors:
        raise ValueError("mirror consistency checkpoint head 또는 mirror 집합이 없습니다.")
    if len(mirrors) > MAX_MIRRORS_PER_CHECKPOINT or quorum < 1 or quorum > len(mirrors):
        raise ValueError("mirror consistency checkpoint quorum이 올바르지 않습니다.")
    if not _valid_sha256(str(head.get("document_sha256") or "")) or not _valid_sha256(str(head.get("latest_entry_sha256") or "")):
        raise ValueError("mirror consistency checkpoint head digest가 올바르지 않습니다.")
    key_ids = [str(item.get("key_id") or "") for item in mirrors if isinstance(item, Mapping)]
    if len(key_ids) != len(mirrors) or key_ids != sorted(set(key_ids)):
        raise ValueError("mirror consistency checkpoint mirror 집합이 정렬·고유하지 않습니다.")
    mirror_by_key = {str(item["key_id"]): item for item in mirrors}
    signature_by_key = {str(item.get("key_id") or ""): item for item in signatures if isinstance(item, Mapping)}
    if set(signature_by_key) != set(mirror_by_key):
        raise ValueError("mirror consistency checkpoint 서명 집합이 mirror 집합과 일치하지 않습니다.")
    for key_id, mirror in mirror_by_key.items():
        for field in ("public_key_sha256", "receipt_document_sha256"):
            value = str(mirror.get(field) or "")
            if field == "public_key_sha256":
                if not value.startswith("sha256:") or not _valid_sha256(value.split(":", 1)[1]):
                    raise ValueError("mirror consistency checkpoint 공개키 fingerprint가 올바르지 않습니다.")
            elif not _valid_sha256(value):
                raise ValueError("mirror consistency checkpoint receipt digest가 올바르지 않습니다.")
        signature = signature_by_key[key_id]
        public_key = str(signature.get("public_key_base64") or "")
        fingerprint = public_key_fingerprint(public_key)
        if str(signature.get("algorithm") or "") != ED25519_ALGORITHM or fingerprint != str(mirror["public_key_sha256"]):
            raise ValueError("mirror consistency checkpoint 서명 공개키 metadata가 올바르지 않습니다.")
        if str(signature.get("public_key_sha256") or "") != fingerprint:
            raise ValueError("mirror consistency checkpoint 서명 fingerprint가 올바르지 않습니다.")
        if not verify_ed25519(signature_base64=str(signature.get("signature_base64") or ""), public_key_base64=public_key, payload=_payload(statement)):
            raise ValueError("mirror consistency checkpoint Ed25519 서명이 유효하지 않습니다.")
    created_at = str(statement.get("created_at") or "")
    try:
        parsed = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("mirror consistency checkpoint created_at이 올바르지 않습니다.") from exc
    if parsed.tzinfo is None:
        raise ValueError("mirror consistency checkpoint created_at에는 시간대가 필요합니다.")
    return {
        "checkpoint_id": checkpoint_id, "sequence": sequence, "previous_checkpoint_sha256": previous_digest,
        "head_id": str(head.get("head_id") or ""), "tree_size": int(head.get("tree_size") or 0),
        "head_document_sha256": str(head.get("document_sha256") or "").lower(),
        "latest_entry_sha256": str(head.get("latest_entry_sha256") or "").lower(),
        "log_key_id": str(head.get("log_key_id") or ""),
        "log_public_key_sha256": str(head.get("log_public_key_sha256") or ""),
        "mirror_quorum": quorum, "mirrors": [dict(item) for item in mirrors],
        "signatures": [dict(item) for item in signatures],
        "document_sha256": consistency_document_sha256(document), "document": dict(document),
    }


def verify_mirror_consistency_chain(
    documents: Sequence[Mapping[str, Any]], *, heads: Sequence[Mapping[str, Any]],
    receipts: Sequence[Mapping[str, Any]], pinned_public_keys: Mapping[str, str] | None,
    minimum_quorum: int = 0, trusted_checkpoint_sha256: str = "",
) -> dict[str, Any]:
    if not documents:
        if minimum_quorum or trusted_checkpoint_sha256:
            raise ValueError("요구된 mirror consistency checkpoint가 제공되지 않았습니다.")
        return {"status": "mirror-consistency-unavailable", "sequence": 0, "quorum": 0}
    if len(documents) > MAX_CONSISTENCY_CHECKPOINTS_PER_PROOF:
        raise ValueError("mirror consistency checkpoint 검증 제한을 초과했습니다.")
    rows = sorted((validate_mirror_consistency_checkpoint_document(item) for item in documents), key=lambda x: int(x["sequence"]))
    heads_by_digest = {str(validate_transparency_head_document(item)["document_sha256"]): validate_transparency_head_document(item) for item in heads}
    receipts_by_digest = {str(validate_transparency_mirror_receipt_document(item)["document_sha256"]): validate_transparency_mirror_receipt_document(item) for item in receipts}
    pins = {str(k): str(v) for k, v in dict(pinned_public_keys or {}).items()}
    expected_sequence = 1
    previous_digest = ZERO_SHA256
    trusted_seen = False
    for row in rows:
        if int(row["sequence"]) != expected_sequence or str(row["previous_checkpoint_sha256"]) != previous_digest:
            raise ValueError("mirror consistency checkpoint chain이 연속적이지 않습니다.")
        head = heads_by_digest.get(str(row["head_document_sha256"]))
        if head is None or int(head["tree_size"]) != int(row["tree_size"]):
            raise ValueError("mirror consistency checkpoint가 제공된 transparency head를 참조하지 않습니다.")
        trusted_signers = 0
        signatures_by_key = {
            str(item.get("key_id") or ""): item
            for item in row["signatures"]
            if isinstance(item, Mapping)
        }
        for mirror in row["mirrors"]:
            receipt = receipts_by_digest.get(str(mirror["receipt_document_sha256"]))
            if receipt is None or str(receipt["head_document_sha256"]) != str(row["head_document_sha256"]):
                raise ValueError("mirror consistency checkpoint가 제공된 mirror receipt를 참조하지 않습니다.")
            key_id = str(mirror["key_id"])
            signature = signatures_by_key.get(key_id)
            if signature is None:
                raise ValueError("mirror consistency checkpoint 서명자가 mirror 집합과 일치하지 않습니다.")
            pinned = str(pins.get(key_id, ""))
            if pinned and pinned == str(signature.get("public_key_base64") or "") and public_key_fingerprint(pinned) == str(mirror["public_key_sha256"]):
                trusted_signers += 1
        required = max(int(minimum_quorum), int(row["mirror_quorum"]))
        if trusted_signers < required:
            raise ValueError(f"mirror consistency quorum이 부족합니다: {trusted_signers}/{required}")
        previous_digest = str(row["document_sha256"])
        expected_sequence += 1
        if str(trusted_checkpoint_sha256 or "").lower() == previous_digest:
            trusted_seen = True
    trusted = str(trusted_checkpoint_sha256 or "").strip().lower()
    if trusted:
        if not _valid_sha256(trusted) or not trusted_seen:
            raise ValueError("외부에서 고정한 mirror consistency checkpoint가 현재 chain에 없습니다.")
    latest = rows[-1]
    return {
        "status": "mirror-consistency-verified", "sequence": int(latest["sequence"]),
        "tree_size": int(latest["tree_size"]), "head_document_sha256": str(latest["head_document_sha256"]),
        "quorum": len(latest["mirrors"]), "required_quorum": max(int(minimum_quorum), int(latest["mirror_quorum"])),
        "document_sha256": str(latest["document_sha256"]), "trusted_checkpoint_observed": bool(trusted),
    }


def _row_to_document(row: Mapping[str, Any]) -> dict[str, Any]:
    return consistency_document(json.loads(str(row["statement_json"])), json.loads(str(row["signatures_json"])))


def list_integrity_proof_mirror_consistency_checkpoints(db_path: str | Path, *, limit: int = 100) -> list[dict[str, Any]]:
    safe_limit = max(1, min(int(limit), 1000))
    with read_connection(db_path, operation="list_integrity_proof_mirror_consistency_checkpoints") as conn:
        rows = conn.execute(
            "SELECT checkpoint_id,sequence,previous_checkpoint_sha256,head_id,tree_size,head_document_sha256,"
            "mirror_quorum,mirror_count,mirror_set_sha256,document_sha256,created_by,created_at,statement_json,signatures_json "
            "FROM integrity_proof_mirror_consistency_checkpoints ORDER BY sequence DESC LIMIT ?", (safe_limit,)
        ).fetchall()
    return [dict(row) | {"document": _row_to_document(row)} for row in rows]


def export_integrity_proof_mirror_consistency_checkpoints(db_path: str | Path) -> list[dict[str, Any]]:
    rows = list_integrity_proof_mirror_consistency_checkpoints(db_path, limit=MAX_CONSISTENCY_CHECKPOINTS_PER_PROOF + 1)
    if len(rows) > MAX_CONSISTENCY_CHECKPOINTS_PER_PROOF:
        raise RuntimeError("proof에 포함할 mirror consistency checkpoint 수가 제한을 초과했습니다.")
    return [dict(row["document"]) for row in reversed(rows)]
