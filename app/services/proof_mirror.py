from __future__ import annotations

"""Independent mirror gossip receipts for transparency-log heads.

A mirror observes an already log-key-signed transparency head and signs a
receipt that links to its own previous observation. Mirror private keys are
provided only for the signing operation and are never persisted. Offline
verifiers pin mirror public keys independently, verify monotonic per-mirror
receipt chains, reject equivocation, and may require a distinct-mirror quorum
for the latest transparency head.
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
from app.services.proof_transparency import (
    ZERO_SHA256,
    transparency_head_document,
    transparency_head_document_sha256,
    validate_transparency_head_document,
)

MIRROR_RECEIPT_FORMAT = "vulnflow-integrity-proof-transparency-mirror-receipt/1"
MAX_MIRROR_RECEIPTS_PER_PROOF = 128


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _valid_sha256(value: str) -> bool:
    return len(value) == 64 and all(ch in "0123456789abcdef" for ch in value.lower())


def _valid_fingerprint(value: str) -> bool:
    text = str(value or "").lower()
    return text.startswith("sha256:") and _valid_sha256(text.split(":", 1)[1])


def _payload(statement: Mapping[str, Any]) -> bytes:
    return b"vulnflow-integrity-proof-transparency-mirror-receipt/1\n" + _canonical_json_bytes(dict(statement))


def mirror_receipt_document(statement: Mapping[str, Any], signature: str) -> dict[str, Any]:
    return {
        "statement": dict(statement),
        "signature": {"algorithm": ED25519_ALGORITHM, "signature_base64": str(signature)},
    }


def mirror_receipt_document_sha256(document: Mapping[str, Any]) -> str:
    return _sha256_bytes(_canonical_json_bytes({
        "statement": document.get("statement"),
        "signature": document.get("signature"),
    }))


def _head_document_from_row(row: Mapping[str, Any]) -> dict[str, Any]:
    return transparency_head_document(json.loads(str(row["statement_json"])), str(row["signature"]))


def create_integrity_proof_transparency_mirror_receipt(
    db_path: str | Path,
    *,
    mirror_key_id: str,
    private_keys: Mapping[str, str],
    public_keys: Mapping[str, str],
    actor: str,
    head_id: str = "",
) -> dict[str, Any]:
    key_id = str(mirror_key_id or "").strip()
    if not KEY_ID_RE.fullmatch(key_id):
        raise ValueError("transparency mirror key ID 형식이 올바르지 않습니다.")
    private_key = str(dict(private_keys).get(key_id, ""))
    public_key = str(dict(public_keys).get(key_id, ""))
    if not private_key or not public_key:
        raise ValueError("mirror receipt 생성에는 mirror private/public key가 모두 필요합니다.")

    with write_transaction(db_path, operation="create_integrity_proof_transparency_mirror_receipt") as conn:
        if str(head_id or "").strip():
            row = conn.execute(
                "SELECT head_id,tree_size,log_key_id,log_public_key_sha256,statement_json,signature,document_sha256 "
                "FROM integrity_proof_transparency_heads WHERE head_id=?",
                (str(head_id).strip(),),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT head_id,tree_size,log_key_id,log_public_key_sha256,statement_json,signature,document_sha256 "
                "FROM integrity_proof_transparency_heads ORDER BY tree_size DESC LIMIT 1"
            ).fetchone()
        if row is None:
            raise ValueError("mirror가 확인할 transparency head가 없습니다.")

        head_document = _head_document_from_row(row)
        head = validate_transparency_head_document(head_document)
        head_digest = transparency_head_document_sha256(head_document)
        if head_digest != str(row["document_sha256"]):
            raise ValueError("transparency head 저장 digest가 문서와 일치하지 않습니다.")

        mirror_fingerprint = public_key_fingerprint(public_key)
        if mirror_fingerprint == str(head["log_public_key_sha256"]):
            raise ValueError("transparency mirror key는 log signing key와 독립된 키여야 합니다.")

        existing = conn.execute(
            "SELECT receipt_id,head_document_sha256 FROM integrity_proof_transparency_mirror_receipts "
            "WHERE mirror_public_key_sha256=? AND tree_size=?",
            (mirror_fingerprint, int(head["tree_size"])),
        ).fetchone()
        if existing:
            if str(existing["head_document_sha256"]) == head_digest:
                raise ValueError(f"해당 mirror는 이미 transparency head를 확인했습니다: {existing['receipt_id']}")
            raise ValueError("동일 mirror가 같은 tree size의 상충 transparency head를 확인할 수 없습니다.")

        previous = conn.execute(
            "SELECT tree_size,document_sha256 FROM integrity_proof_transparency_mirror_receipts "
            "WHERE mirror_public_key_sha256=? ORDER BY tree_size DESC LIMIT 1",
            (mirror_fingerprint,),
        ).fetchone()
        previous_tree_size = int(previous["tree_size"]) if previous else 0
        previous_receipt_sha256 = str(previous["document_sha256"]) if previous else ZERO_SHA256
        if int(head["tree_size"]) <= previous_tree_size:
            raise ValueError("mirror는 이전에 관찰한 tree size보다 오래된 head를 확인할 수 없습니다.")

        observed_at = utc_now()
        receipt_id = f"IPMR-{uuid.uuid4().hex[:20].upper()}"
        statement = {
            "format": MIRROR_RECEIPT_FORMAT,
            "receipt_id": receipt_id,
            "head": {
                "head_id": str(head["head_id"]),
                "tree_size": int(head["tree_size"]),
                "document_sha256": head_digest,
                "latest_entry_sha256": str(head["latest_entry_sha256"]),
                "log_key_id": str(head["log_key_id"]),
                "log_public_key_sha256": str(head["log_public_key_sha256"]),
            },
            "previous_observation": {
                "tree_size": previous_tree_size,
                "receipt_sha256": previous_receipt_sha256,
            },
            "mirror": {
                "algorithm": ED25519_ALGORITHM,
                "key_id": key_id,
                "public_key_base64": public_key,
                "public_key_sha256": mirror_fingerprint,
            },
            "observed_at": observed_at,
        }
        signature = sign_ed25519(private_key, _payload(statement))
        document = mirror_receipt_document(statement, signature)
        document_sha256 = mirror_receipt_document_sha256(document)
        conn.execute(
            """INSERT INTO integrity_proof_transparency_mirror_receipts(
                   receipt_id,head_id,tree_size,head_document_sha256,previous_tree_size,
                   previous_receipt_sha256,mirror_key_id,mirror_public_key_base64,
                   mirror_public_key_sha256,observed_at,statement_json,signature,
                   document_sha256,created_by,created_at
               ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                receipt_id, str(head["head_id"]), int(head["tree_size"]), head_digest,
                previous_tree_size, previous_receipt_sha256, key_id, public_key,
                mirror_fingerprint, observed_at, _canonical_json_bytes(statement).decode("utf-8"),
                signature, document_sha256, str(actor or "local-user"), observed_at,
            ),
        )
        add_audit_event(
            db_path,
            finding_id=None,
            event_type="integrity_proof.transparency_head_mirrored",
            summary=f"Transparency head #{head['tree_size']} mirrored by {key_id}",
            details={
                "receipt_id": receipt_id,
                "head_id": head["head_id"],
                "tree_size": int(head["tree_size"]),
                "head_document_sha256": head_digest,
                "previous_tree_size": previous_tree_size,
                "mirror_key_id": key_id,
                "mirror_public_key_sha256": mirror_fingerprint,
            },
            actor=str(actor or "local-user"),
            conn=conn,
        )
    return document | {"document_sha256": document_sha256}


def validate_transparency_mirror_receipt_document(document: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(document, Mapping):
        raise ValueError("transparency mirror receipt는 JSON 객체여야 합니다.")
    statement = document.get("statement")
    signature = document.get("signature")
    if not isinstance(statement, Mapping) or not isinstance(signature, Mapping):
        raise ValueError("transparency mirror receipt statement 또는 signature가 없습니다.")
    if str(statement.get("format") or "") != MIRROR_RECEIPT_FORMAT:
        raise ValueError("지원하지 않는 transparency mirror receipt 형식입니다.")
    receipt_id = str(statement.get("receipt_id") or "")
    if not receipt_id.startswith("IPMR-"):
        raise ValueError("transparency mirror receipt ID가 올바르지 않습니다.")
    head = statement.get("head")
    previous = statement.get("previous_observation")
    mirror = statement.get("mirror")
    if not isinstance(head, Mapping) or not isinstance(previous, Mapping) or not isinstance(mirror, Mapping):
        raise ValueError("transparency mirror receipt 필수 정보가 없습니다.")
    tree_size = int(head.get("tree_size") or 0)
    previous_tree_size = int(previous.get("tree_size") or 0)
    if tree_size < 1 or previous_tree_size < 0 or previous_tree_size >= tree_size:
        raise ValueError("transparency mirror receipt tree size가 올바르지 않습니다.")
    for value, label in (
        (str(head.get("document_sha256") or ""), "head digest"),
        (str(head.get("latest_entry_sha256") or ""), "latest entry digest"),
        (str(previous.get("receipt_sha256") or ""), "previous receipt digest"),
    ):
        if not _valid_sha256(value):
            raise ValueError(f"transparency mirror receipt {label}가 올바르지 않습니다.")
    if not _valid_fingerprint(str(head.get("log_public_key_sha256") or "")):
        raise ValueError("transparency mirror receipt log key fingerprint가 올바르지 않습니다.")
    if previous_tree_size == 0 and str(previous.get("receipt_sha256") or "").lower() != ZERO_SHA256:
        raise ValueError("첫 mirror receipt의 이전 digest는 zero hash여야 합니다.")
    key_id = str(mirror.get("key_id") or "")
    public_key = str(mirror.get("public_key_base64") or "")
    fingerprint = public_key_fingerprint(public_key)
    if not KEY_ID_RE.fullmatch(key_id) or str(mirror.get("algorithm") or "") != ED25519_ALGORITHM:
        raise ValueError("transparency mirror 공개키 metadata가 올바르지 않습니다.")
    if fingerprint != str(mirror.get("public_key_sha256") or ""):
        raise ValueError("transparency mirror 공개키 fingerprint가 올바르지 않습니다.")
    observed_at = str(statement.get("observed_at") or "")
    try:
        parsed = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("transparency mirror observed_at이 올바르지 않습니다.") from exc
    if parsed.tzinfo is None:
        raise ValueError("transparency mirror observed_at에는 시간대가 필요합니다.")
    if str(signature.get("algorithm") or "") != ED25519_ALGORITHM or not verify_ed25519(
        signature_base64=str(signature.get("signature_base64") or ""),
        public_key_base64=public_key,
        payload=_payload(statement),
    ):
        raise ValueError("transparency mirror receipt Ed25519 서명이 유효하지 않습니다.")
    return {
        "receipt_id": receipt_id,
        "head_id": str(head.get("head_id") or ""),
        "tree_size": tree_size,
        "head_document_sha256": str(head.get("document_sha256") or "").lower(),
        "latest_entry_sha256": str(head.get("latest_entry_sha256") or "").lower(),
        "log_key_id": str(head.get("log_key_id") or ""),
        "log_public_key_sha256": str(head.get("log_public_key_sha256") or "").lower(),
        "previous_tree_size": previous_tree_size,
        "previous_receipt_sha256": str(previous.get("receipt_sha256") or "").lower(),
        "mirror_key_id": key_id,
        "mirror_public_key_base64": public_key,
        "mirror_public_key_sha256": fingerprint,
        "observed_at": parsed.astimezone(timezone.utc).replace(microsecond=0).isoformat(),
        "document_sha256": mirror_receipt_document_sha256(document),
        "document": dict(document),
    }


def verify_transparency_mirror_gossip(
    documents: Sequence[Mapping[str, Any]],
    *,
    heads: Sequence[Mapping[str, Any]],
    pinned_public_keys: Mapping[str, str] | None,
    minimum_quorum: int = 0,
    trusted_receipt_sha256: str = "",
) -> dict[str, Any]:
    required = max(0, int(minimum_quorum))
    validated_heads = [validate_transparency_head_document(item) for item in heads]
    if not validated_heads:
        if documents or required or str(trusted_receipt_sha256 or "").strip():
            raise ValueError("mirror receipt가 참조할 transparency head가 없습니다.")
        return {"status": "mirror-gossip-unavailable", "quorum": 0, "required_quorum": required}
    latest_head = max(validated_heads, key=lambda item: int(item["tree_size"]))
    heads_by_digest = {str(item["document_sha256"]): item for item in validated_heads}
    if not documents:
        if required:
            raise ValueError("요구된 transparency mirror quorum이 제공되지 않았습니다.")
        return {
            "status": "mirror-gossip-unverified",
            "quorum": 0,
            "required_quorum": required,
            "tree_size": int(latest_head["tree_size"]),
            "head_document_sha256": str(latest_head["document_sha256"]),
        }

    rows = [validate_transparency_mirror_receipt_document(item) for item in documents]
    if len(rows) > MAX_MIRROR_RECEIPTS_PER_PROOF:
        raise ValueError("transparency mirror receipt 검증 제한을 초과했습니다.")
    pins = {str(key): str(value) for key, value in dict(pinned_public_keys or {}).items()}
    by_mirror: dict[str, list[dict[str, Any]]] = {}
    seen_sequence: dict[tuple[str, int], str] = {}
    seen_receipt_digests: set[str] = set()
    for row in rows:
        sequence_key = (str(row["mirror_public_key_sha256"]), int(row["tree_size"]))
        previous_head = seen_sequence.get(sequence_key)
        if previous_head and previous_head != str(row["head_document_sha256"]):
            raise ValueError("동일 mirror가 같은 tree size의 상충 transparency head를 서명했습니다.")
        seen_sequence[sequence_key] = str(row["head_document_sha256"])
        head = heads_by_digest.get(str(row["head_document_sha256"]))
        if head is None or int(head["tree_size"]) != int(row["tree_size"]):
            raise ValueError("transparency mirror receipt가 제공된 signed head를 참조하지 않습니다.")
        if str(head["latest_entry_sha256"]) != str(row["latest_entry_sha256"]):
            raise ValueError("transparency mirror receipt latest entry digest가 head와 일치하지 않습니다.")
        if str(head["log_public_key_sha256"]) != str(row["log_public_key_sha256"]):
            raise ValueError("transparency mirror receipt log key fingerprint가 head와 일치하지 않습니다.")
        if str(row["mirror_public_key_sha256"]) == str(head["log_public_key_sha256"]):
            raise ValueError("transparency log key는 독립 mirror quorum에 포함될 수 없습니다.")
        by_mirror.setdefault(str(row["mirror_public_key_sha256"]), []).append(row)
        seen_receipt_digests.add(str(row["document_sha256"]))

    trusted_latest: list[dict[str, Any]] = []
    for fingerprint, mirror_rows in by_mirror.items():
        mirror_rows.sort(key=lambda item: int(item["tree_size"]))
        expected_previous_size = 0
        expected_previous_digest = ZERO_SHA256
        for row in mirror_rows:
            if int(row["previous_tree_size"]) != expected_previous_size:
                raise ValueError("transparency mirror receipt 이전 tree size가 연속적이지 않습니다.")
            if str(row["previous_receipt_sha256"]) != expected_previous_digest:
                raise ValueError("transparency mirror receipt 이전 digest가 일치하지 않습니다.")
            expected_previous_size = int(row["tree_size"])
            expected_previous_digest = str(row["document_sha256"])
        latest_receipt = mirror_rows[-1]
        if str(latest_receipt["head_document_sha256"]) != str(latest_head["document_sha256"]):
            continue
        pinned = str(pins.get(str(latest_receipt["mirror_key_id"]), ""))
        if not pinned or public_key_fingerprint(pinned) != fingerprint:
            continue
        if pinned != str(latest_receipt["mirror_public_key_base64"]):
            raise ValueError("transparency mirror embedded 공개키가 고정 공개키와 일치하지 않습니다.")
        trusted_latest.append(latest_receipt)

    quorum = len({str(item["mirror_public_key_sha256"]) for item in trusted_latest})
    if quorum < required:
        raise ValueError(f"transparency mirror quorum이 부족합니다: {quorum}/{required}")
    trusted_digest = str(trusted_receipt_sha256 or "").strip().lower()
    if trusted_digest:
        if not _valid_sha256(trusted_digest):
            raise ValueError("신뢰 transparency mirror receipt SHA-256 형식이 올바르지 않습니다.")
        if trusted_digest not in seen_receipt_digests:
            raise ValueError("외부에서 고정한 mirror receipt가 현재 gossip chain에 없습니다.")
    return {
        "status": "mirror-gossip-verified" if required and quorum >= required else "mirror-gossip-unverified",
        "quorum": quorum,
        "required_quorum": required,
        "tree_size": int(latest_head["tree_size"]),
        "head_id": str(latest_head["head_id"]),
        "head_document_sha256": str(latest_head["document_sha256"]),
        "mirror_key_ids": sorted(str(item["mirror_key_id"]) for item in trusted_latest),
        "latest_observed_at": max((str(item["observed_at"]) for item in trusted_latest), default=""),
        "trusted_receipt_observed": bool(trusted_digest),
    }


def _row_to_document(row: Mapping[str, Any]) -> dict[str, Any]:
    return mirror_receipt_document(json.loads(str(row["statement_json"])), str(row["signature"]))


def list_integrity_proof_transparency_mirror_receipts(
    db_path: str | Path, *, head_id: str = "", limit: int = 100
) -> list[dict[str, Any]]:
    safe_limit = max(1, min(int(limit), 1000))
    where = " WHERE head_id=?" if str(head_id or "").strip() else ""
    params: tuple[Any, ...] = (str(head_id).strip(), safe_limit) if where else (safe_limit,)
    with read_connection(db_path, operation="list_integrity_proof_transparency_mirror_receipts") as conn:
        rows = conn.execute(
            "SELECT receipt_id,head_id,tree_size,head_document_sha256,previous_tree_size,"
            "previous_receipt_sha256,mirror_key_id,mirror_public_key_sha256,observed_at,"
            "document_sha256,created_by,created_at,statement_json,signature "
            "FROM integrity_proof_transparency_mirror_receipts" + where +
            " ORDER BY tree_size DESC,observed_at,mirror_key_id LIMIT ?",
            params,
        ).fetchall()
    return [dict(row) | {"document": _row_to_document(row)} for row in rows]


def export_integrity_proof_transparency_mirror_receipts(db_path: str | Path) -> list[dict[str, Any]]:
    rows = list_integrity_proof_transparency_mirror_receipts(
        db_path, limit=MAX_MIRROR_RECEIPTS_PER_PROOF + 1
    )
    if len(rows) > MAX_MIRROR_RECEIPTS_PER_PROOF:
        raise RuntimeError(
            f"proof에 포함할 transparency mirror receipt 수가 제한({MAX_MIRROR_RECEIPTS_PER_PROOF})을 초과했습니다."
        )
    return [dict(row["document"]) for row in reversed(rows)]
