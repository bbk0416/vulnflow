from __future__ import annotations

import hmac
import json
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence

from app.core.db import utc_now
from app.core.public_signing import (
    ED25519_ALGORITHM,
    public_key_fingerprint,
    verify_ed25519,
)
from app.core.signing import verify_hmac
from app.repositories.audit import (
    _audit_event_digest,
    _canonical_audit_details,
    _checkpoint_payload,
)
from app.services.integrity_proof_common import (
    BASE_PROOF_FILES,
    MAX_PROOF_FILES,
    MAX_PROOF_UNCOMPRESSED,
    PROOF_FORMAT_ED25519,
    PROOF_FORMAT_ED25519_CHECKPOINTED,
    PROOF_FORMAT_ED25519_CONSISTENT,
    PROOF_FORMAT_ED25519_MIRRORED,
    PROOF_FORMAT_ED25519_RECOVERED,
    PROOF_FORMAT_ED25519_ROTATED,
    PROOF_FORMAT_ED25519_TRANSPARENT,
    PROOF_FORMAT_ED25519_WITNESSED,
    PROOF_FORMAT_HMAC,
    _canonical_json_bytes,
    _json_rows_digest,
    _proof_signature_payload,
    _sha256_bytes,
    _sha256_file,
)
from app.services.proof_transitions import validate_transition_document
from app.services.proof_trust_resolver import resolve_trusted_proof_signer
from app.services.proof_revocation import validate_revocation_document
from app.services.proof_checkpoint import (
    validate_revocation_checkpoint_document,
    verify_revocation_checkpoint_chain,
)
from app.services.proof_witness import (
    validate_checkpoint_witness_document,
    verify_checkpoint_witness_quorum,
)
from app.services.proof_transparency import (
    validate_transparency_entry_document,
    validate_transparency_head_document,
    verify_integrity_proof_transparency_log,
)
from app.services.proof_mirror import (
    validate_transparency_mirror_receipt_document,
    verify_transparency_mirror_gossip,
)
from app.services.proof_consistency import (
    validate_mirror_consistency_checkpoint_document,
    verify_mirror_consistency_chain,
)

def _safe_extract(bundle: Path, destination: Path) -> set[str]:
    with zipfile.ZipFile(bundle) as archive:
        infos = archive.infolist()
        if len(infos) > MAX_PROOF_FILES:
            raise ValueError("무결성 증명 번들의 파일 수가 허용 범위를 초과합니다.")
        total = 0
        names: set[str] = set()
        for info in infos:
            name = PurePosixPath(info.filename)
            if info.is_dir() or name.is_absolute() or ".." in name.parts or len(name.parts) != 1:
                raise ValueError("무결성 증명 번들에 안전하지 않은 경로가 포함되어 있습니다.")
            if info.filename in names:
                raise ValueError("무결성 증명 번들에 중복 파일명이 포함되어 있습니다.")
            names.add(info.filename)
            total += int(info.file_size)
            if total > MAX_PROOF_UNCOMPRESSED:
                raise ValueError("무결성 증명 번들의 압축 해제 크기가 허용 범위를 초과합니다.")
        archive.extractall(destination)
        return names

def _read_sums(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in path.read_text(encoding="ascii").splitlines():
        digest, separator, filename = line.partition("  ")
        if not separator or len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest.lower()):
            raise ValueError("무결성 증명 번들의 SHA256SUMS 형식이 올바르지 않습니다.")
        if filename in result:
            raise ValueError("무결성 증명 번들의 SHA256SUMS에 중복 파일명이 있습니다.")
        result[filename] = digest.lower()
    return result

def verify_integrity_proof_bundle(
    bundle_path: str | Path,
    *,
    signing_key: str = "",
    signing_keys: Mapping[str, str] | None = None,
    ed25519_public_keys: Mapping[str, str] | None = None,
    external_key_revocations: Sequence[Mapping[str, Any]] | None = None,
    external_key_transitions: Sequence[Mapping[str, Any]] | None = None,
    external_revocation_checkpoints: Sequence[Mapping[str, Any]] | None = None,
    external_checkpoint_witnesses: Sequence[Mapping[str, Any]] | None = None,
    witness_public_keys: Mapping[str, str] | None = None,
    external_transparency_entries: Sequence[Mapping[str, Any]] | None = None,
    external_transparency_heads: Sequence[Mapping[str, Any]] | None = None,
    transparency_public_keys: Mapping[str, str] | None = None,
    minimum_transparency_tree_size: int = 0,
    trusted_transparency_head_sha256: str = "",
    external_transparency_mirror_receipts: Sequence[Mapping[str, Any]] | None = None,
    mirror_public_keys: Mapping[str, str] | None = None,
    minimum_mirror_quorum: int = 0,
    trusted_mirror_receipt_sha256: str = "",
    external_mirror_consistency_checkpoints: Sequence[Mapping[str, Any]] | None = None,
    minimum_mirror_consistency_quorum: int = 0,
    trusted_mirror_consistency_checkpoint_sha256: str = "",
    minimum_checkpoint_sequence: int = 0,
    trusted_checkpoint_sha256: str = "",
    minimum_witness_quorum: int = 0,
    allow_embedded_public_key: bool = False,
    require_signature: bool = True,
) -> dict[str, Any]:
    bundle = Path(bundle_path)
    if not bundle.is_file() or bundle.stat().st_size == 0:
        raise ValueError("무결성 증명 번들이 비어 있거나 존재하지 않습니다.")
    try:
        with tempfile.TemporaryDirectory(prefix="vulnflow_integrity_verify_") as temp_name:
            temp = Path(temp_name)
            names = _safe_extract(bundle, temp)
            if not BASE_PROOF_FILES.issubset(names):
                missing = BASE_PROOF_FILES - names
                raise ValueError("무결성 증명 번들 필수 파일이 없습니다: " + ", ".join(sorted(missing)))
            manifest_bytes = (temp / "manifest.json").read_bytes()
            try:
                manifest = json.loads(manifest_bytes)
            except json.JSONDecodeError as exc:
                raise ValueError("무결성 증명 manifest 형식이 올바르지 않습니다.") from exc
            proof_format = str(manifest.get("format") or "") if isinstance(manifest, dict) else ""
            if proof_format == PROOF_FORMAT_HMAC:
                required = BASE_PROOF_FILES | {"proof.hmac"}
                expected_hash_targets = BASE_PROOF_FILES - {"SHA256SUMS.txt"}
                signature_version = 1
            elif proof_format == PROOF_FORMAT_ED25519:
                required = BASE_PROOF_FILES | {"proof.ed25519", "proof-public-key.json"}
                expected_hash_targets = (BASE_PROOF_FILES - {"SHA256SUMS.txt"}) | {"proof-public-key.json"}
                signature_version = 2
            elif proof_format == PROOF_FORMAT_ED25519_ROTATED:
                required = BASE_PROOF_FILES | {"proof.ed25519", "proof-public-key.json", "proof-key-transitions.json"}
                expected_hash_targets = (BASE_PROOF_FILES - {"SHA256SUMS.txt"}) | {
                    "proof-public-key.json", "proof-key-transitions.json"
                }
                signature_version = 3
            elif proof_format == PROOF_FORMAT_ED25519_RECOVERED:
                required = BASE_PROOF_FILES | {
                    "proof.ed25519", "proof-public-key.json",
                    "proof-key-transitions.json", "proof-key-revocations.json",
                }
                expected_hash_targets = (BASE_PROOF_FILES - {"SHA256SUMS.txt"}) | {
                    "proof-public-key.json", "proof-key-transitions.json",
                    "proof-key-revocations.json",
                }
                signature_version = 4
            elif proof_format == PROOF_FORMAT_ED25519_CHECKPOINTED:
                required = BASE_PROOF_FILES | {
                    "proof.ed25519", "proof-public-key.json", "proof-key-transitions.json",
                    "proof-key-revocations.json", "proof-revocation-checkpoints.json",
                }
                expected_hash_targets = (BASE_PROOF_FILES - {"SHA256SUMS.txt"}) | {
                    "proof-public-key.json", "proof-key-transitions.json",
                    "proof-key-revocations.json", "proof-revocation-checkpoints.json",
                }
                signature_version = 5
            elif proof_format == PROOF_FORMAT_ED25519_WITNESSED:
                required = BASE_PROOF_FILES | {
                    "proof.ed25519", "proof-public-key.json", "proof-key-transitions.json",
                    "proof-key-revocations.json", "proof-revocation-checkpoints.json",
                    "proof-revocation-witnesses.json",
                }
                expected_hash_targets = (BASE_PROOF_FILES - {"SHA256SUMS.txt"}) | {
                    "proof-public-key.json", "proof-key-transitions.json", "proof-key-revocations.json",
                    "proof-revocation-checkpoints.json", "proof-revocation-witnesses.json",
                }
                signature_version = 6
            elif proof_format == PROOF_FORMAT_ED25519_TRANSPARENT:
                required = BASE_PROOF_FILES | {
                    "proof.ed25519", "proof-public-key.json", "proof-key-transitions.json",
                    "proof-key-revocations.json", "proof-revocation-checkpoints.json",
                    "proof-revocation-witnesses.json", "proof-transparency-entries.json",
                    "proof-transparency-heads.json",
                }
                expected_hash_targets = (BASE_PROOF_FILES - {"SHA256SUMS.txt"}) | {
                    "proof-public-key.json", "proof-key-transitions.json", "proof-key-revocations.json",
                    "proof-revocation-checkpoints.json", "proof-revocation-witnesses.json",
                    "proof-transparency-entries.json", "proof-transparency-heads.json",
                }
                signature_version = 7
            elif proof_format == PROOF_FORMAT_ED25519_MIRRORED:
                required = BASE_PROOF_FILES | {
                    "proof.ed25519", "proof-public-key.json", "proof-key-transitions.json",
                    "proof-key-revocations.json", "proof-revocation-checkpoints.json",
                    "proof-revocation-witnesses.json", "proof-transparency-entries.json",
                    "proof-transparency-heads.json", "proof-transparency-mirror-receipts.json",
                }
                expected_hash_targets = (BASE_PROOF_FILES - {"SHA256SUMS.txt"}) | {
                    "proof-public-key.json", "proof-key-transitions.json", "proof-key-revocations.json",
                    "proof-revocation-checkpoints.json", "proof-revocation-witnesses.json",
                    "proof-transparency-entries.json", "proof-transparency-heads.json",
                    "proof-transparency-mirror-receipts.json",
                }
                signature_version = 8
            elif proof_format == PROOF_FORMAT_ED25519_CONSISTENT:
                required = BASE_PROOF_FILES | {
                    "proof.ed25519", "proof-public-key.json", "proof-key-transitions.json",
                    "proof-key-revocations.json", "proof-revocation-checkpoints.json",
                    "proof-revocation-witnesses.json", "proof-transparency-entries.json",
                    "proof-transparency-heads.json", "proof-transparency-mirror-receipts.json",
                    "proof-mirror-consistency-checkpoints.json",
                }
                expected_hash_targets = (BASE_PROOF_FILES - {"SHA256SUMS.txt"}) | {
                    "proof-public-key.json", "proof-key-transitions.json", "proof-key-revocations.json",
                    "proof-revocation-checkpoints.json", "proof-revocation-witnesses.json",
                    "proof-transparency-entries.json", "proof-transparency-heads.json",
                    "proof-transparency-mirror-receipts.json", "proof-mirror-consistency-checkpoints.json",
                }
                signature_version = 9
            else:
                raise ValueError("지원하지 않는 무결성 증명 형식입니다.")
            missing = required - names
            if missing:
                raise ValueError("무결성 증명 번들 필수 파일이 없습니다: " + ", ".join(sorted(missing)))
            unexpected = names - required
            if unexpected:
                raise ValueError("무결성 증명 번들에 알 수 없는 파일이 있습니다: " + ", ".join(sorted(unexpected)))

            sums_bytes = (temp / "SHA256SUMS.txt").read_bytes()
            sums = _read_sums(temp / "SHA256SUMS.txt")
            if set(sums) != expected_hash_targets:
                raise ValueError("무결성 증명 번들의 해시 대상 목록이 일치하지 않습니다.")
            for filename, expected in sums.items():
                if _sha256_file(temp / filename) != expected:
                    raise ValueError(f"무결성 증명 파일 해시가 일치하지 않습니다: {filename}")

            signature_meta = manifest.get("signature") if isinstance(manifest.get("signature"), dict) else {}
            signed = bool(signature_meta.get("signed"))
            if require_signature and not signed:
                raise ValueError("서명되지 않은 무결성 증명 번들은 허용되지 않습니다.")
            signature_result: dict[str, Any] = {
                "valid": False, "status": "unsigned", "resolved_key_id": None,
                "algorithm": str(signature_meta.get("algorithm") or ""), "trust_status": "unsigned",
            }
            if signed and proof_format == PROOF_FORMAT_HMAC:
                checked = verify_hmac(
                    signature=(temp / "proof.hmac").read_text(encoding="ascii").strip(),
                    payload=_proof_signature_payload(manifest_bytes, sums_bytes, version=signature_version),
                    signing_keys=signing_keys,
                    key_id=str(signature_meta.get("key_id") or "") or None,
                    legacy_key=signing_key,
                )
                if not checked["valid"]:
                    raise ValueError("무결성 증명 HMAC 서명이 일치하지 않거나 필요한 키를 사용할 수 없습니다.")
                signature_result = checked | {"algorithm": "HMAC-SHA256", "trust_status": "shared-secret"}
            elif signed:
                try:
                    public_document = json.loads((temp / "proof-public-key.json").read_text(encoding="utf-8"))
                except json.JSONDecodeError as exc:
                    raise ValueError("무결성 증명 공개키 문서가 올바른 JSON이 아닙니다.") from exc
                if not isinstance(public_document, dict):
                    raise ValueError("무결성 증명 공개키 문서가 JSON 객체가 아닙니다.")
                key_id = str(signature_meta.get("key_id") or "")
                embedded_key = str(public_document.get("public_key_base64") or "")
                embedded_fingerprint = public_key_fingerprint(embedded_key)
                declared_fingerprint = str(signature_meta.get("public_key_sha256") or "")
                if public_document.get("key_id") != key_id or public_document.get("algorithm") != ED25519_ALGORITHM:
                    raise ValueError("무결성 증명 공개키 metadata가 manifest와 일치하지 않습니다.")
                if embedded_fingerprint != declared_fingerprint or public_document.get("public_key_sha256") != declared_fingerprint:
                    raise ValueError("무결성 증명 공개키 fingerprint가 manifest와 일치하지 않습니다.")
                transition_documents: list[dict[str, Any]] = []
                if proof_format in {PROOF_FORMAT_ED25519_ROTATED, PROOF_FORMAT_ED25519_RECOVERED, PROOF_FORMAT_ED25519_CHECKPOINTED, PROOF_FORMAT_ED25519_WITNESSED, PROOF_FORMAT_ED25519_TRANSPARENT, PROOF_FORMAT_ED25519_MIRRORED, PROOF_FORMAT_ED25519_CONSISTENT}:
                    try:
                        transition_documents = json.loads(
                            (temp / "proof-key-transitions.json").read_text(encoding="utf-8")
                        )
                    except json.JSONDecodeError as exc:
                        raise ValueError("무결성 증명 키 전환 문서가 올바른 JSON이 아닙니다.") from exc
                    if not isinstance(transition_documents, list):
                        raise ValueError("무결성 증명 키 전환 문서가 배열이 아닙니다.")
                    transition_meta = dict(manifest.get("key_transitions") or {})
                    if len(transition_documents) != int(transition_meta.get("count") or 0):
                        raise ValueError("무결성 증명 키 전환 건수가 manifest와 일치하지 않습니다.")
                    if _json_rows_digest(transition_documents) != str(transition_meta.get("sha256") or ""):
                        raise ValueError("무결성 증명 키 전환 digest가 manifest와 일치하지 않습니다.")
                    for transition_document in transition_documents:
                        validate_transition_document(transition_document)
                revocation_documents: list[dict[str, Any]] = []
                if proof_format in {PROOF_FORMAT_ED25519_RECOVERED, PROOF_FORMAT_ED25519_CHECKPOINTED, PROOF_FORMAT_ED25519_WITNESSED, PROOF_FORMAT_ED25519_TRANSPARENT, PROOF_FORMAT_ED25519_MIRRORED, PROOF_FORMAT_ED25519_CONSISTENT}:
                    try:
                        revocation_documents = json.loads(
                            (temp / "proof-key-revocations.json").read_text(encoding="utf-8")
                        )
                    except json.JSONDecodeError as exc:
                        raise ValueError("무결성 증명 키 폐기 문서가 올바른 JSON이 아닙니다.") from exc
                    if not isinstance(revocation_documents, list):
                        raise ValueError("무결성 증명 키 폐기 문서가 배열이 아닙니다.")
                    revocation_meta = dict(manifest.get("key_revocations") or {})
                    if len(revocation_documents) != int(revocation_meta.get("count") or 0):
                        raise ValueError("무결성 증명 키 폐기 건수가 manifest와 일치하지 않습니다.")
                    if _json_rows_digest(revocation_documents) != str(revocation_meta.get("sha256") or ""):
                        raise ValueError("무결성 증명 키 폐기 digest가 manifest와 일치하지 않습니다.")
                    for revocation_document in revocation_documents:
                        validate_revocation_document(revocation_document)
                checkpoint_documents: list[dict[str, Any]] = []
                if proof_format in {PROOF_FORMAT_ED25519_CHECKPOINTED, PROOF_FORMAT_ED25519_WITNESSED, PROOF_FORMAT_ED25519_TRANSPARENT, PROOF_FORMAT_ED25519_MIRRORED, PROOF_FORMAT_ED25519_CONSISTENT}:
                    try:
                        checkpoint_documents = json.loads(
                            (temp / "proof-revocation-checkpoints.json").read_text(encoding="utf-8")
                        )
                    except json.JSONDecodeError as exc:
                        raise ValueError("무결성 증명 registry checkpoint가 올바른 JSON이 아닙니다.") from exc
                    if not isinstance(checkpoint_documents, list):
                        raise ValueError("무결성 증명 registry checkpoint가 배열이 아닙니다.")
                    checkpoint_meta = dict(manifest.get("revocation_checkpoints") or {})
                    if len(checkpoint_documents) != int(checkpoint_meta.get("count") or 0):
                        raise ValueError("무결성 증명 registry checkpoint 건수가 manifest와 일치하지 않습니다.")
                    if _json_rows_digest(checkpoint_documents) != str(checkpoint_meta.get("sha256") or ""):
                        raise ValueError("무결성 증명 registry checkpoint digest가 manifest와 일치하지 않습니다.")
                    for checkpoint_document in checkpoint_documents:
                        validate_revocation_checkpoint_document(checkpoint_document)
                witness_documents: list[dict[str, Any]] = []
                if proof_format in {PROOF_FORMAT_ED25519_WITNESSED, PROOF_FORMAT_ED25519_TRANSPARENT, PROOF_FORMAT_ED25519_MIRRORED, PROOF_FORMAT_ED25519_CONSISTENT}:
                    try:
                        witness_documents = json.loads(
                            (temp / "proof-revocation-witnesses.json").read_text(encoding="utf-8")
                        )
                    except json.JSONDecodeError as exc:
                        raise ValueError("무결성 증명 checkpoint witness가 올바른 JSON이 아닙니다.") from exc
                    if not isinstance(witness_documents, list):
                        raise ValueError("무결성 증명 checkpoint witness가 배열이 아닙니다.")
                    witness_meta = dict(manifest.get("checkpoint_witnesses") or {})
                    if len(witness_documents) != int(witness_meta.get("count") or 0):
                        raise ValueError("무결성 증명 checkpoint witness 건수가 manifest와 일치하지 않습니다.")
                    if _json_rows_digest(witness_documents) != str(witness_meta.get("sha256") or ""):
                        raise ValueError("무결성 증명 checkpoint witness digest가 manifest와 일치하지 않습니다.")
                    for witness_document in witness_documents:
                        validate_checkpoint_witness_document(witness_document)
                transparency_entry_documents: list[dict[str, Any]] = []
                transparency_head_documents: list[dict[str, Any]] = []
                if proof_format in {PROOF_FORMAT_ED25519_TRANSPARENT, PROOF_FORMAT_ED25519_MIRRORED, PROOF_FORMAT_ED25519_CONSISTENT}:
                    try:
                        transparency_entry_documents = json.loads(
                            (temp / "proof-transparency-entries.json").read_text(encoding="utf-8")
                        )
                        transparency_head_documents = json.loads(
                            (temp / "proof-transparency-heads.json").read_text(encoding="utf-8")
                        )
                    except json.JSONDecodeError as exc:
                        raise ValueError("무결성 증명 transparency log 문서가 올바른 JSON이 아닙니다.") from exc
                    if not isinstance(transparency_entry_documents, list) or not isinstance(transparency_head_documents, list):
                        raise ValueError("무결성 증명 transparency log 문서가 배열이 아닙니다.")
                    transparency_meta = dict(manifest.get("transparency_log") or {})
                    if len(transparency_entry_documents) != int(transparency_meta.get("entry_count") or 0):
                        raise ValueError("무결성 증명 transparency entry 건수가 manifest와 일치하지 않습니다.")
                    if len(transparency_head_documents) != int(transparency_meta.get("head_count") or 0):
                        raise ValueError("무결성 증명 transparency head 건수가 manifest와 일치하지 않습니다.")
                    if _json_rows_digest(transparency_entry_documents) != str(transparency_meta.get("entries_sha256") or ""):
                        raise ValueError("무결성 증명 transparency entry digest가 manifest와 일치하지 않습니다.")
                    if _json_rows_digest(transparency_head_documents) != str(transparency_meta.get("heads_sha256") or ""):
                        raise ValueError("무결성 증명 transparency head digest가 manifest와 일치하지 않습니다.")
                    for document in transparency_entry_documents:
                        validate_transparency_entry_document(document)
                    for document in transparency_head_documents:
                        validate_transparency_head_document(document)
                mirror_receipt_documents: list[dict[str, Any]] = []
                if proof_format in {PROOF_FORMAT_ED25519_MIRRORED, PROOF_FORMAT_ED25519_CONSISTENT}:
                    try:
                        mirror_receipt_documents = json.loads(
                            (temp / "proof-transparency-mirror-receipts.json").read_text(encoding="utf-8")
                        )
                    except json.JSONDecodeError as exc:
                        raise ValueError("무결성 증명 transparency mirror receipt가 올바른 JSON이 아닙니다.") from exc
                    if not isinstance(mirror_receipt_documents, list):
                        raise ValueError("무결성 증명 transparency mirror receipt가 배열이 아닙니다.")
                    mirror_meta = dict(manifest.get("mirror_gossip") or {})
                    if len(mirror_receipt_documents) != int(mirror_meta.get("receipt_count") or 0):
                        raise ValueError("무결성 증명 mirror receipt 건수가 manifest와 일치하지 않습니다.")
                    if _json_rows_digest(mirror_receipt_documents) != str(mirror_meta.get("receipts_sha256") or ""):
                        raise ValueError("무결성 증명 mirror receipt digest가 manifest와 일치하지 않습니다.")
                    for document in mirror_receipt_documents:
                        validate_transparency_mirror_receipt_document(document)
                mirror_consistency_documents: list[dict[str, Any]] = []
                if proof_format == PROOF_FORMAT_ED25519_CONSISTENT:
                    try:
                        mirror_consistency_documents = json.loads(
                            (temp / "proof-mirror-consistency-checkpoints.json").read_text(encoding="utf-8")
                        )
                    except json.JSONDecodeError as exc:
                        raise ValueError("무결성 증명 mirror consistency checkpoint가 올바른 JSON이 아닙니다.") from exc
                    if not isinstance(mirror_consistency_documents, list):
                        raise ValueError("무결성 증명 mirror consistency checkpoint가 배열이 아닙니다.")
                    consistency_meta = dict(manifest.get("mirror_consistency") or {})
                    if len(mirror_consistency_documents) != int(consistency_meta.get("checkpoint_count") or 0):
                        raise ValueError("무결성 증명 mirror consistency checkpoint 건수가 manifest와 일치하지 않습니다.")
                    if _json_rows_digest(mirror_consistency_documents) != str(consistency_meta.get("checkpoints_sha256") or ""):
                        raise ValueError("무결성 증명 mirror consistency checkpoint digest가 manifest와 일치하지 않습니다.")
                    for document in mirror_consistency_documents:
                        validate_mirror_consistency_checkpoint_document(document)

                combined_transitions = transition_documents + [dict(item) for item in (external_key_transitions or [])]
                combined_revocations = revocation_documents + [dict(item) for item in (external_key_revocations or [])]
                combined_checkpoints = checkpoint_documents + [dict(item) for item in (external_revocation_checkpoints or [])]
                combined_witnesses = witness_documents + [dict(item) for item in (external_checkpoint_witnesses or [])]
                combined_transparency_entries = transparency_entry_documents + [
                    dict(item) for item in (external_transparency_entries or [])
                ]
                combined_transparency_heads = transparency_head_documents + [
                    dict(item) for item in (external_transparency_heads or [])
                ]
                combined_mirror_receipts = mirror_receipt_documents + [
                    dict(item) for item in (external_transparency_mirror_receipts or [])
                ]
                combined_mirror_consistency = mirror_consistency_documents + [
                    dict(item) for item in (external_mirror_consistency_checkpoints or [])
                ]
                # Remove byte-identical duplicate public documents while preserving order.
                def _dedupe(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
                    result: list[dict[str, Any]] = []
                    seen: set[str] = set()
                    for row in rows:
                        digest = _sha256_bytes(_canonical_json_bytes(row))
                        if digest not in seen:
                            result.append(row)
                            seen.add(digest)
                    return result
                combined_transitions = _dedupe(combined_transitions)
                combined_revocations = _dedupe(combined_revocations)
                combined_checkpoints = _dedupe(combined_checkpoints)
                combined_witnesses = _dedupe(combined_witnesses)
                combined_transparency_entries = _dedupe(combined_transparency_entries)
                combined_transparency_heads = _dedupe(combined_transparency_heads)
                combined_mirror_receipts = _dedupe(combined_mirror_receipts)
                combined_mirror_consistency = _dedupe(combined_mirror_consistency)
                freshness = verify_revocation_checkpoint_chain(
                    combined_checkpoints,
                    pinned_public_keys=ed25519_public_keys,
                    revocations=combined_revocations,
                    transitions=combined_transitions,
                    minimum_sequence=minimum_checkpoint_sequence,
                    trusted_checkpoint_sha256=trusted_checkpoint_sha256,
                )
                witness_meta = dict(manifest.get("checkpoint_witnesses") or {})
                effective_witness_quorum = max(
                    max(0, int(minimum_witness_quorum)),
                    int(witness_meta.get("minimum_quorum") or 0),
                )
                witness_quorum = verify_checkpoint_witness_quorum(
                    combined_witnesses,
                    checkpoints=combined_checkpoints,
                    pinned_public_keys=witness_public_keys,
                    minimum_quorum=effective_witness_quorum,
                )
                transparency_log = verify_integrity_proof_transparency_log(
                    combined_transparency_entries,
                    combined_transparency_heads,
                    pinned_public_keys=transparency_public_keys,
                    checkpoints=combined_checkpoints,
                    witnesses=combined_witnesses,
                    minimum_tree_size=minimum_transparency_tree_size,
                    trusted_head_sha256=trusted_transparency_head_sha256,
                )
                mirror_meta = dict(manifest.get("mirror_gossip") or {})
                effective_mirror_quorum = max(
                    max(0, int(minimum_mirror_quorum)),
                    int(mirror_meta.get("minimum_quorum") or 0),
                )
                mirror_gossip = verify_transparency_mirror_gossip(
                    combined_mirror_receipts,
                    heads=combined_transparency_heads,
                    pinned_public_keys=mirror_public_keys,
                    minimum_quorum=effective_mirror_quorum,
                    trusted_receipt_sha256=trusted_mirror_receipt_sha256,
                )
                consistency_meta = dict(manifest.get("mirror_consistency") or {})
                effective_consistency_quorum = max(
                    max(0, int(minimum_mirror_consistency_quorum)),
                    int(consistency_meta.get("minimum_quorum") or 0),
                )
                mirror_consistency = verify_mirror_consistency_chain(
                    combined_mirror_consistency,
                    heads=combined_transparency_heads,
                    receipts=combined_mirror_receipts,
                    pinned_public_keys=mirror_public_keys,
                    minimum_quorum=effective_consistency_quorum,
                    trusted_checkpoint_sha256=trusted_mirror_consistency_checkpoint_sha256,
                )
                resolved = resolve_trusted_proof_signer(
                    target_key_id=key_id,
                    target_public_key=embedded_key,
                    transitions=combined_transitions,
                    pinned_public_keys=ed25519_public_keys,
                    proof_created_at=str(manifest.get("created_at") or ""),
                    revocations=combined_revocations,
                )
                if resolved:
                    verification_key = str(resolved["verification_key"])
                    trust_status = str(resolved["trust_status"])
                    trust_path = list(resolved.get("trust_path") or [])
                    transition_ids = list(resolved.get("transition_ids") or [])
                    revocation_ids = list(resolved.get("revocation_ids") or [])
                elif allow_embedded_public_key:
                    verification_key = embedded_key
                    trust_status = "embedded-key-untrusted"
                    trust_path = [key_id]
                    transition_ids = []
                    revocation_ids = []
                else:
                    raise ValueError("무결성 증명 검증에 신뢰된 Ed25519 공개키 또는 유효한 키 전환 체인이 필요합니다.")
                if not verify_ed25519(
                    signature_base64=(temp / "proof.ed25519").read_text(encoding="ascii").strip(),
                    public_key_base64=verification_key,
                    payload=_proof_signature_payload(manifest_bytes, sums_bytes, version=signature_version),
                ):
                    raise ValueError("무결성 증명 Ed25519 서명이 일치하지 않습니다.")
                signature_result = {
                    "valid": True,
                    "status": "valid",
                    "resolved_key_id": key_id,
                    "algorithm": ED25519_ALGORITHM,
                    "trust_status": trust_status,
                    "public_key_sha256": declared_fingerprint,
                    "trust_path": trust_path,
                    "transition_ids": transition_ids,
                    "revocation_ids": revocation_ids,
                    "revocation_freshness": freshness,
                    "witness_quorum": witness_quorum,
                    "transparency_log": transparency_log,
                    "mirror_gossip": mirror_gossip,
                    "mirror_consistency": mirror_consistency,
                }

            events: list[dict[str, Any]] = []
            for line in (temp / "audit-events.jsonl").read_text(encoding="utf-8").splitlines():
                if line.strip():
                    row = json.loads(line)
                    if not isinstance(row, dict):
                        raise ValueError("감사 이벤트 증명 행이 JSON 객체가 아닙니다.")
                    events.append(row)
            audit_meta = dict(manifest.get("audit") or {})
            if _sha256_file(temp / "audit-events.jsonl") != str(audit_meta.get("events_sha256") or ""):
                raise ValueError("감사 이벤트 집합 digest가 manifest와 일치하지 않습니다.")
            if len(events) != int(audit_meta.get("retained_event_count") or 0):
                raise ValueError("감사 이벤트 건수가 manifest와 일치하지 않습니다.")
            expected_seq = int(audit_meta.get("anchor_seq") or 0) + 1
            previous_hash = str(audit_meta.get("anchor_hash") or "")
            for row in events:
                seq = int(row.get("chain_seq") or 0)
                if seq != expected_seq:
                    raise ValueError(f"감사 이벤트 순번이 연속적이지 않습니다: expected={expected_seq}, actual={seq}")
                if not hmac.compare_digest(str(row.get("prev_hash") or ""), previous_hash):
                    raise ValueError(f"감사 이벤트 이전 해시가 일치하지 않습니다: chain_seq={seq}")
                expected_hash = _audit_event_digest(
                    chain_seq=seq,
                    finding_id=row.get("finding_id"),
                    event_type=str(row.get("event_type") or ""),
                    actor=str(row.get("actor") or ""),
                    summary=str(row.get("summary") or ""),
                    details_json=_canonical_audit_details(raw=str(row.get("details_json") or "{}")),
                    created_at=str(row.get("created_at") or ""),
                    prev_hash=str(row.get("prev_hash") or ""),
                )
                if not hmac.compare_digest(expected_hash, str(row.get("event_hash") or "")):
                    raise ValueError(f"감사 이벤트 해시가 일치하지 않습니다: chain_seq={seq}")
                previous_hash = str(row["event_hash"])
                expected_seq += 1
            calculated_last_seq = expected_seq - 1
            if calculated_last_seq != int(audit_meta.get("last_seq") or 0):
                raise ValueError("감사 체인 마지막 순번이 manifest와 일치하지 않습니다.")
            if not hmac.compare_digest(previous_hash, str(audit_meta.get("last_hash") or "")):
                raise ValueError("감사 체인 마지막 해시가 manifest와 일치하지 않습니다.")

            checkpoints = json.loads((temp / "audit-checkpoints.json").read_text(encoding="utf-8"))
            if not isinstance(checkpoints, list):
                raise ValueError("감사 체크포인트 증명이 배열이 아닙니다.")
            checkpoint = next(
                (item for item in checkpoints if item.get("checkpoint_id") == audit_meta.get("checkpoint_id")), None
            )
            if checkpoint is None:
                raise ValueError("manifest가 참조한 감사 체크포인트가 없습니다.")
            if int(checkpoint.get("chain_seq") or 0) != calculated_last_seq or not hmac.compare_digest(
                str(checkpoint.get("event_hash") or ""), previous_hash
            ):
                raise ValueError("최종 감사 체크포인트가 현재 체인 head와 일치하지 않습니다.")
            checkpoint_result = verify_hmac(
                signature=str(checkpoint.get("signature") or ""),
                payload=_checkpoint_payload(
                    chain_seq=int(checkpoint["chain_seq"]),
                    event_hash=str(checkpoint["event_hash"]),
                    created_at=str(checkpoint["created_at"]),
                    key_id=checkpoint.get("key_id"),
                ),
                signing_keys=signing_keys,
                key_id=checkpoint.get("key_id"),
                legacy_key=signing_key,
            )
            if proof_format == PROOF_FORMAT_HMAC and not checkpoint_result["valid"]:
                raise ValueError("최종 감사 체크포인트 서명이 유효하지 않습니다.")
            checkpoint_signature_status = (
                "valid" if checkpoint_result["valid"] else "covered-by-ed25519-proof-not-independently-verified"
            )

            prune_history = json.loads((temp / "audit-prune-history.json").read_text(encoding="utf-8"))
            archives = json.loads((temp / "execution-receipt-archives.json").read_text(encoding="utf-8"))
            for label, rows, meta in (
                ("prune history", prune_history, manifest.get("prune_history") or {}),
                ("execution receipt archives", archives, manifest.get("execution_receipt_archives") or {}),
            ):
                if not isinstance(rows, list):
                    raise ValueError(f"{label} 증명이 배열이 아닙니다.")
                if len(rows) != int(dict(meta).get("count") or 0):
                    raise ValueError(f"{label} 건수가 manifest와 일치하지 않습니다.")
                if _json_rows_digest(rows) != str(dict(meta).get("sha256") or ""):
                    raise ValueError(f"{label} digest가 manifest와 일치하지 않습니다.")

            return {
                "valid": True,
                "proof_id": manifest.get("proof_id"),
                "proof_format": proof_format,
                "bundle_sha256": _sha256_file(bundle),
                "signed": signed,
                "signature_algorithm": signature_result.get("algorithm"),
                "signature_status": signature_result.get("status"),
                "trust_status": signature_result.get("trust_status"),
                "signing_key_id": signature_result.get("resolved_key_id"),
                "public_key_sha256": signature_result.get("public_key_sha256"),
                "trust_path": signature_result.get("trust_path") or [],
                "transition_ids": signature_result.get("transition_ids") or [],
                "revocation_ids": signature_result.get("revocation_ids") or [],
                "revocation_freshness": signature_result.get("revocation_freshness") or {
                    "status": "not-applicable", "sequence": 0, "document_sha256": ""
                },
                "witness_quorum": signature_result.get("witness_quorum") or {
                    "status": "not-applicable", "quorum": 0, "required_quorum": 0
                },
                "transparency_log": signature_result.get("transparency_log") or {
                    "status": "not-applicable", "tree_size": 0, "head_document_sha256": ""
                },
                "mirror_gossip": signature_result.get("mirror_gossip") or {
                    "status": "not-applicable", "quorum": 0, "required_quorum": 0
                },
                "mirror_consistency": signature_result.get("mirror_consistency") or {
                    "status": "not-applicable", "sequence": 0, "quorum": 0
                },
                "audit": {
                    "anchor_seq": int(audit_meta.get("anchor_seq") or 0),
                    "last_seq": calculated_last_seq,
                    "last_hash": previous_hash,
                    "retained_event_count": len(events),
                    "checkpoint_id": checkpoint.get("checkpoint_id"),
                    "checkpoint_signature_status": checkpoint_signature_status,
                },
                "prune_history_count": len(prune_history),
                "execution_receipt_archive_count": len(archives),
                "verified_at": utc_now(),
            }
    except zipfile.BadZipFile as exc:
        raise ValueError("유효한 ZIP 무결성 증명 번들이 아닙니다.") from exc
