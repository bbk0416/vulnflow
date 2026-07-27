from __future__ import annotations

import shutil
import tempfile
import uuid
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping

from app.core.db import utc_now
from app.core.public_signing import (
    ED25519_ALGORITHM,
    public_key_fingerprint,
    public_key_from_private,
    sign_ed25519,
)
from app.core.signing import KEY_ID_RE, hmac_sha256
from app.core.transactions import read_connection
from app.repositories.audit import create_audit_checkpoint, verify_audit_integrity
from app.services.exports import register_export_artifact
from app.services.integrity_proof_common import (
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
    _event_export_row,
    _events_jsonl,
    _proof_signature_payload,
    _sha256_bytes,
    _sha256_file,
)
from app.services.proof_transitions import export_integrity_proof_key_transitions
from app.services.proof_revocation import export_integrity_proof_key_revocations
from app.services.proof_checkpoint import (
    export_integrity_proof_revocation_checkpoints,
    verify_revocation_checkpoint_chain,
)
from app.services.proof_witness import (
    export_integrity_proof_checkpoint_witnesses,
    verify_checkpoint_witness_quorum,
)
from app.services.proof_transparency import (
    export_integrity_proof_transparency_entries,
    export_integrity_proof_transparency_heads,
    verify_integrity_proof_transparency_log,
)
from app.services.proof_mirror import (
    export_integrity_proof_transparency_mirror_receipts,
    verify_transparency_mirror_gossip,
)
from app.services.proof_consistency import (
    export_integrity_proof_mirror_consistency_checkpoints,
    verify_mirror_consistency_chain,
)

def create_integrity_proof_bundle(
    db_path: str | Path,
    export_dir: str | Path,
    *,
    actor: str,
    app_version: str,
    schema_version: int,
    signing_key: str,
    signing_key_id: str,
    signing_keys: Mapping[str, str] | None = None,
    ed25519_private_key: str = "",
    ed25519_public_key: str = "",
    ed25519_key_id: str = "",
    require_public_signature: bool = False,
    minimum_witness_quorum: int = 1,
    require_transparency_log: bool = False,
    minimum_mirror_quorum: int = 1,
    require_mirror_gossip: bool = False,
    require_mirror_consistency: bool = False,
    retention_days: int = 7,
    max_storage_bytes: int = 0,
    min_free_bytes: int = 0,
) -> dict[str, Any]:
    if len(str(signing_key)) < 16:
        raise ValueError("무결성 증명 번들에는 최소 16자 이상의 활성 감사 서명 키가 필요합니다.")
    if not signing_key_id or not KEY_ID_RE.fullmatch(str(signing_key_id)):
        raise ValueError("무결성 증명 번들의 감사 서명 키 ID가 올바르지 않습니다.")
    use_ed25519 = bool(str(ed25519_private_key or "").strip())
    if require_public_signature and not use_ed25519:
        raise ValueError("공개 검증 필수 모드에는 활성 Ed25519 proof signing key가 필요합니다.")
    if use_ed25519:
        if not ed25519_key_id or not KEY_ID_RE.fullmatch(str(ed25519_key_id)):
            raise ValueError("무결성 증명 번들의 Ed25519 키 ID가 올바르지 않습니다.")
        derived_public_key = public_key_from_private(str(ed25519_private_key))
        if not str(ed25519_public_key or "").strip():
            ed25519_public_key = derived_public_key
        elif str(ed25519_public_key) != derived_public_key:
            raise ValueError("무결성 증명 Ed25519 private/public key가 일치하지 않습니다.")
        derived_fingerprint = public_key_fingerprint(str(ed25519_public_key))
    else:
        derived_fingerprint = ""

    integrity = verify_audit_integrity(
        db_path, signing_keys=dict(signing_keys or {}) or {str(signing_key_id): str(signing_key)}
    )
    if not integrity.get("valid"):
        raise RuntimeError("감사 체인 무결성이 정상일 때만 증명 번들을 생성할 수 있습니다.")

    checkpoint = create_audit_checkpoint(
        db_path,
        signing_key=str(signing_key),
        signing_key_id=str(signing_key_id),
        actor=actor,
    )
    with read_connection(db_path, operation="create_integrity_proof_bundle") as conn:
        state = dict(conn.execute(
            "SELECT anchor_seq,anchor_hash,last_seq,last_hash,updated_at FROM audit_chain_state WHERE singleton_id=1"
        ).fetchone())
        event_rows = [_event_export_row(row) for row in conn.execute(
            "SELECT chain_seq,finding_id,event_type,actor,summary,details_json,created_at,prev_hash,event_hash "
            "FROM audit_events ORDER BY chain_seq"
        ).fetchall()]
        checkpoints = [dict(row) for row in conn.execute(
            "SELECT checkpoint_id,chain_seq,event_hash,signature,key_id,algorithm,created_by,created_at "
            "FROM audit_checkpoints ORDER BY chain_seq,created_at,checkpoint_id"
        ).fetchall()]
        prune_history = [dict(row) for row in conn.execute(
            "SELECT prune_id,from_seq,to_seq,anchor_hash,deleted_count,cutoff_at,actor,created_at "
            "FROM audit_prune_history ORDER BY created_at,prune_id"
        ).fetchall()]
        receipt_archives = [dict(row) for row in conn.execute(
            "SELECT archive_id,cutoff_at,receipt_count,first_created_at,last_created_at,receipt_digest_sha256,"
            "operation_summary_json,outcome_summary_json,subtype_summary_json,actor_sha256,created_at "
            "FROM execution_receipt_archives ORDER BY created_at,archive_id"
        ).fetchall()]

    key_transitions = export_integrity_proof_key_transitions(db_path) if use_ed25519 else []
    key_revocations = export_integrity_proof_key_revocations(db_path) if use_ed25519 else []
    revocation_checkpoints = export_integrity_proof_revocation_checkpoints(db_path) if use_ed25519 else []
    checkpoint_witnesses = export_integrity_proof_checkpoint_witnesses(db_path) if use_ed25519 else []
    transparency_entries = export_integrity_proof_transparency_entries(db_path) if use_ed25519 else []
    transparency_heads = export_integrity_proof_transparency_heads(db_path) if use_ed25519 else []
    mirror_receipts = export_integrity_proof_transparency_mirror_receipts(db_path) if use_ed25519 else []
    mirror_consistency_checkpoints = export_integrity_proof_mirror_consistency_checkpoints(db_path) if use_ed25519 else []
    if revocation_checkpoints:
        checkpoint_pins = {
            str((item.get("statement") or {}).get("recovery", {}).get("key_id") or ""):
            str((item.get("statement") or {}).get("recovery", {}).get("public_key_base64") or "")
            for item in revocation_checkpoints
        }
        verify_revocation_checkpoint_chain(
            revocation_checkpoints,
            pinned_public_keys=checkpoint_pins,
            revocations=key_revocations,
            transitions=key_transitions,
        )
    if checkpoint_witnesses:
        witness_pins = {
            str((item.get("statement") or {}).get("witness", {}).get("key_id") or ""):
            str((item.get("statement") or {}).get("witness", {}).get("public_key_base64") or "")
            for item in checkpoint_witnesses
        }
        verify_checkpoint_witness_quorum(
            checkpoint_witnesses,
            checkpoints=revocation_checkpoints,
            pinned_public_keys=witness_pins,
            minimum_quorum=max(1, int(minimum_witness_quorum)),
        )
    if transparency_entries or transparency_heads:
        transparency_pins = {
            str((item.get("statement") or {}).get("log", {}).get("key_id") or ""):
            str((item.get("statement") or {}).get("log", {}).get("public_key_base64") or "")
            for item in transparency_heads
        }
        verify_integrity_proof_transparency_log(
            transparency_entries,
            transparency_heads,
            pinned_public_keys=transparency_pins,
            checkpoints=revocation_checkpoints,
            witnesses=checkpoint_witnesses,
        )
    elif require_transparency_log and use_ed25519:
        raise ValueError("공개 transparency log 필수 모드에는 게시된 signed log head가 필요합니다.")
    if mirror_receipts:
        mirror_pins = {
            str((item.get("statement") or {}).get("mirror", {}).get("key_id") or ""):
            str((item.get("statement") or {}).get("mirror", {}).get("public_key_base64") or "")
            for item in mirror_receipts
        }
        verify_transparency_mirror_gossip(
            mirror_receipts,
            heads=transparency_heads,
            pinned_public_keys=mirror_pins,
            minimum_quorum=max(1, int(minimum_mirror_quorum)),
        )
    elif require_mirror_gossip and use_ed25519:
        raise ValueError("공개 mirror gossip 필수 모드에는 최신 transparency head의 mirror receipt가 필요합니다.")
    if mirror_consistency_checkpoints:
        consistency_pins = {
            str((signature or {}).get("key_id") or ""):
            str((signature or {}).get("public_key_base64") or "")
            for item in mirror_consistency_checkpoints
            for signature in (item.get("signatures") or [])
        }
        verify_mirror_consistency_chain(
            mirror_consistency_checkpoints, heads=transparency_heads, receipts=mirror_receipts,
            pinned_public_keys=consistency_pins, minimum_quorum=max(1, int(minimum_mirror_quorum)),
        )
    elif require_mirror_consistency and use_ed25519:
        raise ValueError("공개 mirror consistency 필수 모드에는 공동서명 consistency checkpoint가 필요합니다.")
    snapshot_at = utc_now()
    proof_id = f"IPR-{uuid.uuid4().hex[:20].upper()}"
    event_bytes = _events_jsonl(event_rows)
    checkpoints_bytes = _canonical_json_bytes(checkpoints)
    prune_bytes = _canonical_json_bytes(prune_history)
    archives_bytes = _canonical_json_bytes(receipt_archives)
    transitions_bytes = _canonical_json_bytes(key_transitions)
    revocations_bytes = _canonical_json_bytes(key_revocations)
    revocation_checkpoints_bytes = _canonical_json_bytes(revocation_checkpoints)
    checkpoint_witnesses_bytes = _canonical_json_bytes(checkpoint_witnesses)
    transparency_entries_bytes = _canonical_json_bytes(transparency_entries)
    transparency_heads_bytes = _canonical_json_bytes(transparency_heads)
    mirror_receipts_bytes = _canonical_json_bytes(mirror_receipts)
    mirror_consistency_bytes = _canonical_json_bytes(mirror_consistency_checkpoints)
    signature_meta: dict[str, Any]
    if use_ed25519:
        signature_meta = {
            "algorithm": ED25519_ALGORITHM,
            "key_id": str(ed25519_key_id),
            "public_key_sha256": derived_fingerprint,
            "trust_model": "pinned-public-key",
            "signed": True,
        }
        if mirror_consistency_checkpoints:
            proof_format = PROOF_FORMAT_ED25519_CONSISTENT
        elif mirror_receipts:
            proof_format = PROOF_FORMAT_ED25519_MIRRORED
        elif transparency_heads:
            proof_format = PROOF_FORMAT_ED25519_TRANSPARENT
        elif checkpoint_witnesses:
            proof_format = PROOF_FORMAT_ED25519_WITNESSED
        elif revocation_checkpoints:
            proof_format = PROOF_FORMAT_ED25519_CHECKPOINTED
        elif key_revocations:
            proof_format = PROOF_FORMAT_ED25519_RECOVERED
        else:
            proof_format = PROOF_FORMAT_ED25519_ROTATED if key_transitions else PROOF_FORMAT_ED25519
    else:
        signature_meta = {
            "algorithm": "HMAC-SHA256",
            "key_id": str(signing_key_id),
            "signed": True,
        }
        proof_format = PROOF_FORMAT_HMAC
    manifest = {
        "format": proof_format,
        "proof_id": proof_id,
        "created_at": snapshot_at,
        "created_by": actor,
        "application": {"name": "VulnFlow", "version": str(app_version)},
        "schema_version": int(schema_version),
        "audit": {
            "anchor_seq": int(state["anchor_seq"]),
            "anchor_hash": str(state["anchor_hash"]),
            "last_seq": int(state["last_seq"]),
            "last_hash": str(state["last_hash"]),
            "retained_event_count": len(event_rows),
            "events_sha256": _sha256_bytes(event_bytes),
            "checkpoint_id": checkpoint["checkpoint_id"],
            "checkpoint_key_id": checkpoint.get("key_id"),
        },
        "prune_history": {"count": len(prune_history), "sha256": _sha256_bytes(prune_bytes)},
        "execution_receipt_archives": {
            "count": len(receipt_archives),
            "sha256": _sha256_bytes(archives_bytes),
        },
        "key_transitions": {
            "count": len(key_transitions),
            "sha256": _sha256_bytes(transitions_bytes),
        } if use_ed25519 else {"count": 0, "sha256": _sha256_bytes(b"[]")},
        "key_revocations": {
            "count": len(key_revocations),
            "sha256": _sha256_bytes(revocations_bytes),
        } if use_ed25519 else {"count": 0, "sha256": _sha256_bytes(b"[]")},
        "revocation_checkpoints": {
            "count": len(revocation_checkpoints),
            "sha256": _sha256_bytes(revocation_checkpoints_bytes),
            "latest_sequence": int((revocation_checkpoints[-1].get("statement") or {}).get("sequence") or 0) if revocation_checkpoints else 0,
        } if use_ed25519 else {"count": 0, "sha256": _sha256_bytes(b"[]"), "latest_sequence": 0},
        "checkpoint_witnesses": {
            "count": len(checkpoint_witnesses),
            "sha256": _sha256_bytes(checkpoint_witnesses_bytes),
            "minimum_quorum": max(1, int(minimum_witness_quorum)) if checkpoint_witnesses else 0,
        } if use_ed25519 else {"count": 0, "sha256": _sha256_bytes(b"[]"), "minimum_quorum": 0},
        "transparency_log": {
            "entry_count": len(transparency_entries),
            "entries_sha256": _sha256_bytes(transparency_entries_bytes),
            "head_count": len(transparency_heads),
            "heads_sha256": _sha256_bytes(transparency_heads_bytes),
            "latest_tree_size": int((transparency_heads[-1].get("statement") or {}).get("tree_size") or 0) if transparency_heads else 0,
            "latest_head_sha256": _sha256_bytes(_canonical_json_bytes(transparency_heads[-1])) if transparency_heads else "",
        } if use_ed25519 else {
            "entry_count": 0, "entries_sha256": _sha256_bytes(b"[]"),
            "head_count": 0, "heads_sha256": _sha256_bytes(b"[]"),
            "latest_tree_size": 0, "latest_head_sha256": "",
        },
        "mirror_gossip": {
            "receipt_count": len(mirror_receipts),
            "receipts_sha256": _sha256_bytes(mirror_receipts_bytes),
            "minimum_quorum": max(1, int(minimum_mirror_quorum)) if mirror_receipts else 0,
            "latest_tree_size": int((transparency_heads[-1].get("statement") or {}).get("tree_size") or 0) if mirror_receipts and transparency_heads else 0,
        } if use_ed25519 else {
            "receipt_count": 0, "receipts_sha256": _sha256_bytes(b"[]"),
            "minimum_quorum": 0, "latest_tree_size": 0,
        },
        "mirror_consistency": {
            "checkpoint_count": len(mirror_consistency_checkpoints),
            "checkpoints_sha256": _sha256_bytes(mirror_consistency_bytes),
            "minimum_quorum": max(1, int(minimum_mirror_quorum)) if mirror_consistency_checkpoints else 0,
            "latest_sequence": int((mirror_consistency_checkpoints[-1].get("statement") or {}).get("sequence") or 0) if mirror_consistency_checkpoints else 0,
        } if use_ed25519 else {
            "checkpoint_count": 0, "checkpoints_sha256": _sha256_bytes(b"[]"),
            "minimum_quorum": 0, "latest_sequence": 0,
        },
        "signature": signature_meta,
    }
    manifest_bytes = _canonical_json_bytes(manifest)

    export_root = Path(export_dir)
    export_root.mkdir(parents=True, exist_ok=True)
    free_before = int(shutil.disk_usage(export_root).free)
    if int(min_free_bytes) > 0 and free_before <= int(min_free_bytes):
        raise RuntimeError("무결성 증명 번들을 생성할 최소 여유 공간이 부족합니다.")

    token = uuid.uuid4().hex
    stored_filename = f"integrity_proof_{token}.zip"
    destination = export_root / stored_filename
    with tempfile.TemporaryDirectory(prefix="vulnflow_integrity_proof_", dir=export_root) as temp_name:
        temp = Path(temp_name)
        files = {
            "manifest.json": manifest_bytes,
            "audit-events.jsonl": event_bytes,
            "audit-checkpoints.json": checkpoints_bytes,
            "audit-prune-history.json": prune_bytes,
            "execution-receipt-archives.json": archives_bytes,
        }
        if use_ed25519 and (key_transitions or key_revocations or revocation_checkpoints):
            files["proof-key-transitions.json"] = transitions_bytes
        if use_ed25519 and (key_revocations or revocation_checkpoints):
            files["proof-key-revocations.json"] = revocations_bytes
        if use_ed25519 and revocation_checkpoints:
            files["proof-revocation-checkpoints.json"] = revocation_checkpoints_bytes
        if use_ed25519 and checkpoint_witnesses:
            files["proof-revocation-witnesses.json"] = checkpoint_witnesses_bytes
        if use_ed25519 and transparency_heads:
            files["proof-transparency-entries.json"] = transparency_entries_bytes
            files["proof-transparency-heads.json"] = transparency_heads_bytes
        if use_ed25519 and mirror_receipts:
            files["proof-transparency-mirror-receipts.json"] = mirror_receipts_bytes
        if use_ed25519 and mirror_consistency_checkpoints:
            files["proof-mirror-consistency-checkpoints.json"] = mirror_consistency_bytes
        if use_ed25519:
            public_key_document = _canonical_json_bytes({
                "algorithm": ED25519_ALGORITHM,
                "key_id": str(ed25519_key_id),
                "public_key_base64": str(ed25519_public_key),
                "public_key_sha256": derived_fingerprint,
            })
            files["proof-public-key.json"] = public_key_document
        for name, data in files.items():
            (temp / name).write_bytes(data)
        sums_bytes = ("\n".join(
            f"{_sha256_bytes(files[name])}  {name}" for name in sorted(files)
        ) + "\n").encode("ascii")
        (temp / "SHA256SUMS.txt").write_bytes(sums_bytes)
        if use_ed25519:
            signature_name = "proof.ed25519"
            signature = sign_ed25519(
                str(ed25519_private_key),
                _proof_signature_payload(
                    manifest_bytes, sums_bytes,
                    version=(
                        9 if proof_format == PROOF_FORMAT_ED25519_CONSISTENT
                        else 8 if proof_format == PROOF_FORMAT_ED25519_MIRRORED
                        else 7 if proof_format == PROOF_FORMAT_ED25519_TRANSPARENT
                        else 6 if proof_format == PROOF_FORMAT_ED25519_WITNESSED
                        else 5 if proof_format == PROOF_FORMAT_ED25519_CHECKPOINTED
                        else 4 if proof_format == PROOF_FORMAT_ED25519_RECOVERED
                        else 3 if proof_format == PROOF_FORMAT_ED25519_ROTATED
                        else 2
                    ),
                ),
            )
        else:
            signature_name = "proof.hmac"
            signature = hmac_sha256(
                str(signing_key), _proof_signature_payload(manifest_bytes, sums_bytes, version=1)
            )
        (temp / signature_name).write_text(signature + "\n", encoding="ascii")
        try:
            with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
                for name in sorted(files):
                    archive.write(temp / name, arcname=name)
                archive.write(temp / "SHA256SUMS.txt", arcname="SHA256SUMS.txt")
                archive.write(temp / signature_name, arcname=signature_name)
        except Exception:
            destination.unlink(missing_ok=True)
            raise

    size_bytes = destination.stat().st_size
    if int(min_free_bytes) > 0 and int(shutil.disk_usage(export_root).free) < int(min_free_bytes):
        destination.unlink(missing_ok=True)
        raise RuntimeError("무결성 증명 번들 생성 후 최소 여유 공간 기준을 충족하지 못했습니다.")
    expires_at = None
    if int(retention_days) > 0:
        expires_at = (
            datetime.now(timezone.utc) + timedelta(days=int(retention_days))
        ).replace(microsecond=0).isoformat()
    try:
        artifact = register_export_artifact(
            db_path,
            job_id=None,
            export_type="INTEGRITY_PROOF_ZIP",
            stored_filename=stored_filename,
            download_filename=f"vulnflow_integrity_proof_{snapshot_at[:10].replace('-', '')}_{proof_id}.zip",
            content_type="application/zip",
            row_count=len(event_rows),
            size_bytes=size_bytes,
            sha256=_sha256_file(destination),
            filters={"signature_algorithm": signature_meta["algorithm"], "signing_key_id": signature_meta["key_id"]},
            snapshot_at=snapshot_at,
            created_by=actor,
            expires_at=expires_at,
            max_storage_bytes=max_storage_bytes,
        )
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    return artifact | {"proof_id": proof_id, "manifest": manifest}
