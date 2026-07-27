from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from app.repositories.audit import _canonical_audit_details

PROOF_FORMAT_HMAC = "vulnflow-integrity-proof/1"
PROOF_FORMAT_ED25519 = "vulnflow-integrity-proof/2"
PROOF_FORMAT_ED25519_ROTATED = "vulnflow-integrity-proof/3"
PROOF_FORMAT_ED25519_RECOVERED = "vulnflow-integrity-proof/4"
PROOF_FORMAT_ED25519_CHECKPOINTED = "vulnflow-integrity-proof/5"
PROOF_FORMAT_ED25519_WITNESSED = "vulnflow-integrity-proof/6"
PROOF_FORMAT_ED25519_TRANSPARENT = "vulnflow-integrity-proof/7"
PROOF_FORMAT_ED25519_MIRRORED = "vulnflow-integrity-proof/8"
PROOF_FORMAT_ED25519_CONSISTENT = "vulnflow-integrity-proof/9"
PROOF_FORMAT = PROOF_FORMAT_ED25519_CONSISTENT
MAX_PROOF_FILES = 27
MAX_PROOF_UNCOMPRESSED = 128 * 1024 * 1024
BASE_PROOF_FILES = {
    "manifest.json",
    "audit-events.jsonl",
    "audit-checkpoints.json",
    "audit-prune-history.json",
    "execution-receipt-archives.json",
    "SHA256SUMS.txt",
}

def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")

def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()

def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

def _json_rows_digest(rows: list[dict[str, Any]]) -> str:
    return _sha256_bytes(_canonical_json_bytes(rows))

def _event_export_row(row: Any) -> dict[str, Any]:
    return {
        "chain_seq": int(row["chain_seq"]),
        "finding_id": row["finding_id"],
        "event_type": str(row["event_type"]),
        "actor": str(row["actor"]),
        "summary": str(row["summary"]),
        "details_json": _canonical_audit_details(raw=str(row["details_json"] or "{}")),
        "created_at": str(row["created_at"]),
        "prev_hash": str(row["prev_hash"]),
        "event_hash": str(row["event_hash"]),
    }

def _events_jsonl(rows: list[dict[str, Any]]) -> bytes:
    if not rows:
        return b""
    return b"\n".join(_canonical_json_bytes(row) for row in rows) + b"\n"

def _proof_signature_payload(manifest_bytes: bytes, sums_bytes: bytes, *, version: int) -> bytes:
    return f"vulnflow-integrity-proof-signature/{version}\n".encode("ascii") + manifest_bytes + b"\n" + sums_bytes
