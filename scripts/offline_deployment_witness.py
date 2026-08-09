from __future__ import annotations

"""External Ed25519 witness receipts for offline deployment audit checkpoints.

A local deployment-history keyring and audit log can be rolled back together to
an older internally consistent snapshot.  A witness receipt anchors one audit
checkpoint outside that local rollback boundary.  Verification accepts a local
log that is equal to or newer than the witnessed checkpoint, but rejects a log
that is shorter or has a different hash at the witnessed sequence.
"""

from datetime import datetime, timezone
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

try:
    from scripts.offline_deployment_activation import absolute_path
    from scripts.offline_deployment_audit import (
        verify_deployment_audit_checkpoint,
        verify_deployment_audit_log,
    )
    from scripts.offline_deployment_keyring import history_keyring_status
except ModuleNotFoundError:  # standalone signed release-kit execution
    from offline_deployment_activation import absolute_path
    from offline_deployment_audit import (
        verify_deployment_audit_checkpoint,
        verify_deployment_audit_log,
    )
    from offline_deployment_keyring import history_keyring_status

PRIVATE_KEY_FORMAT = "vulnflow-offline-deployment-witness-private-key/1"
PUBLIC_KEY_FORMAT = "vulnflow-offline-deployment-witness-public-key/1"
RECEIPT_FORMAT = "vulnflow-offline-deployment-witness-receipt/1"
MAX_KEY_FILE_BYTES = 64 * 1024
MAX_RECEIPT_BYTES = 1024 * 1024


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64decode(value: str, *, expected_bytes: int, label: str) -> bytes:
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception as exc:
        raise ValueError(f"{label} is not valid URL-safe base64") from exc
    if len(raw) != expected_bytes:
        raise ValueError(f"{label} must contain {expected_bytes} bytes")
    return raw


def _fingerprint(public_raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(public_raw).hexdigest()


def _canonical(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _safe_parent(path: Path) -> Path:
    parent = absolute_path(path).parent
    if parent.is_symlink() or not parent.is_dir():
        raise ValueError("witness output parent must be a real directory")
    if os.name == "posix" and parent.stat().st_mode & 0o022:
        raise ValueError("witness output parent must not be group- or world-writable")
    return parent


def _write_atomic(path: Path, raw: bytes, *, mode: int) -> None:
    path = absolute_path(path)
    _safe_parent(path)
    if os.path.lexists(path):
        raise FileExistsError(f"witness output already exists: {path}")
    temporary = path.with_name(path.name + f".tmp-{secrets.token_hex(8)}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(temporary, flags, mode)
    try:
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    if os.name == "posix":
        path.chmod(mode)
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _read_regular(path: Path, *, maximum_bytes: int, private: bool, trusted: bool = False) -> bytes:
    path = absolute_path(path)
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError as exc:
        raise ValueError(f"witness file is missing: {path}") from exc
    try:
        metadata = os.fstat(descriptor)
        import stat

        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError("witness file must be one regular file")
        if metadata.st_size > maximum_bytes:
            raise ValueError("witness file exceeds its size boundary")
        if private and os.name == "posix" and metadata.st_mode & 0o077:
            raise ValueError("witness private key permissions are too broad")
        if trusted and os.name == "posix" and metadata.st_mode & 0o022:
            raise ValueError("trusted witness public key permissions are too broad")
        chunks: list[bytes] = []
        remaining = metadata.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _load_json(path: Path, *, maximum_bytes: int, private: bool) -> dict[str, Any]:
    raw = _read_regular(path, maximum_bytes=maximum_bytes, private=private, trusted=False)
    try:
        payload = json.loads(raw)
    except Exception as exc:
        raise ValueError("witness JSON is invalid") from exc
    if not isinstance(payload, dict):
        raise ValueError("witness JSON must be an object")
    return payload


def generate_witness_keypair(
    *,
    private_key_path: Path,
    public_key_path: Path,
    key_id: str,
) -> dict[str, Any]:
    key_id = str(key_id).strip()
    if absolute_path(private_key_path) == absolute_path(public_key_path):
        raise ValueError("witness private and public key paths must be different")
    if not key_id or len(key_id) > 100:
        raise ValueError("witness key ID is invalid")
    private = Ed25519PrivateKey.generate()
    private_raw = private.private_bytes_raw()
    public_raw = private.public_key().public_bytes_raw()
    created_at = _utc_now()
    fingerprint = _fingerprint(public_raw)
    private_payload = {
        "format": PRIVATE_KEY_FORMAT,
        "key_id": key_id,
        "created_at": created_at,
        "private_key_base64": _b64encode(private_raw),
        "public_key_base64": _b64encode(public_raw),
        "public_key_fingerprint": fingerprint,
    }
    public_payload = {
        "format": PUBLIC_KEY_FORMAT,
        "key_id": key_id,
        "created_at": created_at,
        "public_key_base64": _b64encode(public_raw),
        "public_key_fingerprint": fingerprint,
    }
    _write_atomic(
        private_key_path,
        (json.dumps(private_payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8"),
        mode=0o600,
    )
    try:
        _write_atomic(
            public_key_path,
            (json.dumps(public_payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8"),
            mode=0o644,
        )
    except BaseException:
        absolute_path(private_key_path).unlink(missing_ok=True)
        raise
    return {
        "private_key": str(absolute_path(private_key_path)),
        "public_key": str(absolute_path(public_key_path)),
        "key_id": key_id,
        "public_key_fingerprint": fingerprint,
        "notice": "Keep the private witness key offline and pin the public key outside the deployment host.",
    }


def _load_private_key(path: Path) -> tuple[str, str, Ed25519PrivateKey]:
    payload = _load_json(path, maximum_bytes=MAX_KEY_FILE_BYTES, private=True)
    if payload.get("format") != PRIVATE_KEY_FORMAT:
        raise ValueError("witness private key format is invalid")
    key_id = str(payload.get("key_id") or "")
    private_raw = _b64decode(str(payload.get("private_key_base64") or ""), expected_bytes=32, label="witness private key")
    public_raw = _b64decode(str(payload.get("public_key_base64") or ""), expected_bytes=32, label="witness public key")
    private = Ed25519PrivateKey.from_private_bytes(private_raw)
    derived_public = private.public_key().public_bytes_raw()
    fingerprint = _fingerprint(derived_public)
    if derived_public != public_raw or payload.get("public_key_fingerprint") != fingerprint or not key_id:
        raise ValueError("witness private key metadata is inconsistent")
    return key_id, fingerprint, private


def _load_public_key(path: Path) -> tuple[str, str, Ed25519PublicKey]:
    raw = _read_regular(path, maximum_bytes=MAX_KEY_FILE_BYTES, private=False, trusted=True)
    try:
        payload = json.loads(raw)
    except Exception as exc:
        raise ValueError("witness JSON is invalid") from exc
    if not isinstance(payload, dict):
        raise ValueError("witness JSON must be an object")
    if payload.get("format") != PUBLIC_KEY_FORMAT:
        raise ValueError("witness public key format is invalid")
    key_id = str(payload.get("key_id") or "")
    public_raw = _b64decode(str(payload.get("public_key_base64") or ""), expected_bytes=32, label="witness public key")
    fingerprint = _fingerprint(public_raw)
    if payload.get("public_key_fingerprint") != fingerprint or not key_id:
        raise ValueError("witness public key metadata is inconsistent")
    return key_id, fingerprint, Ed25519PublicKey.from_public_bytes(public_raw)


def sign_witness_document(payload: dict[str, Any], *, private_key_path: Path) -> dict[str, Any]:
    """Bind one canonical JSON document to the configured offline witness key."""

    key_id, fingerprint, private = _load_private_key(private_key_path)
    unsigned = dict(payload)
    unsigned.pop("ed25519_signature_base64", None)
    unsigned["witness_key_id"] = key_id
    unsigned["witness_public_key_fingerprint"] = fingerprint
    return {
        **unsigned,
        "ed25519_signature_base64": _b64encode(private.sign(_canonical(unsigned))),
    }


def verify_witness_document(
    document: dict[str, Any],
    *,
    public_key_path: Path,
    label: str = "witness document",
) -> dict[str, Any]:
    """Verify one canonical JSON document against a pinned witness public key."""

    if not isinstance(document, dict):
        raise ValueError(f"{label} must be an object")
    key_id, fingerprint, public = _load_public_key(public_key_path)
    signature = _b64decode(
        str(document.get("ed25519_signature_base64") or ""),
        expected_bytes=64,
        label=f"{label} signature",
    )
    unsigned = dict(document)
    unsigned.pop("ed25519_signature_base64", None)
    if unsigned.get("witness_key_id") != key_id or unsigned.get("witness_public_key_fingerprint") != fingerprint:
        raise ValueError(f"{label} does not match the trusted public key")
    try:
        public.verify(signature, _canonical(unsigned))
    except Exception as exc:
        raise ValueError(f"{label} signature verification failed") from exc
    return unsigned


def _receipt_payload(target: Path, *, key_id: str, fingerprint: str) -> dict[str, Any]:
    target = absolute_path(target)
    audit = verify_deployment_audit_log(target)
    keyring = history_keyring_status(target)
    if not keyring.get("available"):
        raise ValueError("deployment history keyring is unavailable")
    return {
        "format": RECEIPT_FORMAT,
        "receipt_id": secrets.token_hex(16),
        "issued_at": _utc_now(),
        "target_name": target.name,
        "audit_sequence": int(audit["last_sequence"]),
        "audit_head_sha256": str(audit["last_entry_sha256"]),
        "history_key_id": str(keyring["current_key_id"]),
        "history_key_fingerprint": str(keyring["fingerprint"]),
        "witness_key_id": key_id,
        "witness_public_key_fingerprint": fingerprint,
    }


def issue_witness_receipt(
    target: Path,
    *,
    private_key_path: Path,
    output_path: Path,
) -> dict[str, Any]:
    key_id, fingerprint, _ = _load_private_key(private_key_path)
    payload = _receipt_payload(target, key_id=key_id, fingerprint=fingerprint)
    receipt = sign_witness_document(payload, private_key_path=private_key_path)
    raw = (json.dumps(receipt, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
    _write_atomic(output_path, raw, mode=0o644)
    return {
        "receipt": str(absolute_path(output_path)),
        "receipt_id": payload["receipt_id"],
        "target_name": payload["target_name"],
        "audit_sequence": payload["audit_sequence"],
        "audit_head_sha256": payload["audit_head_sha256"],
        "witness_key_id": key_id,
        "witness_public_key_fingerprint": fingerprint,
        "notice": "Store this receipt on an external append-only or independently protected system.",
    }


def verify_witness_receipt_signature(
    *,
    receipt_path: Path,
    public_key_path: Path,
) -> dict[str, Any]:
    receipt = _load_json(receipt_path, maximum_bytes=MAX_RECEIPT_BYTES, private=False)
    if receipt.get("format") != RECEIPT_FORMAT:
        raise ValueError("deployment history witness receipt format is invalid")
    payload = verify_witness_document(
        receipt,
        public_key_path=public_key_path,
        label="witness receipt",
    )
    sequence = int(payload.get("audit_sequence") or -1)
    head = str(payload.get("audit_head_sha256") or "").lower()
    if sequence < 0 or len(head) != 64 or any(ch not in "0123456789abcdef" for ch in head):
        raise ValueError("witness receipt audit checkpoint is invalid")
    target_name = str(payload.get("target_name") or "")
    receipt_id = str(payload.get("receipt_id") or "")
    if not target_name or not receipt_id:
        raise ValueError("witness receipt identity is invalid")
    return payload


def verify_witness_receipt(
    target: Path,
    *,
    receipt_path: Path,
    public_key_path: Path,
) -> dict[str, Any]:
    target = absolute_path(target)
    payload = verify_witness_receipt_signature(receipt_path=receipt_path, public_key_path=public_key_path)
    if payload["target_name"] != target.name:
        raise ValueError("witness receipt target does not match the deployment target")
    checkpoint = verify_deployment_audit_checkpoint(
        target,
        sequence=int(payload["audit_sequence"]),
        head_sha256=str(payload["audit_head_sha256"]),
    )
    return {
        "valid": True,
        "target": str(target),
        "receipt": str(absolute_path(receipt_path)),
        "receipt_id": payload["receipt_id"],
        "witness_key_id": payload["witness_key_id"],
        "witness_public_key_fingerprint": payload["witness_public_key_fingerprint"],
        "witness_sequence": int(payload["audit_sequence"]),
        "witness_head_sha256": payload["audit_head_sha256"],
        "local_sequence": checkpoint["last_sequence"],
        "local_head_sha256": checkpoint["last_entry_sha256"],
        "local_events_after_witness": checkpoint["last_sequence"] - int(payload["audit_sequence"]),
    }
