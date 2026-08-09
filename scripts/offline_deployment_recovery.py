from __future__ import annotations

"""Consistent recovery bundles for offline deployment history.

A history keyring and its authenticated audit log are one recovery unit.  This
module packages both files together with the externally signed witness receipt
that anchors the minimum acceptable audit prefix.  Restore validates the
candidate in an isolated sibling directory before replacing either live file.
"""

from datetime import datetime, timezone
import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import secrets
import shutil
import stat
import tempfile
import time
from typing import Any
import zipfile

try:
    from scripts.offline_deployment_activation import absolute_path
    from scripts.offline_deployment_audit import (
        MAX_AUDIT_BYTES,
        append_deployment_audit_event,
        audit_log_path,
        read_verified_deployment_audit_events,
        verify_deployment_audit_checkpoint,
        verify_deployment_audit_log,
    )
    from scripts.offline_deployment_history import (
        SEAL_RELATIVE_PATH,
        verify_retained_deployment,
    )
    from scripts.offline_deployment_keyring import (
        MAX_KEYRING_BYTES,
        history_keyring_path,
        history_keyring_status,
        read_history_keyring_bytes,
    )
    from scripts.offline_deployment_witness import (
        MAX_KEY_FILE_BYTES,
        MAX_RECEIPT_BYTES,
        sign_witness_document,
        verify_witness_receipt,
        verify_witness_receipt_signature,
        verify_witness_document,
    )
except ModuleNotFoundError:  # standalone signed release-kit execution
    from offline_deployment_activation import absolute_path
    from offline_deployment_audit import (
        MAX_AUDIT_BYTES,
        append_deployment_audit_event,
        audit_log_path,
        read_verified_deployment_audit_events,
        verify_deployment_audit_checkpoint,
        verify_deployment_audit_log,
    )
    from offline_deployment_history import SEAL_RELATIVE_PATH, verify_retained_deployment
    from offline_deployment_keyring import (
        MAX_KEYRING_BYTES,
        history_keyring_path,
        history_keyring_status,
        read_history_keyring_bytes,
    )
    from offline_deployment_witness import (
        MAX_KEY_FILE_BYTES,
        MAX_RECEIPT_BYTES,
        sign_witness_document,
        verify_witness_receipt,
        verify_witness_receipt_signature,
        verify_witness_document,
    )

BUNDLE_FORMAT = "vulnflow-offline-deployment-history-recovery/1"
MANIFEST_NAME = "manifest.json"
KEYRING_NAME = "history-keyring.bin"
AUDIT_NAME = "history-audit.jsonl"
WITNESS_RECEIPT_NAME = "witness-receipt.json"
WITNESS_PUBLIC_KEY_NAME = "witness-public-key.json"
SHA256SUMS_NAME = "SHA256SUMS.txt"
EXPECTED_MEMBERS = {
    MANIFEST_NAME,
    KEYRING_NAME,
    AUDIT_NAME,
    WITNESS_RECEIPT_NAME,
    WITNESS_PUBLIC_KEY_NAME,
    SHA256SUMS_NAME,
}
MAX_BUNDLE_BYTES = 72 * 1024 * 1024
MAX_MANIFEST_BYTES = 256 * 1024
MAX_SUMS_BYTES = 64 * 1024
MAX_COMPRESSION_RATIO = 500
_TRANSACTION_SUFFIX = ".deployment-history.recovery-"
_TRANSACTION_FORMAT = "vulnflow-offline-deployment-history-recovery-transaction/3"
_INTEGRITY_TRANSACTION_FORMAT = "vulnflow-offline-deployment-history-recovery-transaction/2"
_LEGACY_TRANSACTION_FORMAT = "vulnflow-offline-deployment-history-recovery-transaction/1"
_JOURNAL_KEY_SUFFIX = ".deployment-history.journal-auth.key"
JOURNAL_KEY_BYTES = 32
LEGACY_JOURNAL_KEY_BACKUP_FORMAT = "vulnflow-offline-deployment-recovery-journal-key-backup/1"
JOURNAL_KEY_BACKUP_FORMAT = "vulnflow-offline-deployment-recovery-journal-key-backup/2"
MAX_JOURNAL_KEY_BACKUP_BYTES = 64 * 1024


def recovery_journal_key_path(target: Path) -> Path:
    target = absolute_path(target)
    return target.parent / f".{target.name}{_JOURNAL_KEY_SUFFIX}"


def _validate_journal_key_metadata(metadata: os.stat_result) -> None:
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_size != JOURNAL_KEY_BYTES:
        raise ValueError("deployment history recovery journal key is unsafe")
    if os.name == "posix" and metadata.st_mode & 0o077:
        raise ValueError("deployment history recovery journal key permissions are too broad")
    if os.name == "posix" and metadata.st_uid != os.geteuid():
        raise ValueError("deployment history recovery journal key owner is invalid")


def _read_recovery_journal_key(target: Path) -> bytes:
    path = recovery_journal_key_path(target)
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError as exc:
        raise ValueError("deployment history recovery journal authentication key is missing") from exc
    except OSError as exc:
        raise ValueError("deployment history recovery journal key is unsafe") from exc
    try:
        metadata = os.fstat(descriptor)
        _validate_journal_key_metadata(metadata)
        raw = os.read(descriptor, JOURNAL_KEY_BYTES + 1)
        if len(raw) != JOURNAL_KEY_BYTES:
            raise ValueError("deployment history recovery journal key has an invalid length")
        return raw
    finally:
        os.close(descriptor)


def _load_or_create_recovery_journal_key(target: Path) -> bytes:
    target = absolute_path(target)
    _private_parent(recovery_journal_key_path(target), label="recovery journal key")
    path = recovery_journal_key_path(target)
    if not os.path.lexists(path):
        raw = secrets.token_bytes(JOURNAL_KEY_BYTES)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(path, flags, 0o600)
        except FileExistsError:
            pass
        else:
            try:
                view = memoryview(raw)
                while view:
                    written = os.write(descriptor, view)
                    view = view[written:]
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            _fsync_directory(path.parent)
    last_error: Exception | None = None
    for attempt in range(100):
        try:
            return _read_recovery_journal_key(target)
        except ValueError as exc:
            last_error = exc
            try:
                metadata = os.lstat(path)
            except OSError:
                raise
            transient = (
                stat.S_ISREG(metadata.st_mode)
                and metadata.st_nlink == 1
                and metadata.st_size <= JOURNAL_KEY_BYTES
                and (os.name != "posix" or not (metadata.st_mode & 0o077))
                and (os.name != "posix" or metadata.st_uid == os.geteuid())
            )
            if not transient or attempt == 99:
                raise
            time.sleep(0.005)
    assert last_error is not None
    raise last_error


def _journal_key_fingerprint(key: bytes) -> str:
    return "sha256:" + hashlib.sha256(key).hexdigest()


def _journal_auth_payload(payload: dict[str, Any]) -> bytes:
    unsigned = dict(payload)
    unsigned.pop("journal_hmac_sha256", None)
    return _canonical(unsigned)


def _authenticate_transaction_manifest(target: Path, payload: dict[str, Any]) -> dict[str, Any]:
    key = _load_or_create_recovery_journal_key(target)
    payload = dict(payload)
    payload["journal_key_fingerprint"] = _journal_key_fingerprint(key)
    payload["journal_hmac_sha256"] = hmac.new(key, _journal_auth_payload(payload), hashlib.sha256).hexdigest()
    return payload


def _verify_transaction_authentication_with_key(payload: dict[str, Any], key: bytes) -> None:
    fingerprint = str(payload.get("journal_key_fingerprint") or "")
    signature = str(payload.get("journal_hmac_sha256") or "").lower()
    if fingerprint != _journal_key_fingerprint(key):
        raise ValueError("deployment history recovery journal key fingerprint does not match")
    if len(signature) != 64 or any(ch not in "0123456789abcdef" for ch in signature):
        raise ValueError("deployment history recovery journal authentication is invalid")
    expected = hmac.new(key, _journal_auth_payload(payload), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        raise ValueError("deployment history recovery journal authentication failed")


def _verify_transaction_authentication(target: Path, payload: dict[str, Any]) -> None:
    _verify_transaction_authentication_with_key(payload, _read_recovery_journal_key(target))


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical(payload: object) -> bytes:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _fsync_directory(path: Path) -> None:
    if os.name != "posix":
        return
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _private_parent(path: Path, *, label: str) -> Path:
    parent = absolute_path(path).parent
    if parent.is_symlink() or not parent.is_dir():
        raise ValueError(f"{label} parent must be a real directory")
    if os.name == "posix" and parent.stat().st_mode & 0o022:
        raise ValueError(f"{label} parent must not be group- or world-writable")
    return parent


def _read_regular(
    path: Path,
    *,
    maximum_bytes: int,
    private: bool,
    trusted: bool = False,
) -> bytes:
    path = absolute_path(path)
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError as exc:
        raise ValueError(f"required recovery file is missing: {path}") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError("recovery input must be one regular file")
        if metadata.st_size > maximum_bytes:
            raise ValueError("recovery input exceeds its size boundary")
        if private and os.name == "posix" and metadata.st_mode & 0o077:
            raise ValueError("private recovery input permissions are too broad")
        if trusted and os.name == "posix" and metadata.st_mode & 0o022:
            raise ValueError("trusted recovery input permissions are too broad")
        remaining = metadata.st_size
        chunks: list[bytes] = []
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) != metadata.st_size:
            raise ValueError("recovery input changed while it was read")
        return raw
    finally:
        os.close(descriptor)


def _write_atomic(path: Path, raw: bytes, *, mode: int) -> None:
    path = absolute_path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
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
    _fsync_directory(path.parent)


def _valid_journal_key_fingerprint(value: object) -> bool:
    normalized = str(value or "")
    return (
        normalized.startswith("sha256:")
        and len(normalized) == 71
        and all(ch in "0123456789abcdef" for ch in normalized[7:])
    )


def _journal_key_audit_state(
    target: Path,
    *,
    sequence: int | None = None,
    expected_fingerprint: str | None = None,
) -> dict[str, Any]:
    """Derive the monotonic journal-key generation from authenticated audit events."""

    target = absolute_path(target)
    audit = read_verified_deployment_audit_events(target)
    records = list(audit["records"])
    if sequence is None:
        limit = len(records)
    else:
        limit = int(sequence)
        if limit < 0 or limit > len(records):
            raise ValueError("journal key audit generation checkpoint is outside the verified audit log")
    generation = 1
    current_fingerprint: str | None = None
    fingerprint_generations: dict[str, int] = {}
    for record in records[:limit]:
        action = str(record.get("action") or "")
        details = record.get("details")
        if not isinstance(details, dict):
            continue
        if action == "recovery_journal_key_backup_created":
            fingerprint = str(details.get("journal_key_fingerprint") or "")
            if not _valid_journal_key_fingerprint(fingerprint):
                raise ValueError("journal key backup audit fingerprint is invalid")
            declared = details.get("journal_key_generation")
            if declared is not None and int(declared) != generation:
                raise ValueError("journal key backup audit generation is inconsistent")
            known = fingerprint_generations.get(fingerprint)
            if known is not None and known != generation:
                raise ValueError("journal key backup audit fingerprint generation is inconsistent")
            if current_fingerprint is not None and current_fingerprint != fingerprint:
                raise ValueError("journal key changed without an authenticated rotation event")
            fingerprint_generations[fingerprint] = generation
            current_fingerprint = fingerprint
        elif action == "recovery_journal_key_rotated":
            previous = str(details.get("previous_fingerprint") or "")
            current = str(details.get("current_fingerprint") or "")
            if not _valid_journal_key_fingerprint(previous) or not _valid_journal_key_fingerprint(current) or previous == current:
                raise ValueError("journal key rotation audit fingerprints are invalid")
            declared_previous = details.get("previous_generation")
            declared_current = details.get("current_generation")
            if declared_previous is not None and int(declared_previous) != generation:
                raise ValueError("journal key rotation previous generation is inconsistent")
            if current_fingerprint is not None and previous != current_fingerprint:
                raise ValueError("journal key rotation audit chain is inconsistent")
            known_previous = fingerprint_generations.get(previous)
            if known_previous is not None and known_previous != generation:
                raise ValueError("journal key rotation previous fingerprint generation is inconsistent")
            fingerprint_generations[previous] = generation
            generation += 1
            if declared_current is not None and int(declared_current) != generation:
                raise ValueError("journal key rotation current generation is inconsistent")
            known_current = fingerprint_generations.get(current)
            if known_current is not None and known_current != generation:
                raise ValueError("journal key rotation reuses an older fingerprint generation")
            fingerprint_generations[current] = generation
            current_fingerprint = current
        elif action == "recovery_journal_key_restored":
            fingerprint = str(details.get("journal_key_fingerprint") or "")
            if not _valid_journal_key_fingerprint(fingerprint):
                raise ValueError("journal key restore audit fingerprint is invalid")
            declared = details.get("journal_key_generation")
            known = fingerprint_generations.get(fingerprint)
            restored_generation = int(declared) if declared is not None else known
            if restored_generation is None:
                if current_fingerprint is None:
                    restored_generation = generation
                elif current_fingerprint == fingerprint:
                    restored_generation = generation
                else:
                    raise ValueError("legacy journal key restore generation is ambiguous")
            if restored_generation < generation:
                raise ValueError("journal key audit records a generation rollback")
            if restored_generation > generation:
                raise ValueError("journal key restore generation is ahead of the authenticated audit chain")
            if known is not None and known != restored_generation:
                raise ValueError("journal key restore fingerprint generation is inconsistent")
            fingerprint_generations[fingerprint] = restored_generation
            current_fingerprint = fingerprint
    if expected_fingerprint is not None:
        if not _valid_journal_key_fingerprint(expected_fingerprint):
            raise ValueError("current journal key fingerprint is invalid")
        if current_fingerprint is not None and current_fingerprint != expected_fingerprint:
            raise ValueError("current journal key does not match the authenticated audit generation")
        fingerprint_generations.setdefault(expected_fingerprint, generation)
        current_fingerprint = expected_fingerprint
    if limit == 0:
        checkpoint_head = "0" * 64
    else:
        checkpoint_head = _sha256(_canonical(records[limit - 1]))
    return {
        "generation": generation,
        "fingerprint": current_fingerprint,
        "audit_sequence": limit,
        "audit_head_sha256": checkpoint_head,
        "audit_events": len(records),
    }


def recovery_journal_key_status(target: Path) -> dict[str, Any]:
    target = absolute_path(target)
    path = recovery_journal_key_path(target)
    transactions = _transaction_directories(target)
    try:
        key = _read_recovery_journal_key(target)
        fingerprint = _journal_key_fingerprint(key)
        generation = _journal_key_audit_state(target, expected_fingerprint=fingerprint)
    except Exception as exc:
        return {
            "target": str(target),
            "path": str(path),
            "available": False,
            "pending_transactions": len(transactions),
            "error": str(exc),
        }
    verified = 0
    transaction_error: str | None = None
    for root in transactions:
        try:
            _transaction_manifest(root, target=target)
            verified += 1
        except Exception as exc:
            transaction_error = str(exc)
            break
    return {
        "target": str(target),
        "path": str(path),
        "available": True,
        "fingerprint": fingerprint,
        "generation": generation["generation"],
        "audit_sequence": generation["audit_sequence"],
        "audit_head_sha256": generation["audit_head_sha256"],
        "bytes": len(key),
        "pending_transactions": len(transactions),
        "authenticated_transactions": verified,
        "transactions_valid": transaction_error is None,
        "transaction_error": transaction_error,
    }


def _journal_key_backup_payload(
    target: Path,
    key: bytes,
    *,
    generation: dict[str, Any],
) -> dict[str, Any]:
    return {
        "format": JOURNAL_KEY_BACKUP_FORMAT,
        "backup_id": secrets.token_hex(16),
        "target_name": absolute_path(target).name,
        "created_at": _utc_now(),
        "key_hex": key.hex(),
        "fingerprint": _journal_key_fingerprint(key),
        "generation": int(generation["generation"]),
        "audit_sequence": int(generation["audit_sequence"]),
        "audit_head_sha256": str(generation["audit_head_sha256"]),
    }


def _read_recovery_journal_key_backup(
    source: Path,
    *,
    target: Path,
    trusted_public_key: Path,
) -> tuple[bytes, dict[str, Any]]:
    raw = _read_regular(source, maximum_bytes=MAX_JOURNAL_KEY_BACKUP_BYTES, private=True)
    try:
        document = json.loads(raw)
    except Exception as exc:
        raise ValueError("deployment history recovery journal key backup is invalid") from exc
    if not isinstance(document, dict):
        raise ValueError("deployment history recovery journal key backup must be an object")
    if document.get("format") == LEGACY_JOURNAL_KEY_BACKUP_FORMAT:
        raise ValueError("unsigned v1 recovery journal key backups are not accepted; create a witness-signed v2 backup")
    if document.get("format") != JOURNAL_KEY_BACKUP_FORMAT:
        raise ValueError("deployment history recovery journal key backup format is invalid")
    payload = verify_witness_document(
        document,
        public_key_path=trusted_public_key,
        label="recovery journal key backup",
    )
    if str(payload.get("target_name") or "") != absolute_path(target).name:
        raise ValueError("deployment history recovery journal key backup target does not match")
    created_at = str(payload.get("created_at") or "")
    backup_id = str(payload.get("backup_id") or "")
    if not created_at.endswith("Z") or len(backup_id) != 32 or any(ch not in "0123456789abcdef" for ch in backup_id):
        raise ValueError("deployment history recovery journal key backup identity is invalid")
    try:
        key = bytes.fromhex(str(payload.get("key_hex") or ""))
    except ValueError as exc:
        raise ValueError("deployment history recovery journal key backup key is invalid") from exc
    if len(key) != JOURNAL_KEY_BYTES or payload.get("fingerprint") != _journal_key_fingerprint(key):
        raise ValueError("deployment history recovery journal key backup integrity check failed")
    generation = payload.get("generation")
    audit_sequence = payload.get("audit_sequence")
    audit_head = str(payload.get("audit_head_sha256") or "").lower()
    if not isinstance(generation, int) or generation < 1:
        raise ValueError("deployment history recovery journal key backup generation is invalid")
    if not isinstance(audit_sequence, int) or audit_sequence < 0:
        raise ValueError("deployment history recovery journal key backup audit sequence is invalid")
    if len(audit_head) != 64 or any(ch not in "0123456789abcdef" for ch in audit_head):
        raise ValueError("deployment history recovery journal key backup audit checkpoint is invalid")
    return key, payload


def backup_recovery_journal_key(
    target: Path,
    *,
    output: Path,
    witness_private_key: Path,
) -> dict[str, Any]:
    target = absolute_path(target)
    output = absolute_path(output)
    if os.path.lexists(output):
        raise FileExistsError(f"deployment history recovery journal key backup already exists: {output}")
    _private_parent(output, label="recovery journal key backup")
    key = _read_recovery_journal_key(target)
    fingerprint = _journal_key_fingerprint(key)
    generation = _journal_key_audit_state(target, expected_fingerprint=fingerprint)
    document = sign_witness_document(
        _journal_key_backup_payload(target, key, generation=generation),
        private_key_path=witness_private_key,
    )
    raw = json.dumps(document, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8") + b"\n"
    _write_atomic(output, raw, mode=0o600)
    try:
        audit = append_deployment_audit_event(
            target,
            action="recovery_journal_key_backup_created",
            details={
                "backup_name": output.name,
                "backup_sha256": _sha256(raw),
                "journal_key_fingerprint": fingerprint,
                "journal_key_generation": generation["generation"],
                "backup_audit_sequence": generation["audit_sequence"],
                "backup_audit_head_sha256": generation["audit_head_sha256"],
                "witness_key_id": document["witness_key_id"],
                "witness_public_key_fingerprint": document["witness_public_key_fingerprint"],
            },
        )
    except BaseException:
        output.unlink(missing_ok=True)
        _fsync_directory(output.parent)
        raise
    return {
        "target": str(target),
        "backup": str(output),
        "sha256": _sha256(raw),
        "bytes": len(raw),
        "fingerprint": fingerprint,
        "generation": generation["generation"],
        "audit_sequence": generation["audit_sequence"],
        "audit_head_sha256": generation["audit_head_sha256"],
        "witness_key_id": document["witness_key_id"],
        "witness_public_key_fingerprint": document["witness_public_key_fingerprint"],
        "audit": audit["audit"],
        "notice": "This witness-signed backup contains a secret journal HMAC key; store it on encrypted offline media.",
    }


def _transaction_snapshots_with_journal_key(
    target: Path,
    key: bytes,
) -> list[tuple[bytes | None, bytes | None]]:
    target = absolute_path(target)
    transactions = _transaction_directories(target)
    snapshots: list[tuple[bytes | None, bytes | None]] = []
    for root in transactions:
        manifest = _transaction_manifest(root, target=target, journal_key=key)
        if manifest.get("format") != _TRANSACTION_FORMAT:
            raise ValueError("recovery journal key backup cannot authenticate a legacy transaction")
        previous_keyring = _transaction_file(
            root,
            manifest,
            filename="previous-keyring.bin",
            presence_key="previous_keyring_present",
            maximum_bytes=MAX_KEYRING_BYTES,
            allow_legacy=False,
        )
        previous_audit = _transaction_file(
            root,
            manifest,
            filename="previous-audit.jsonl",
            presence_key="previous_audit_present",
            maximum_bytes=MAX_AUDIT_BYTES,
            allow_legacy=False,
        )
        snapshots.append((previous_keyring, previous_audit))
    return snapshots


def _verify_transactions_with_journal_key(target: Path, key: bytes) -> int:
    return len(_transaction_snapshots_with_journal_key(target, key))


def _verify_journal_key_restore_policy(
    target: Path,
    *,
    backup: dict[str, Any],
    candidate_fingerprint: str,
    trusted_witness_public_key: Path,
    minimum_witness_receipt: Path,
    snapshot: tuple[bytes | None, bytes | None] | None,
    expected_fingerprint: str | None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    target = absolute_path(target)

    def verify_against(check_target: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        verify_deployment_audit_checkpoint(
            check_target,
            sequence=int(backup["audit_sequence"]),
            head_sha256=str(backup["audit_head_sha256"]),
        )
        minimum = verify_witness_receipt(
            check_target,
            receipt_path=minimum_witness_receipt,
            public_key_path=trusted_witness_public_key,
        )
        minimum_generation = _journal_key_audit_state(
            check_target,
            sequence=int(minimum["witness_sequence"]),
        )
        current_generation = _journal_key_audit_state(
            check_target,
            expected_fingerprint=expected_fingerprint,
        )
        return minimum, minimum_generation, current_generation

    if snapshot is None:
        return verify_against(target)
    previous_keyring, previous_audit = snapshot
    if previous_keyring is None or previous_audit is None:
        raise ValueError("pending recovery journal does not contain the authenticated history needed to verify key generation")
    with tempfile.TemporaryDirectory(prefix="vulnflow-journal-key-policy-") as temporary:
        parent = Path(temporary)
        if os.name == "posix":
            parent.chmod(0o700)
        staged_target = parent / target.name
        _write_atomic(history_keyring_path(staged_target), previous_keyring, mode=0o600)
        _write_atomic(audit_log_path(staged_target), previous_audit, mode=0o600)
        return verify_against(staged_target)


def restore_recovery_journal_key(
    target: Path,
    *,
    source: Path,
    trusted_witness_public_key: Path,
    minimum_witness_receipt: Path,
) -> dict[str, Any]:
    target = absolute_path(target)
    candidate, backup = _read_recovery_journal_key_backup(
        source,
        target=target,
        trusted_public_key=trusted_witness_public_key,
    )
    candidate_fingerprint = _journal_key_fingerprint(candidate)
    snapshots = _transaction_snapshots_with_journal_key(target, candidate)
    if len(snapshots) > 1:
        raise RuntimeError("multiple interrupted deployment history recovery transactions require manual review")
    path = recovery_journal_key_path(target)
    previous: bytes | None
    if os.path.lexists(path):
        previous = _read_recovery_journal_key(target)
    else:
        previous = None
    minimum, minimum_generation, current_generation = _verify_journal_key_restore_policy(
        target,
        backup=backup,
        candidate_fingerprint=candidate_fingerprint,
        trusted_witness_public_key=trusted_witness_public_key,
        minimum_witness_receipt=minimum_witness_receipt,
        snapshot=snapshots[0] if snapshots else None,
        expected_fingerprint=(
            candidate_fingerprint
            if snapshots
            else (_journal_key_fingerprint(previous) if previous is not None else None)
        ),
    )
    candidate_generation = int(backup["generation"])
    if candidate_generation < int(minimum_generation["generation"]):
        raise ValueError("recovery journal key backup is older than the external minimum witness generation")
    if candidate_generation < int(current_generation["generation"]):
        raise ValueError("recovery journal key backup would roll back the authenticated audit generation")
    if candidate_generation > int(current_generation["generation"]):
        raise ValueError("recovery journal key backup generation is ahead of the authenticated audit chain")
    audited_fingerprint = current_generation.get("fingerprint")
    if audited_fingerprint is not None and candidate_fingerprint != audited_fingerprint:
        raise ValueError("recovery journal key backup does not match the current authenticated generation")
    pending = len(snapshots)
    if previous is not None and previous != candidate and pending == 0:
        raise ValueError("refusing to replace an available recovery journal key without a matching pending journal; rotate it instead")
    if previous == candidate:
        return {
            "target": str(target),
            "source": str(absolute_path(source)),
            "changed": False,
            "fingerprint": candidate_fingerprint,
            "generation": candidate_generation,
            "authenticated_transactions": pending,
            "witness_key_id": backup["witness_key_id"],
            "witness_public_key_fingerprint": backup["witness_public_key_fingerprint"],
        }
    _write_atomic(path, candidate, mode=0o600)
    try:
        verified = _verify_transactions_with_journal_key(target, candidate)
        audit = None
        if verified == 0:
            audit = append_deployment_audit_event(
                target,
                action="recovery_journal_key_restored",
                details={
                    "backup_name": absolute_path(source).name,
                    "journal_key_fingerprint": candidate_fingerprint,
                    "journal_key_generation": candidate_generation,
                    "witness_key_id": backup["witness_key_id"],
                    "witness_public_key_fingerprint": backup["witness_public_key_fingerprint"],
                    "minimum_witness_sequence": minimum["witness_sequence"],
                    "minimum_witness_head_sha256": minimum["witness_head_sha256"],
                },
            )["audit"]
    except BaseException:
        if previous is None:
            path.unlink(missing_ok=True)
            _fsync_directory(path.parent)
        else:
            _write_atomic(path, previous, mode=0o600)
        raise
    return {
        "target": str(target),
        "source": str(absolute_path(source)),
        "changed": True,
        "fingerprint": candidate_fingerprint,
        "generation": candidate_generation,
        "authenticated_transactions": verified,
        "witness_key_id": backup["witness_key_id"],
        "witness_public_key_fingerprint": backup["witness_public_key_fingerprint"],
        "minimum_witness_sequence": minimum["witness_sequence"],
        "audit": audit,
        "notice": "When a pending transaction is authenticated, run startup preflight or recover-interrupted to complete recovery.",
    }


def rotate_recovery_journal_key(target: Path) -> dict[str, Any]:
    target = absolute_path(target)
    if _transaction_directories(target):
        raise RuntimeError("cannot rotate the recovery journal key while a recovery transaction is pending")
    path = recovery_journal_key_path(target)
    previous = _read_recovery_journal_key(target)
    previous_fingerprint = _journal_key_fingerprint(previous)
    generation = _journal_key_audit_state(target, expected_fingerprint=previous_fingerprint)
    replacement = secrets.token_bytes(JOURNAL_KEY_BYTES)
    replacement_fingerprint = _journal_key_fingerprint(replacement)
    _write_atomic(path, replacement, mode=0o600)
    try:
        audit = append_deployment_audit_event(
            target,
            action="recovery_journal_key_rotated",
            details={
                "previous_fingerprint": previous_fingerprint,
                "current_fingerprint": replacement_fingerprint,
                "previous_generation": generation["generation"],
                "current_generation": int(generation["generation"]) + 1,
            },
        )
    except BaseException:
        _write_atomic(path, previous, mode=0o600)
        raise
    return {
        "target": str(target),
        "previous_fingerprint": previous_fingerprint,
        "current_fingerprint": replacement_fingerprint,
        "previous_generation": generation["generation"],
        "current_generation": int(generation["generation"]) + 1,
        "audit": audit["audit"],
    }

def _restore_file(path: Path, raw: bytes | None) -> None:
    if raw is None:
        path.unlink(missing_ok=True)
        _fsync_directory(path.parent)
        return
    _write_atomic(path, raw, mode=0o600)


def _safe_current_bytes(path: Path, *, maximum_bytes: int) -> bytes | None:
    if not os.path.lexists(path):
        return None
    return _read_regular(path, maximum_bytes=maximum_bytes, private=True)


def _zip_info(name: str, *, private: bool) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=(2026, 8, 3, 0, 0, 0))
    info.create_system = 3
    mode = 0o600 if private else 0o644
    info.external_attr = (stat.S_IFREG | mode) << 16
    info.compress_type = zipfile.ZIP_DEFLATED
    return info


def _member_limits(name: str) -> int:
    return {
        MANIFEST_NAME: MAX_MANIFEST_BYTES,
        KEYRING_NAME: MAX_KEYRING_BYTES,
        AUDIT_NAME: MAX_AUDIT_BYTES,
        WITNESS_RECEIPT_NAME: MAX_RECEIPT_BYTES,
        WITNESS_PUBLIC_KEY_NAME: MAX_KEY_FILE_BYTES,
        SHA256SUMS_NAME: MAX_SUMS_BYTES,
    }[name]


def _build_sums(files: dict[str, bytes]) -> bytes:
    return "".join(f"{_sha256(files[name])}  {name}\n" for name in sorted(files)).encode("ascii")


def _parse_sums(raw: bytes) -> dict[str, str]:
    if len(raw) > MAX_SUMS_BYTES:
        raise ValueError("recovery checksum file exceeds its size boundary")
    rows: dict[str, str] = {}
    for line in raw.decode("ascii").splitlines():
        digest, separator, name = line.partition("  ")
        if not separator or name in rows or name not in EXPECTED_MEMBERS - {SHA256SUMS_NAME}:
            raise ValueError("recovery checksum file is invalid")
        if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
            raise ValueError("recovery checksum digest is invalid")
        rows[name] = digest
    if set(rows) != EXPECTED_MEMBERS - {SHA256SUMS_NAME}:
        raise ValueError("recovery checksum coverage is incomplete")
    return rows


def _read_bundle(path: Path) -> tuple[dict[str, bytes], dict[str, Any]]:
    raw = _read_regular(path, maximum_bytes=MAX_BUNDLE_BYTES, private=True)
    try:
        archive = zipfile.ZipFile(io.BytesIO(raw))
    except Exception as exc:
        raise ValueError("deployment history recovery bundle is not a valid ZIP") from exc
    with archive:
        infos = archive.infolist()
        names = [item.filename for item in infos]
        if len(infos) != len(EXPECTED_MEMBERS) or set(names) != EXPECTED_MEMBERS or len(names) != len(set(names)):
            raise ValueError("deployment history recovery bundle member contract is invalid")
        members: dict[str, bytes] = {}
        total = 0
        for info in infos:
            if info.flag_bits & 0x1 or info.is_dir() or info.filename.startswith(("/", "\\")) or ".." in Path(info.filename).parts:
                raise ValueError("deployment history recovery bundle contains an unsafe member")
            mode = (info.external_attr >> 16) & 0o170000
            if mode not in {0, stat.S_IFREG}:
                raise ValueError("deployment history recovery bundle member type is unsafe")
            limit = _member_limits(info.filename)
            if info.file_size > limit:
                raise ValueError("deployment history recovery bundle member exceeds its size boundary")
            if info.compress_size == 0 and info.file_size:
                raise ValueError("deployment history recovery bundle compression metadata is invalid")
            if info.compress_size and info.file_size / info.compress_size > MAX_COMPRESSION_RATIO:
                raise ValueError("deployment history recovery bundle compression ratio is unsafe")
            data = archive.read(info)
            if len(data) != info.file_size:
                raise ValueError("deployment history recovery bundle member size changed during extraction")
            total += len(data)
            if total > MAX_BUNDLE_BYTES:
                raise ValueError("deployment history recovery bundle exceeds its total size boundary")
            members[info.filename] = data
    sums = _parse_sums(members[SHA256SUMS_NAME])
    for name, expected in sums.items():
        if _sha256(members[name]) != expected:
            raise ValueError(f"deployment history recovery bundle checksum mismatch: {name}")
    try:
        manifest = json.loads(members[MANIFEST_NAME])
    except Exception as exc:
        raise ValueError("deployment history recovery manifest is invalid JSON") from exc
    if not isinstance(manifest, dict) or manifest.get("format") != BUNDLE_FORMAT:
        raise ValueError("deployment history recovery manifest format is invalid")
    return members, manifest


def _retained_paths(target: Path) -> list[Path]:
    target = absolute_path(target)
    prefix = f".{target.name}.previous-"
    return sorted(
        (
            path
            for path in target.parent.iterdir()
            if path.name.startswith(prefix) and path.is_dir() and not path.is_symlink() and (path / SEAL_RELATIVE_PATH).is_file()
        ),
        key=lambda item: item.name,
    )


def _validate_candidate(
    target: Path,
    *,
    members: dict[str, bytes],
    manifest: dict[str, Any],
    trusted_public_key: Path,
    minimum_witness_receipt: Path,
) -> dict[str, Any]:
    target = absolute_path(target)
    if manifest.get("target_name") != target.name:
        raise ValueError("deployment history recovery bundle target does not match")
    bundle_id = str(manifest.get("bundle_id") or "")
    created_at = str(manifest.get("created_at") or "")
    if len(bundle_id) != 32 or any(ch not in "0123456789abcdef" for ch in bundle_id) or not created_at.endswith("Z"):
        raise ValueError("deployment history recovery bundle identity is invalid")
    trusted_public_raw = _read_regular(trusted_public_key, maximum_bytes=MAX_KEY_FILE_BYTES, private=False, trusted=True)
    if members[WITNESS_PUBLIC_KEY_NAME] != trusted_public_raw:
        raise ValueError("recovery bundle witness public key does not match the trusted public key")

    with tempfile.TemporaryDirectory(prefix=f".{target.name}.history-recovery-verify-", dir=target.parent) as temporary:
        private_root = Path(temporary)
        private_root.chmod(0o700)
        candidate_target = private_root / target.name
        _write_atomic(history_keyring_path(candidate_target), members[KEYRING_NAME], mode=0o600)
        _write_atomic(audit_log_path(candidate_target), members[AUDIT_NAME], mode=0o600)
        bundled_receipt = private_root / WITNESS_RECEIPT_NAME
        _write_atomic(bundled_receipt, members[WITNESS_RECEIPT_NAME], mode=0o600)

        audit = verify_deployment_audit_log(candidate_target)
        keyring = history_keyring_status(candidate_target)
        if not keyring.get("available"):
            raise ValueError("recovery bundle keyring is unavailable")
        bundled_witness = verify_witness_receipt(
            candidate_target,
            receipt_path=bundled_receipt,
            public_key_path=trusted_public_key,
        )
        minimum_witness = verify_witness_receipt(
            candidate_target,
            receipt_path=minimum_witness_receipt,
            public_key_path=trusted_public_key,
        )

        expected = {
            "audit_sequence": int(audit["last_sequence"]),
            "audit_head_sha256": str(audit["last_entry_sha256"]),
            "history_key_id": str(keyring["current_key_id"]),
            "history_key_fingerprint": str(keyring["fingerprint"]),
            "witness_receipt_id": str(bundled_witness["receipt_id"]),
            "witness_sequence": int(bundled_witness["witness_sequence"]),
            "witness_head_sha256": str(bundled_witness["witness_head_sha256"]),
            "witness_public_key_fingerprint": str(bundled_witness["witness_public_key_fingerprint"]),
        }
        for key, value in expected.items():
            if manifest.get(key) != value:
                raise ValueError(f"deployment history recovery manifest does not match candidate state: {key}")
        file_rows = manifest.get("files")
        if not isinstance(file_rows, dict):
            raise ValueError("deployment history recovery manifest file inventory is invalid")
        for name in EXPECTED_MEMBERS - {MANIFEST_NAME, SHA256SUMS_NAME}:
            row = file_rows.get(name)
            if not isinstance(row, dict) or row.get("sha256") != _sha256(members[name]) or int(row.get("bytes") or -1) != len(members[name]):
                raise ValueError(f"deployment history recovery manifest file inventory mismatch: {name}")

        verified_retained = 0
        for retained in _retained_paths(target):
            verify_retained_deployment(candidate_target, retained)
            verified_retained += 1
        return {
            "valid": True,
            "bundle_id": str(manifest.get("bundle_id") or ""),
            "target": str(target),
            "audit": audit,
            "keyring": keyring,
            "bundled_witness": bundled_witness,
            "minimum_witness": minimum_witness,
            "verified_retained_deployments": verified_retained,
        }


def create_history_recovery_bundle(
    target: Path,
    *,
    trusted_public_key: Path,
    witness_receipt: Path,
    output: Path,
) -> dict[str, Any]:
    target = absolute_path(target)
    output = absolute_path(output)
    if os.path.lexists(output):
        raise FileExistsError(f"deployment history recovery bundle already exists: {output}")
    _private_parent(output, label="deployment history recovery bundle")
    audit = verify_deployment_audit_log(target)
    keyring = history_keyring_status(target)
    if not keyring.get("available"):
        raise ValueError("deployment history keyring is unavailable")
    witness = verify_witness_receipt(target, receipt_path=witness_receipt, public_key_path=trusted_public_key)
    keyring_raw = read_history_keyring_bytes(target)
    audit_raw = _safe_current_bytes(audit_log_path(target), maximum_bytes=MAX_AUDIT_BYTES) or b""
    receipt_raw = _read_regular(witness_receipt, maximum_bytes=MAX_RECEIPT_BYTES, private=False)
    public_raw = _read_regular(trusted_public_key, maximum_bytes=MAX_KEY_FILE_BYTES, private=False, trusted=True)
    payload_files = {
        KEYRING_NAME: keyring_raw,
        AUDIT_NAME: audit_raw,
        WITNESS_RECEIPT_NAME: receipt_raw,
        WITNESS_PUBLIC_KEY_NAME: public_raw,
    }
    manifest: dict[str, Any] = {
        "format": BUNDLE_FORMAT,
        "bundle_id": secrets.token_hex(16),
        "created_at": _utc_now(),
        "target_name": target.name,
        "audit_sequence": int(audit["last_sequence"]),
        "audit_head_sha256": str(audit["last_entry_sha256"]),
        "history_key_id": str(keyring["current_key_id"]),
        "history_key_fingerprint": str(keyring["fingerprint"]),
        "witness_receipt_id": str(witness["receipt_id"]),
        "witness_sequence": int(witness["witness_sequence"]),
        "witness_head_sha256": str(witness["witness_head_sha256"]),
        "witness_public_key_fingerprint": str(witness["witness_public_key_fingerprint"]),
        "files": {
            name: {"bytes": len(raw), "sha256": _sha256(raw)}
            for name, raw in sorted(payload_files.items())
        },
    }
    members = {MANIFEST_NAME: json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8") + b"\n", **payload_files}
    members[SHA256SUMS_NAME] = _build_sums(members)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name in sorted(members):
            archive.writestr(_zip_info(name, private=name in {KEYRING_NAME, AUDIT_NAME, WITNESS_RECEIPT_NAME}), members[name])
    raw = buffer.getvalue()
    if len(raw) > MAX_BUNDLE_BYTES:
        raise ValueError("deployment history recovery bundle exceeds its size boundary")
    _write_atomic(output, raw, mode=0o600)
    try:
        audit_event = append_deployment_audit_event(
            target,
            action="history_recovery_bundle_created",
            details={
                "bundle_id": manifest["bundle_id"],
                "bundle_name": output.name,
                "bundle_sha256": _sha256(raw),
                "snapshot_audit_sequence": manifest["audit_sequence"],
                "witness_sequence": manifest["witness_sequence"],
            },
        )
    except BaseException:
        output.unlink(missing_ok=True)
        _fsync_directory(output.parent)
        raise
    return {
        "bundle": str(output),
        "bundle_id": manifest["bundle_id"],
        "sha256": _sha256(raw),
        "bytes": len(raw),
        "snapshot_audit_sequence": manifest["audit_sequence"],
        "witness_sequence": manifest["witness_sequence"],
        "audit": audit_event["audit"],
        "notice": "The bundle contains secret HMAC key material; keep it on encrypted offline media with the external witness receipt.",
    }


def verify_history_recovery_bundle(
    target: Path,
    *,
    bundle: Path,
    trusted_public_key: Path,
    minimum_witness_receipt: Path,
) -> dict[str, Any]:
    target = absolute_path(target)
    members, manifest = _read_bundle(bundle)
    result = _validate_candidate(
        target,
        members=members,
        manifest=manifest,
        trusted_public_key=trusted_public_key,
        minimum_witness_receipt=minimum_witness_receipt,
    )
    return {
        **result,
        "bundle": str(absolute_path(bundle)),
        "bundle_sha256": _sha256(_read_regular(bundle, maximum_bytes=MAX_BUNDLE_BYTES, private=True)),
    }


def _transaction_directories(target: Path) -> list[Path]:
    target = absolute_path(target)
    prefix = f".{target.name}{_TRANSACTION_SUFFIX}"
    matches: list[Path] = []
    for path in target.parent.iterdir():
        if not path.name.startswith(prefix):
            continue
        if path.is_symlink() or not path.is_dir():
            raise RuntimeError("deployment history recovery journal path is unsafe")
        metadata = path.stat()
        if os.name == "posix" and metadata.st_mode & 0o077:
            raise RuntimeError("deployment history recovery journal permissions are too broad")
        if os.name == "posix" and metadata.st_uid != os.geteuid():
            raise RuntimeError("deployment history recovery journal owner is invalid")
        matches.append(path)
    return sorted(matches, key=lambda item: item.name)


def _transaction_manifest(
    path: Path,
    *,
    target: Path | None = None,
    journal_key: bytes | None = None,
) -> dict[str, Any]:
    raw = _read_regular(path / "transaction.json", maximum_bytes=64 * 1024, private=True)
    try:
        payload = json.loads(raw)
    except Exception as exc:
        raise ValueError("deployment history recovery transaction manifest is invalid") from exc
    allowed_formats = {_TRANSACTION_FORMAT, _INTEGRITY_TRANSACTION_FORMAT, _LEGACY_TRANSACTION_FORMAT}
    if not isinstance(payload, dict) or payload.get("format") not in allowed_formats:
        raise ValueError("deployment history recovery transaction format is invalid")
    target_name = str(payload.get("target_name") or "")
    if not target_name or target_name in {".", ".."} or Path(target_name).name != target_name:
        raise ValueError("deployment history recovery transaction target is invalid")
    resolved_target = absolute_path(target) if target is not None else absolute_path(path.parent / target_name)
    if resolved_target.name != target_name or resolved_target.parent != absolute_path(path.parent):
        raise ValueError("deployment history recovery transaction target is invalid")
    if payload.get("format") == _TRANSACTION_FORMAT:
        if journal_key is None:
            _verify_transaction_authentication(resolved_target, payload)
        else:
            _verify_transaction_authentication_with_key(payload, journal_key)
    transaction_id = str(payload.get("transaction_id") or "")
    created_at = str(payload.get("created_at") or "")
    state = str(payload.get("state") or "")
    if len(transaction_id) != 32 or any(ch not in "0123456789abcdef" for ch in transaction_id):
        raise ValueError("deployment history recovery transaction ID is invalid")
    if not created_at.endswith("Z") or state not in {"prepared", "committed"}:
        raise ValueError("deployment history recovery transaction state is invalid")
    if payload.get("format") in {_TRANSACTION_FORMAT, _INTEGRITY_TRANSACTION_FORMAT}:
        expected_files = {
            filename
            for filename, present in (
                ("previous-keyring.bin", bool(payload.get("previous_keyring_present"))),
                ("previous-audit.jsonl", bool(payload.get("previous_audit_present"))),
            )
            if present
        }
        files = payload.get("previous_files")
        if not isinstance(files, dict) or set(files) != expected_files:
            raise ValueError("deployment history recovery transaction file inventory is invalid")
        for row in files.values():
            if not isinstance(row, dict):
                raise ValueError("deployment history recovery transaction file inventory is invalid")
            digest = str(row.get("sha256") or "")
            size = row.get("bytes")
            if not isinstance(size, int) or size < 0 or len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
                raise ValueError("deployment history recovery transaction file inventory is invalid")
    return payload


def _transaction_file(
    root: Path,
    manifest: dict[str, Any],
    *,
    filename: str,
    presence_key: str,
    maximum_bytes: int,
    allow_legacy: bool,
) -> bytes | None:
    present = bool(manifest.get(presence_key))
    path = root / filename
    if not present:
        if os.path.lexists(path):
            raise ValueError("deployment history recovery journal contains an unexpected backup file")
        return None
    raw = _read_regular(path, maximum_bytes=maximum_bytes, private=True)
    if manifest.get("format") in {_LEGACY_TRANSACTION_FORMAT, _INTEGRITY_TRANSACTION_FORMAT}:
        if not allow_legacy:
            raise RuntimeError(
                "legacy deployment history recovery journal is unauthenticated; "
                "run the management CLI with explicit legacy confirmation"
            )
        if manifest.get("format") == _LEGACY_TRANSACTION_FORMAT:
            return raw
    files = manifest.get("previous_files")
    row = files.get(filename) if isinstance(files, dict) else None
    if not isinstance(row, dict):
        raise ValueError("deployment history recovery journal file inventory is invalid")
    if int(row.get("bytes") or -1) != len(raw) or str(row.get("sha256") or "") != _sha256(raw):
        raise ValueError("deployment history recovery journal backup integrity check failed")
    return raw


def inspect_interrupted_history_recovery(target: Path) -> dict[str, Any]:
    target = absolute_path(target)
    transactions = _transaction_directories(target)
    rows: list[dict[str, Any]] = []
    for root in transactions:
        manifest = _transaction_manifest(root, target=target)
        rows.append({
            "path": str(root),
            "format": str(manifest.get("format") or ""),
            "state": str(manifest.get("state") or ""),
            "transaction_id": str(manifest.get("transaction_id") or ""),
            "created_at": str(manifest.get("created_at") or ""),
            "integrity_checked": manifest.get("format") in {_TRANSACTION_FORMAT, _INTEGRITY_TRANSACTION_FORMAT},
            "authenticated": manifest.get("format") == _TRANSACTION_FORMAT,
            "journal_key_fingerprint": str(manifest.get("journal_key_fingerprint") or ""),
        })
    return {
        "target": str(target),
        "pending": bool(rows),
        "count": len(rows),
        "transactions": rows,
    }


def _recover_interrupted_transaction(target: Path, *, allow_legacy: bool = False) -> dict[str, Any] | None:
    target = absolute_path(target)
    transactions = _transaction_directories(target)
    if not transactions:
        return None
    if len(transactions) != 1:
        raise RuntimeError("multiple interrupted deployment history recovery transactions require manual review")
    root = transactions[0]
    manifest = _transaction_manifest(root, target=target)
    if manifest.get("format") != _TRANSACTION_FORMAT and not allow_legacy:
        raise RuntimeError(
            "legacy deployment history recovery journal is unauthenticated; "
            "run the management CLI with explicit legacy confirmation"
        )
    if manifest.get("target_name") != target.name:
        raise RuntimeError("interrupted deployment history recovery target is invalid")
    state = str(manifest.get("state") or "")
    if state == "committed":
        verify_deployment_audit_log(target)
        for retained in _retained_paths(target):
            verify_retained_deployment(target, retained)
        shutil.rmtree(root)
        _fsync_directory(target.parent)
        return {"action": "removed_committed_recovery_journal", "verified": True, "transaction": str(root)}

    previous_key = _transaction_file(
        root,
        manifest,
        filename="previous-keyring.bin",
        presence_key="previous_keyring_present",
        maximum_bytes=MAX_KEYRING_BYTES,
        allow_legacy=allow_legacy,
    )
    previous_audit = _transaction_file(
        root,
        manifest,
        filename="previous-audit.jsonl",
        presence_key="previous_audit_present",
        maximum_bytes=MAX_AUDIT_BYTES,
        allow_legacy=allow_legacy,
    )
    _restore_file(audit_log_path(target), previous_audit)
    _restore_file(history_keyring_path(target), previous_key)
    if previous_key is not None:
        verify_deployment_audit_log(target)
        for retained in _retained_paths(target):
            verify_retained_deployment(target, retained)
    elif previous_audit is not None:
        raise ValueError("deployment history recovery journal contains audit data without a keyring")
    shutil.rmtree(root)
    _fsync_directory(target.parent)
    return {"action": "restored_interrupted_recovery", "verified": True, "transaction": str(root)}


def recover_interrupted_history_recovery(target: Path, *, allow_legacy: bool = False) -> dict[str, Any]:
    target = absolute_path(target)
    result = _recover_interrupted_transaction(target, allow_legacy=allow_legacy)
    return {
        "target": str(target),
        "recovered": result is not None,
        "result": result,
        "status": inspect_interrupted_history_recovery(target),
    }


def _prepare_transaction(target: Path, previous_key: bytes | None, previous_audit: bytes | None) -> Path:
    root = target.parent / f".{target.name}{_TRANSACTION_SUFFIX}{secrets.token_hex(8)}"
    root.mkdir(mode=0o700)
    files: dict[str, dict[str, Any]] = {}
    if previous_key is not None:
        _write_atomic(root / "previous-keyring.bin", previous_key, mode=0o600)
        files["previous-keyring.bin"] = {"bytes": len(previous_key), "sha256": _sha256(previous_key)}
    if previous_audit is not None:
        _write_atomic(root / "previous-audit.jsonl", previous_audit, mode=0o600)
        files["previous-audit.jsonl"] = {"bytes": len(previous_audit), "sha256": _sha256(previous_audit)}
    manifest = {
        "format": _TRANSACTION_FORMAT,
        "transaction_id": secrets.token_hex(16),
        "created_at": _utc_now(),
        "target_name": target.name,
        "state": "prepared",
        "previous_keyring_present": previous_key is not None,
        "previous_audit_present": previous_audit is not None,
        "previous_files": files,
    }
    manifest = _authenticate_transaction_manifest(target, manifest)
    _write_atomic(root / "transaction.json", json.dumps(manifest, sort_keys=True, indent=2).encode("utf-8") + b"\n", mode=0o600)
    _fsync_directory(root)
    _fsync_directory(target.parent)
    return root


def _set_transaction_state(root: Path, state: str) -> None:
    if state not in {"prepared", "committed"}:
        raise ValueError("deployment history recovery transaction state is invalid")
    manifest = _transaction_manifest(root)
    target = absolute_path(root.parent / str(manifest.get("target_name") or ""))
    manifest["state"] = state
    manifest = _authenticate_transaction_manifest(target, manifest)
    _write_atomic(root / "transaction.json", json.dumps(manifest, sort_keys=True, indent=2).encode("utf-8") + b"\n", mode=0o600)
    _fsync_directory(root)


def restore_history_recovery_bundle(
    target: Path,
    *,
    bundle: Path,
    trusted_public_key: Path,
    minimum_witness_receipt: Path,
) -> dict[str, Any]:
    target = absolute_path(target)
    interrupted = _recover_interrupted_transaction(target)
    members, manifest = _read_bundle(bundle)
    candidate = _validate_candidate(
        target,
        members=members,
        manifest=manifest,
        trusted_public_key=trusted_public_key,
        minimum_witness_receipt=minimum_witness_receipt,
    )
    try:
        current = verify_deployment_audit_log(target)
    except Exception:
        current = None
    if current is not None:
        candidate_sequence = int(candidate["audit"]["last_sequence"])
        current_sequence = int(current["last_sequence"])
        if current_sequence > candidate_sequence:
            raise ValueError("deployment history recovery bundle is older than the current local audit history")
        if current_sequence == candidate_sequence and current["last_entry_sha256"] != candidate["audit"]["last_entry_sha256"]:
            raise ValueError("deployment history recovery bundle conflicts with the current local audit history")

    key_path = history_keyring_path(target)
    audit_path = audit_log_path(target)
    previous_key = _safe_current_bytes(key_path, maximum_bytes=MAX_KEYRING_BYTES)
    previous_audit = _safe_current_bytes(audit_path, maximum_bytes=MAX_AUDIT_BYTES)
    transaction = _prepare_transaction(target, previous_key, previous_audit)
    try:
        _write_atomic(audit_path, members[AUDIT_NAME], mode=0o600)
        _write_atomic(key_path, members[KEYRING_NAME], mode=0o600)
        installed = verify_deployment_audit_log(target)
        verify_witness_receipt(target, receipt_path=minimum_witness_receipt, public_key_path=trusted_public_key)
        for retained in _retained_paths(target):
            verify_retained_deployment(target, retained)
        audit_event = append_deployment_audit_event(
            target,
            action="history_recovery_bundle_restored",
            details={
                "bundle_id": manifest["bundle_id"],
                "bundle_name": absolute_path(bundle).name,
                "bundle_sha256": _sha256(_read_regular(bundle, maximum_bytes=MAX_BUNDLE_BYTES, private=True)),
                "restored_audit_sequence": installed["last_sequence"],
                "minimum_witness_sequence": candidate["minimum_witness"]["witness_sequence"],
            },
        )
        verify_witness_receipt(target, receipt_path=minimum_witness_receipt, public_key_path=trusted_public_key)
        _set_transaction_state(transaction, "committed")
    except BaseException:
        _restore_file(audit_path, previous_audit)
        _restore_file(key_path, previous_key)
        if previous_key is not None:
            verify_deployment_audit_log(target)
        shutil.rmtree(transaction, ignore_errors=True)
        _fsync_directory(target.parent)
        raise
    shutil.rmtree(transaction)
    _fsync_directory(target.parent)
    return {
        "target": str(target),
        "bundle": str(absolute_path(bundle)),
        "bundle_id": manifest["bundle_id"],
        "restored_snapshot_sequence": candidate["audit"]["last_sequence"],
        "final_audit_sequence": audit_event["audit"]["last_sequence"],
        "verified_retained_deployments": candidate["verified_retained_deployments"],
        "minimum_witness_sequence": candidate["minimum_witness"]["witness_sequence"],
        "interrupted_recovery_handled": interrupted,
        "audit": audit_event["audit"],
    }
