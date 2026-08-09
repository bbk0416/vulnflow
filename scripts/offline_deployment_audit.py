from __future__ import annotations

"""Authenticated append-only audit chain for offline deployment operations."""

from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
from typing import Any

try:
    from scripts.offline_deployment_activation import absolute_path
    from scripts.offline_deployment_keyring import (
        current_history_key,
        history_audit_checkpoint,
        resolve_history_key,
        update_history_audit_checkpoint,
    )
except ModuleNotFoundError:  # standalone signed release-kit execution
    from offline_deployment_activation import absolute_path
    from offline_deployment_keyring import (
        current_history_key,
        history_audit_checkpoint,
        resolve_history_key,
        update_history_audit_checkpoint,
    )

AUDIT_FORMAT = "vulnflow-offline-deployment-audit/1"
_AUDIT_SUFFIX = ".deployment-history.audit.jsonl"
MAX_AUDIT_BYTES = 64 * 1024 * 1024
MAX_AUDIT_LINE_BYTES = 1024 * 1024
MAX_AUDIT_EVENTS = 100_000


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def audit_log_path(target: Path) -> Path:
    target = absolute_path(target)
    return target.parent / f".{target.name}{_AUDIT_SUFFIX}"


def _canonical(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _entry_hash(payload: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(payload)).hexdigest()


def _validate_metadata(metadata: os.stat_result) -> None:
    import stat

    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_size > MAX_AUDIT_BYTES:
        raise ValueError("deployment history audit log exceeds its safety boundary")
    if os.name == "posix" and metadata.st_mode & 0o077:
        raise ValueError("deployment history audit log permissions are too broad")


def _verify_lines(target: Path, lines: list[bytes]) -> dict[str, Any]:
    if len(lines) > MAX_AUDIT_EVENTS or any(len(line) > MAX_AUDIT_LINE_BYTES for line in lines):
        raise ValueError("deployment history audit log exceeds its event boundary")
    previous_hash = "0" * 64
    events: list[dict[str, Any]] = []
    entry_hashes: list[str] = []
    for sequence, raw in enumerate(lines, start=1):
        try:
            loaded = json.loads(raw)
        except Exception as exc:
            raise ValueError(f"deployment history audit event {sequence} is invalid JSON") from exc
        if not isinstance(loaded, dict) or loaded.get("format") != AUDIT_FORMAT:
            raise ValueError(f"deployment history audit event {sequence} has an invalid format")
        record = dict(loaded)
        signature = str(record.pop("hmac_sha256", "")).lower()
        if int(record.get("sequence") or 0) != sequence:
            raise ValueError("deployment history audit sequence is not contiguous")
        if record.get("previous_entry_sha256") != previous_hash:
            raise ValueError("deployment history audit chain is broken")
        key = resolve_history_key(
            target,
            key_id=str(record.get("history_key_id") or ""),
            fingerprint=str(record.get("history_key_fingerprint") or ""),
            require_current=False,
        )
        expected = hmac.new(key.key, _canonical(record), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            raise ValueError("deployment history audit authentication failed")
        full = {**record, "hmac_sha256": signature}
        previous_hash = _entry_hash(full)
        entry_hashes.append(previous_hash)
        events.append(full)
    checkpoint_sequence, checkpoint_head = history_audit_checkpoint(target)
    if checkpoint_sequence > len(events):
        raise ValueError("deployment history audit log was truncated below its keyring checkpoint")
    if checkpoint_sequence and entry_hashes[checkpoint_sequence - 1] != checkpoint_head:
        raise ValueError("deployment history audit log does not match its keyring checkpoint")
    return {
        "valid": True,
        "events": len(events),
        "last_sequence": len(events),
        "last_entry_sha256": previous_hash,
        "last_event": events[-1] if events else None,
    }


def _read_descriptor(descriptor: int, size: int) -> bytes:
    os.lseek(descriptor, 0, os.SEEK_SET)
    remaining = size
    chunks: list[bytes] = []
    while remaining:
        chunk = os.read(descriptor, min(1024 * 1024, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _read_verified_audit_lines(target: Path) -> tuple[Path, list[bytes], dict[str, Any]]:
    target = absolute_path(target)
    path = audit_log_path(target)
    if not os.path.lexists(path):
        lines: list[bytes] = []
        return path, lines, _verify_lines(target, lines)
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        _validate_metadata(metadata)
        raw = _read_descriptor(descriptor, metadata.st_size)
    finally:
        os.close(descriptor)
    lines = raw.splitlines()
    return path, lines, _verify_lines(target, lines)


def verify_deployment_audit_log(target: Path) -> dict[str, Any]:
    path, _, state = _read_verified_audit_lines(target)
    return {"path": str(path), **state}


def read_verified_deployment_audit_events(target: Path) -> dict[str, Any]:
    """Return authenticated audit records for internal policy evaluation.

    Callers must not treat unparsed JSONL bytes as trusted input. This helper
    reuses the normal keyring/HMAC/chain verification first, then exposes the
    already-authenticated records so higher-level recovery policies can derive
    monotonic generations from the audit prefix.
    """

    path, lines, state = _read_verified_audit_lines(target)
    records = [json.loads(line) for line in lines]
    return {"path": str(path), **state, "records": records}


def verify_deployment_audit_checkpoint(
    target: Path,
    *,
    sequence: int,
    head_sha256: str,
) -> dict[str, Any]:
    """Require the local audit log to contain one externally anchored prefix."""

    normalized_sequence = int(sequence)
    normalized_head = str(head_sha256).lower()
    if normalized_sequence < 0 or len(normalized_head) != 64 or any(ch not in "0123456789abcdef" for ch in normalized_head):
        raise ValueError("external deployment history audit checkpoint is invalid")
    path, lines, state = _read_verified_audit_lines(target)
    if normalized_sequence > len(lines):
        raise ValueError("deployment history audit log is older than the external witness checkpoint")
    if normalized_sequence == 0:
        actual_head = "0" * 64
    else:
        # The complete chain was already authenticated above. Re-hashing the
        # witnessed entry avoids exposing all intermediate hashes to callers.
        try:
            loaded = json.loads(lines[normalized_sequence - 1])
        except Exception as exc:  # defensive; _verify_lines already parsed it
            raise ValueError("deployment history witness checkpoint entry is invalid") from exc
        actual_head = _entry_hash(loaded)
    if actual_head != normalized_head:
        raise ValueError("deployment history audit log does not match the external witness checkpoint")
    return {"path": str(path), **state, "witness_sequence": normalized_sequence, "witness_head_sha256": normalized_head}


def append_deployment_audit_event(target: Path, *, action: str, details: dict[str, Any]) -> dict[str, Any]:
    target = absolute_path(target)
    if not action or len(action) > 100:
        raise ValueError("deployment history audit action is invalid")
    # Create/load the key before locking the audit file so key creation cannot
    # happen after a destructive operation has already been logged.
    key = current_history_key(target, create=True)
    path = audit_log_path(target)
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        if os.name == "posix":
            import fcntl

            fcntl.flock(descriptor, fcntl.LOCK_EX)
        metadata = os.fstat(descriptor)
        _validate_metadata(metadata)
        raw = _read_descriptor(descriptor, metadata.st_size)
        state = _verify_lines(target, raw.splitlines())
        record: dict[str, Any] = {
            "format": AUDIT_FORMAT,
            "sequence": state["last_sequence"] + 1,
            "event_id": secrets.token_hex(16),
            "occurred_at": _utc_now(),
            "action": action,
            "target_name": target.name,
            "operator_uid": os.getuid() if hasattr(os, "getuid") else None,
            "process_id": os.getpid(),
            "previous_entry_sha256": state["last_entry_sha256"],
            "history_key_id": key.key_id,
            "history_key_fingerprint": key.fingerprint,
            "details": details,
        }
        record["hmac_sha256"] = hmac.new(key.key, _canonical(record), hashlib.sha256).hexdigest()
        encoded = json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
        if len(encoded) > MAX_AUDIT_LINE_BYTES:
            raise ValueError("deployment history audit event exceeds the size limit")
        if metadata.st_size + len(encoded) > MAX_AUDIT_BYTES:
            raise ValueError("deployment history audit log exceeds the size limit")
        os.lseek(descriptor, 0, os.SEEK_END)
        view = memoryview(encoded)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
        verified = _verify_lines(target, (raw + encoded).splitlines())
        update_history_audit_checkpoint(
            target,
            sequence=verified["last_sequence"],
            head_sha256=verified["last_entry_sha256"],
        )
    finally:
        if os.name == "posix":
            try:
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_UN)
            except Exception:
                pass
        os.close(descriptor)
    if os.name == "posix":
        path.chmod(0o600)
    return {"event": record, "audit": {"path": str(path), **verified}}
