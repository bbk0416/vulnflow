from __future__ import annotations

"""Private keyring for authenticated offline deployment history.

The original v27 format stored one raw 32-byte HMAC key.  This module accepts
that legacy format and upgrades it atomically to a versioned keyring when a key
rotation is requested.  Retired keys remain available only for verification of
older audit-log entries; retained deployment seals must always use the current
key.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import time
from typing import Any

try:
    from scripts.offline_deployment_activation import absolute_path
except ModuleNotFoundError:  # standalone signed release-kit execution
    from offline_deployment_activation import absolute_path

KEYRING_FORMAT = "vulnflow-offline-deployment-keyring/1"
_HISTORY_KEY_SUFFIX = ".deployment-history.key"
MAX_KEYRING_BYTES = 64 * 1024
MAX_KEYS = 32


@dataclass(frozen=True)
class HistoryKey:
    key_id: str
    key: bytes
    created_at: str
    status: str

    @property
    def fingerprint(self) -> str:
        return "sha256:" + hashlib.sha256(self.key).hexdigest()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def history_keyring_path(target: Path) -> Path:
    target = absolute_path(target)
    return target.parent / f".{target.name}{_HISTORY_KEY_SUFFIX}"


def _key_id(key: bytes) -> str:
    return hashlib.sha256(b"vulnflow-history-key-id\0" + key).hexdigest()[:32]


def _validate_parent(target: Path) -> None:
    parent = absolute_path(target).parent
    if parent.is_symlink() or not parent.is_dir():
        raise ValueError("deployment target parent must be a real directory")
    if os.name == "posix" and parent.stat().st_mode & 0o022:
        raise ValueError("deployment target parent must not be group- or world-writable")


def _read_private_file(path: Path) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError as exc:
        raise ValueError("deployment history signing key is missing") from exc
    try:
        metadata = os.fstat(descriptor)
        import stat

        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_size > MAX_KEYRING_BYTES:
            raise ValueError("deployment history signing key is unsafe")
        if os.name == "posix" and metadata.st_mode & 0o077:
            raise ValueError("deployment history signing key permissions are too broad")
        return os.read(descriptor, MAX_KEYRING_BYTES + 1)
    finally:
        os.close(descriptor)


def _write_private_atomic(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + f".tmp-{secrets.token_hex(8)}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(temporary, flags, 0o600)
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    if os.name == "posix":
        path.chmod(0o600)
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _new_key(*, status: str = "current") -> HistoryKey:
    key = secrets.token_bytes(32)
    return HistoryKey(key_id=_key_id(key), key=key, created_at=_utc_now(), status=status)


def _serialize(
    keys: list[HistoryKey],
    current_key_id: str,
    *,
    audit_sequence: int = 0,
    audit_head_sha256: str = "0" * 64,
) -> bytes:
    payload = {
        "format": KEYRING_FORMAT,
        "current_key_id": current_key_id,
        "audit_sequence": int(audit_sequence),
        "audit_head_sha256": audit_head_sha256,
        "keys": [
            {
                "key_id": item.key_id,
                "key_hex": item.key.hex(),
                "created_at": item.created_at,
                "status": item.status,
            }
            for item in keys
        ],
    }
    return (json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _parse(raw: bytes) -> tuple[list[HistoryKey], str, bool, int, str]:
    text = raw.decode("utf-8").strip()
    # v27 legacy single-key format.
    try:
        legacy = bytes.fromhex(text)
    except ValueError:
        legacy = b""
    if len(legacy) == 32:
        item = HistoryKey(
            key_id=_key_id(legacy),
            key=legacy,
            created_at="1970-01-01T00:00:00Z",
            status="current",
        )
        return [item], item.key_id, True, 0, "0" * 64

    try:
        payload = json.loads(text)
    except Exception as exc:
        raise ValueError("deployment history signing key is invalid") from exc
    if not isinstance(payload, dict) or payload.get("format") != KEYRING_FORMAT:
        raise ValueError("deployment history keyring format is invalid")
    current_key_id = str(payload.get("current_key_id") or "")
    audit_sequence = int(payload.get("audit_sequence") or 0)
    audit_head_sha256 = str(payload.get("audit_head_sha256") or ("0" * 64)).lower()
    if audit_sequence < 0 or len(audit_head_sha256) != 64 or any(ch not in "0123456789abcdef" for ch in audit_head_sha256):
        raise ValueError("deployment history keyring audit checkpoint is invalid")
    if audit_sequence == 0 and audit_head_sha256 != "0" * 64:
        raise ValueError("deployment history keyring empty audit checkpoint is invalid")
    rows = payload.get("keys")
    if not isinstance(rows, list) or not rows or len(rows) > MAX_KEYS:
        raise ValueError("deployment history keyring entries are invalid")
    keys: list[HistoryKey] = []
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("deployment history keyring entry is invalid")
        try:
            key = bytes.fromhex(str(row.get("key_hex") or ""))
        except ValueError as exc:
            raise ValueError("deployment history keyring key is invalid") from exc
        if len(key) != 32:
            raise ValueError("deployment history keyring key must contain 32 bytes")
        key_id = str(row.get("key_id") or "")
        if key_id != _key_id(key) or key_id in seen:
            raise ValueError("deployment history keyring key ID is invalid or duplicated")
        status = str(row.get("status") or "")
        if status not in {"current", "retired"}:
            raise ValueError("deployment history keyring status is invalid")
        created_at = str(row.get("created_at") or "")
        if not created_at.endswith("Z"):
            raise ValueError("deployment history keyring timestamp is invalid")
        keys.append(HistoryKey(key_id=key_id, key=key, created_at=created_at, status=status))
        seen.add(key_id)
    current = [item for item in keys if item.status == "current"]
    if len(current) != 1 or current[0].key_id != current_key_id:
        raise ValueError("deployment history keyring current key is invalid")
    return keys, current_key_id, False, audit_sequence, audit_head_sha256


def load_history_keyring(target: Path, *, create: bool) -> tuple[list[HistoryKey], str, bool, int, str]:
    target = absolute_path(target)
    _validate_parent(target)
    path = history_keyring_path(target)
    if create and not os.path.lexists(path):
        item = _new_key()
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(path, flags, 0o600)
        except FileExistsError:
            pass
        else:
            try:
                data = item.key.hex().encode("ascii") + b"\n"
                view = memoryview(data)
                while view:
                    written = os.write(descriptor, view)
                    view = view[written:]
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    last_error: Exception | None = None
    for attempt in range(100 if create else 1):
        try:
            raw = _read_private_file(path)
            return _parse(raw)
        except ValueError as exc:
            last_error = exc
            if not create or attempt == 99:
                raise
            time.sleep(0.005)
    assert last_error is not None
    raise last_error


def current_history_key(target: Path, *, create: bool) -> HistoryKey:
    keys, current_key_id, _, _, _ = load_history_keyring(target, create=create)
    return next(item for item in keys if item.key_id == current_key_id)


def resolve_history_key(
    target: Path,
    *,
    key_id: str | None = None,
    fingerprint: str | None = None,
    require_current: bool = False,
) -> HistoryKey:
    keys, current_key_id, _, _, _ = load_history_keyring(target, create=False)
    matches = [
        item
        for item in keys
        if (key_id is None or item.key_id == key_id)
        and (fingerprint is None or item.fingerprint == fingerprint)
    ]
    if len(matches) != 1:
        raise ValueError("deployment history signing key does not match the authenticated record")
    item = matches[0]
    if require_current and item.key_id != current_key_id:
        raise ValueError("deployment history record was not authenticated with the current key")
    return item


def history_keyring_status(target: Path) -> dict[str, Any]:
    path = history_keyring_path(target)
    try:
        keys, current_key_id, legacy, audit_sequence, audit_head_sha256 = load_history_keyring(target, create=False)
    except Exception as exc:
        return {"path": str(path), "available": False, "error": str(exc)}
    current = next(item for item in keys if item.key_id == current_key_id)
    return {
        "path": str(path),
        "available": True,
        "format": "legacy-single-key" if legacy else KEYRING_FORMAT,
        "current_key_id": current.key_id,
        "fingerprint": current.fingerprint,
        "keys_total": len(keys),
        "retired_keys": sum(item.status == "retired" for item in keys),
        "audit_sequence": audit_sequence,
        "audit_head_sha256": audit_head_sha256,
    }


def rotate_history_keyring(target: Path) -> dict[str, Any]:
    """Rotate the current key and retain the old key for audit verification."""

    target = absolute_path(target)
    keys, current_key_id, legacy, audit_sequence, audit_head_sha256 = load_history_keyring(target, create=True)
    if len(keys) >= MAX_KEYS:
        raise ValueError("deployment history keyring reached its maximum key count")
    old = next(item for item in keys if item.key_id == current_key_id)
    updated = [
        HistoryKey(item.key_id, item.key, item.created_at, "retired" if item.key_id == old.key_id else item.status)
        for item in keys
    ]
    new = _new_key()
    updated.append(new)
    path = history_keyring_path(target)
    previous_bytes = _read_private_file(path)
    _write_private_atomic(path, _serialize(updated, new.key_id, audit_sequence=audit_sequence, audit_head_sha256=audit_head_sha256))
    return {
        "path": str(path),
        "legacy_upgraded": legacy,
        "previous_key_id": old.key_id,
        "previous_fingerprint": old.fingerprint,
        "current_key_id": new.key_id,
        "current_fingerprint": new.fingerprint,
        "keys_total": len(updated),
        "previous_bytes": previous_bytes,
    }


def restore_history_keyring(target: Path, raw: bytes) -> None:
    # Parse before replacing so a failed recovery cannot install malformed key material.
    _parse(raw)
    _write_private_atomic(history_keyring_path(target), raw)


def history_audit_checkpoint(target: Path) -> tuple[int, str]:
    try:
        _, _, _, sequence, head = load_history_keyring(target, create=False)
    except ValueError as exc:
        if "is missing" in str(exc):
            return 0, "0" * 64
        raise
    return sequence, head


def update_history_audit_checkpoint(target: Path, *, sequence: int, head_sha256: str) -> None:
    if int(sequence) < 0 or len(head_sha256) != 64 or any(ch not in "0123456789abcdef" for ch in head_sha256):
        raise ValueError("deployment history audit checkpoint is invalid")
    keys, current_key_id, _, current_sequence, current_head = load_history_keyring(target, create=True)
    normalized_sequence = int(sequence)
    if normalized_sequence < current_sequence:
        raise ValueError("deployment history audit checkpoint must not move backwards")
    if normalized_sequence == current_sequence and head_sha256 != current_head:
        raise ValueError("deployment history audit checkpoint must not change at the same sequence")
    _write_private_atomic(
        history_keyring_path(target),
        _serialize(keys, current_key_id, audit_sequence=normalized_sequence, audit_head_sha256=head_sha256),
    )


def read_history_keyring_bytes(target: Path) -> bytes:
    return _read_private_file(history_keyring_path(target))


def backup_history_keyring(target: Path, destination: Path) -> dict[str, Any]:
    target = absolute_path(target)
    destination = absolute_path(destination)
    if os.path.lexists(destination):
        raise FileExistsError(f"deployment history keyring backup already exists: {destination}")
    if destination.parent.is_symlink() or not destination.parent.is_dir():
        raise ValueError("deployment history keyring backup parent must be a real directory")
    if os.name == "posix" and destination.parent.stat().st_mode & 0o022:
        raise ValueError("deployment history keyring backup parent must not be group- or world-writable")
    raw = read_history_keyring_bytes(target)
    _parse(raw)
    _write_private_atomic(destination, raw)
    return {
        "source": str(history_keyring_path(target)),
        "backup": str(destination),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "bytes": len(raw),
        "notice": "This backup contains secret HMAC key material and must be stored on encrypted offline media.",
    }


def read_history_keyring_backup(path: Path) -> bytes:
    path = absolute_path(path)
    raw = _read_private_file(path)
    _parse(raw)
    return raw
