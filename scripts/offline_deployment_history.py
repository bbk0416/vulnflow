from __future__ import annotations

"""Inventory, rollback, and retention helpers for offline deployments.

Retained deployments live beside the active target under private hidden names.
Only deployments carrying a validated identity marker are managed automatically;
unknown directories are reported and left untouched for manual review.
"""

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
from typing import Any, Callable, TypeVar

try:
    from scripts.offline_deployment_activation import (
        absolute_path,
        activate_staged_directory,
        remove_tree,
    )
    from scripts.offline_deployment_audit import audit_log_path, append_deployment_audit_event, verify_deployment_audit_log
    from scripts.offline_deployment_keyring import (
        backup_history_keyring,
        current_history_key,
        history_keyring_status,
        history_keyring_path,
        read_history_keyring_backup,
        resolve_history_key,
        restore_history_keyring,
        rotate_history_keyring,
    )
except ModuleNotFoundError:  # standalone signed release-kit execution
    from offline_deployment_activation import (
        absolute_path,
        activate_staged_directory,
        remove_tree,
    )
    from offline_deployment_audit import audit_log_path, append_deployment_audit_event, verify_deployment_audit_log
    from offline_deployment_keyring import (
        backup_history_keyring,
        current_history_key,
        history_keyring_status,
        history_keyring_path,
        read_history_keyring_backup,
        resolve_history_key,
        restore_history_keyring,
        rotate_history_keyring,
    )

T = TypeVar("T")

IDENTITY_FORMAT = "vulnflow-offline-deployment-identity/1"
IDENTITY_RELATIVE_PATH = Path("config") / "OFFLINE_DEPLOYMENT_IDENTITY.json"
MAX_IDENTITY_BYTES = 64 * 1024
SEAL_FORMAT = "vulnflow-offline-deployment-seal/1"
SEAL_RELATIVE_PATH = Path("config") / "OFFLINE_DEPLOYMENT_SEAL.json"
MAX_SEAL_BYTES = 64 * 1024
_INSTALLATION_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class DeploymentIdentity:
    format: str
    installation_id: str
    application_version: str
    schema_version: int
    release_kit_sha256: str
    release_public_key_fingerprint: str
    installed_at: str
    target_name: str


@dataclass(frozen=True)
class RetainedDeployment:
    path: Path
    identity: DeploymentIdentity


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: str) -> datetime:
    text = value.strip()
    if not text.endswith("Z"):
        raise ValueError("deployment identity timestamp must use UTC Z notation")
    parsed = datetime.fromisoformat(text[:-1] + "+00:00")
    if parsed.tzinfo is None:
        raise ValueError("deployment identity timestamp is missing timezone information")
    return parsed.astimezone(timezone.utc)


def _private_real_directory(path: Path, *, label: str) -> Path:
    path = absolute_path(path)
    if path.is_symlink() or not path.is_dir():
        raise ValueError(f"{label} must be a real directory")
    if os.name == "posix" and path.stat().st_mode & 0o022:
        raise ValueError(f"{label} must not be group- or world-writable")
    return path


def _canonical_json(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _tree_attestation(root: Path) -> dict[str, Any]:
    root = _private_real_directory(root, label="retained deployment")
    digest = hashlib.sha256()
    entries = 0
    total_bytes = 0
    excluded = {SEAL_RELATIVE_PATH.as_posix()}
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        if relative in excluded:
            continue
        stat_result = path.lstat()
        mode = stat_result.st_mode & 0o7777
        ownership = {"uid": int(stat_result.st_uid), "gid": int(stat_result.st_gid)}
        if path.is_symlink():
            record = {"path": relative, "type": "symlink", "mode": mode, **ownership, "target": os.readlink(path)}
        elif path.is_dir():
            record = {"path": relative, "type": "directory", "mode": mode, **ownership}
        elif path.is_file():
            file_digest = hashlib.sha256()
            size = 0
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    size += len(chunk)
                    file_digest.update(chunk)
            total_bytes += size
            record = {
                "path": relative,
                "type": "file",
                "mode": mode,
                **ownership,
                "size": size,
                "sha256": file_digest.hexdigest(),
            }
        else:
            raise ValueError(f"retained deployment contains an unsupported filesystem entry: {relative}")
        digest.update(_canonical_json(record) + b"\n")
        entries += 1
    return {"tree_sha256": digest.hexdigest(), "entry_count": entries, "total_file_bytes": total_bytes}


def seal_retained_deployment(target: Path, retained: Path) -> dict[str, Any]:
    target = absolute_path(target)
    retained = absolute_path(retained)
    if retained.parent != target.parent or not retained.name.startswith(f".{target.name}.previous-"):
        raise ValueError("retained deployment path is outside the managed history boundary")
    identity = load_deployment_identity(retained, expected_target_name=target.name)
    key = current_history_key(target, create=True)
    first_attestation = _tree_attestation(retained)
    second_attestation = _tree_attestation(retained)
    if first_attestation != second_attestation:
        raise RuntimeError("retained deployment changed while its history seal was being created")
    payload = {
        "format": SEAL_FORMAT,
        "installation_id": identity.installation_id,
        "target_name": identity.target_name,
        "identity_sha256": hashlib.sha256(_canonical_json(asdict(identity))).hexdigest(),
        "sealed_at": _utc_now(),
        "history_key_id": key.key_id,
        "history_key_fingerprint": key.fingerprint,
        **second_attestation,
    }
    payload["hmac_sha256"] = hmac.new(key.key, _canonical_json(payload), hashlib.sha256).hexdigest()
    path = retained / SEAL_RELATIVE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + f".tmp-{secrets.token_hex(8)}")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    temporary.chmod(0o600)
    os.replace(temporary, path)
    return payload


def verify_retained_deployment(target: Path, retained: Path) -> dict[str, Any]:
    target = absolute_path(target)
    retained = absolute_path(retained)
    if retained.parent != target.parent or not retained.name.startswith(f".{target.name}.previous-"):
        raise ValueError("retained deployment path is outside the managed history boundary")
    identity = load_deployment_identity(retained, expected_target_name=target.name)
    path = retained / SEAL_RELATIVE_PATH
    if path.is_symlink() or not path.is_file():
        raise ValueError("deployment history seal is missing or unsafe")
    seal_stat = path.stat()
    if seal_stat.st_nlink != 1 or seal_stat.st_size > MAX_SEAL_BYTES:
        raise ValueError("deployment history seal is missing or unsafe")
    if os.name == "posix" and seal_stat.st_mode & 0o077:
        raise ValueError("deployment history seal permissions are too broad")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or payload.get("format") != SEAL_FORMAT:
        raise ValueError("deployment history seal format is invalid")
    signature = str(payload.pop("hmac_sha256", "")).lower()
    key = resolve_history_key(
        target,
        key_id=str(payload.get("history_key_id") or "") or None,
        fingerprint=str(payload.get("history_key_fingerprint") or "") or None,
        require_current=True,
    )
    expected = hmac.new(key.key, _canonical_json(payload), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        raise ValueError("deployment history seal authentication failed")
    if payload.get("installation_id") != identity.installation_id or payload.get("target_name") != identity.target_name:
        raise ValueError("deployment history seal identity does not match")
    identity_digest = hashlib.sha256(_canonical_json(asdict(identity))).hexdigest()
    if payload.get("identity_sha256") != identity_digest:
        raise ValueError("deployment history identity was modified after sealing")
    current = _tree_attestation(retained)
    for field in ("tree_sha256", "entry_count", "total_file_bytes"):
        if payload.get(field) != current[field]:
            raise ValueError("retained deployment content was modified after sealing")
    return {**payload, "hmac_sha256": signature}


def write_deployment_identity(
    root: Path,
    *,
    application_version: str,
    schema_version: int,
    release_kit_sha256: str,
    release_public_key_fingerprint: str,
    target_name: str,
    installation_id: str | None = None,
    installed_at: str | None = None,
) -> DeploymentIdentity:
    root = _private_real_directory(root, label="deployment root")
    if not application_version.strip():
        raise ValueError("deployment application version is required")
    if int(schema_version) <= 0:
        raise ValueError("deployment schema version must be positive")
    release_sha = release_kit_sha256.strip().lower()
    if not _SHA256_RE.fullmatch(release_sha):
        raise ValueError("deployment release-kit SHA-256 is invalid")
    fingerprint = release_public_key_fingerprint.strip().lower()
    if not fingerprint.startswith("sha256:") or not _SHA256_RE.fullmatch(fingerprint[7:]):
        raise ValueError("deployment release public-key fingerprint is invalid")
    if not target_name or Path(target_name).name != target_name or target_name in {".", ".."}:
        raise ValueError("deployment target name is invalid")
    identity = DeploymentIdentity(
        format=IDENTITY_FORMAT,
        installation_id=(installation_id or secrets.token_hex(16)).strip().lower(),
        application_version=application_version.strip(),
        schema_version=int(schema_version),
        release_kit_sha256=release_sha,
        release_public_key_fingerprint=fingerprint,
        installed_at=(installed_at or _utc_now()).strip(),
        target_name=target_name,
    )
    if not _INSTALLATION_ID_RE.fullmatch(identity.installation_id):
        raise ValueError("deployment installation ID is invalid")
    _parse_timestamp(identity.installed_at)
    path = root / IDENTITY_RELATIVE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(asdict(identity), ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    path.chmod(0o600)
    return identity


def load_deployment_identity(root: Path, *, expected_target_name: str | None = None) -> DeploymentIdentity:
    root = _private_real_directory(root, label="deployment root")
    path = root / IDENTITY_RELATIVE_PATH
    if path.is_symlink() or not path.is_file():
        raise ValueError("deployment identity marker is missing or unsafe")
    if path.stat().st_size > MAX_IDENTITY_BYTES:
        raise ValueError("deployment identity marker exceeds the size limit")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("deployment identity marker must contain a JSON object")
    identity = DeploymentIdentity(
        format=str(payload.get("format") or ""),
        installation_id=str(payload.get("installation_id") or "").lower(),
        application_version=str(payload.get("application_version") or ""),
        schema_version=int(payload.get("schema_version") or 0),
        release_kit_sha256=str(payload.get("release_kit_sha256") or "").lower(),
        release_public_key_fingerprint=str(payload.get("release_public_key_fingerprint") or "").lower(),
        installed_at=str(payload.get("installed_at") or ""),
        target_name=str(payload.get("target_name") or ""),
    )
    if identity.format != IDENTITY_FORMAT:
        raise ValueError("unexpected deployment identity format")
    if not _INSTALLATION_ID_RE.fullmatch(identity.installation_id):
        raise ValueError("deployment identity installation ID is invalid")
    if not identity.application_version.strip() or identity.schema_version <= 0:
        raise ValueError("deployment identity version metadata is invalid")
    if not _SHA256_RE.fullmatch(identity.release_kit_sha256):
        raise ValueError("deployment identity release-kit SHA-256 is invalid")
    if not identity.release_public_key_fingerprint.startswith("sha256:") or not _SHA256_RE.fullmatch(
        identity.release_public_key_fingerprint[7:]
    ):
        raise ValueError("deployment identity public-key fingerprint is invalid")
    _parse_timestamp(identity.installed_at)
    if Path(identity.target_name).name != identity.target_name or identity.target_name in {"", ".", ".."}:
        raise ValueError("deployment identity target name is invalid")
    if expected_target_name is not None and identity.target_name != expected_target_name:
        raise ValueError("deployment identity target name does not match the managed deployment")
    return identity


def deployment_history_key_status(target: Path) -> dict[str, Any]:
    return history_keyring_status(target)


def inventory_retained_deployments(target: Path) -> dict[str, Any]:
    target = absolute_path(target)
    parent = _private_real_directory(target.parent, label="deployment target parent")
    prefix = f".{target.name}.previous-"
    retained: list[RetainedDeployment] = []
    unmanaged: list[dict[str, str]] = []
    for candidate in sorted(parent.iterdir(), key=lambda item: item.name):
        if not candidate.name.startswith(prefix):
            continue
        try:
            identity = load_deployment_identity(candidate, expected_target_name=target.name)
            verify_retained_deployment(target, candidate)
            retained.append(RetainedDeployment(path=absolute_path(candidate), identity=identity))
        except Exception as exc:
            unmanaged.append({"path": str(candidate), "reason": str(exc)})
    retained.sort(
        key=lambda item: (_parse_timestamp(item.identity.installed_at), item.identity.installation_id),
        reverse=True,
    )
    try:
        audit = verify_deployment_audit_log(target)
    except Exception as exc:
        audit = {"path": str(audit_log_path(target)), "valid": False, "error": str(exc)}
    return {
        "target": str(target),
        "history_key": deployment_history_key_status(target),
        "audit": audit,
        "managed": [
            {
                "path": str(item.path),
                **asdict(item.identity),
            }
            for item in retained
        ],
        "unmanaged": unmanaged,
    }


def select_retained_deployment(target: Path, installation_id: str) -> RetainedDeployment:
    wanted = installation_id.strip().lower()
    if not _INSTALLATION_ID_RE.fullmatch(wanted):
        raise ValueError("rollback installation ID is invalid")
    inventory = inventory_retained_deployments(target)
    matches = [item for item in inventory["managed"] if item["installation_id"] == wanted]
    if len(matches) != 1:
        raise ValueError(f"expected exactly one retained deployment for installation ID {wanted}; found {len(matches)}")
    item = matches[0]
    path = Path(item["path"])
    identity = load_deployment_identity(path, expected_target_name=absolute_path(target).name)
    return RetainedDeployment(path=path, identity=identity)


def adopt_retained_deployment(target: Path, installation_id: str) -> dict[str, Any]:
    """Establish a new local integrity baseline for an unsealed legacy history.

    Adoption cannot prove that the retained tree was historically untampered;
    it only authenticates the exact filesystem state reviewed by the operator.
    Existing invalid seals are never overwritten.
    """

    target = absolute_path(target)
    wanted = installation_id.strip().lower()
    if not _INSTALLATION_ID_RE.fullmatch(wanted):
        raise ValueError("deployment adoption installation ID is invalid")
    parent = _private_real_directory(target.parent, label="deployment target parent")
    prefix = f".{target.name}.previous-"
    matches: list[Path] = []
    for candidate in parent.iterdir():
        if not candidate.name.startswith(prefix):
            continue
        try:
            identity = load_deployment_identity(candidate, expected_target_name=target.name)
        except Exception:
            continue
        if identity.installation_id == wanted:
            matches.append(candidate)
    if len(matches) != 1:
        raise ValueError(f"expected exactly one legacy retained deployment for installation ID {wanted}; found {len(matches)}")
    candidate = absolute_path(matches[0])
    seal_path = candidate / SEAL_RELATIVE_PATH
    if os.path.lexists(seal_path):
        raise ValueError("legacy adoption refuses to overwrite an existing deployment history seal")
    append_deployment_audit_event(
        target,
        action="adopt_started",
        details={"installation_id": wanted, "path": str(candidate)},
    )
    seal = seal_retained_deployment(target, candidate)
    audit = append_deployment_audit_event(
        target,
        action="adopt_completed",
        details={"installation_id": wanted, "path": str(candidate), "tree_sha256": seal["tree_sha256"]},
    )
    return {
        "target": str(target),
        "adopted_path": str(candidate),
        "installation_id": wanted,
        "seal": seal,
        "audit": audit["audit"],
        "notice": "Adoption establishes trust in the current filesystem state; it does not prove historical integrity.",
    }


def prune_retained_deployments(target: Path, *, keep: int, dry_run: bool = False) -> dict[str, Any]:
    if int(keep) < 1:
        raise ValueError("at least one retained deployment must be preserved")
    inventory = inventory_retained_deployments(target)
    managed = inventory["managed"]
    removable = managed[int(keep):]
    removed: list[str] = []
    if removable and not dry_run:
        append_deployment_audit_event(
            target,
            action="prune_started",
            details={
                "keep": int(keep),
                "installation_ids": [item["installation_id"] for item in removable],
                "paths": [item["path"] for item in removable],
            },
        )
    try:
        for item in removable:
            path = Path(item["path"])
            verify_retained_deployment(target, path)
            if not dry_run:
                remove_tree(path)
            removed.append(str(path))
    except BaseException as exc:
        if not dry_run:
            try:
                append_deployment_audit_event(
                    target,
                    action="prune_failed",
                    details={"keep": int(keep), "removed": removed, "error": str(exc)},
                )
            except Exception:
                pass
        raise
    audit = None
    if removable and not dry_run:
        audit = append_deployment_audit_event(
            target,
            action="prune_completed",
            details={"keep": int(keep), "removed": removed},
        )["audit"]
    return {
        **inventory,
        "keep": int(keep),
        "dry_run": bool(dry_run),
        "removed": removed,
        "remaining_managed": len(managed) - len(removable),
        "audit_after": audit,
    }


def backup_deployment_history_keyring(target: Path, destination: Path) -> dict[str, Any]:
    target = absolute_path(target)
    report = backup_history_keyring(target, destination)
    audit = append_deployment_audit_event(
        target,
        action="history_keyring_backup_created",
        details={"backup_name": absolute_path(destination).name, "sha256": report["sha256"], "bytes": report["bytes"]},
    )
    return {**report, "audit": audit["audit"]}


def _restore_raw_file(path: Path, raw: bytes | None) -> None:
    if raw is None:
        path.unlink(missing_ok=True)
        return
    temporary = path.with_name(path.name + f".tmp-{secrets.token_hex(8)}")
    temporary.write_bytes(raw)
    temporary.chmod(0o600)
    os.replace(temporary, path)


def restore_deployment_history_keyring(target: Path, source: Path) -> dict[str, Any]:
    target = absolute_path(target)
    key_path = history_keyring_path(target)
    previous_keyring = key_path.read_bytes() if key_path.exists() else None
    audit_path = audit_log_path(target)
    previous_audit = audit_path.read_bytes() if audit_path.exists() else None
    candidate = read_history_keyring_backup(source)
    try:
        restore_history_keyring(target, candidate)
        parent = _private_real_directory(target.parent, label="deployment target parent")
        prefix = f".{target.name}.previous-"
        verified = 0
        for retained in parent.iterdir():
            if retained.name.startswith(prefix) and (retained / SEAL_RELATIVE_PATH).is_file():
                verify_retained_deployment(target, retained)
                verified += 1
        audit_before = verify_deployment_audit_log(target)
        audit = append_deployment_audit_event(
            target,
            action="history_keyring_restored",
            details={
                "backup_name": absolute_path(source).name,
                "backup_sha256": hashlib.sha256(candidate).hexdigest(),
                "verified_retained_deployments": verified,
                "verified_previous_audit_events": audit_before["events"],
            },
        )
    except BaseException:
        _restore_raw_file(key_path, previous_keyring)
        _restore_raw_file(audit_path, previous_audit)
        raise
    return {
        "target": str(target),
        "source": str(absolute_path(source)),
        "sha256": hashlib.sha256(candidate).hexdigest(),
        "verified_retained_deployments": verified,
        "audit": audit["audit"],
    }


def rotate_deployment_history_key(target: Path) -> dict[str, Any]:
    """Rotate the history key and atomically reseal every managed deployment."""

    target = absolute_path(target)
    inventory = inventory_retained_deployments(target)
    managed_paths = [Path(item["path"]) for item in inventory["managed"]]
    key_path = history_keyring_path(target)
    previous_keyring = key_path.read_bytes() if key_path.exists() else None
    seal_backups = {path: (path / SEAL_RELATIVE_PATH).read_bytes() for path in managed_paths}
    audit_path = audit_log_path(target)
    previous_audit = audit_path.read_bytes() if audit_path.exists() else None
    rotation = rotate_history_keyring(target)
    rotation.pop("previous_bytes", None)
    resealed: list[dict[str, Any]] = []
    try:
        for path in managed_paths:
            seal = seal_retained_deployment(target, path)
            resealed.append({"path": str(path), "installation_id": seal["installation_id"], "tree_sha256": seal["tree_sha256"]})
        audit = append_deployment_audit_event(
            target,
            action="history_key_rotated",
            details={**rotation, "resealed": resealed},
        )
    except BaseException:
        if previous_keyring is None:
            key_path.unlink(missing_ok=True)
        else:
            restore_history_keyring(target, previous_keyring)
        for path, raw in seal_backups.items():
            seal_path = path / SEAL_RELATIVE_PATH
            seal_path.write_bytes(raw)
            seal_path.chmod(0o600)
        if previous_audit is None:
            audit_path.unlink(missing_ok=True)
        else:
            audit_path.write_bytes(previous_audit)
            audit_path.chmod(0o600)
        raise
    return {
        "target": str(target),
        **rotation,
        "resealed": resealed,
        "audit": audit["audit"],
    }

def rollback_to_retained_deployment(
    target: Path,
    *,
    installation_id: str,
    verify: Callable[[Path, Path, DeploymentIdentity], T],
) -> dict[str, Any]:
    target = absolute_path(target)
    candidate = select_retained_deployment(target, installation_id)
    previous_root = candidate.path
    append_deployment_audit_event(
        target,
        action="rollback_started",
        details={
            "installation_id": candidate.identity.installation_id,
            "version": candidate.identity.application_version,
            "path": str(candidate.path),
        },
    )
    try:
        activation = activate_staged_directory(
        candidate.path,
        target,
        allow_replace=True,
        verify=lambda activated_target: verify(activated_target, previous_root, candidate.identity),
            restore_staging_on_failure=True,
        )
        if activation.previous_target is not None:
            try:
                seal_retained_deployment(target, activation.previous_target)
            except BaseException:
                failed_candidate = candidate.path
                os.replace(target, failed_candidate)
                os.replace(activation.previous_target, target)
                raise
        audit = append_deployment_audit_event(
            target,
            action="rollback_completed",
            details={
                "installation_id": candidate.identity.installation_id,
                "version": candidate.identity.application_version,
                "previous_deployment": str(activation.previous_target) if activation.previous_target else None,
            },
        )
    except BaseException as exc:
        try:
            append_deployment_audit_event(
                target,
                action="rollback_failed",
                details={"installation_id": candidate.identity.installation_id, "error": str(exc)},
            )
        except Exception:
            pass
        raise
    return {
        "target": str(activation.target),
        "rolled_back_installation_id": candidate.identity.installation_id,
        "rolled_back_version": candidate.identity.application_version,
        "previous_deployment": str(activation.previous_target) if activation.previous_target else None,
        "verification": activation.verification,
        "audit": audit["audit"],
    }
