from __future__ import annotations

import json
from pathlib import Path

import pytest


from scripts.offline_deployment_audit import append_deployment_audit_event, audit_log_path, verify_deployment_audit_log
from scripts.offline_deployment_history import (
    SEAL_RELATIVE_PATH,
    inventory_retained_deployments,
    prune_retained_deployments,
    rotate_deployment_history_key,
    seal_retained_deployment,
    verify_retained_deployment,
    write_deployment_identity,
)
from scripts.offline_deployment_keyring import (
    history_audit_checkpoint,
    history_keyring_path,
    history_keyring_status,
    update_history_audit_checkpoint,
)

SHA_A = "a" * 64
FINGERPRINT = "sha256:" + "c" * 64


def _private(path: Path) -> Path:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.chmod(0o700)
    return path


def _candidate(parent: Path, suffix: str, installation_id: str, installed_at: str) -> Path:
    root = _private(parent / f".deployment.previous-{suffix}")
    write_deployment_identity(
        root,
        application_version="72.0.50",
        schema_version=46,
        release_kit_sha256=SHA_A,
        release_public_key_fingerprint=FINGERPRINT,
        target_name="deployment",
        installation_id=installation_id,
        installed_at=installed_at,
    )
    (root / "state.txt").write_text(suffix, encoding="utf-8")
    return root


@pytest.mark.skipif(
    __import__("os").name != "posix",
    reason="Windows validation: POSIX filesystem semantics",
)
def test_rotation_upgrades_legacy_key_reseals_and_preserves_audit_chain(tmp_path: Path) -> None:
    parent = _private(tmp_path / "parent")
    target = _private(parent / "deployment")
    first = _candidate(parent, "one", "1" * 32, "2026-08-03T10:00:00Z")
    second = _candidate(parent, "two", "2" * 32, "2026-08-03T11:00:00Z")
    seal_retained_deployment(target, first)
    seal_retained_deployment(target, second)
    legacy = history_keyring_status(target)
    assert legacy["format"] == "legacy-single-key"
    append_deployment_audit_event(target, action="before_rotation", details={"ok": True})

    before = history_keyring_status(target)
    assert before["audit_sequence"] == 1
    result = rotate_deployment_history_key(target)

    after = history_keyring_status(target)
    assert result["previous_key_id"] == before["current_key_id"]
    assert result["current_key_id"] == after["current_key_id"]
    assert after["format"] != "legacy-single-key"
    assert after["keys_total"] == 2
    assert after["retired_keys"] == 1
    assert len(result["resealed"]) == 2
    assert verify_retained_deployment(target, first)["history_key_id"] == after["current_key_id"]
    assert verify_retained_deployment(target, second)["history_key_id"] == after["current_key_id"]
    audit = verify_deployment_audit_log(target)
    assert audit["events"] == 2
    assert audit["last_event"]["action"] == "history_key_rotated"


@pytest.mark.skipif(
    __import__("os").name != "posix",
    reason="Windows validation: POSIX filesystem semantics",
)
def test_old_seal_is_rejected_after_rotation(tmp_path: Path) -> None:
    parent = _private(tmp_path / "parent")
    target = _private(parent / "deployment")
    candidate = _candidate(parent, "old", "3" * 32, "2026-08-03T10:00:00Z")
    seal_retained_deployment(target, candidate)
    seal_path = candidate / SEAL_RELATIVE_PATH
    old_seal = seal_path.read_bytes()

    rotate_deployment_history_key(target)
    seal_path.write_bytes(old_seal)
    seal_path.chmod(0o600)
    with pytest.raises(ValueError, match="current key"):
        verify_retained_deployment(target, candidate)


@pytest.mark.skipif(
    __import__("os").name != "posix",
    reason="Windows validation: POSIX filesystem semantics",
)
def test_rotation_failure_restores_keyring_seals_and_audit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import scripts.offline_deployment_history as history

    parent = _private(tmp_path / "parent")
    target = _private(parent / "deployment")
    first = _candidate(parent, "one", "4" * 32, "2026-08-03T10:00:00Z")
    second = _candidate(parent, "two", "5" * 32, "2026-08-03T11:00:00Z")
    seal_retained_deployment(target, first)
    seal_retained_deployment(target, second)
    append_deployment_audit_event(target, action="baseline", details={})
    key_before = history_keyring_path(target).read_bytes()
    audit_before = audit_log_path(target).read_bytes()
    seals_before = {path: (path / SEAL_RELATIVE_PATH).read_bytes() for path in (first, second)}
    original = history.seal_retained_deployment
    calls = 0

    def fail_second(target_path: Path, retained_path: Path):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError("injected reseal failure")
        return original(target_path, retained_path)

    monkeypatch.setattr(history, "seal_retained_deployment", fail_second)
    with pytest.raises(RuntimeError, match="injected"):
        rotate_deployment_history_key(target)

    assert history_keyring_path(target).read_bytes() == key_before
    assert audit_log_path(target).read_bytes() == audit_before
    for path, raw in seals_before.items():
        assert (path / SEAL_RELATIVE_PATH).read_bytes() == raw
        assert verify_retained_deployment(target, path)


@pytest.mark.skipif(
    __import__("os").name != "posix",
    reason="Windows validation: POSIX filesystem semantics",
)
def test_tampered_audit_chain_is_rejected(tmp_path: Path) -> None:
    parent = _private(tmp_path / "parent")
    target = _private(parent / "deployment")
    append_deployment_audit_event(target, action="one", details={"value": 1})
    append_deployment_audit_event(target, action="two", details={"value": 2})
    path = audit_log_path(target)
    lines = path.read_text(encoding="utf-8").splitlines()
    payload = json.loads(lines[0])
    payload["details"]["value"] = 999
    lines[0] = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    path.chmod(0o600)

    with pytest.raises(ValueError, match="authentication failed"):
        verify_deployment_audit_log(target)


@pytest.mark.skipif(
    __import__("os").name != "posix",
    reason="Windows validation: POSIX filesystem semantics",
)
def test_retired_key_is_required_to_verify_pre_rotation_audit(tmp_path: Path) -> None:
    parent = _private(tmp_path / "parent")
    target = _private(parent / "deployment")
    append_deployment_audit_event(target, action="before", details={})
    rotate_deployment_history_key(target)
    keyring = history_keyring_path(target)
    payload = json.loads(keyring.read_text(encoding="utf-8"))
    payload["keys"] = [item for item in payload["keys"] if item["status"] == "current"]
    keyring.write_text(json.dumps(payload), encoding="utf-8")
    keyring.chmod(0o600)

    with pytest.raises(ValueError, match="does not match"):
        verify_deployment_audit_log(target)


@pytest.mark.skipif(
    __import__("os").name != "posix",
    reason="Windows validation: POSIX filesystem semantics",
)
def test_prune_records_intent_and_completion(tmp_path: Path) -> None:
    parent = _private(tmp_path / "parent")
    target = _private(parent / "deployment")
    for index in range(3):
        candidate = _candidate(
            parent,
            str(index),
            f"{index + 1:032x}",
            f"2026-08-03T1{index}:00:00Z",
        )
        seal_retained_deployment(target, candidate)

    result = prune_retained_deployments(target, keep=1)
    assert len(result["removed"]) == 2
    audit = verify_deployment_audit_log(target)
    assert audit["events"] == 2
    assert audit["last_event"]["action"] == "prune_completed"
    inventory = inventory_retained_deployments(target)
    assert len(inventory["managed"]) == 1
    assert inventory["audit"]["valid"] is True


@pytest.mark.skipif(
    __import__("os").name != "posix",
    reason="Windows validation: POSIX filesystem semantics",
)
def test_private_keyring_backup_restores_after_key_loss(tmp_path: Path) -> None:
    from scripts.offline_deployment_history import (
        backup_deployment_history_keyring,
        restore_deployment_history_keyring,
    )

    parent = _private(tmp_path / "parent")
    target = _private(parent / "deployment")
    candidate = _candidate(parent, "backup", "6" * 32, "2026-08-03T10:00:00Z")
    seal_retained_deployment(target, candidate)
    append_deployment_audit_event(target, action="baseline", details={})
    rotate_deployment_history_key(target)
    backup_dir = _private(tmp_path / "offline-secret-backup")
    backup = backup_dir / "history-keyring.backup"
    report = backup_deployment_history_keyring(target, backup)
    assert report["sha256"]
    assert backup.stat().st_mode & 0o077 == 0

    history_keyring_path(target).unlink()
    with pytest.raises(ValueError, match="signing key is missing"):
        verify_retained_deployment(target, candidate)
    restored = restore_deployment_history_keyring(target, backup)
    assert restored["verified_retained_deployments"] == 1
    assert verify_retained_deployment(target, candidate)
    assert verify_deployment_audit_log(target)["last_event"]["action"] == "history_keyring_restored"


@pytest.mark.skipif(
    __import__("os").name != "posix",
    reason="Windows validation: POSIX filesystem semantics",
)
def test_incompatible_keyring_backup_is_rejected_without_replacing_current(tmp_path: Path) -> None:
    from scripts.offline_deployment_history import (
        backup_deployment_history_keyring,
        restore_deployment_history_keyring,
    )

    parent = _private(tmp_path / "parent")
    target = _private(parent / "deployment")
    candidate = _candidate(parent, "restore", "7" * 32, "2026-08-03T10:00:00Z")
    seal_retained_deployment(target, candidate)
    backup_dir = _private(tmp_path / "backup")
    old_backup = backup_dir / "old.keyring"
    backup_deployment_history_keyring(target, old_backup)
    rotate_deployment_history_key(target)
    current_bytes = history_keyring_path(target).read_bytes()
    current_audit = audit_log_path(target).read_bytes()

    with pytest.raises(ValueError, match="current key|does not match"):
        restore_deployment_history_keyring(target, old_backup)
    assert history_keyring_path(target).read_bytes() == current_bytes
    assert audit_log_path(target).read_bytes() == current_audit
    assert verify_retained_deployment(target, candidate)


@pytest.mark.skipif(
    __import__("os").name != "posix",
    reason="Windows validation: POSIX filesystem semantics",
)
def test_concurrent_audit_appends_keep_contiguous_chain(tmp_path: Path) -> None:
    from concurrent.futures import ThreadPoolExecutor

    parent = _private(tmp_path / "parent")
    target = _private(parent / "deployment")

    def write(index: int) -> None:
        append_deployment_audit_event(target, action="parallel", details={"index": index})

    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(write, range(24)))
    audit = verify_deployment_audit_log(target)
    assert audit["events"] == 24
    assert audit["last_sequence"] == 24


@pytest.mark.skipif(
    __import__("os").name != "posix",
    reason="Windows validation: POSIX filesystem semantics",
)
def test_deleted_audit_log_is_detected_by_keyring_checkpoint(tmp_path: Path) -> None:
    parent = _private(tmp_path / "parent")
    target = _private(parent / "deployment")
    append_deployment_audit_event(target, action="one", details={})
    audit_log_path(target).unlink()
    with pytest.raises(ValueError, match="truncated below"):
        verify_deployment_audit_log(target)


@pytest.mark.skipif(
    __import__("os").name != "posix",
    reason="Windows validation: POSIX filesystem semantics",
)
def test_valid_audit_prefix_truncation_is_detected(tmp_path: Path) -> None:
    parent = _private(tmp_path / "parent")
    target = _private(parent / "deployment")
    append_deployment_audit_event(target, action="one", details={})
    append_deployment_audit_event(target, action="two", details={})
    path = audit_log_path(target)
    first = path.read_text(encoding="utf-8").splitlines()[0]
    path.write_text(first + "\n", encoding="utf-8")
    path.chmod(0o600)
    with pytest.raises(ValueError, match="truncated below"):
        verify_deployment_audit_log(target)


@pytest.mark.skipif(
    __import__("os").name != "posix",
    reason="Windows validation: POSIX filesystem semantics",
)
def test_audit_checkpoint_cannot_change_head_at_same_sequence(tmp_path: Path) -> None:
    parent = _private(tmp_path / "parent")
    target = _private(parent / "deployment")
    append_deployment_audit_event(target, action="one", details={})
    sequence, head = history_audit_checkpoint(target)
    assert sequence == 1
    assert len(head) == 64

    with pytest.raises(ValueError, match="must not change"):
        update_history_audit_checkpoint(target, sequence=sequence, head_sha256="f" * 64)
    assert history_audit_checkpoint(target) == (sequence, head)
