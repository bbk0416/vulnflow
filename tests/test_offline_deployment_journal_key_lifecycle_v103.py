from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

import pytest


from scripts.offline_deployment_audit import append_deployment_audit_event, audit_log_path, verify_deployment_audit_log
from scripts.offline_deployment_keyring import history_keyring_path
from scripts.offline_deployment_preflight import preflight_deployment_history
from scripts.offline_deployment_recovery import (
    _load_or_create_recovery_journal_key,
    _prepare_transaction,
    backup_recovery_journal_key,
    recovery_journal_key_path,
    recovery_journal_key_status,
    restore_recovery_journal_key,
    rotate_recovery_journal_key,
)
from scripts.offline_deployment_witness import generate_witness_keypair, issue_witness_receipt


def _private(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(0o700)
    return path


def _baseline(target: Path) -> tuple[bytes, bytes]:
    append_deployment_audit_event(target, action="baseline", details={})
    return history_keyring_path(target).read_bytes(), audit_log_path(target).read_bytes()


def _witness(parent: Path, target: Path, *, receipt_name: str = "minimum-witness.json") -> tuple[Path, Path, Path]:
    root = _private(parent / "witness")
    private = root / "private.json"
    public = root / "public.json"
    generate_witness_keypair(
        private_key_path=private,
        public_key_path=public,
        key_id="journal-key-witness",
    )
    receipt = root / receipt_name
    issue_witness_receipt(target, private_key_path=private, output_path=receipt)
    return private, public, receipt


def _break_live(target: Path) -> None:
    history_keyring_path(target).write_bytes(b"broken-keyring")
    history_keyring_path(target).chmod(0o600)
    audit_log_path(target).write_bytes(b"broken-audit\n")
    audit_log_path(target).chmod(0o600)


@pytest.mark.skipif(
    __import__("os").name != "posix",
    reason="Windows validation: POSIX filesystem semantics",
)
def test_journal_key_backup_and_status_are_bound_to_target(tmp_path: Path) -> None:
    parent = _private(tmp_path / "parent")
    backup_parent = _private(tmp_path / "backup")
    target = parent / "deployment"
    key = _load_or_create_recovery_journal_key(target)
    append_deployment_audit_event(target, action="baseline", details={})
    private, _, _ = _witness(tmp_path, target)
    output = backup_parent / "journal-key.json"

    result = backup_recovery_journal_key(target, output=output, witness_private_key=private)
    payload = json.loads(output.read_text(encoding="utf-8"))
    status = recovery_journal_key_status(target)

    assert output.stat().st_mode & 0o077 == 0
    assert payload["target_name"] == target.name
    assert payload["key_hex"] == key.hex()
    assert payload["fingerprint"] == result["fingerprint"] == status["fingerprint"]
    assert status["available"] is True
    assert status["pending_transactions"] == 0
    assert verify_deployment_audit_log(target)["last_event"]["action"] == "recovery_journal_key_backup_created"


@pytest.mark.skipif(
    __import__("os").name != "posix",
    reason="Windows validation: POSIX filesystem semantics",
)
def test_backup_is_removed_when_audit_recording_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import scripts.offline_deployment_recovery as recovery

    parent = _private(tmp_path / "parent")
    backup_parent = _private(tmp_path / "backup")
    target = parent / "deployment"
    _load_or_create_recovery_journal_key(target)
    append_deployment_audit_event(target, action="baseline", details={})
    private, _, _ = _witness(tmp_path, target)
    output = backup_parent / "journal-key.json"

    def fail_audit(*args, **kwargs):
        raise RuntimeError("injected journal backup audit failure")

    monkeypatch.setattr(recovery, "append_deployment_audit_event", fail_audit)
    with pytest.raises(RuntimeError, match="injected"):
        backup_recovery_journal_key(target, output=output, witness_private_key=private)
    assert not output.exists()


@pytest.mark.skipif(
    __import__("os").name != "posix",
    reason="Windows validation: POSIX filesystem semantics",
)
def test_restore_key_authenticates_pending_journal_before_install(tmp_path: Path) -> None:
    parent = _private(tmp_path / "parent")
    backup_parent = _private(tmp_path / "backup")
    target = parent / "deployment"
    original_key = _load_or_create_recovery_journal_key(target)
    output = backup_parent / "journal-key.json"
    append_deployment_audit_event(target, action="key-ready", details={})
    private, public, _ = _witness(tmp_path, target)
    backup_recovery_journal_key(target, output=output, witness_private_key=private)
    minimum = backup_parent / "minimum-witness.json"
    issue_witness_receipt(target, private_key_path=private, output_path=minimum)
    previous_keyring, previous_audit = _baseline(target)
    transaction = _prepare_transaction(target, previous_keyring, previous_audit)
    _break_live(target)
    recovery_journal_key_path(target).unlink()

    restored = restore_recovery_journal_key(
        target,
        source=output,
        trusted_witness_public_key=public,
        minimum_witness_receipt=minimum,
    )
    assert restored["authenticated_transactions"] == 1
    assert recovery_journal_key_path(target).read_bytes() == original_key
    assert transaction.is_dir()

    preflight = preflight_deployment_history(target)
    assert preflight["recovered"] is True
    assert history_keyring_path(target).read_bytes() == previous_keyring
    assert audit_log_path(target).read_bytes() == previous_audit
    assert not transaction.exists()


@pytest.mark.skipif(
    __import__("os").name != "posix",
    reason="Windows validation: POSIX filesystem semantics",
)
def test_wrong_backup_is_rejected_before_key_replacement(tmp_path: Path) -> None:
    parent = _private(tmp_path / "parent")
    backup_parent = _private(tmp_path / "backup")
    target = parent / "deployment"
    _load_or_create_recovery_journal_key(target)
    old_backup = backup_parent / "old-key.json"
    append_deployment_audit_event(target, action="baseline", details={})
    private, public, _ = _witness(tmp_path, target)
    backup_recovery_journal_key(target, output=old_backup, witness_private_key=private)
    rotate_recovery_journal_key(target)
    minimum = backup_parent / "minimum-witness.json"
    issue_witness_receipt(target, private_key_path=private, output_path=minimum)
    current_key = recovery_journal_key_path(target).read_bytes()
    previous_keyring, previous_audit = _baseline(target)
    transaction = _prepare_transaction(target, previous_keyring, previous_audit)

    with pytest.raises(ValueError, match="fingerprint|authentication"):
        restore_recovery_journal_key(
            target,
            source=old_backup,
            trusted_witness_public_key=public,
            minimum_witness_receipt=minimum,
        )
    assert recovery_journal_key_path(target).read_bytes() == current_key
    assert transaction.is_dir()


@pytest.mark.skipif(
    __import__("os").name != "posix",
    reason="Windows validation: POSIX filesystem semantics",
)
def test_restore_refuses_silent_key_rollback_without_pending_journal(tmp_path: Path) -> None:
    parent = _private(tmp_path / "parent")
    backup_parent = _private(tmp_path / "backup")
    target = parent / "deployment"
    _load_or_create_recovery_journal_key(target)
    append_deployment_audit_event(target, action="baseline", details={})
    old_backup = backup_parent / "old-key.json"
    private, public, _ = _witness(tmp_path, target)
    backup_recovery_journal_key(target, output=old_backup, witness_private_key=private)
    rotate_recovery_journal_key(target)
    minimum = backup_parent / "minimum-witness.json"
    issue_witness_receipt(target, private_key_path=private, output_path=minimum)
    current = recovery_journal_key_path(target).read_bytes()

    with pytest.raises(ValueError, match="generation"):
        restore_recovery_journal_key(
            target,
            source=old_backup,
            trusted_witness_public_key=public,
            minimum_witness_receipt=minimum,
        )
    assert recovery_journal_key_path(target).read_bytes() == current


@pytest.mark.skipif(
    __import__("os").name != "posix",
    reason="Windows validation: POSIX filesystem semantics",
)
def test_restore_missing_key_without_pending_journal_is_audited(tmp_path: Path) -> None:
    parent = _private(tmp_path / "parent")
    backup_parent = _private(tmp_path / "backup")
    target = parent / "deployment"
    key = _load_or_create_recovery_journal_key(target)
    append_deployment_audit_event(target, action="baseline", details={})
    output = backup_parent / "journal-key.json"
    private, public, _ = _witness(tmp_path, target)
    backup_recovery_journal_key(target, output=output, witness_private_key=private)
    minimum = backup_parent / "minimum-witness.json"
    issue_witness_receipt(target, private_key_path=private, output_path=minimum)
    recovery_journal_key_path(target).unlink()

    restored = restore_recovery_journal_key(
        target,
        source=output,
        trusted_witness_public_key=public,
        minimum_witness_receipt=minimum,
    )
    assert restored["changed"] is True
    assert restored["authenticated_transactions"] == 0
    assert recovery_journal_key_path(target).read_bytes() == key
    assert verify_deployment_audit_log(target)["last_event"]["action"] == "recovery_journal_key_restored"


@pytest.mark.skipif(
    __import__("os").name != "posix",
    reason="Windows validation: POSIX filesystem semantics",
)
def test_rotation_is_blocked_while_transaction_is_pending(tmp_path: Path) -> None:
    parent = _private(tmp_path / "parent")
    target = parent / "deployment"
    previous_keyring, previous_audit = _baseline(target)
    _prepare_transaction(target, previous_keyring, previous_audit)
    original = recovery_journal_key_path(target).read_bytes()

    with pytest.raises(RuntimeError, match="pending"):
        rotate_recovery_journal_key(target)
    assert recovery_journal_key_path(target).read_bytes() == original


@pytest.mark.skipif(
    __import__("os").name != "posix",
    reason="Windows validation: POSIX filesystem semantics",
)
def test_rotation_rolls_back_key_when_audit_recording_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import scripts.offline_deployment_recovery as recovery

    parent = _private(tmp_path / "parent")
    target = parent / "deployment"
    original = _load_or_create_recovery_journal_key(target)
    append_deployment_audit_event(target, action="baseline", details={})

    def fail_audit(*args, **kwargs):
        raise RuntimeError("injected journal rotation audit failure")

    monkeypatch.setattr(recovery, "append_deployment_audit_event", fail_audit)
    with pytest.raises(RuntimeError, match="injected"):
        rotate_recovery_journal_key(target)
    assert recovery_journal_key_path(target).read_bytes() == original


@pytest.mark.skipif(
    __import__("os").name != "posix",
    reason="Windows validation: POSIX filesystem semantics",
)
def test_rotation_changes_key_and_records_fingerprints(tmp_path: Path) -> None:
    parent = _private(tmp_path / "parent")
    target = parent / "deployment"
    original = _load_or_create_recovery_journal_key(target)
    append_deployment_audit_event(target, action="baseline", details={})

    result = rotate_recovery_journal_key(target)
    replacement = recovery_journal_key_path(target).read_bytes()
    event = verify_deployment_audit_log(target)["last_event"]

    assert replacement != original
    assert result["previous_fingerprint"] != result["current_fingerprint"]
    assert event["action"] == "recovery_journal_key_rotated"
    assert event["details"]["current_fingerprint"] == result["current_fingerprint"]


@pytest.mark.skipif(
    __import__("os").name != "posix",
    reason="Windows validation: POSIX filesystem semantics",
)
def test_manager_cli_exposes_journal_key_lifecycle(tmp_path: Path) -> None:
    parent = _private(tmp_path / "parent")
    backup_parent = _private(tmp_path / "backup")
    target = parent / "deployment"
    _load_or_create_recovery_journal_key(target)
    append_deployment_audit_event(target, action="baseline", details={})
    private, _, _ = _witness(tmp_path, target)
    backup = backup_parent / "journal-key.json"
    root = Path(__file__).resolve().parents[1]

    commands = [
        ["journal-key-status", "--target", str(target)],
        [
            "backup-journal-key", "--target", str(target), "--output", str(backup),
            "--witness-private-key", str(private),
            "--confirm", "BACKUP-RECOVERY-JOURNAL-KEY",
        ],
        [
            "rotate-journal-key", "--target", str(target),
            "--confirm", "ROTATE-RECOVERY-JOURNAL-KEY",
        ],
    ]
    outputs = []
    for command in commands:
        completed = subprocess.run(
            [sys.executable, "scripts/manage_offline_deployments.py", *command],
            cwd=root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        assert completed.returncode == 0, completed.stdout
        outputs.append(json.loads(completed.stdout))

    assert outputs[0]["available"] is True
    assert outputs[1]["backup"] == str(backup.resolve())
    assert outputs[2]["previous_fingerprint"] != outputs[2]["current_fingerprint"]
