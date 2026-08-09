from __future__ import annotations

import io
import json
from pathlib import Path
import subprocess
import sys
import zipfile

import pytest


from scripts.offline_deployment_audit import append_deployment_audit_event, audit_log_path, verify_deployment_audit_log
from scripts.offline_deployment_keyring import history_keyring_path
from scripts.offline_deployment_recovery import (
    _prepare_transaction,
    _recover_interrupted_transaction,
    create_history_recovery_bundle,
    restore_history_recovery_bundle,
    verify_history_recovery_bundle,
)
from scripts.offline_deployment_witness import generate_witness_keypair, issue_witness_receipt


def _private(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(0o700)
    return path


def _witness(parent: Path, target: Path) -> tuple[Path, Path, Path]:
    private = parent / "witness-private.json"
    public = parent / "witness-public.json"
    receipt = parent / "witness-receipt.json"
    generate_witness_keypair(private_key_path=private, public_key_path=public, key_id="recovery-witness")
    issue_witness_receipt(target, private_key_path=private, output_path=receipt)
    return private, public, receipt


def _bundle(parent: Path, target: Path, public: Path, receipt: Path) -> Path:
    output = parent / "history-recovery.zip"
    result = create_history_recovery_bundle(
        target,
        trusted_public_key=public,
        witness_receipt=receipt,
        output=output,
    )
    assert result["bundle_id"]
    assert output.stat().st_mode & 0o077 == 0
    return output


@pytest.mark.skipif(
    __import__("os").name != "posix",
    reason="Windows validation: POSIX filesystem semantics",
)
def test_recovery_bundle_verifies_keyring_audit_and_external_witness(tmp_path: Path) -> None:
    parent = _private(tmp_path / "parent")
    target = parent / "deployment"
    append_deployment_audit_event(target, action="baseline", details={"version": 1})
    _, public, receipt = _witness(parent, target)
    bundle = _bundle(parent, target, public, receipt)

    verified = verify_history_recovery_bundle(
        target,
        bundle=bundle,
        trusted_public_key=public,
        minimum_witness_receipt=receipt,
    )
    assert verified["valid"] is True
    assert verified["audit"]["last_sequence"] == 1
    assert verified["minimum_witness"]["witness_sequence"] == 1


@pytest.mark.skipif(
    __import__("os").name != "posix",
    reason="Windows validation: POSIX filesystem semantics",
)
def test_recovery_bundle_restores_keyring_and_audit_together(tmp_path: Path) -> None:
    parent = _private(tmp_path / "parent")
    target = parent / "deployment"
    append_deployment_audit_event(target, action="baseline", details={})
    _, public, receipt = _witness(parent, target)
    bundle = _bundle(parent, target, public, receipt)

    history_keyring_path(target).unlink()
    audit_log_path(target).unlink()
    restored = restore_history_recovery_bundle(
        target,
        bundle=bundle,
        trusted_public_key=public,
        minimum_witness_receipt=receipt,
    )
    audit = verify_deployment_audit_log(target)
    assert restored["restored_snapshot_sequence"] == 1
    assert restored["final_audit_sequence"] == 2
    assert audit["last_event"]["action"] == "history_recovery_bundle_restored"


@pytest.mark.skipif(
    __import__("os").name != "posix",
    reason="Windows validation: POSIX filesystem semantics",
)
def test_recovery_rejects_bundle_older_than_external_minimum_witness(tmp_path: Path) -> None:
    parent = _private(tmp_path / "parent")
    target = parent / "deployment"
    append_deployment_audit_event(target, action="first", details={})
    private, public, first_receipt = _witness(parent, target)
    bundle = _bundle(parent, target, public, first_receipt)
    append_deployment_audit_event(target, action="second", details={})
    latest_receipt = parent / "latest-receipt.json"
    issue_witness_receipt(target, private_key_path=private, output_path=latest_receipt)

    with pytest.raises(ValueError, match="older than the external witness"):
        verify_history_recovery_bundle(
            target,
            bundle=bundle,
            trusted_public_key=public,
            minimum_witness_receipt=latest_receipt,
        )


@pytest.mark.skipif(
    __import__("os").name != "posix",
    reason="Windows validation: POSIX filesystem semantics",
)
def test_recovery_rejects_rollback_below_valid_current_history(tmp_path: Path) -> None:
    parent = _private(tmp_path / "parent")
    target = parent / "deployment"
    append_deployment_audit_event(target, action="first", details={})
    _, public, receipt = _witness(parent, target)
    bundle = _bundle(parent, target, public, receipt)
    current_key = history_keyring_path(target).read_bytes()
    current_audit = audit_log_path(target).read_bytes()

    with pytest.raises(ValueError, match="older than the current local audit"):
        restore_history_recovery_bundle(
            target,
            bundle=bundle,
            trusted_public_key=public,
            minimum_witness_receipt=receipt,
        )
    assert history_keyring_path(target).read_bytes() == current_key
    assert audit_log_path(target).read_bytes() == current_audit


@pytest.mark.skipif(
    __import__("os").name != "posix",
    reason="Windows validation: POSIX filesystem semantics",
)
def test_recovery_bundle_tampering_and_wrong_public_key_are_rejected(tmp_path: Path) -> None:
    parent = _private(tmp_path / "parent")
    target = parent / "deployment"
    append_deployment_audit_event(target, action="baseline", details={})
    _, public, receipt = _witness(parent, target)
    bundle = _bundle(parent, target, public, receipt)

    with zipfile.ZipFile(bundle) as archive:
        members = {name: archive.read(name) for name in archive.namelist()}
    members["history-audit.jsonl"] += b"tamper\n"
    damaged = parent / "damaged.zip"
    with zipfile.ZipFile(damaged, "w") as archive:
        for name, raw in members.items():
            archive.writestr(name, raw)
    damaged.chmod(0o600)
    with pytest.raises(ValueError, match="checksum mismatch"):
        verify_history_recovery_bundle(
            target,
            bundle=damaged,
            trusted_public_key=public,
            minimum_witness_receipt=receipt,
        )

    other_private = parent / "other-private.json"
    wrong_public = parent / "other-public.json"
    generate_witness_keypair(private_key_path=other_private, public_key_path=wrong_public, key_id="other")
    with pytest.raises(ValueError, match="does not match the trusted public key"):
        verify_history_recovery_bundle(
            target,
            bundle=bundle,
            trusted_public_key=wrong_public,
            minimum_witness_receipt=receipt,
        )


@pytest.mark.skipif(
    __import__("os").name != "posix",
    reason="Windows validation: POSIX filesystem semantics",
)
def test_restore_failure_rolls_back_both_live_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import scripts.offline_deployment_recovery as recovery

    parent = _private(tmp_path / "parent")
    target = parent / "deployment"
    append_deployment_audit_event(target, action="baseline", details={})
    _, public, receipt = _witness(parent, target)
    bundle = _bundle(parent, target, public, receipt)
    live_key = history_keyring_path(target).read_bytes()
    live_audit = audit_log_path(target).read_bytes()
    history_keyring_path(target).unlink()
    audit_log_path(target).unlink()

    def fail_append(*args, **kwargs):
        raise RuntimeError("injected recovery audit failure")

    monkeypatch.setattr(recovery, "append_deployment_audit_event", fail_append)
    with pytest.raises(RuntimeError, match="injected"):
        restore_history_recovery_bundle(
            target,
            bundle=bundle,
            trusted_public_key=public,
            minimum_witness_receipt=receipt,
        )
    assert not history_keyring_path(target).exists()
    assert not audit_log_path(target).exists()
    assert not list(parent.glob(".deployment.deployment-history.recovery-*"))
    assert live_key and live_audit


@pytest.mark.skipif(
    __import__("os").name != "posix",
    reason="Windows validation: POSIX filesystem semantics",
)
def test_interrupted_recovery_journal_restores_previous_pair(tmp_path: Path) -> None:
    parent = _private(tmp_path / "parent")
    target = parent / "deployment"
    append_deployment_audit_event(target, action="baseline", details={})
    previous_key = history_keyring_path(target).read_bytes()
    previous_audit = audit_log_path(target).read_bytes()
    transaction = _prepare_transaction(target, previous_key, previous_audit)
    history_keyring_path(target).write_bytes(b"broken")
    history_keyring_path(target).chmod(0o600)
    audit_log_path(target).write_bytes(b"broken\n")
    audit_log_path(target).chmod(0o600)

    recovered = _recover_interrupted_transaction(target)
    assert recovered and recovered["action"] == "restored_interrupted_recovery"
    assert history_keyring_path(target).read_bytes() == previous_key
    assert audit_log_path(target).read_bytes() == previous_audit
    assert not transaction.exists()
    assert verify_deployment_audit_log(target)["valid"] is True


@pytest.mark.skipif(
    __import__("os").name != "posix",
    reason="Windows validation: POSIX filesystem semantics",
)
def test_manager_cli_create_verify_and_restore_recovery_bundle(tmp_path: Path) -> None:
    parent = _private(tmp_path / "parent")
    target = parent / "deployment"
    append_deployment_audit_event(target, action="baseline", details={})
    _, public, receipt = _witness(parent, target)
    bundle = parent / "recovery.zip"
    root = Path(__file__).resolve().parents[1]

    commands = [
        [
            "create-recovery-bundle", "--target", str(target), "--public-key", str(public),
            "--witness-receipt", str(receipt), "--output", str(bundle),
            "--confirm", "CREATE-HISTORY-RECOVERY-BUNDLE",
        ],
        [
            "verify-recovery-bundle", "--target", str(target), "--bundle", str(bundle),
            "--public-key", str(public), "--minimum-witness", str(receipt),
        ],
    ]
    for command in commands:
        completed = subprocess.run(
            [sys.executable, "scripts/manage_offline_deployments.py", *command],
            cwd=root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=30,
            check=False,
        )
        assert completed.returncode == 0, completed.stdout
        assert json.loads(completed.stdout)

    history_keyring_path(target).unlink()
    audit_log_path(target).unlink()
    restored = subprocess.run(
        [
            sys.executable, "scripts/manage_offline_deployments.py", "restore-recovery-bundle",
            "--target", str(target), "--bundle", str(bundle), "--public-key", str(public),
            "--minimum-witness", str(receipt), "--confirm", "RESTORE-HISTORY-RECOVERY-BUNDLE",
        ],
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=30,
        check=False,
    )
    assert restored.returncode == 0, restored.stdout
    assert json.loads(restored.stdout)["final_audit_sequence"] == 2


@pytest.mark.skipif(
    __import__("os").name != "posix",
    reason="Windows validation: POSIX filesystem semantics",
)
def test_bundle_creation_failure_removes_unaudited_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import scripts.offline_deployment_recovery as recovery

    parent = _private(tmp_path / "parent")
    target = parent / "deployment"
    append_deployment_audit_event(target, action="baseline", details={})
    _, public, receipt = _witness(parent, target)
    output = parent / "failed-recovery.zip"

    def fail_append(*args, **kwargs):
        raise RuntimeError("injected bundle audit failure")

    monkeypatch.setattr(recovery, "append_deployment_audit_event", fail_append)
    with pytest.raises(RuntimeError, match="injected"):
        create_history_recovery_bundle(
            target,
            trusted_public_key=public,
            witness_receipt=receipt,
            output=output,
        )
    assert not output.exists()
