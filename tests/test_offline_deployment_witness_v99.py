from __future__ import annotations

import json
from pathlib import Path

import pytest


from scripts.manage_offline_deployments import (
    generate_history_witness_key,
    issue_history_witness,
    verify_history_witness,
)
from scripts.offline_deployment_audit import (
    append_deployment_audit_event,
    audit_log_path,
    verify_deployment_audit_checkpoint,
)
from scripts.offline_deployment_keyring import history_keyring_path
from scripts.offline_deployment_witness import (
    generate_witness_keypair,
    issue_witness_receipt,
    verify_witness_receipt,
)


def _private(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(0o700)
    return path


def _keypair(parent: Path, *, key_id: str = "witness-a") -> tuple[Path, Path]:
    parent = _private(parent)
    private = parent / "witness-private.json"
    public = parent / "witness-public.json"
    result = generate_witness_keypair(
        private_key_path=private,
        public_key_path=public,
        key_id=key_id,
    )
    assert result["key_id"] == key_id
    assert private.stat().st_mode & 0o077 == 0
    return private, public


@pytest.mark.skipif(
    __import__("os").name != "posix",
    reason="Windows validation: POSIX filesystem semantics",
)
def test_witness_receipt_accepts_equal_and_newer_local_history(tmp_path: Path) -> None:
    parent = _private(tmp_path / "parent")
    target = parent / "deployment"
    private, public = _keypair(parent)
    append_deployment_audit_event(target, action="created", details={"version": 1})
    receipt = parent / "checkpoint.json"
    issued = issue_witness_receipt(target, private_key_path=private, output_path=receipt)

    equal = verify_witness_receipt(target, receipt_path=receipt, public_key_path=public)
    assert equal["witness_sequence"] == 1
    assert equal["local_sequence"] == 1
    assert equal["local_events_after_witness"] == 0

    append_deployment_audit_event(target, action="updated", details={"version": 2})
    newer = verify_witness_receipt(target, receipt_path=receipt, public_key_path=public)
    assert newer["local_sequence"] == 2
    assert newer["local_events_after_witness"] == 1
    assert issued["witness_public_key_fingerprint"] == newer["witness_public_key_fingerprint"]


@pytest.mark.skipif(
    __import__("os").name != "posix",
    reason="Windows validation: POSIX filesystem semantics",
)
def test_external_witness_detects_consistent_keyring_and_audit_rollback(tmp_path: Path) -> None:
    parent = _private(tmp_path / "parent")
    target = parent / "deployment"
    private, public = _keypair(parent)
    append_deployment_audit_event(target, action="first", details={})
    old_keyring = history_keyring_path(target).read_bytes()
    old_audit = audit_log_path(target).read_bytes()
    append_deployment_audit_event(target, action="second", details={})
    receipt = parent / "latest-checkpoint.json"
    issue_witness_receipt(target, private_key_path=private, output_path=receipt)

    history_keyring_path(target).write_bytes(old_keyring)
    history_keyring_path(target).chmod(0o600)
    audit_log_path(target).write_bytes(old_audit)
    audit_log_path(target).chmod(0o600)

    with pytest.raises(ValueError, match="older than the external witness"):
        verify_witness_receipt(target, receipt_path=receipt, public_key_path=public)


@pytest.mark.skipif(
    __import__("os").name != "posix",
    reason="Windows validation: POSIX filesystem semantics",
)
def test_witness_rejects_changed_prefix_even_when_local_log_is_long_enough(tmp_path: Path) -> None:
    parent = _private(tmp_path / "parent")
    target = parent / "deployment"
    private, public = _keypair(parent)
    append_deployment_audit_event(target, action="first", details={})
    receipt = parent / "checkpoint.json"
    issued = issue_witness_receipt(target, private_key_path=private, output_path=receipt)

    with pytest.raises(ValueError, match="does not match the external witness"):
        verify_deployment_audit_checkpoint(
            target,
            sequence=issued["audit_sequence"],
            head_sha256="f" * 64,
        )
    assert verify_witness_receipt(target, receipt_path=receipt, public_key_path=public)["valid"] is True


@pytest.mark.skipif(
    __import__("os").name != "posix",
    reason="Windows validation: POSIX filesystem semantics",
)
def test_witness_rejects_tampered_receipt_wrong_key_and_target(tmp_path: Path) -> None:
    parent = _private(tmp_path / "parent")
    target = parent / "deployment"
    private, public = _keypair(parent, key_id="trusted")
    append_deployment_audit_event(target, action="first", details={})
    receipt = parent / "checkpoint.json"
    issue_witness_receipt(target, private_key_path=private, output_path=receipt)

    payload = json.loads(receipt.read_text(encoding="utf-8"))
    payload["audit_sequence"] = 0
    tampered = parent / "tampered.json"
    tampered.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="signature verification failed"):
        verify_witness_receipt(target, receipt_path=tampered, public_key_path=public)

    _, wrong_public = _keypair(parent / "other", key_id="wrong")
    with pytest.raises(ValueError, match="trusted public key"):
        verify_witness_receipt(target, receipt_path=receipt, public_key_path=wrong_public)

    other_target = parent / "other-deployment"
    append_deployment_audit_event(other_target, action="first", details={})
    with pytest.raises(ValueError, match="target does not match"):
        verify_witness_receipt(other_target, receipt_path=receipt, public_key_path=public)


@pytest.mark.skipif(
    __import__("os").name != "posix",
    reason="Windows validation: POSIX filesystem semantics",
)
def test_private_witness_key_permissions_are_enforced(tmp_path: Path) -> None:
    parent = _private(tmp_path / "parent")
    target = parent / "deployment"
    private, _ = _keypair(parent)
    append_deployment_audit_event(target, action="first", details={})
    private.chmod(0o644)
    with pytest.raises(ValueError, match="permissions are too broad"):
        issue_witness_receipt(target, private_key_path=private, output_path=parent / "receipt.json")



@pytest.mark.skipif(
    __import__("os").name != "posix",
    reason="Windows validation: POSIX filesystem semantics",
)
def test_trusted_public_key_must_not_be_group_or_world_writable(tmp_path: Path) -> None:
    parent = _private(tmp_path / "parent")
    target = parent / "deployment"
    private, public = _keypair(parent)
    append_deployment_audit_event(target, action="first", details={})
    receipt = parent / "receipt.json"
    issue_witness_receipt(target, private_key_path=private, output_path=receipt)
    public.chmod(0o666)
    with pytest.raises(ValueError, match="trusted witness public key permissions"):
        verify_witness_receipt(target, receipt_path=receipt, public_key_path=public)

@pytest.mark.skipif(
    __import__("os").name != "posix",
    reason="Windows validation: POSIX filesystem semantics",
)
def test_manager_wrappers_generate_issue_and_verify(tmp_path: Path) -> None:
    parent = _private(tmp_path / "parent")
    target = parent / "deployment"
    private = parent / "private.json"
    public = parent / "public.json"
    generated = generate_history_witness_key(
        private_key=private,
        public_key=public,
        key_id="operations-witness",
    )
    append_deployment_audit_event(target, action="first", details={})
    receipt = parent / "receipt.json"
    issued = issue_history_witness(target, private_key=private, output=receipt)
    verified = verify_history_witness(target, public_key=public, receipt=receipt)
    assert generated["key_id"] == "operations-witness"
    assert issued["receipt_id"] == verified["receipt_id"]
    assert verified["valid"] is True


@pytest.mark.skipif(
    __import__("os").name != "posix",
    reason="Windows validation: POSIX filesystem semantics",
)
def test_manager_cli_generates_and_verifies_witness_receipt(tmp_path: Path) -> None:
    import subprocess
    import sys

    parent = _private(tmp_path / "parent")
    target = parent / "deployment"
    private = parent / "private.json"
    public = parent / "public.json"
    receipt = parent / "receipt.json"
    root = Path(__file__).resolve().parents[1]

    generated = subprocess.run(
        [
            sys.executable,
            "scripts/manage_offline_deployments.py",
            "generate-witness-key",
            "--private-key",
            str(private),
            "--public-key",
            str(public),
            "--key-id",
            "cli-witness",
            "--confirm",
            "GENERATE-HISTORY-WITNESS",
        ],
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
        timeout=20,
    )
    assert generated.returncode == 0, generated.stdout
    append_deployment_audit_event(target, action="first", details={})

    issued = subprocess.run(
        [
            sys.executable,
            "scripts/manage_offline_deployments.py",
            "issue-witness",
            "--target",
            str(target),
            "--private-key",
            str(private),
            "--output",
            str(receipt),
            "--confirm",
            "ISSUE-HISTORY-WITNESS",
        ],
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
        timeout=20,
    )
    assert issued.returncode == 0, issued.stdout

    verified = subprocess.run(
        [
            sys.executable,
            "scripts/manage_offline_deployments.py",
            "verify-witness",
            "--target",
            str(target),
            "--public-key",
            str(public),
            "--receipt",
            str(receipt),
        ],
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
        timeout=20,
    )
    assert verified.returncode == 0, verified.stdout
    assert json.loads(verified.stdout)["valid"] is True
