from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys

import pytest


from scripts.offline_deployment_audit import append_deployment_audit_event
from scripts.offline_deployment_recovery import (
    JOURNAL_KEY_BACKUP_FORMAT,
    LEGACY_JOURNAL_KEY_BACKUP_FORMAT,
    _load_or_create_recovery_journal_key,
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


def _witness(parent: Path, *, key_id: str = "journal-witness") -> tuple[Path, Path]:
    root = _private(parent)
    private = root / "private.json"
    public = root / "public.json"
    generate_witness_keypair(
        private_key_path=private,
        public_key_path=public,
        key_id=key_id,
    )
    return private, public


def _receipt(target: Path, private: Path, output: Path) -> Path:
    issue_witness_receipt(target, private_key_path=private, output_path=output)
    return output


def _baseline(tmp_path: Path) -> tuple[Path, Path, Path, Path, Path]:
    parent = _private(tmp_path / "parent")
    backups = _private(tmp_path / "backups")
    target = parent / "deployment"
    _load_or_create_recovery_journal_key(target)
    append_deployment_audit_event(target, action="baseline", details={})
    private, public = _witness(tmp_path / "witness")
    backup = backups / "journal-key.json"
    backup_recovery_journal_key(target, output=backup, witness_private_key=private)
    minimum = _receipt(target, private, backups / "minimum-witness.json")
    return target, backup, private, public, minimum


@pytest.mark.skipif(
    __import__("os").name != "posix",
    reason="Windows validation: POSIX filesystem semantics",
)
def test_signed_backup_binds_generation_target_and_audit_checkpoint(tmp_path: Path) -> None:
    target, backup, _, _, _ = _baseline(tmp_path)
    payload = json.loads(backup.read_text(encoding="utf-8"))
    status = recovery_journal_key_status(target)

    assert payload["format"] == JOURNAL_KEY_BACKUP_FORMAT
    assert payload["target_name"] == target.name
    assert payload["generation"] == status["generation"] == 1
    assert payload["audit_sequence"] >= 1
    assert len(payload["audit_head_sha256"]) == 64
    assert payload["witness_key_id"] == "journal-witness"
    assert str(payload["witness_public_key_fingerprint"]).startswith("sha256:")
    assert payload["ed25519_signature_base64"]


@pytest.mark.skipif(
    __import__("os").name != "posix",
    reason="Windows validation: POSIX filesystem semantics",
)
def test_forged_key_and_recomputed_fingerprint_fails_before_install(tmp_path: Path) -> None:
    target, backup, _, public, minimum = _baseline(tmp_path)
    payload = json.loads(backup.read_text(encoding="utf-8"))
    forged_key = secrets.token_bytes(32)
    payload["key_hex"] = forged_key.hex()
    payload["fingerprint"] = "sha256:" + hashlib.sha256(forged_key).hexdigest()
    forged = backup.with_name("forged.json")
    forged.write_text(json.dumps(payload), encoding="utf-8")
    forged.chmod(0o600)
    recovery_journal_key_path(target).unlink()

    with pytest.raises(ValueError, match="signature verification failed"):
        restore_recovery_journal_key(
            target,
            source=forged,
            trusted_witness_public_key=public,
            minimum_witness_receipt=minimum,
        )
    assert not recovery_journal_key_path(target).exists()


@pytest.mark.parametrize("field,value", [
    ("generation", 999),
    ("target_name", "other-deployment"),
    ("audit_head_sha256", "f" * 64),
])
@pytest.mark.skipif(
    __import__("os").name != "posix",
    reason="Windows validation: POSIX filesystem semantics",
)
def test_signed_backup_metadata_tampering_is_rejected(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    target, backup, _, public, minimum = _baseline(tmp_path)
    payload = json.loads(backup.read_text(encoding="utf-8"))
    payload[field] = value
    tampered = backup.with_name(f"tampered-{field}.json")
    tampered.write_text(json.dumps(payload), encoding="utf-8")
    tampered.chmod(0o600)

    with pytest.raises(ValueError, match="signature verification failed"):
        restore_recovery_journal_key(
            target,
            source=tampered,
            trusted_witness_public_key=public,
            minimum_witness_receipt=minimum,
        )


@pytest.mark.skipif(
    __import__("os").name != "posix",
    reason="Windows validation: POSIX filesystem semantics",
)
def test_backup_signed_by_another_witness_is_rejected(tmp_path: Path) -> None:
    target, backup, _, _, minimum = _baseline(tmp_path)
    _, wrong_public = _witness(tmp_path / "wrong-witness", key_id="wrong")

    with pytest.raises(ValueError, match="trusted public key"):
        restore_recovery_journal_key(
            target,
            source=backup,
            trusted_witness_public_key=wrong_public,
            minimum_witness_receipt=minimum,
        )


@pytest.mark.skipif(
    __import__("os").name != "posix",
    reason="Windows validation: POSIX filesystem semantics",
)
def test_old_backup_is_rejected_by_newer_external_minimum_generation(tmp_path: Path) -> None:
    target, backup, private, public, _ = _baseline(tmp_path)
    rotate_recovery_journal_key(target)
    minimum = _receipt(target, private, backup.with_name("generation-2-witness.json"))
    recovery_journal_key_path(target).unlink()

    with pytest.raises(ValueError, match="external minimum witness generation"):
        restore_recovery_journal_key(
            target,
            source=backup,
            trusted_witness_public_key=public,
            minimum_witness_receipt=minimum,
        )
    assert not recovery_journal_key_path(target).exists()


@pytest.mark.skipif(
    __import__("os").name != "posix",
    reason="Windows validation: POSIX filesystem semantics",
)
def test_current_audit_generation_rejects_old_backup_even_with_old_minimum(tmp_path: Path) -> None:
    target, backup, _, public, old_minimum = _baseline(tmp_path)
    rotate_recovery_journal_key(target)
    recovery_journal_key_path(target).unlink()

    with pytest.raises(ValueError, match="authenticated audit generation"):
        restore_recovery_journal_key(
            target,
            source=backup,
            trusted_witness_public_key=public,
            minimum_witness_receipt=old_minimum,
        )
    assert not recovery_journal_key_path(target).exists()


@pytest.mark.skipif(
    __import__("os").name != "posix",
    reason="Windows validation: POSIX filesystem semantics",
)
def test_current_generation_backup_restores_missing_key(tmp_path: Path) -> None:
    target, _, private, public, _ = _baseline(tmp_path)
    rotate_recovery_journal_key(target)
    backup = _private(tmp_path / "generation-2") / "journal-key.json"
    result = backup_recovery_journal_key(target, output=backup, witness_private_key=private)
    minimum = _receipt(target, private, backup.with_name("minimum.json"))
    expected = recovery_journal_key_path(target).read_bytes()
    recovery_journal_key_path(target).unlink()

    restored = restore_recovery_journal_key(
        target,
        source=backup,
        trusted_witness_public_key=public,
        minimum_witness_receipt=minimum,
    )
    assert result["generation"] == restored["generation"] == 2
    assert recovery_journal_key_path(target).read_bytes() == expected
    assert recovery_journal_key_status(target)["generation"] == 2


@pytest.mark.skipif(
    __import__("os").name != "posix",
    reason="Windows validation: POSIX filesystem semantics",
)
def test_unsigned_v1_backup_is_rejected(tmp_path: Path) -> None:
    target, _, _, public, minimum = _baseline(tmp_path)
    key = recovery_journal_key_path(target).read_bytes()
    legacy = _private(tmp_path / "legacy") / "journal-key.json"
    legacy.write_text(json.dumps({
        "format": LEGACY_JOURNAL_KEY_BACKUP_FORMAT,
        "target_name": target.name,
        "created_at": "2026-08-04T00:00:00Z",
        "key_hex": key.hex(),
        "fingerprint": "sha256:" + hashlib.sha256(key).hexdigest(),
    }), encoding="utf-8")
    legacy.chmod(0o600)

    with pytest.raises(ValueError, match="unsigned v1"):
        restore_recovery_journal_key(
            target,
            source=legacy,
            trusted_witness_public_key=public,
            minimum_witness_receipt=minimum,
        )


@pytest.mark.skipif(
    __import__("os").name != "posix",
    reason="Windows validation: POSIX filesystem semantics",
)
def test_legacy_audit_restore_rollback_is_detected_by_status(tmp_path: Path) -> None:
    target, backup, _, _, _ = _baseline(tmp_path)
    old_key = bytes.fromhex(json.loads(backup.read_text(encoding="utf-8"))["key_hex"])
    rotate_recovery_journal_key(target)
    path = recovery_journal_key_path(target)
    path.write_bytes(old_key)
    path.chmod(0o600)
    append_deployment_audit_event(
        target,
        action="recovery_journal_key_restored",
        details={"journal_key_fingerprint": "sha256:" + hashlib.sha256(old_key).hexdigest()},
    )

    status = recovery_journal_key_status(target)
    assert status["available"] is False
    assert "generation rollback" in status["error"]


@pytest.mark.skipif(
    __import__("os").name != "posix",
    reason="Windows validation: POSIX filesystem semantics",
)
def test_manager_cli_restores_signed_backup_with_generation_floor(tmp_path: Path) -> None:
    target, backup, _, public, minimum = _baseline(tmp_path)
    recovery_journal_key_path(target).unlink()
    root = Path(__file__).resolve().parents[1]
    completed = subprocess.run(
        [
            sys.executable,
            "scripts/manage_offline_deployments.py",
            "restore-journal-key",
            "--target", str(target),
            "--source", str(backup),
            "--trusted-witness-public-key", str(public),
            "--minimum-witness-receipt", str(minimum),
            "--confirm", "RESTORE-RECOVERY-JOURNAL-KEY",
        ],
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
        timeout=20,
    )
    assert completed.returncode == 0, completed.stdout
    payload = json.loads(completed.stdout)
    assert payload["changed"] is True
    assert payload["generation"] == 1
    assert recovery_journal_key_path(target).exists()
