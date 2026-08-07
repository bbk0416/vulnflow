from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import secrets

import pytest


from scripts.offline_deployment_audit import append_deployment_audit_event, audit_log_path
from scripts.offline_deployment_keyring import history_keyring_path
from scripts.offline_deployment_preflight import preflight_deployment_history
from scripts.offline_deployment_recovery import (
    _INTEGRITY_TRANSACTION_FORMAT,
    _load_or_create_recovery_journal_key,
    _prepare_transaction,
    inspect_interrupted_history_recovery,
    recover_interrupted_history_recovery,
    recovery_journal_key_path,
)


def _private(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(0o700)
    return path


def _baseline(target: Path) -> tuple[bytes, bytes]:
    append_deployment_audit_event(target, action="baseline", details={})
    return history_keyring_path(target).read_bytes(), audit_log_path(target).read_bytes()


def _break_live(target: Path) -> None:
    history_keyring_path(target).write_bytes(b"broken-keyring")
    history_keyring_path(target).chmod(0o600)
    audit_log_path(target).write_bytes(b"broken-audit\n")
    audit_log_path(target).chmod(0o600)


def _manifest(transaction: Path) -> dict[str, object]:
    return json.loads((transaction / "transaction.json").read_text(encoding="utf-8"))


def _write_manifest(transaction: Path, payload: dict[str, object]) -> None:
    path = transaction / "transaction.json"
    path.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    path.chmod(0o600)


@pytest.mark.skipif(
    __import__("os").name != "posix",
    reason="Windows validation: POSIX filesystem semantics",
)
def test_v3_journal_is_hmac_authenticated_and_reported(tmp_path: Path) -> None:
    parent = _private(tmp_path / "parent")
    target = parent / "deployment"
    key, audit = _baseline(target)
    transaction = _prepare_transaction(target, key, audit)

    payload = _manifest(transaction)
    assert payload["format"].endswith("/3")
    assert str(payload["journal_key_fingerprint"]).startswith("sha256:")
    assert len(str(payload["journal_hmac_sha256"])) == 64
    status = inspect_interrupted_history_recovery(target)
    assert status["transactions"][0]["authenticated"] is True
    assert status["transactions"][0]["journal_key_fingerprint"] == payload["journal_key_fingerprint"]
    assert recovery_journal_key_path(target).stat().st_size == 32


@pytest.mark.skipif(
    __import__("os").name != "posix",
    reason="Windows validation: POSIX filesystem semantics",
)
def test_manifest_state_tamper_blocks_preflight_before_live_restore(tmp_path: Path) -> None:
    parent = _private(tmp_path / "parent")
    target = parent / "deployment"
    key, audit = _baseline(target)
    transaction = _prepare_transaction(target, key, audit)
    payload = _manifest(transaction)
    payload["state"] = "committed"
    _write_manifest(transaction, payload)
    _break_live(target)

    with pytest.raises(ValueError, match="authentication failed"):
        preflight_deployment_history(target)
    assert transaction.is_dir()
    assert audit_log_path(target).read_bytes() == b"broken-audit\n"


@pytest.mark.skipif(
    __import__("os").name != "posix",
    reason="Windows validation: POSIX filesystem semantics",
)
def test_recomputed_backup_inventory_without_hmac_is_rejected(tmp_path: Path) -> None:
    parent = _private(tmp_path / "parent")
    target = parent / "deployment"
    key, audit = _baseline(target)
    transaction = _prepare_transaction(target, key, audit)
    forged_audit = audit + b"forged"
    (transaction / "previous-audit.jsonl").write_bytes(forged_audit)
    (transaction / "previous-audit.jsonl").chmod(0o600)
    payload = _manifest(transaction)
    files = payload["previous_files"]
    assert isinstance(files, dict)
    files["previous-audit.jsonl"] = {
        "bytes": len(forged_audit),
        "sha256": hashlib.sha256(forged_audit).hexdigest(),
    }
    _write_manifest(transaction, payload)
    _break_live(target)

    with pytest.raises(ValueError, match="authentication failed"):
        recover_interrupted_history_recovery(target)
    assert audit_log_path(target).read_bytes() == b"broken-audit\n"


@pytest.mark.skipif(
    __import__("os").name != "posix",
    reason="Windows validation: POSIX filesystem semantics",
)
def test_missing_or_replaced_journal_key_blocks_automatic_recovery(tmp_path: Path) -> None:
    parent = _private(tmp_path / "parent")
    target = parent / "deployment"
    key, audit = _baseline(target)
    transaction = _prepare_transaction(target, key, audit)
    journal_key = recovery_journal_key_path(target)
    journal_key.unlink()

    with pytest.raises(ValueError, match="authentication key is missing"):
        preflight_deployment_history(target)
    assert transaction.is_dir()

    journal_key.write_bytes(secrets.token_bytes(32))
    journal_key.chmod(0o600)
    with pytest.raises(ValueError, match="fingerprint does not match"):
        preflight_deployment_history(target)
    assert transaction.is_dir()


def test_journal_key_permissions_are_fail_closed(tmp_path: Path) -> None:
    if os.name != "posix":
        pytest.skip("POSIX permission boundary")
    parent = _private(tmp_path / "parent")
    target = parent / "deployment"
    key, audit = _baseline(target)
    transaction = _prepare_transaction(target, key, audit)
    recovery_journal_key_path(target).chmod(0o644)

    with pytest.raises(ValueError, match="permissions are too broad"):
        preflight_deployment_history(target)
    assert transaction.is_dir()


@pytest.mark.skipif(
    __import__("os").name != "posix",
    reason="Windows validation: POSIX filesystem semantics",
)
def test_integrity_only_v2_journal_requires_explicit_legacy_recovery(tmp_path: Path) -> None:
    parent = _private(tmp_path / "parent")
    target = parent / "deployment"
    key, audit = _baseline(target)
    transaction = _prepare_transaction(target, key, audit)
    payload = _manifest(transaction)
    payload["format"] = _INTEGRITY_TRANSACTION_FORMAT
    payload.pop("journal_key_fingerprint", None)
    payload.pop("journal_hmac_sha256", None)
    _write_manifest(transaction, payload)
    _break_live(target)

    status = inspect_interrupted_history_recovery(target)
    assert status["transactions"][0]["integrity_checked"] is True
    assert status["transactions"][0]["authenticated"] is False
    with pytest.raises(RuntimeError, match="unauthenticated legacy recovery journal"):
        preflight_deployment_history(target)

    recovered = recover_interrupted_history_recovery(target, allow_legacy=True)
    assert recovered["recovered"] is True
    assert history_keyring_path(target).read_bytes() == key
    assert audit_log_path(target).read_bytes() == audit


@pytest.mark.skipif(
    __import__("os").name != "posix",
    reason="Windows validation: POSIX filesystem semantics",
)
def test_concurrent_first_journal_key_creation_has_one_stable_winner(tmp_path: Path) -> None:
    parent = _private(tmp_path / "parent")
    target = parent / "deployment"

    with ThreadPoolExecutor(max_workers=12) as executor:
        values = list(executor.map(lambda _: _load_or_create_recovery_journal_key(target), range(36)))

    assert len({value for value in values}) == 1
    assert values[0] == recovery_journal_key_path(target).read_bytes()
    assert len(values[0]) == 32


@pytest.mark.skipif(
    __import__("os").name != "posix",
    reason="Windows validation: POSIX filesystem semantics",
)
def test_manifest_target_rewrite_is_authenticated(tmp_path: Path) -> None:
    parent = _private(tmp_path / "parent")
    target = parent / "deployment"
    key, audit = _baseline(target)
    transaction = _prepare_transaction(target, key, audit)
    payload = _manifest(transaction)
    payload["target_name"] = "other-deployment"
    _write_manifest(transaction, payload)

    with pytest.raises(ValueError, match="transaction target is invalid|authentication failed"):
        inspect_interrupted_history_recovery(target)
    assert transaction.is_dir()


def test_journal_key_symlink_and_hardlink_are_rejected(tmp_path: Path) -> None:
    if os.name != "posix":
        pytest.skip("POSIX link boundary")
    parent = _private(tmp_path / "parent")
    target = parent / "deployment"
    key, audit = _baseline(target)
    transaction = _prepare_transaction(target, key, audit)
    journal_key = recovery_journal_key_path(target)
    raw = journal_key.read_bytes()

    external = parent / "external-key"
    external.write_bytes(raw)
    external.chmod(0o600)
    journal_key.unlink()
    journal_key.symlink_to(external)
    with pytest.raises(ValueError, match="key is unsafe"):
        preflight_deployment_history(target)
    assert transaction.is_dir()

    journal_key.unlink()
    journal_key.write_bytes(raw)
    journal_key.chmod(0o600)
    linked = parent / "linked-journal-key"
    os.link(journal_key, linked)
    with pytest.raises(ValueError, match="key is unsafe"):
        preflight_deployment_history(target)
    assert transaction.is_dir()
