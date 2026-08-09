from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest


from scripts.offline_deployment_audit import append_deployment_audit_event, audit_log_path, verify_deployment_audit_log
from scripts.offline_deployment_bootstrap import OFFLINE_MANAGEMENT_FILES, _install_management_tools, _write_launchers
from scripts.offline_deployment_keyring import history_keyring_path
from scripts.offline_deployment_preflight import preflight_deployment_history
from scripts.offline_deployment_recovery import (
    _LEGACY_TRANSACTION_FORMAT,
    _prepare_transaction,
    _recover_interrupted_transaction,
    _set_transaction_state,
    inspect_interrupted_history_recovery,
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


@pytest.mark.skipif(
    __import__("os").name != "posix",
    reason="Windows validation: POSIX filesystem semantics",
)
def test_journal_backup_checksum_failure_blocks_recovery_and_preserves_journal(tmp_path: Path) -> None:
    parent = _private(tmp_path / "parent")
    target = parent / "deployment"
    key, audit = _baseline(target)
    transaction = _prepare_transaction(target, key, audit)
    (transaction / "previous-audit.jsonl").write_bytes(audit + b"corrupt")
    (transaction / "previous-audit.jsonl").chmod(0o600)
    _break_live(target)

    with pytest.raises(ValueError, match="integrity check failed"):
        _recover_interrupted_transaction(target)
    assert transaction.is_dir()
    assert history_keyring_path(target).read_bytes() == b"broken-keyring"


@pytest.mark.skipif(
    __import__("os").name != "posix",
    reason="Windows validation: POSIX filesystem semantics",
)
def test_invalid_restored_pair_keeps_journal_for_manual_review(tmp_path: Path) -> None:
    parent = _private(tmp_path / "parent")
    target = parent / "deployment"
    key, audit = _baseline(target)
    transaction = _prepare_transaction(target, key, audit)
    invalid_audit = b"not-json\n"
    (transaction / "previous-audit.jsonl").write_bytes(invalid_audit)
    manifest_path = transaction / "transaction.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    import hashlib
    manifest["previous_files"]["previous-audit.jsonl"] = {
        "bytes": len(invalid_audit),
        "sha256": hashlib.sha256(invalid_audit).hexdigest(),
    }
    manifest_path.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    manifest_path.chmod(0o600)
    _break_live(target)

    with pytest.raises(Exception):
        _recover_interrupted_transaction(target)
    assert transaction.is_dir()
    assert audit_log_path(target).read_bytes() == b"broken-audit\n"


@pytest.mark.skipif(
    __import__("os").name != "posix",
    reason="Windows validation: POSIX filesystem semantics",
)
def test_committed_journal_is_not_removed_until_live_history_verifies(tmp_path: Path) -> None:
    parent = _private(tmp_path / "parent")
    target = parent / "deployment"
    key, audit = _baseline(target)
    transaction = _prepare_transaction(target, key, audit)
    _set_transaction_state(transaction, "committed")
    _break_live(target)

    with pytest.raises(Exception):
        _recover_interrupted_transaction(target)
    assert transaction.is_dir()


@pytest.mark.skipif(
    __import__("os").name != "posix",
    reason="Windows validation: POSIX filesystem semantics",
)
def test_startup_preflight_recovers_one_integrity_checked_journal(tmp_path: Path) -> None:
    parent = _private(tmp_path / "parent")
    target = parent / "deployment"
    key, audit = _baseline(target)
    transaction = _prepare_transaction(target, key, audit)
    _break_live(target)

    result = preflight_deployment_history(target)
    assert result["status"] == "recovered"
    assert history_keyring_path(target).read_bytes() == key
    assert audit_log_path(target).read_bytes() == audit
    assert not transaction.exists()
    assert verify_deployment_audit_log(target)["valid"] is True


@pytest.mark.skipif(
    __import__("os").name != "posix",
    reason="Windows validation: POSIX filesystem semantics",
)
def test_startup_preflight_blocks_legacy_and_multiple_journals(tmp_path: Path) -> None:
    parent = _private(tmp_path / "parent")
    target = parent / "deployment"
    key, audit = _baseline(target)
    first = _prepare_transaction(target, key, audit)
    manifest_path = first / "transaction.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["format"] = _LEGACY_TRANSACTION_FORMAT
    manifest.pop("previous_files", None)
    manifest_path.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    manifest_path.chmod(0o600)

    with pytest.raises(RuntimeError, match="unauthenticated legacy recovery journal"):
        preflight_deployment_history(target)
    second = _prepare_transaction(target, key, audit)
    with pytest.raises(RuntimeError, match="multiple"):
        preflight_deployment_history(target)
    assert first.exists() and second.exists()


@pytest.mark.skipif(
    __import__("os").name != "posix",
    reason="Windows validation: POSIX filesystem semantics",
)
def test_unsafe_journal_path_blocks_status_and_startup(tmp_path: Path) -> None:
    parent = _private(tmp_path / "parent")
    target = parent / "deployment"
    unsafe = parent / ".deployment.deployment-history.recovery-unsafe"
    unsafe.write_text("not-a-directory", encoding="utf-8")

    with pytest.raises(RuntimeError, match="path is unsafe"):
        inspect_interrupted_history_recovery(target)
    with pytest.raises(RuntimeError, match="path is unsafe"):
        preflight_deployment_history(target)


@pytest.mark.skipif(
    __import__("os").name != "posix",
    reason="Windows validation: POSIX filesystem semantics",
)
def test_management_cli_reports_and_recovers_interrupted_journal(tmp_path: Path) -> None:
    parent = _private(tmp_path / "parent")
    target = parent / "deployment"
    key, audit = _baseline(target)
    _prepare_transaction(target, key, audit)
    _break_live(target)
    root = Path(__file__).resolve().parents[1]

    status = subprocess.run(
        [sys.executable, "scripts/manage_offline_deployments.py", "interrupted-recovery-status", "--target", str(target)],
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=30,
        check=False,
    )
    assert status.returncode == 0, status.stdout
    assert json.loads(status.stdout)["count"] == 1
    recovered = subprocess.run(
        [sys.executable, "scripts/manage_offline_deployments.py", "recover-interrupted", "--target", str(target)],
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=30,
        check=False,
    )
    assert recovered.returncode == 0, recovered.stdout
    assert json.loads(recovered.stdout)["recovered"] is True


def test_signed_management_tools_and_launcher_include_startup_preflight(tmp_path: Path) -> None:
    target = _private(tmp_path / "deployment")
    kit = _private(tmp_path / "kit")
    root = Path(__file__).resolve().parents[1]
    for name in OFFLINE_MANAGEMENT_FILES:
        (kit / name).write_bytes((root / "scripts" / name).read_bytes())
    management = _install_management_tools(target, kit)
    venv_python = target / "venv" / "bin" / "python"
    executable = target / "venv" / "bin" / "vulnflow"
    venv_python.parent.mkdir(parents=True)
    venv_python.write_text("python", encoding="utf-8")
    executable.write_text("vulnflow", encoding="utf-8")
    config = target / "config" / "runtime_environment.json"
    config.parent.mkdir(parents=True)
    config.write_text(json.dumps({"VULNFLOW_BASE_DIR": str(target)}), encoding="utf-8")

    _write_launchers(target, venv_python, executable, config, management)
    launcher = (target / "bin" / "run_vulnflow.py").read_text(encoding="utf-8")
    assert "preflight_deployment_history" in launcher
    assert "offline-management" in launcher
    assert {path.name for path in management.iterdir()} == set(OFFLINE_MANAGEMENT_FILES)
    if os.name == "posix":
        assert all(path.stat().st_mode & 0o077 == 0 for path in management.iterdir())
