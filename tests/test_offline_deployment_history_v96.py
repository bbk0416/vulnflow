from __future__ import annotations

import multiprocessing
from pathlib import Path
import time

import pytest


from scripts.offline_deployment_activation import deployment_operation_lock
from scripts.offline_deployment_history import (
    inventory_retained_deployments,
    load_deployment_identity,
    prune_retained_deployments,
    rollback_to_retained_deployment,
    seal_retained_deployment,
    verify_retained_deployment,
    write_deployment_identity,
)

SHA_A = "a" * 64
FINGERPRINT = "sha256:" + "c" * 64


def _private(path: Path) -> Path:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.chmod(0o700)
    return path


def _identity(root: Path, *, installation_id: str, installed_at: str, version: str = "72.0.50"):
    return write_deployment_identity(
        root,
        application_version=version,
        schema_version=46,
        release_kit_sha256=SHA_A,
        release_public_key_fingerprint=FINGERPRINT,
        target_name="deployment",
        installation_id=installation_id,
        installed_at=installed_at,
    )


@pytest.mark.skipif(
    __import__("os").name != "posix",
    reason="Windows validation: POSIX filesystem semantics",
)
def test_identity_round_trip_and_target_boundary(tmp_path: Path) -> None:
    root = _private(tmp_path / "deployment")
    identity = _identity(root, installation_id="1" * 32, installed_at="2026-08-03T10:00:00Z")
    loaded = load_deployment_identity(root, expected_target_name="deployment")
    assert loaded == identity
    assert (root / "config" / "OFFLINE_DEPLOYMENT_IDENTITY.json").stat().st_mode & 0o077 == 0
    with pytest.raises(ValueError, match="target name"):
        load_deployment_identity(root, expected_target_name="other")


def test_inventory_sorts_managed_and_preserves_unmanaged(tmp_path: Path) -> None:
    parent = _private(tmp_path / "parent")
    target = _private(parent / "deployment")
    older = _private(parent / ".deployment.previous-old")
    newer = _private(parent / ".deployment.previous-new")
    unmanaged = _private(parent / ".deployment.previous-legacy")
    _identity(older, installation_id="1" * 32, installed_at="2026-08-03T10:00:00Z")
    _identity(newer, installation_id="2" * 32, installed_at="2026-08-03T11:00:00Z")
    seal_retained_deployment(target, older)
    seal_retained_deployment(target, newer)
    (unmanaged / "legacy.txt").write_text("review me", encoding="utf-8")

    inventory = inventory_retained_deployments(target)
    assert [item["installation_id"] for item in inventory["managed"]] == ["2" * 32, "1" * 32]
    assert inventory["unmanaged"] == [
        {"path": str(unmanaged), "reason": "deployment identity marker is missing or unsafe"}
    ]


@pytest.mark.skipif(
    __import__("os").name != "posix",
    reason="Windows validation: POSIX filesystem semantics",
)
def test_prune_removes_only_old_validated_deployments(tmp_path: Path) -> None:
    parent = _private(tmp_path / "parent")
    target = _private(parent / "deployment")
    candidates = []
    for index in range(4):
        candidate = _private(parent / f".deployment.previous-{index}")
        _identity(
            candidate,
            installation_id=f"{index + 1:032x}",
            installed_at=f"2026-08-03T1{index}:00:00Z",
        )
        seal_retained_deployment(target, candidate)
        candidates.append(candidate)
    unmanaged = _private(parent / ".deployment.previous-unmanaged")

    dry = prune_retained_deployments(target, keep=2, dry_run=True)
    assert len(dry["removed"]) == 2
    assert all(item.exists() for item in candidates)

    result = prune_retained_deployments(target, keep=2)
    assert len(result["removed"]) == 2
    assert candidates[3].exists() and candidates[2].exists()
    assert not candidates[1].exists() and not candidates[0].exists()
    assert unmanaged.exists()
    with pytest.raises(ValueError, match="at least one"):
        prune_retained_deployments(target, keep=0)


@pytest.mark.skipif(
    __import__("os").name != "posix",
    reason="Windows validation: POSIX filesystem semantics",
)
def test_rollback_reactivates_candidate_and_retains_current(tmp_path: Path) -> None:
    parent = _private(tmp_path / "parent")
    target = _private(parent / "deployment")
    current_identity = _identity(target, installation_id="a" * 32, installed_at="2026-08-03T12:00:00Z", version="72.0.50")
    (target / "marker.txt").write_text("current", encoding="utf-8")
    candidate = _private(parent / ".deployment.previous-candidate")
    wanted = _identity(candidate, installation_id="b" * 32, installed_at="2026-08-03T11:00:00Z", version="72.0.50")
    (candidate / "marker.txt").write_text("candidate", encoding="utf-8")
    seal_retained_deployment(target, candidate)

    result = rollback_to_retained_deployment(
        target,
        installation_id=wanted.installation_id,
        verify=lambda activated, previous, identity: {
            "activated": (activated / "marker.txt").read_text(encoding="utf-8"),
            "previous": str(previous),
            "version": identity.application_version,
        },
    )

    assert (target / "marker.txt").read_text(encoding="utf-8") == "candidate"
    assert load_deployment_identity(target).installation_id == wanted.installation_id
    previous = Path(result["previous_deployment"])
    assert previous.is_dir()
    assert (previous / "marker.txt").read_text(encoding="utf-8") == "current"
    assert load_deployment_identity(previous).installation_id == current_identity.installation_id
    assert verify_retained_deployment(target, previous)["installation_id"] == current_identity.installation_id
    assert result["verification"]["version"] == "72.0.50"


@pytest.mark.skipif(
    __import__("os").name != "posix",
    reason="Windows validation: POSIX filesystem semantics",
)
def test_failed_rollback_restores_current_and_candidate(tmp_path: Path) -> None:
    parent = _private(tmp_path / "parent")
    target = _private(parent / "deployment")
    _identity(target, installation_id="a" * 32, installed_at="2026-08-03T12:00:00Z")
    (target / "marker.txt").write_text("current", encoding="utf-8")
    candidate = _private(parent / ".deployment.previous-candidate")
    wanted = _identity(candidate, installation_id="b" * 32, installed_at="2026-08-03T11:00:00Z")
    (candidate / "marker.txt").write_text("candidate", encoding="utf-8")
    seal_retained_deployment(target, candidate)

    with pytest.raises(RuntimeError, match="verification failed"):
        rollback_to_retained_deployment(
            target,
            installation_id=wanted.installation_id,
            verify=lambda *_: (_ for _ in ()).throw(RuntimeError("verification failed")),
        )

    assert (target / "marker.txt").read_text(encoding="utf-8") == "current"
    assert candidate.is_dir()
    assert (candidate / "marker.txt").read_text(encoding="utf-8") == "candidate"


def _hold_lock(target: str, ready: multiprocessing.Event, release: multiprocessing.Event) -> None:
    with deployment_operation_lock(Path(target)):
        ready.set()
        release.wait(10)


@pytest.mark.skipif(
    __import__("os").name != "posix",
    reason="Windows validation: POSIX filesystem semantics",
)
def test_deployment_operation_lock_blocks_concurrent_mutation(tmp_path: Path) -> None:
    parent = _private(tmp_path / "parent")
    target = parent / "deployment"
    ready = multiprocessing.Event()
    release = multiprocessing.Event()
    process = multiprocessing.Process(target=_hold_lock, args=(str(target), ready, release))
    process.start()
    assert ready.wait(5)
    try:
        with pytest.raises(RuntimeError, match="already in progress"):
            with deployment_operation_lock(target):
                pass
    finally:
        release.set()
        process.join(5)
    assert process.exitcode == 0
    with deployment_operation_lock(target):
        pass


@pytest.mark.skipif(
    __import__("os").name != "posix",
    reason="Windows validation: POSIX filesystem semantics",
)
def test_deployment_operation_lock_rejects_symlink(tmp_path: Path) -> None:
    parent = _private(tmp_path / "parent")
    target = parent / "deployment"
    destination = parent / "unexpected"
    destination.write_text("do not overwrite", encoding="utf-8")
    lock = parent / ".deployment.deployment.lock"
    lock.symlink_to(destination)
    with pytest.raises(RuntimeError, match="unsafe or inaccessible"):
        with deployment_operation_lock(target):
            pass
    assert destination.read_text(encoding="utf-8") == "do not overwrite"


def test_signed_release_kit_scripts_import_standalone(tmp_path: Path) -> None:
    import shutil
    import subprocess
    import sys

    root = Path(__file__).resolve().parents[1]
    for name in (
        "offline_deployment_activation.py",
        "offline_deployment_keyring.py",
        "offline_deployment_audit.py",
        "offline_deployment_witness.py",
        "offline_deployment_recovery.py",
        "offline_deployment_preflight.py",
        "offline_deployment_history.py",
        "offline_deployment_bootstrap.py",
        "manage_offline_deployments.py",
    ):
        shutil.copyfile(root / "scripts" / name, tmp_path / name)
    for script in ("offline_deployment_bootstrap.py", "manage_offline_deployments.py"):
        completed = subprocess.run(
            [sys.executable, script, "--help"],
            cwd=tmp_path,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=20,
            check=False,
            env={"PYTHONDONTWRITEBYTECODE": "1", "PATH": str(Path(sys.executable).parent)},
        )
        assert completed.returncode == 0, completed.stdout
        assert "usage:" in completed.stdout.lower()


def test_release_distribution_requires_all_standalone_deployment_artifacts(tmp_path: Path) -> None:
    from scripts.release_distribution_bundle import _artifact_definitions
    from scripts.verify_release_distribution import REQUIRED_ROLES

    version = "72.0.50"
    (tmp_path / "VERSION").write_text(version + "\n", encoding="utf-8")
    dist = _private(tmp_path / "dist")
    (dist / f"bbk_vulnflow-{version}-py3-none-any.whl").write_bytes(b"wheel")
    (dist / f"bbk_vulnflow-{version}.tar.gz").write_bytes(b"sdist")
    (dist / f"vulnflow_runtime_dependencies-{version}-cp313-linux_x86_64.tar.gz").write_bytes(b"snapshot")
    project = tmp_path / "project.zip"
    project.write_bytes(b"project")

    roles = {role for role, _, _ in _artifact_definitions(tmp_path, project)}
    expected = {
        "offline_deployment_activation",
        "offline_deployment_keyring",
        "offline_deployment_audit",
        "offline_deployment_witness",
        "offline_deployment_recovery",
        "offline_deployment_preflight",
        "offline_deployment_history",
        "offline_deployment_bootstrap",
        "offline_deployment_manager",
    }
    assert expected.issubset(roles)
    assert expected.issubset(set(REQUIRED_ROLES))
