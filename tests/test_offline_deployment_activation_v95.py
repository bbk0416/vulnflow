from __future__ import annotations

import json
import os
from pathlib import Path

import pytest


from scripts.offline_deployment_activation import (
    activate_staged_directory,
    rollback_activated_directory,
    sibling_staging_directory,
)
from scripts.offline_deployment_bootstrap import _relocate_runtime_configuration


def _write(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")


def test_activation_failure_restores_existing_target(tmp_path: Path) -> None:
    target = tmp_path / "vulnflow"
    staging = sibling_staging_directory(target)
    _write(target / "state.txt", "stable")
    _write(staging / "state.txt", "candidate")

    def fail(_: Path) -> None:
        raise RuntimeError("post-activation failure")

    with pytest.raises(RuntimeError, match="post-activation failure"):
        activate_staged_directory(staging, target, allow_replace=True, verify=fail)

    assert (target / "state.txt").read_text(encoding="utf-8") == "stable"
    assert not list(tmp_path.glob(".vulnflow.failed-*"))
    assert not list(tmp_path.glob(".vulnflow.previous-*"))


def test_activation_failure_without_previous_target_leaves_no_install(tmp_path: Path) -> None:
    target = tmp_path / "vulnflow"
    staging = sibling_staging_directory(target)
    _write(staging / "state.txt", "candidate")

    with pytest.raises(ValueError, match="reject"):
        activate_staged_directory(
            staging,
            target,
            allow_replace=False,
            verify=lambda _: (_ for _ in ()).throw(ValueError("reject")),
        )

    assert not target.exists()
    assert not list(tmp_path.glob(".vulnflow.failed-*"))


def test_successful_replacement_retains_private_previous_tree(tmp_path: Path) -> None:
    target = tmp_path / "vulnflow"
    staging = sibling_staging_directory(target)
    _write(target / "state.txt", "stable")
    _write(staging / "state.txt", "candidate")

    result = activate_staged_directory(
        staging,
        target,
        allow_replace=True,
        verify=lambda path: (path / "state.txt").read_text(encoding="utf-8"),
    )

    assert result.verification == "candidate"
    assert (target / "state.txt").read_text(encoding="utf-8") == "candidate"
    assert result.previous_target is not None
    assert result.previous_target.parent == target.parent
    assert result.previous_target.name.startswith(".vulnflow.previous-")
    assert (result.previous_target / "state.txt").read_text(encoding="utf-8") == "stable"


def test_explicit_rollback_restores_previous_tree(tmp_path: Path) -> None:
    target = tmp_path / "vulnflow"
    staging = sibling_staging_directory(target)
    _write(target / "state.txt", "stable")
    _write(staging / "state.txt", "candidate")
    result = activate_staged_directory(
        staging,
        target,
        allow_replace=True,
        verify=lambda _: True,
    )

    rollback_activated_directory(target, result.previous_target)

    assert (target / "state.txt").read_text(encoding="utf-8") == "stable"
    assert not list(tmp_path.glob(".vulnflow.failed-*"))


def test_existing_target_requires_explicit_replace(tmp_path: Path) -> None:
    target = tmp_path / "vulnflow"
    staging = sibling_staging_directory(target)
    _write(target / "state.txt", "stable")
    _write(staging / "state.txt", "candidate")

    with pytest.raises(FileExistsError):
        activate_staged_directory(staging, target, allow_replace=False, verify=lambda _: True)

    assert (target / "state.txt").read_text(encoding="utf-8") == "stable"
    assert (staging / "state.txt").read_text(encoding="utf-8") == "candidate"


def test_target_symlink_is_rejected(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    target = tmp_path / "vulnflow"
    try:
        target.symlink_to(real, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation is unavailable")
    staging = sibling_staging_directory(target)
    _write(staging / "state.txt", "candidate")

    with pytest.raises(ValueError, match="symbolic link"):
        activate_staged_directory(staging, target, allow_replace=True, verify=lambda _: True)

    assert target.is_symlink()


def test_runtime_configuration_relocation_rewrites_only_staging_prefix(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    old = tmp_path / ".vulnflow.staging-old"
    target = tmp_path / "vulnflow"
    (target / "config").mkdir(parents=True)
    (target / "venv" / "bin").mkdir(parents=True)
    _write(target / "venv" / "bin" / "vulnflow", "entry")
    os.chmod(target / "venv" / "bin" / "vulnflow", 0o700)
    config = {
        "VULNFLOW_BASE_DIR": str(old),
        "VULNFLOW_DATA_DIR": str(old / "data"),
        "UNRELATED": "/srv/elsewhere",
    }
    credentials = {"admin_api_token": "secret"}
    _write(target / "config" / "runtime_environment.json", json.dumps(config))
    _write(target / "config" / "INITIAL_CREDENTIALS.json", json.dumps(credentials))
    monkeypatch.setattr(
        "scripts.offline_deployment_bootstrap._venv_paths",
        lambda _: (target / "venv" / "bin" / "python", target / "venv" / "bin", target / "site-packages"),
    )
    monkeypatch.setattr("scripts.offline_deployment_bootstrap._write_launchers", lambda *args: None)

    relocated, loaded_credentials, _, _ = _relocate_runtime_configuration(target, old)

    assert relocated["VULNFLOW_BASE_DIR"] == str(target)
    assert relocated["VULNFLOW_DATA_DIR"] == str(target / "data")
    assert relocated["UNRELATED"] == "/srv/elsewhere"
    assert loaded_credentials == credentials
    persisted = json.loads((target / "config" / "runtime_environment.json").read_text(encoding="utf-8"))
    assert persisted == relocated


def _zip(path: Path, entries: list[tuple[str, bytes]]) -> None:
    import zipfile

    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in entries:
            archive.writestr(name, data)


def test_release_kit_zip_entry_limit_is_enforced(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from scripts.offline_deployment_bootstrap import _safe_extract_zip

    archive = tmp_path / "kit.zip"
    _zip(archive, [("kit/a.txt", b"a"), ("kit/b.txt", b"b")])
    monkeypatch.setattr("scripts.offline_deployment_bootstrap.MAX_RELEASE_KIT_ENTRIES", 1)
    with pytest.raises(ValueError, match="too many"):
        _safe_extract_zip(archive, tmp_path / "extract")


def test_release_kit_zip_total_size_limit_is_enforced(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from scripts.offline_deployment_bootstrap import _safe_extract_zip

    archive = tmp_path / "kit.zip"
    _zip(archive, [("kit/a.bin", b"123456")])
    monkeypatch.setattr("scripts.offline_deployment_bootstrap.MAX_RELEASE_KIT_UNCOMPRESSED_BYTES", 5)
    with pytest.raises(ValueError, match="total uncompressed"):
        _safe_extract_zip(archive, tmp_path / "extract")


def test_release_kit_zip_compression_ratio_limit_is_enforced(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from scripts.offline_deployment_bootstrap import _safe_extract_zip

    archive = tmp_path / "kit.zip"
    _zip(archive, [("kit/zeros.bin", b"0" * 50_000)])
    monkeypatch.setattr("scripts.offline_deployment_bootstrap.MAX_RELEASE_KIT_COMPRESSION_RATIO", 2)
    with pytest.raises(ValueError, match="compression-ratio"):
        _safe_extract_zip(archive, tmp_path / "extract")


def test_release_kit_zip_duplicate_entries_are_rejected(tmp_path: Path) -> None:
    import warnings
    import zipfile

    from scripts.offline_deployment_bootstrap import _safe_extract_zip

    archive = tmp_path / "kit.zip"
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(archive, "w") as handle:
            handle.writestr("kit/a.txt", b"first")
            handle.writestr("kit/a.txt", b"second")
    with pytest.raises(ValueError, match="duplicate"):
        _safe_extract_zip(archive, tmp_path / "extract")


@pytest.mark.skipif(
    __import__("os").name != "posix",
    reason="Windows validation: POSIX filesystem semantics",
)
def test_force_deploy_staging_failure_preserves_existing_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from scripts.offline_deployment_bootstrap import deploy_release_kit, sha256_file

    kit = tmp_path / "release.zip"
    kit.write_bytes(b"not-a-real-release-kit")
    target = tmp_path / "vulnflow"
    _write(target / "state.txt", "stable")
    monkeypatch.setattr(
        "scripts.offline_deployment_bootstrap._safe_extract_zip",
        lambda *_: (_ for _ in ()).throw(ValueError("signed content rejected")),
    )

    with pytest.raises(ValueError, match="signed content rejected"):
        deploy_release_kit(
            kit,
            target,
            expected_kit_sha256=sha256_file(kit),
            expected_public_key_fingerprint="sha256:" + "0" * 64,
            expected_version="72.0.50",
            force=True,
            run_cycles=2,
        )

    assert (target / "state.txt").read_text(encoding="utf-8") == "stable"
    assert not list(tmp_path.glob(".vulnflow.staging-*"))


@pytest.mark.skipif(
    __import__("os").name != "posix",
    reason="Windows validation: POSIX filesystem semantics",
)
def test_force_deploy_rejects_target_symlink_before_staging(tmp_path: Path) -> None:
    from scripts.offline_deployment_bootstrap import deploy_release_kit, sha256_file

    kit = tmp_path / "release.zip"
    kit.write_bytes(b"release")
    real = tmp_path / "real"
    real.mkdir()
    target = tmp_path / "vulnflow"
    try:
        target.symlink_to(real, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation is unavailable")

    with pytest.raises(ValueError, match="symbolic link"):
        deploy_release_kit(
            kit,
            target,
            expected_kit_sha256=sha256_file(kit),
            expected_public_key_fingerprint="sha256:" + "0" * 64,
            expected_version="72.0.50",
            force=True,
            run_cycles=2,
        )

    assert target.is_symlink()
    assert not list(tmp_path.glob(".vulnflow.staging-*"))


def _runtime_snapshot(path: Path, payload: bytes) -> None:
    import io
    import tarfile

    manifest = b'{}'
    with tarfile.open(path, "w:gz") as archive:
        manifest_info = tarfile.TarInfo("vulnflow-runtime-snapshot/manifest.json")
        manifest_info.size = len(manifest)
        archive.addfile(manifest_info, io.BytesIO(manifest))
        payload_info = tarfile.TarInfo("vulnflow-runtime-snapshot/site-packages/demo.bin")
        payload_info.size = len(payload)
        archive.addfile(payload_info, io.BytesIO(payload))


def test_runtime_snapshot_member_limit_is_enforced(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from scripts.offline_deployment_bootstrap import inspect_snapshot

    snapshot = tmp_path / "snapshot.tar.gz"
    _runtime_snapshot(snapshot, b"payload")
    monkeypatch.setattr("scripts.offline_deployment_bootstrap.MAX_RUNTIME_SNAPSHOT_MEMBERS", 1)
    with pytest.raises(ValueError, match="too many members"):
        inspect_snapshot(snapshot, "72.0.50")


def test_runtime_snapshot_uncompressed_size_limit_is_enforced(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from scripts.offline_deployment_bootstrap import inspect_snapshot

    snapshot = tmp_path / "snapshot.tar.gz"
    _runtime_snapshot(snapshot, b"payload")
    monkeypatch.setattr("scripts.offline_deployment_bootstrap.MAX_RUNTIME_SNAPSHOT_BYTES", 4)
    with pytest.raises(ValueError, match="uncompressed size"):
        inspect_snapshot(snapshot, "72.0.50")


def test_existing_non_directory_target_is_rejected(tmp_path: Path) -> None:
    target = tmp_path / "vulnflow"
    target.write_text("not-a-directory", encoding="utf-8")
    staging = tmp_path / ".vulnflow.staging-manual"
    staging.mkdir(mode=0o700)

    with pytest.raises(ValueError, match="must be a directory"):
        activate_staged_directory(staging, target, allow_replace=True, verify=lambda _: True)

    assert target.read_text(encoding="utf-8") == "not-a-directory"


@pytest.mark.skipif(
    __import__("os").name != "posix",
    reason="Windows validation: POSIX filesystem semantics",
)
def test_group_writable_deployment_parent_is_rejected(tmp_path: Path) -> None:
    parent = tmp_path / "unsafe"
    parent.mkdir(mode=0o770)
    parent.chmod(0o770)
    target = parent / "vulnflow"

    with pytest.raises(ValueError, match="group- or world-writable"):
        sibling_staging_directory(target)


def test_runtime_snapshot_member_size_limit_is_enforced(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from scripts.offline_deployment_bootstrap import inspect_snapshot

    snapshot = tmp_path / "snapshot.tar.gz"
    _runtime_snapshot(snapshot, b"payload")
    monkeypatch.setattr("scripts.offline_deployment_bootstrap.MAX_RUNTIME_SNAPSHOT_MEMBER_BYTES", 4)
    with pytest.raises(ValueError, match="member exceeds"):
        inspect_snapshot(snapshot, "72.0.50")
