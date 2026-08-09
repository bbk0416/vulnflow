from __future__ import annotations

from pathlib import Path

import pytest


from scripts.offline_deployment_history import (
    adopt_retained_deployment,
    inventory_retained_deployments,
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


def test_tampered_retained_content_is_unmanaged_and_not_selectable(tmp_path: Path) -> None:
    parent = _private(tmp_path / "parent")
    target = _private(parent / "deployment")
    candidate = _private(parent / ".deployment.previous-candidate")
    identity = _identity(candidate, installation_id="d" * 32, installed_at="2026-08-03T11:00:00Z")
    (candidate / "app.py").write_text("trusted", encoding="utf-8")
    seal_retained_deployment(target, candidate)
    (candidate / "app.py").write_text("tampered", encoding="utf-8")

    inventory = inventory_retained_deployments(target)
    assert inventory["managed"] == []
    assert "modified after sealing" in inventory["unmanaged"][0]["reason"]
    with pytest.raises(ValueError, match="found 0"):
        rollback_to_retained_deployment(target, installation_id=identity.installation_id, verify=lambda *_: True)


def test_tampered_identity_is_rejected_by_authenticated_seal(tmp_path: Path) -> None:
    import json

    parent = _private(tmp_path / "parent")
    target = _private(parent / "deployment")
    candidate = _private(parent / ".deployment.previous-candidate")
    _identity(candidate, installation_id="e" * 32, installed_at="2026-08-03T11:00:00Z")
    seal_retained_deployment(target, candidate)
    marker = candidate / "config" / "OFFLINE_DEPLOYMENT_IDENTITY.json"
    payload = json.loads(marker.read_text(encoding="utf-8"))
    payload["application_version"] = "99.0.0"
    marker.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="identity was modified|content was modified"):
        verify_retained_deployment(target, candidate)


@pytest.mark.skipif(
    __import__("os").name != "posix",
    reason="Windows validation: POSIX filesystem semantics",
)
def test_history_key_is_private_and_required(tmp_path: Path) -> None:
    parent = _private(tmp_path / "parent")
    target = _private(parent / "deployment")
    candidate = _private(parent / ".deployment.previous-candidate")
    _identity(candidate, installation_id="f" * 32, installed_at="2026-08-03T11:00:00Z")
    seal_retained_deployment(target, candidate)
    key = parent / ".deployment.deployment-history.key"
    assert key.stat().st_mode & 0o077 == 0
    key.unlink()
    with pytest.raises(ValueError, match="signing key is missing"):
        verify_retained_deployment(target, candidate)


def test_prune_preserves_tampered_history(tmp_path: Path) -> None:
    parent = _private(tmp_path / "parent")
    target = _private(parent / "deployment")
    good = _private(parent / ".deployment.previous-good")
    bad = _private(parent / ".deployment.previous-bad")
    _identity(good, installation_id="1" * 32, installed_at="2026-08-03T12:00:00Z")
    _identity(bad, installation_id="2" * 32, installed_at="2026-08-03T11:00:00Z")
    (good / "state").write_text("good", encoding="utf-8")
    (bad / "state").write_text("good", encoding="utf-8")
    seal_retained_deployment(target, good)
    seal_retained_deployment(target, bad)
    (bad / "state").write_text("tampered", encoding="utf-8")

    result = prune_retained_deployments(target, keep=1)
    assert good.exists()
    assert bad.exists()
    assert result["removed"] == []
    assert result["unmanaged"]


@pytest.mark.skipif(
    __import__("os").name != "posix",
    reason="Windows validation: POSIX filesystem semantics",
)
def test_legacy_history_requires_explicit_adoption(tmp_path: Path) -> None:
    parent = _private(tmp_path / "parent")
    target = _private(parent / "deployment")
    candidate = _private(parent / ".deployment.previous-legacy")
    identity = _identity(candidate, installation_id="3" * 32, installed_at="2026-08-03T09:00:00Z")
    (candidate / "state").write_text("reviewed", encoding="utf-8")

    before = inventory_retained_deployments(target)
    assert before["managed"] == []
    assert "seal is missing" in before["unmanaged"][0]["reason"]

    result = adopt_retained_deployment(target, identity.installation_id)
    assert result["installation_id"] == identity.installation_id
    after = inventory_retained_deployments(target)
    assert [item["installation_id"] for item in after["managed"]] == [identity.installation_id]
    assert after["unmanaged"] == []


def test_adoption_refuses_to_overwrite_invalid_existing_seal(tmp_path: Path) -> None:
    parent = _private(tmp_path / "parent")
    target = _private(parent / "deployment")
    candidate = _private(parent / ".deployment.previous-legacy")
    identity = _identity(candidate, installation_id="4" * 32, installed_at="2026-08-03T09:00:00Z")
    seal = candidate / "config" / "OFFLINE_DEPLOYMENT_SEAL.json"
    seal.write_text("{}", encoding="utf-8")

    with pytest.raises(ValueError, match="refuses to overwrite"):
        adopt_retained_deployment(target, identity.installation_id)


def test_wrong_history_key_is_rejected(tmp_path: Path) -> None:
    parent = _private(tmp_path / "parent")
    target = _private(parent / "deployment")
    candidate = _private(parent / ".deployment.previous-candidate")
    _identity(candidate, installation_id="5" * 32, installed_at="2026-08-03T09:00:00Z")
    seal_retained_deployment(target, candidate)
    key = parent / ".deployment.deployment-history.key"
    key.write_text("11" * 32 + "\n", encoding="ascii")
    key.chmod(0o600)

    with pytest.raises(ValueError, match="does not match"):
        verify_retained_deployment(target, candidate)
