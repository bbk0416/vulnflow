from __future__ import annotations

import hashlib
from pathlib import Path

from scripts.dependency_lock import consistency_issues
from scripts.dependency_wheelhouse_rehearsal import wheelhouse_manifest

ROOT = Path(__file__).resolve().parents[1]


def test_runtime_dependency_surface_excludes_rehearsal_only_requests():
    runtime = (ROOT / "requirements.txt").read_text(encoding="utf-8")
    development = (ROOT / "requirements-dev.txt").read_text(encoding="utf-8")
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    runtime_lock = (ROOT / "requirements.lock").read_text(encoding="utf-8")
    development_lock = (ROOT / "requirements-dev.lock").read_text(encoding="utf-8")

    assert "requests==" not in runtime.lower()
    assert "requests==" not in runtime_lock.lower()
    assert '"requests==' not in pyproject.lower()
    assert "requests==2.34.2" in development
    assert "requests==2.34.2" in development_lock


def test_production_image_copies_only_reviewed_runtime_administration_scripts():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "COPY scripts ./scripts" not in dockerfile
    allowed = {
        "scripts/__init__.py",
        "scripts/manage_users.py",
        "scripts/manage_control_recovery.py",
        "scripts/prepare_storage.py",
        "scripts/generate_integrity_proof_key.py",
        "scripts/verify_integrity_proof.py",
    }
    for relative in allowed:
        assert relative in dockerfile
    for excluded in (
        "scripts/run_public_tests.py",
        "scripts/run_browser_e2e.py",
        "scripts/production_compose_rehearsal.py",
        "scripts/scanner_collection_bundle.py",
        "scripts/runtime_stability_soak.py",
    ):
        assert excluded not in dockerfile


def test_wheelhouse_manifest_records_names_sizes_and_hashes(tmp_path: Path):
    first = tmp_path / "alpha-1.0-py3-none-any.whl"
    second = tmp_path / "beta-2.0-py3-none-any.whl"
    first.write_bytes(b"alpha-wheel")
    second.write_bytes(b"beta-wheel")

    manifest = wheelhouse_manifest(tmp_path)
    assert [item["filename"] for item in manifest] == [first.name, second.name]
    assert manifest[0]["size"] == len(b"alpha-wheel")
    assert manifest[0]["sha256"] == hashlib.sha256(b"alpha-wheel").hexdigest()
    assert manifest[1]["sha256"] == hashlib.sha256(b"beta-wheel").hexdigest()


def test_public_ci_requires_clean_wheelhouse_reinstall():
    workflow = (ROOT / ".github/workflows/public-ci.yml").read_text(encoding="utf-8")
    assert "dependency-wheelhouse" in workflow
    assert "scripts/dependency_wheelhouse_rehearsal.py" in workflow
    assert "--json-output reports/dependency_wheelhouse_rehearsal.json" in workflow
    assert "actions/upload-artifact@v6" in workflow
    assert "name: dependency-wheelhouse-report" in workflow
    assert "path: reports/dependency_wheelhouse_rehearsal.json" in workflow
    assert "--allow-index-unavailable" not in workflow


def test_dependency_files_remain_statically_consistent():
    assert consistency_issues(check_installed=False) == []
