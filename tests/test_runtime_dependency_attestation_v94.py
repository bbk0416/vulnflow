from __future__ import annotations

from importlib import metadata
import json
from pathlib import Path

import pytest

from app.core.schema_versions import CURRENT_SCHEMA_VERSION
from app.services.runtime_dependency_policy import (
    enforce_runtime_dependencies,
    evaluate_runtime_dependencies,
    load_runtime_dependency_manifest,
)
from app.services.security_profile import evaluate_security_profile
from scripts.offline_deployment_bootstrap import _verified_release_schema
from scripts.runtime_dependency_manifest import build_manifest, rendered

ROOT = Path(__file__).resolve().parents[1]


def _version_map(manifest: dict[str, object]) -> dict[str, str]:
    return {
        str(item["name"]): str(item["version"])
        for item in manifest["packages"]  # type: ignore[index]
    }


def _lookup(values: dict[str, str]):
    def lookup(name: str) -> str:
        if name not in values:
            raise metadata.PackageNotFoundError(name)
        return values[name]

    return lookup


def test_packaged_runtime_dependency_manifest_matches_source_lock() -> None:
    path = ROOT / "app/resources/runtime_dependency_lock.json"
    assert path.read_text(encoding="utf-8") == rendered()
    assert load_runtime_dependency_manifest(path) == build_manifest()


def test_runtime_dependency_policy_passes_exact_active_linux_closure() -> None:
    manifest = build_manifest()
    report = evaluate_runtime_dependencies(
        policy="enforce",
        manifest=manifest,
        version_lookup=_lookup(_version_map(manifest)),
        platform_name="linux",
        implementation_name="cpython",
    )
    assert report.passed
    assert report.checked
    assert report.expected_packages == len(manifest["packages"]) - 1  # colorama is Windows-only


def test_runtime_dependency_platform_conditions_are_fail_closed() -> None:
    manifest = build_manifest()
    values = _version_map(manifest)
    linux = evaluate_runtime_dependencies(
        policy="warn",
        manifest=manifest,
        version_lookup=_lookup(values),
        platform_name="linux",
        implementation_name="cpython",
    )
    windows = evaluate_runtime_dependencies(
        policy="warn",
        manifest=manifest,
        version_lookup=_lookup(values),
        platform_name="win32",
        implementation_name="cpython",
    )
    assert linux.expected_packages == windows.expected_packages
    assert linux.passed and windows.passed


def test_runtime_dependency_policy_reports_missing_and_drifted_packages() -> None:
    manifest = {
        "format": "vulnflow-runtime-dependency-lock/1",
        "packages": [
            {"name": "alpha", "version": "1.0", "condition": "always"},
            {"name": "beta", "version": "2.0", "condition": "always"},
        ],
    }
    report = evaluate_runtime_dependencies(
        policy="warn",
        manifest=manifest,
        version_lookup=_lookup({"alpha": "0.9"}),
    )
    assert {item.code for item in report.findings} == {
        "dependency.version",
        "dependency.missing",
    }


def test_runtime_dependency_enforce_rejects_version_drift() -> None:
    manifest = {
        "format": "vulnflow-runtime-dependency-lock/1",
        "packages": [{"name": "alpha", "version": "1.0", "condition": "always"}],
    }
    with pytest.raises(RuntimeError, match="런타임 의존성 검증 실패"):
        enforce_runtime_dependencies(
            policy="enforce",
            manifest=manifest,
            version_lookup=_lookup({"alpha": "0.9"}),
        )


def test_production_security_profile_requires_dependency_enforcement(tmp_path: Path) -> None:
    values = {
        "SECURITY_PROFILE": "production",
        "PUBLIC_BASE_URL": "https://vulnflow.example.test",
        "COOKIE_SECURE": True,
        "DEMO_MODE": False,
        "ALLOW_LOCAL_ADMIN_FALLBACK": False,
        "AUTH_SESSION_BINDING": "user-agent",
        "AUTH_SESSION_IDLE_MINUTES": 30,
        "RUNTIME_DEPENDENCY_POLICY": "warn",
        "OUTBOUND_ALLOW_PRIVATE_NETWORKS": False,
        "EVIDENCE_REQUIRE_CLEAN": True,
        "EVIDENCE_SCANNER_MODE": "builtin",
        "AUDIT_REQUIRE_SIGNATURE": True,
        "AUDIT_SIGNING_KEY": "audit-key",
        "BACKUP_REQUIRE_SIGNATURE": True,
        "BACKUP_SIGNING_KEY": "backup-key",
        "CURSOR_SIGNING_KEY_CONFIGURED": True,
        "BACKUP_INTERVAL_HOURS": 12,
        "EXTERNAL_BACKUP_DIR": tmp_path / "external",
    }
    report = evaluate_security_profile(values, tokens={})
    assert "dependency.enforce" in {item.code for item in report.findings}
    values["RUNTIME_DEPENDENCY_POLICY"] = "enforce"
    assert "dependency.enforce" not in {
        item.code for item in evaluate_security_profile(values, tokens={}).findings
    }


def test_offline_bootstrap_uses_verified_release_schema(tmp_path: Path) -> None:
    index = tmp_path / "release_distribution_index.json"
    index.write_text(
        json.dumps({"version": "72.0.50", "schemaVersion": CURRENT_SCHEMA_VERSION}),
        encoding="utf-8",
    )
    assert _verified_release_schema(tmp_path, "72.0.50") == CURRENT_SCHEMA_VERSION
    with pytest.raises(ValueError, match="version mismatch"):
        _verified_release_schema(tmp_path, "72.0.33")
    index.write_text(json.dumps({"version": "72.0.50", "schemaVersion": 0}), encoding="utf-8")
    with pytest.raises(ValueError, match="schemaVersion"):
        _verified_release_schema(tmp_path, "72.0.50")


def test_release_tools_do_not_hardcode_obsolete_schema_40() -> None:
    for relative in (
        "scripts/distribution_artifact_rehearsal.py",
        "scripts/runtime_dependency_snapshot.py",
        "scripts/offline_deployment_bootstrap.py",
    ):
        text = (ROOT / relative).read_text(encoding="utf-8")
        assert "EXPECTED_SCHEMA_VERSION = 40" not in text
    assert "CURRENT_SCHEMA_VERSION" in (
        ROOT / "scripts/distribution_artifact_rehearsal.py"
    ).read_text(encoding="utf-8")
    offline = (ROOT / "scripts/offline_deployment_bootstrap.py").read_text(encoding="utf-8")
    assert "expected_schema_version = _verified_release_schema" in offline
    assert 'database = Path(config["VULNFLOW_DEFAULT_PROJECT_DB"])' in offline
    for relative in (
        "scripts/distribution_artifact_rehearsal.py",
        "scripts/runtime_dependency_snapshot.py",
        "scripts/offline_deployment_bootstrap.py",
    ):
        text = (ROOT / relative).read_text(encoding="utf-8")
        assert "VULNFLOW_DEFAULT_PROJECT_DB" in text
        assert 'VULNFLOW_CONTROL_DB' in text
