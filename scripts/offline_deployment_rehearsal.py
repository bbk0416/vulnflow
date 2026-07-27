from __future__ import annotations

"""Rehearse a complete VulnFlow deployment from the signed offline release kit."""

import argparse
import json
import shutil
import tempfile
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.core.public_signing import public_key_fingerprint
from scripts.offline_deployment_bootstrap import deploy_release_kit
from scripts.release_distribution_bundle import (
    build_index,
    build_project_archive,
    build_release_kit,
    keypair,
    sign_index,
    stage_artifacts,
    write_distribution_metadata,
)
from scripts.release_provenance import sha256_file

REPORT_JSON = ROOT / "reports" / "offline_deployment_bootstrap_verification.json"
REPORT_TEXT = ROOT / "reports" / "offline_deployment_bootstrap_verification.txt"
DOC_PATH = ROOT / "docs" / "91_SIGNED_OFFLINE_DEPLOYMENT_BOOTSTRAP.md"


def run_rehearsal(root: Path = ROOT, *, keep_workspace: bool = False) -> dict[str, Any]:
    version = (root / "VERSION").read_text(encoding="utf-8").strip()
    workspace_obj = tempfile.TemporaryDirectory(prefix="vulnflow-offline-bootstrap-")
    workspace = Path(workspace_obj.name)
    try:
        project_a = workspace / "project-a.zip"
        project_b = workspace / "project-b.zip"
        project_result_a = build_project_archive(root, project_a)
        project_result_b = build_project_archive(root, project_b)
        staging = workspace / "staging"
        artifacts = stage_artifacts(root, project_a, staging)
        private_key, public_key = keypair()
        index = build_index(root, artifacts, trust_state="rehearsal-key-untrusted")
        envelope = sign_index(index, private_key)
        write_distribution_metadata(staging, index, envelope, public_key)
        kit_a = workspace / "release-kit-a.zip"
        kit_b = workspace / "release-kit-b.zip"
        kit_result_a = build_release_kit(staging, kit_a, version=version)
        kit_result_b = build_release_kit(staging, kit_b, version=version)
        target = workspace / "deployment"
        deployment = deploy_release_kit(
            kit_a,
            target,
            expected_kit_sha256=sha256_file(kit_a),
            expected_public_key_fingerprint=public_key_fingerprint(public_key),
            expected_version=version,
            run_cycles=2,
        )
        checks = {
            "project_archive_reproducible": project_result_a["sha256"] == project_result_b["sha256"],
            "release_kit_reproducible": kit_result_a["sha256"] == kit_result_b["sha256"],
            "release_kit_nontrivial": kit_result_a["size"] >= 25 * 1024 * 1024,
            "signed_artifact_roles_complete": len(artifacts) >= 16,
            "bootstrap_script_signed": any(item["role"] == "offline_deployment_bootstrap" for item in artifacts),
            "bootstrap_all_checks_passed": deployment["checks_failed"] == 0,
            "bootstrap_two_cycles": len(deployment["cycles"]) == 2,
            "bootstrap_restart_persistence": deployment["cycles"][-1]["persistence_verified"] is True,
            "bootstrap_authentication_closed": all(item["anonymous_root_status"] == 401 for item in deployment["cycles"]),
            "bootstrap_authenticated_access": all(item["authenticated_root_status"] == 200 for item in deployment["cycles"]),
            "bootstrap_healthchecks": all(item["live_status"] == 200 and item["ready_status"] == 200 for item in deployment["cycles"]),
            "bootstrap_sigterm_bounded": all(item["shutdown_ms"] <= 12_000 for item in deployment["cycles"]),
            "bootstrap_sqlite_integrity": deployment["sqlite"]["integrity"] == "ok",
            "bootstrap_schema_current": deployment["sqlite"]["schema_version"] == 40,
            "bootstrap_credentials_private": Path(deployment["credentials_file"]).stat().st_mode & 0o077 == 0,
            "bootstrap_runtime_config_private": (target / "config" / "runtime_environment.json").stat().st_mode & 0o077 == 0,
            "bootstrap_operator_run_script": (target / "bin" / "run.sh").is_file(),
            "bootstrap_operator_verify_script": (target / "bin" / "verify_installation.sh").is_file(),
        }
        passed = sum(checks.values())
        result = {
            "format": "vulnflow-offline-deployment-bootstrap-rehearsal/1",
            "version": version,
            "checks_total": len(checks),
            "checks_passed": passed,
            "checks_failed": len(checks) - passed,
            "checks": [{"name": name, "passed": bool(value)} for name, value in checks.items()],
            "project_archive_sha256": project_result_a["sha256"],
            "release_kit_sha256": kit_result_a["sha256"],
            "release_public_key_fingerprint": public_key_fingerprint(public_key),
            "deployment": deployment,
            "private_key_persisted": False,
            "scope": "Linux CPython signed offline release-kit deployment bootstrap",
            "limits": [
                "the rehearsal uses an in-memory untrusted release key rather than an organizational trust root",
                "the runtime snapshot remains platform-specific and is not an upstream package-index wheelhouse",
                "the service is bound to loopback and does not validate TLS termination or a real container engine",
            ],
        }
        if passed != len(checks):
            failed = [name for name, value in checks.items() if not value]
            raise RuntimeError("offline deployment rehearsal failed: " + ", ".join(failed))
        _write_reports(result)
        if keep_workspace:
            kept = root / "dist" / "offline-deployment-rehearsal-workspace"
            if kept.exists():
                shutil.rmtree(kept)
            shutil.copytree(workspace, kept)
            result["workspace"] = str(kept)
        return result
    finally:
        workspace_obj.cleanup()


def _write_reports(result: dict[str, Any]) -> None:
    REPORT_JSON.parent.mkdir(parents=True, exist_ok=True)
    REPORT_JSON.write_text(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    deployment = result["deployment"]
    lines = [
        f"VulnFlow {result['version']} signed offline deployment bootstrap rehearsal",
        "",
        f"checks: {result['checks_passed']}/{result['checks_total']} PASS",
        f"release_kit_sha256: {result['release_kit_sha256']}",
        f"release_public_key_fingerprint: {result['release_public_key_fingerprint']}",
        f"runtime_packages: {deployment['runtime_snapshot']['packages']}",
        f"runtime_files: {deployment['runtime_snapshot']['files']}",
        f"restored_files: {deployment['runtime_snapshot']['restored_files']}",
        f"cycles: {len(deployment['cycles'])}",
        f"restart_persistence: {deployment['cycles'][-1]['persistence_verified']}",
        f"sqlite_integrity: {deployment['sqlite']['integrity']}",
        f"schema_version: {deployment['sqlite']['schema_version']}",
        "initial_credentials_exposed_in_report: false",
        "trust_state: rehearsal-key-untrusted",
    ]
    REPORT_TEXT.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Rehearse VulnFlow signed offline release-kit deployment.")
    parser.add_argument("--keep-workspace", action="store_true")
    args = parser.parse_args()
    result = run_rehearsal(keep_workspace=args.keep_workspace)
    print(
        f"VulnFlow {result['version']} offline deployment bootstrap rehearsal: "
        f"{result['checks_passed']}/{result['checks_total']} PASS"
    )


if __name__ == "__main__":
    main()
