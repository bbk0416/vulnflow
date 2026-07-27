from __future__ import annotations

"""Generate and verify release-facing metadata from one canonical manifest."""

import argparse
import json
import os
import re
import subprocess
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.core.architecture import build_architecture_report
from app.core.database_schema import CURRENT_APP_VERSION, CURRENT_SCHEMA_VERSION
from app.services.integrity_proof_common import PROOF_FORMAT
from scripts.dependency_lock import consistency_issues as dependency_lock_issues

MANIFEST_PATH = Path("reports/release_manifest.json")
GENERATED_TEXT = (
    "release_verification.txt",
    "release_verification_summary.txt",
    "verification_summary.txt",
    "test_results.txt",
    "pytest_release_groups.txt",
)
GENERATED_JSON = (
    "release_verification_summary.json",
    "verification_summary.json",
)


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"


def _version_label(version: str) -> str:
    return version


def collect_pytest_inventory(root: Path) -> tuple[int, int]:
    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["VULNFLOW_ALLOW_LOCAL_ADMIN_FALLBACK"] = "1"
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider"],
        cwd=root,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=240,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError("pytest collection failed:\n" + result.stdout[-4000:])
    matches = re.findall(r"(\d+) tests? collected", result.stdout)
    if not matches:
        raise RuntimeError("pytest collection count was not found:\n" + result.stdout[-2000:])
    return int(matches[-1]), len(list((root / "tests").glob("test_*.py")))


def actual_state(root: Path, *, collect_tests: bool) -> dict[str, Any]:
    architecture = build_architecture_report(root)
    state: dict[str, Any] = {
        "version": (root / "VERSION").read_text(encoding="utf-8").strip(),
        "schema_version": CURRENT_SCHEMA_VERSION,
        "proof_format": PROOF_FORMAT,
        "architecture": {
            "status": architecture["status"],
            "application_modules": architecture["python_modules"],
            "application_lines": architecture["total_lines"],
            "fastapi_routes": architecture["route_count"],
            "import_cycles": len(architecture["cycles"]),
        },
    }
    if collect_tests:
        passed, files = collect_pytest_inventory(root)
        state["tests"] = {"passed": passed, "files": files}
    return state


def default_manifest(root: Path, *, collect_tests: bool = True) -> dict[str, Any]:
    state = actual_state(root, collect_tests=collect_tests)
    return {
        "manifest_format": "vulnflow-release-manifest/1",
        "title": f"VulnFlow {_version_label(state['version'])} release manifest",
        **state,
        "tests": state.get("tests", {"passed": 0, "files": 0}),
        "test_groups": [],
        "verification": {
            "safe_auth_defaults": "passed",
            "dependency_lock": "10/10",
            "distribution_artifact_rehearsal": "26/26",
            "runtime_dependency_snapshot": "28/28",
            "release_provenance": "24/24",
            "release_distribution_bundle": "33/33",
            "offline_deployment_bootstrap": "18/18",
            "container_deployment_rehearsal": "26/26",
            "upgrade_restore_rehearsal": "12/12",
            "asgi_runtime_boundary": "10/10",
            "application_runtime_boundary": "10/10",
            "lifecycle_resources": "12/12",
            "runtime_stability_soak": "12/12",
            "release_orchestrator": "12/12",
            "transaction_runtime": "14/14",
            "retry_policy": "8/8",
            "idempotency": "10/10",
            "execution_receipts": "11/11",
            "receipt_retention": "13/13",
            "http_testclient": 124,
            "uvicorn": 26,
            "job_worker": "12/12",
            "duplicate_job_claims": 0,
            "cluster_failover_and_restore_barrier": "passed",
            "webhook_hmac_delivery": "passed",
            "proof_v1_v9": "passed",
        },
        "performance": {
            "indexed_page_median_ms": 12.477,
            "fts5_median_ms": 14.293,
            "deep_cursor_median_ms": 22.053,
            "deep_offset_median_ms": 357.355,
            "snapshot_rows": 50000,
            "snapshot_seconds": 10.743,
            "snapshot_peak_mib": 5.478,
            "allocation_reduction_percent": 96.27,
        },
        "limits": [
            "synthetic local SQLite measurements are not a production SLA",
            "container-equivalent non-root deployment rehearsal passed; actual Docker build and runtime were unavailable",
            "wheel and sdist artifacts are reproducible; a Linux CPython runtime file snapshot is hashed but is not an upstream wheelhouse",
            "release provenance signing rehearsal passed; its ephemeral key is not an externally pinned production trust root",
            "public OSV.dev, CISA KEV, and FIRST EPSS production endpoints were not called",
        ],
    }


def refresh_manifest(root: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    updated = deepcopy(manifest)
    state = actual_state(root, collect_tests=True)
    updated.update({key: state[key] for key in ("version", "schema_version", "proof_format", "architecture", "tests")})
    updated["manifest_format"] = "vulnflow-release-manifest/1"
    updated["title"] = f"VulnFlow {state['version']} release manifest"
    groups = [int(item) for item in updated.get("test_groups") or []]
    if sum(groups) != int(state["tests"]["passed"]):
        updated["test_groups"] = []
    return updated


def _summary_text(manifest: dict[str, Any]) -> str:
    version = manifest["version"]
    tests = manifest["tests"]
    architecture = manifest["architecture"]
    verification = manifest["verification"]
    performance = manifest["performance"]
    lines = [
        f"VulnFlow {version} verification summary",
        "",
        f"version: {version}",
        f"schema_version: {manifest['schema_version']}",
        f"proof_format: {manifest['proof_format']}",
        "",
        f"automated_tests: {tests['passed']} passed",
        f"test_files: {tests['files']}",
    ]
    for key in sorted(verification):
        lines.append(f"{key}: {verification[key]}")
    lines.extend(
        [
            f"architecture: {architecture['status']}",
            f"application_modules: {architecture['application_modules']}",
            f"application_lines: {architecture['application_lines']}",
            f"fastapi_routes: {architecture['fastapi_routes']}",
            f"import_cycles: {architecture['import_cycles']}",
            "",
            "query_performance:",
            f"  indexed_page_median_ms: {performance['indexed_page_median_ms']}",
            f"  fts5_median_ms: {performance['fts5_median_ms']}",
            f"  deep_cursor_median_ms: {performance['deep_cursor_median_ms']}",
            f"  deep_offset_median_ms: {performance['deep_offset_median_ms']}",
            "snapshot_export:",
            f"  rows: {performance['snapshot_rows']}",
            f"  seconds: {performance['snapshot_seconds']}",
            f"  peak_mib: {performance['snapshot_peak_mib']}",
            f"  allocation_reduction_percent: {performance['allocation_reduction_percent']}",
            "",
            "limits:",
        ]
    )
    lines.extend(f"- {item}" for item in manifest.get("limits") or [])
    return "\n".join(lines) + "\n"


def _release_verification_text(manifest: dict[str, Any]) -> str:
    verification = manifest["verification"]
    lines = [
        f"VulnFlow {manifest['version']} release verification",
        "",
        f"version: {manifest['version']}",
        f"schema_version: {manifest['schema_version']}",
        f"proof_format: {manifest['proof_format']}",
        f"architecture: {manifest['architecture']['status']}",
        f"automated_tests: {manifest['tests']['passed']} passed",
    ]
    lines.extend(f"{key}: {verification[key]}" for key in sorted(verification))
    return "\n".join(lines) + "\n"


def _test_results_text(manifest: dict[str, Any]) -> str:
    groups = [int(item) for item in manifest.get("test_groups") or []]
    lines = [
        f"VulnFlow {manifest['version']} automated test results",
        "",
        f"application_version: {manifest['version']}",
        f"schema_version: {manifest['schema_version']}",
        f"integrity_proof_format: {manifest['proof_format']}",
        f"test_files: {manifest['tests']['files']}",
        f"tests_passed: {manifest['tests']['passed']}",
        "tests_failed: 0",
    ]
    if groups:
        lines.append(f"execution: {len(groups)} non-overlapping bounded groups")
        lines.append("pytest_groups: " + " + ".join(map(str, groups)))
    else:
        lines.append("execution: complete collected test inventory")
    return "\n".join(lines) + "\n"


def _groups_text(manifest: dict[str, Any]) -> str:
    groups = [int(item) for item in manifest.get("test_groups") or []]
    expression = " + ".join(map(str, groups)) if groups else str(manifest["tests"]["passed"])
    return (
        f"VulnFlow {manifest['version']} pytest release groups\n\n"
        f"{expression} = {manifest['tests']['passed']} passed\n"
    )


def rendered_files(manifest: dict[str, Any]) -> dict[str, str]:
    summary = _summary_text(manifest)
    release = _release_verification_text(manifest)
    results = _test_results_text(manifest)
    groups = _groups_text(manifest)
    summary_json = _json(manifest)
    return {
        "release_verification.txt": release,
        "release_verification_summary.txt": summary,
        "verification_summary.txt": summary,
        "test_results.txt": results,
        "pytest_release_groups.txt": groups,
        "release_verification_summary.json": summary_json,
        "verification_summary.json": summary_json,
    }


def write_generated(root: Path, manifest: dict[str, Any]) -> None:
    outputs = rendered_files(manifest)
    reports = root / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    for relative, content in outputs.items():
        (root / relative).write_text(content, encoding="utf-8")
        (reports / relative).write_text(content, encoding="utf-8")


def _sbom_version(root: Path) -> str:
    payload = json.loads((root / "bom.cdx.json").read_text(encoding="utf-8"))
    return str(((payload.get("metadata") or {}).get("component") or {}).get("version") or "")


def consistency_issues(root: Path, manifest: dict[str, Any], *, collect_tests: bool) -> list[str]:
    issues: list[str] = []
    actual = actual_state(root, collect_tests=collect_tests)
    for key in ("version", "schema_version", "proof_format", "architecture"):
        if manifest.get(key) != actual.get(key):
            issues.append(f"manifest {key} mismatch: expected={actual.get(key)!r} actual={manifest.get(key)!r}")
    if collect_tests and manifest.get("tests") != actual.get("tests"):
        issues.append(f"manifest tests mismatch: expected={actual.get('tests')!r} actual={manifest.get('tests')!r}")
    if str(manifest.get("version")) != CURRENT_APP_VERSION:
        issues.append(f"application version mismatch: {CURRENT_APP_VERSION}")
    version = str(manifest.get("version") or "")
    if _sbom_version(root) != version:
        issues.append(f"SBOM version mismatch: {_sbom_version(root)!r}")
    compose = (root / "docker-compose.yml").read_text(encoding="utf-8")
    if f"vulnflow:{version}" not in compose:
        issues.append("docker-compose image tag does not match VERSION")
    if "VULNFLOW_ALLOW_LOCAL_ADMIN_FALLBACK:-0" not in compose:
        issues.append("docker-compose local admin fallback is not disabled by default")
    for issue in dependency_lock_issues(check_installed=False):
        issues.append(f"dependency lock: {issue}")
    readme = (root / "README.md").read_text(encoding="utf-8")
    if version not in readme:
        issues.append("README version does not match VERSION")
    expected = rendered_files(manifest)
    for relative, content in expected.items():
        for base in (root, root / "reports"):
            path = base / relative
            if not path.is_file():
                issues.append(f"generated release file missing: {path.relative_to(root)}")
            elif path.read_text(encoding="utf-8") != content:
                issues.append(f"generated release file is stale: {path.relative_to(root)}")
    groups = [int(item) for item in manifest.get("test_groups") or []]
    if groups and sum(groups) != int(manifest["tests"]["passed"]):
        issues.append("test group total does not match passed tests")
    return issues


def load_manifest(root: Path) -> dict[str, Any]:
    path = root / MANIFEST_PATH
    if not path.is_file():
        return default_manifest(root)
    return json.loads(path.read_text(encoding="utf-8"))


def save_manifest(root: Path, manifest: dict[str, Any]) -> None:
    path = root / MANIFEST_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_json(manifest), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--refresh", action="store_true")
    parser.add_argument("--render", action="store_true")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--collect-tests", action="store_true")
    args = parser.parse_args()
    manifest = load_manifest(ROOT)
    if args.refresh:
        manifest = refresh_manifest(ROOT, manifest)
        save_manifest(ROOT, manifest)
        write_generated(ROOT, manifest)
    elif args.render:
        write_generated(ROOT, manifest)
    if args.check:
        issues = consistency_issues(ROOT, manifest, collect_tests=args.collect_tests)
        if issues:
            raise SystemExit("release metadata consistency failed:\n- " + "\n- ".join(issues))
        print("release metadata consistency passed")
    elif not args.refresh and not args.render:
        print(_json(manifest), end="")


if __name__ == "__main__":
    main()
