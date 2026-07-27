from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.core.database_schema import CURRENT_APP_VERSION


def _contains(path: Path, marker: str) -> bool:
    return path.exists() and marker in path.read_text(encoding="utf-8")


def _public_checks(version: str) -> list[tuple[str, bool]]:
    workflow = ROOT / ".github/workflows/public-ci.yml"
    workflow_text = workflow.read_text(encoding="utf-8") if workflow.exists() else ""
    base = (ROOT / "app/templates/base.html").read_text(encoding="utf-8")
    main_text = (ROOT / "app/main.py").read_text(encoding="utf-8")
    osv = (ROOT / "app/services/osv.py").read_text(encoding="utf-8")
    evidence = (ROOT / "app/services/evidence.py").read_text(encoding="utf-8")
    return [
        ("canonical_version", version == CURRENT_APP_VERSION),
        ("dynamic_template_version", "{{ app_version }}" in base),
        ("stale_ui_version_absent", "<span>44.0</span>" not in base),
        ("template_global", 'templates.env.globals["app_version"] = CURRENT_APP_VERSION' in main_text),
        ("dynamic_osv_user_agent", 'f"VulnFlow/{CURRENT_APP_VERSION}"' in osv and "VulnFlow/21.0" not in osv),
        ("runtime_lock_header", (ROOT / "requirements.lock").read_text(encoding="utf-8").startswith(f"# VulnFlow {version}")),
        ("dev_lock_header", (ROOT / "requirements-dev.lock").read_text(encoding="utf-8").startswith(f"# VulnFlow {version}")),
        ("baseline_not_clean", '"BASELINE_ONLY"' in evidence),
        ("public_ci_exists", workflow.exists()),
        ("public_ci_minimal_permissions", "contents: read" in workflow_text),
        ("public_ci_python_312", '"3.12"' in workflow_text),
        ("public_ci_python_313", '"3.13"' in workflow_text),
        ("public_ci_windows", "windows-latest" in workflow_text),
        ("public_ci_architecture", "architecture_review.py" in workflow_text),
        ("public_ci_manifest", "verify_public_manifest.py" in workflow_text),
        ("python_floor_windows_ps1", "Python 3.12" in (ROOT / "run_windows.ps1").read_text(encoding="utf-8")),
        ("python_floor_windows_bat", "Python 3.12" in (ROOT / "run_windows.bat").read_text(encoding="utf-8")),
        ("python_floor_linux", "Python 3.12" in (ROOT / "run_linux.sh").read_text(encoding="utf-8")),
    ]


def _internal_checks(version: str) -> list[tuple[str, bool]]:
    manifest_path = ROOT / "reports/release_manifest.json"
    full_pytest_path = ROOT / "reports/full_pytest_verification.txt"
    if not manifest_path.exists() or not full_pytest_path.exists():
        raise FileNotFoundError("internal readiness requires reports/release_manifest.json and reports/full_pytest_verification.txt")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    full_pytest = full_pytest_path.read_text(encoding="utf-8")
    full_ci = ROOT / ".github/workflows/full-release.yml"
    coverage_script = ROOT / "scripts/coverage_verification.py"
    checks = _public_checks(version)
    checks.extend([
        ("release_manifest_version", version == str(manifest.get("version"))),
        ("current_pytest_report", f"VulnFlow {version} full pytest verification" in full_pytest),
        ("pytest_count", f"{manifest['tests']['passed']} passed" in full_pytest),
        ("full_ci_workflow", full_ci.exists() and "verify_release.py --full" in full_ci.read_text(encoding="utf-8")),
        ("coverage_workflow", coverage_script.exists() and full_ci.exists() and "coverage_verification.py" in full_ci.read_text(encoding="utf-8")),
    ])
    return checks


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify public or internal submission readiness.")
    parser.add_argument("--public", action="store_true", help="Run checks that are self-contained in the public repository.")
    args = parser.parse_args()

    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    internal_artifacts_exist = (ROOT / "reports/release_manifest.json").exists()
    mode = "public" if args.public or not internal_artifacts_exist else "internal"
    checks = _public_checks(version) if mode == "public" else _internal_checks(version)
    failed = [name for name, passed in checks if not passed]
    lines = [f"VulnFlow {version} {mode} submission readiness verification", ""]
    lines.extend(f"{name}: {'PASS' if passed else 'FAIL'}" for name, passed in checks)
    lines.extend(["", f"passed: {len(checks)-len(failed)}/{len(checks)}"])
    output = "\n".join(lines) + "\n"
    reports = ROOT / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    (reports / "submission_readiness_verification.txt").write_text(output, encoding="utf-8")
    print(output, end="")
    if failed:
        raise SystemExit("submission readiness failed: " + ", ".join(failed))


if __name__ == "__main__":
    main()
