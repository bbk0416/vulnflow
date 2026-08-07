from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.core.schema_versions import CURRENT_APP_VERSION
from scripts.dependency_lock import PUBLIC_CI_WORKFLOW, consistency_issues, summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify VulnFlow dependency lock consistency.")
    parser.add_argument(
        "--static-only",
        action="store_true",
        help="Check source, lock, Docker, CI, and SBOM consistency without comparing the active interpreter.",
    )
    args = parser.parse_args()

    check_installed = not args.static_only
    static_issues = consistency_issues(check_installed=False)
    installed_issues = consistency_issues(check_installed=True) if check_installed else []
    payload = summary(check_installed=check_installed)
    checks = {
        "static_consistency": not static_issues,
        "installed_consistency": None if not check_installed else not installed_issues,
        "runtime_lock_present": (ROOT / "requirements.lock").is_file(),
        "development_lock_present": (ROOT / "requirements-dev.lock").is_file(),
        "python_version_present": (ROOT / ".python-version").is_file(),
        "docker_uses_runtime_lock": "requirements.lock" in (ROOT / "Dockerfile").read_text(encoding="utf-8"),
        "ci_uses_development_lock": PUBLIC_CI_WORKFLOW.is_file()
        and "requirements-dev.lock" in PUBLIC_CI_WORKFLOW.read_text(encoding="utf-8"),
        "runtime_closure_nontrivial": int(payload["runtime_locked_packages"]) >= 20,
        "development_extends_runtime": int(payload["development_locked_packages"]) > int(payload["runtime_locked_packages"]),
        "artifact_hash_limit_disclosed": payload["artifact_hashes"] is False,
    }
    report = {
        "title": f"VulnFlow {CURRENT_APP_VERSION} dependency lock verification",
        "version": CURRENT_APP_VERSION,
        "mode": "static-only" if args.static_only else "installed",
        "checks": [
            {"name": key, "passed": value, "status": "NOT_CHECKED" if value is None else ("PASS" if value else "FAIL")}
            for key, value in checks.items()
        ],
        "summary": payload,
        "static_issues": static_issues,
        "installed_issues": installed_issues,
    }
    reports = ROOT / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    (reports / "dependency_lock_verification.json").write_text(
        json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    lines = [report["title"], "", f"mode: {report['mode']}"]
    for key, value in checks.items():
        status = "NOT_CHECKED" if value is None else ("PASS" if value else "FAIL")
        lines.append(f"{status}: {key}")
    lines.extend(
        [
            "",
            f"runtime_locked_packages: {payload['runtime_locked_packages']}",
            f"development_locked_packages: {payload['development_locked_packages']}",
            "artifact_hashes: unavailable in source locks; wheelhouse CI records downloaded artifact hashes per run",
        ]
    )
    (reports / "dependency_lock_verification.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")

    required_values = [value for value in checks.values() if value is not None]
    if not all(required_values):
        raise SystemExit(1)
    print(f"dependency lock smoke: {sum(bool(value) for value in required_values)}/{len(required_values)} ({report['mode']})")


if __name__ == "__main__":
    main()
