from __future__ import annotations

import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.dependency_lock import PUBLIC_CI_WORKFLOW, consistency_issues, summary


def main() -> None:
    issues = consistency_issues(check_installed=True)
    payload = summary(check_installed=True)
    checks = {
        "static_consistency": not consistency_issues(check_installed=False),
        "installed_consistency": not issues,
        "runtime_lock_present": (ROOT / "requirements.lock").is_file(),
        "development_lock_present": (ROOT / "requirements-dev.lock").is_file(),
        "python_version_present": (ROOT / ".python-version").is_file(),
        "docker_uses_runtime_lock": "requirements.lock" in (ROOT / "Dockerfile").read_text(encoding="utf-8"),
        "ci_uses_development_lock": PUBLIC_CI_WORKFLOW.is_file()
        and "requirements-dev.lock" in PUBLIC_CI_WORKFLOW.read_text(encoding="utf-8"),
        "runtime_closure_nontrivial": int(payload["runtime_locked_packages"]) >= 25,
        "development_extends_runtime": int(payload["development_locked_packages"]) > int(payload["runtime_locked_packages"]),
        "artifact_hash_limit_disclosed": payload["artifact_hashes"] is False,
    }
    report = {
        "title": "VulnFlow 72.0.13 dependency lock verification",
        "version": "72.0.13",
        "checks": [{"name": key, "passed": value} for key, value in checks.items()],
        "summary": payload,
    }
    reports = ROOT / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    (reports / "dependency_lock_verification.json").write_text(
        json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    lines = [report["title"], "", *[f"{'PASS' if value else 'FAIL'}: {key}" for key, value in checks.items()]]
    lines.append("")
    lines.append(f"runtime_locked_packages: {payload['runtime_locked_packages']}")
    lines.append(f"development_locked_packages: {payload['development_locked_packages']}")
    lines.append("artifact_hashes: unavailable in offline build environment")
    (reports / "dependency_lock_verification.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    if not all(checks.values()):
        raise SystemExit(1)
    print(f"dependency lock smoke: {sum(checks.values())}/{len(checks)}")


if __name__ == "__main__":
    main()
