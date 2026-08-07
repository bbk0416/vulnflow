from __future__ import annotations

"""Run the self-contained pre-pilot production validation checks."""

import argparse
import json
from pathlib import Path
import shutil
import sys
import tempfile
from typing import Any

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.docker_upgrade_rehearsal import run_docker_rehearsal, run_host_rehearsal  # noqa: E402
from scripts.scanner_fixture_matrix import run_matrix  # noqa: E402
from scripts.scanner_parser_robustness import run_robustness_matrix  # noqa: E402
from scripts.scanner_anonymization_rehearsal import run_anonymization_rehearsal  # noqa: E402


def run_validation(*, work_dir: Path, docker_mode: str = "auto") -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    host = run_host_rehearsal(work_dir / "host-upgrade")
    checks.append({"name": "schema42_to_current_host_upgrade", "passed": bool(host.get("passed")), "details": host})

    fixtures = run_matrix()
    checks.append({"name": "synthetic_scanner_fixture_matrix", "passed": bool(fixtures.get("passed")), "details": fixtures})

    robustness = run_robustness_matrix()
    checks.append({"name": "scanner_parser_robustness", "passed": bool(robustness.get("passed")), "details": robustness})

    anonymization = run_anonymization_rehearsal()
    checks.append({"name": "scanner_anonymization_rehearsal", "passed": bool(anonymization.get("passed")), "details": anonymization})

    docker_available = bool(shutil.which("docker"))
    if docker_mode == "required" and not docker_available:
        checks.append({"name": "docker_upgrade_rehearsal", "passed": False, "details": {"reason": "docker command not found"}})
    elif docker_mode != "skip" and docker_available:
        try:
            docker = run_docker_rehearsal(
                work_dir / "docker-upgrade",
                image="vulnflow:production-validation",
                build=True,
            )
            checks.append({"name": "docker_upgrade_rehearsal", "passed": bool(docker.get("passed")), "details": docker})
        except Exception as exc:  # boundary script must report the failed external tool cleanly
            checks.append({"name": "docker_upgrade_rehearsal", "passed": False, "details": {"reason": str(exc)}})
    else:
        checks.append({"name": "docker_upgrade_rehearsal", "passed": None, "details": {"reason": "skipped: docker unavailable or disabled"}})

    required = [item for item in checks if item["passed"] is not None]
    return {
        "format": "vulnflow-production-validation/1",
        "passed": all(bool(item["passed"]) for item in required),
        "checks": checks,
        "limits": [
            "scanner fixtures are synthetic and do not certify every vendor export version",
            "anonymized bundles require human review before sharing",
            "SMTP and Jira diagnostics require customer-provided endpoints and credentials",
            "Docker status is only conclusive when the Docker rehearsal runs",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path)
    parser.add_argument("--docker", choices=("auto", "required", "skip"), default="auto")
    parser.add_argument("--json-output", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="vulnflow_production_validation_") as temporary:
        work_dir = args.work_dir or Path(temporary)
        work_dir.mkdir(parents=True, exist_ok=True)
        report = run_validation(work_dir=work_dir, docker_mode=args.docker)
    if args.json_output:
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        args.json_output.write_text(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    for check in report["checks"]:
        state = "SKIP" if check["passed"] is None else ("PASS" if check["passed"] else "FAIL")
        print(f"{state}: {check['name']}")
    print(f"production validation: {'PASS' if report['passed'] else 'FAIL'}")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
