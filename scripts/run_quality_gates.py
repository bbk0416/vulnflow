from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _run(label: str, command: list[str]) -> None:
    print(f"\n[{label}] {' '.join(command)}")
    completed = subprocess.run(command, cwd=ROOT, check=False)
    if completed.returncode:
        raise SystemExit(f"{label} failed with exit code {completed.returncode}")


def _module_command(module: str, *args: str) -> list[str]:
    return [sys.executable, "-m", module, *args]


def main() -> None:
    parser = argparse.ArgumentParser(description="Run VulnFlow public static quality gates.")
    parser.add_argument(
        "--skip-dependency-audit",
        action="store_true",
        help="Skip pip-audit only when the advisory service is unavailable.",
    )
    args = parser.parse_args()

    _run(
        "compileall",
        _module_command("compileall", "-q", "app", "scripts", "tests"),
    )
    _run(
        "static-security-boundary",
        [sys.executable, "scripts/static_security_boundary_audit.py"],
    )
    _run(
        "ruff-fatal",
        _module_command(
            "ruff",
            "check",
            "app",
            "scripts",
            "tests",
            "--select",
            "E9,F63,F7,F82",
        ),
    )
    _run(
        "bandit-high",
        _module_command(
            "bandit",
            "-q",
            "-r",
            "app",
            "scripts",
            "-lll",
            "-iii",
        ),
    )
    if args.skip_dependency_audit:
        print("\n[pip-audit] SKIPPED by explicit offline option")
    else:
        _run(
            "pip-audit",
            _module_command(
                "pip_audit",
                "-r",
                "requirements.txt",
                "--progress-spinner",
                "off",
            ),
        )

    print("\nVulnFlow public static quality gates: PASS")


if __name__ == "__main__":
    main()
