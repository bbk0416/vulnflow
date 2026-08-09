from __future__ import annotations

"""Run the Chromium workflow tests and emit explicit environment evidence.

A browser managed policy can block every URL before application assertions run.
That is not a product pass or a product failure.  This runner records that state
as ``blocked`` so release automation cannot silently treat it as success.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[1]
FORMAT = "vulnflow-browser-e2e-evidence/1"
DEFAULT_POLICY_ROOTS = (
    Path("/etc/chromium/policies"),
    Path("/etc/opt/chrome/policies"),
    Path("/Library/Managed Preferences"),
)


def _write_report(path: Path | None, payload: dict[str, Any]) -> None:
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )


def _policy_blocks_all_urls(payload: Any) -> bool:
    if not isinstance(payload, dict):
        return False
    values = payload.get("URLBlocklist")
    return isinstance(values, list) and any(str(item).strip() == "*" for item in values)


def find_blocking_browser_policies(
    roots: Iterable[Path] = DEFAULT_POLICY_ROOTS,
) -> list[str]:
    """Return managed policy files that explicitly block every URL."""

    matches: list[str] = []
    for root in roots:
        if not root.exists():
            continue
        candidates = [root] if root.is_file() else sorted(root.rglob("*.json"))
        for path in candidates:
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError):
                continue
            if _policy_blocks_all_urls(payload):
                matches.append(str(path))
    return sorted(set(matches))


def _pytest_counts(output: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for name in ("passed", "failed", "skipped", "error", "errors"):
        matches = re.findall(rf"(\d+)\s+{name}\b", output)
        if matches:
            normalized = "errors" if name in {"error", "errors"} else name
            counts[normalized] = max(int(item) for item in matches)
    return counts


def run_browser_e2e(
    *,
    chromium: str = "",
    timeout_seconds: int = 900,
    policy_roots: Iterable[Path] = DEFAULT_POLICY_ROOTS,
) -> dict[str, Any]:
    started = time.monotonic()
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    blocking = find_blocking_browser_policies(policy_roots)
    payload: dict[str, Any] = {
        "format": FORMAT,
        "version": version,
        "passed": False,
        "status": "failed",
        "checks": [],
        "pytest_counts": {},
    }

    def check(name: str, passed: bool, detail: str = "") -> None:
        payload["checks"].append(
            {"name": name, "passed": bool(passed), "detail": detail}
        )

    if blocking:
        payload.update(
            {
                "status": "blocked",
                "reason": "managed browser policy blocks all URLs",
                "blocking_policy_files": blocking,
            }
        )
        check("browser_navigation_allowed", False, "URLBlocklist contains '*'")
        payload["duration_seconds"] = round(time.monotonic() - started, 3)
        return payload

    command = [
        sys.executable,
        "-m",
        "pytest",
        "-q",
        "-p",
        "no:cacheprovider",
        "tests/e2e",
    ]
    env = os.environ.copy()
    selected = chromium.strip() or env.get("VULNFLOW_E2E_CHROMIUM", "").strip()
    if selected:
        env["VULNFLOW_E2E_CHROMIUM"] = selected
    payload["chromium_executable"] = selected or "playwright-managed"

    try:
        result = subprocess.run(
            command,
            cwd=ROOT,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=max(30, int(timeout_seconds)),
            check=False,
        )
        output = result.stdout or ""
        payload["exit_code"] = result.returncode
        payload["output_tail"] = output[-12000:]
        payload["pytest_counts"] = _pytest_counts(output)
        if result.returncode == 0:
            payload["status"] = "passed"
            payload["passed"] = True
            check("browser_workflows", True, "pytest exit 0")
        elif "ERR_BLOCKED_BY_ADMINISTRATOR" in output:
            payload["status"] = "blocked"
            payload["reason"] = "browser navigation blocked by administrator policy"
            check("browser_navigation_allowed", False, "ERR_BLOCKED_BY_ADMINISTRATOR")
        else:
            payload["status"] = "failed"
            payload["reason"] = f"pytest exit {result.returncode}"
            check("browser_workflows", False, payload["reason"])
    except subprocess.TimeoutExpired as exc:
        output = ""
        if isinstance(exc.stdout, bytes):
            output = exc.stdout.decode("utf-8", errors="replace")
        elif isinstance(exc.stdout, str):
            output = exc.stdout
        payload.update(
            {
                "status": "failed",
                "reason": f"browser E2E exceeded {timeout_seconds}s",
                "output_tail": output[-12000:],
            }
        )
        check("browser_workflows", False, payload["reason"])
    except OSError as exc:
        payload.update({"status": "unavailable", "reason": str(exc)})
        check("browser_runtime_available", False, str(exc))

    payload["duration_seconds"] = round(time.monotonic() - started, 3)
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json-output", type=Path)
    parser.add_argument("--chromium", default="")
    parser.add_argument("--timeout-seconds", type=int, default=900)
    parser.add_argument(
        "--allow-environment-blocked",
        action="store_true",
        help="Return zero for a recorded blocked/unavailable environment; the report remains non-passing.",
    )
    args = parser.parse_args()

    report = run_browser_e2e(
        chromium=args.chromium,
        timeout_seconds=args.timeout_seconds,
    )
    _write_report(args.json_output, report)
    output = str(report.get("output_tail") or "")
    if output:
        print(output, end="" if output.endswith("\n") else "\n")
    print(
        f"browser E2E: {str(report['status']).upper()} "
        f"({report.get('duration_seconds', 0)}s)"
    )
    if report["passed"]:
        return 0
    if report["status"] in {"blocked", "unavailable"}:
        return 0 if args.allow_environment_blocked else 3
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
