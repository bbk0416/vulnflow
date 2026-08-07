from __future__ import annotations

"""Validate the synthetic scanner compatibility fixture matrix."""

import argparse
import json
from pathlib import Path
import sys
from typing import Any

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.scanner_compatibility_report import inspect_file  # noqa: E402

DEFAULT_FIXTURE_DIR = ROOT / "tests" / "fixtures" / "scanners"


def run_matrix(fixture_dir: Path = DEFAULT_FIXTURE_DIR) -> dict[str, Any]:
    expected_path = fixture_dir / "expected.json"
    expected = json.loads(expected_path.read_text(encoding="utf-8"))
    results: list[dict[str, Any]] = []
    failures: list[str] = []
    keys = ("detected_format", "status", "importable_rows", "unsupported_source_items")
    for filename, contract in sorted(expected.items()):
        path = fixture_dir / filename
        try:
            report = inspect_file(path)
        except (OSError, ValueError) as exc:
            failures.append(f"{filename}: inspection failed: {exc}")
            continue
        observed = {key: report.get(key) for key in keys}
        wanted = {key: contract.get(key) for key in keys}
        mismatches = {
            key: {"expected": wanted[key], "actual": observed[key]}
            for key in keys if observed[key] != wanted[key]
        }
        results.append({
            "filename": filename,
            "passed": not mismatches,
            "expected": wanted,
            "observed": observed,
            "mismatches": mismatches,
        })
        failures.extend(
            f"{filename}: {key}: expected {values['expected']!r}, got {values['actual']!r}"
            for key, values in mismatches.items()
        )
    return {
        "format": "vulnflow-scanner-fixture-matrix/1",
        "fixture_scope": "synthetic regression fixtures; not a vendor-version certification",
        "passed": not failures,
        "fixtures": len(expected),
        "results": results,
        "failures": failures,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture-dir", type=Path, default=DEFAULT_FIXTURE_DIR)
    parser.add_argument("--json-output", type=Path)
    args = parser.parse_args()
    report = run_matrix(args.fixture_dir)
    if args.json_output:
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        args.json_output.write_text(
            json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
    for item in report["results"]:
        state = "PASS" if item["passed"] else "FAIL"
        print(f"{state}: {item['filename']} -> {item['observed']['status']} ({item['observed']['detected_format']})")
    for failure in report["failures"]:
        print(f"FAIL: {failure}", file=sys.stderr)
    print(f"scanner fixture matrix: {'PASS' if report['passed'] else 'FAIL'} ({report['fixtures']} fixtures)")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
