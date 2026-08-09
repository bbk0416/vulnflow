from __future__ import annotations

"""Independently verify a VulnFlow external-validation evidence directory.

This verifier checks internal integrity and execution/report binding. It does
not turn the unsigned local evidence directory into an external trust anchor;
an operator still needs trusted transport or an independently signed archive.
"""

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.core.schema_versions import CURRENT_SCHEMA_VERSION
from scripts.external_validation_gate import (
    FORMAT as GATE_FORMAT,
    OUTPUT_MARKER,
    OUTPUT_MARKER_FORMAT,
    REQUIRED_CHECKS,
    REPORT_REQUIRED_CHECKS,
    EXECUTION_REQUIRED_CHECKS,
    TERMINAL_STATUSES,
    _aggregate_contract_issues,
    _load_required_report,
    _read_json,
    _report_contract_issues,
    _sha256,
    _status_from_report,
)

FORMAT = "vulnflow-external-validation-evidence-verifier/1"
MANIFEST_LINE = re.compile(r"^([0-9a-f]{64})  (.+)$")


def _safe_relative(value: str) -> bool:
    path = PurePosixPath(value)
    return bool(value) and not path.is_absolute() and ".." not in path.parts and "\\" not in value


def _load_manifest(path: Path) -> tuple[dict[str, str], list[str]]:
    issues: list[str] = []
    entries: dict[str, str] = {}
    if path.is_symlink() or not path.is_file():
        return {}, ["SHA256SUMS.txt is missing or not a regular file"]
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return {}, ["SHA256SUMS.txt could not be read as UTF-8"]
    for number, line in enumerate(lines, 1):
        match = MANIFEST_LINE.fullmatch(line)
        if not match:
            issues.append(f"invalid manifest line {number}")
            continue
        digest, relative = match.groups()
        if not _safe_relative(relative):
            issues.append(f"unsafe manifest path at line {number}")
            continue
        if relative in entries:
            issues.append(f"duplicate manifest path: {relative}")
            continue
        entries[relative] = digest
    return entries, issues


def verify_evidence_directory(
    directory: Path,
    *,
    source_root: Path | None = ROOT,
) -> dict[str, Any]:
    resolved = directory.resolve()
    issues: list[str] = []
    checks: list[dict[str, Any]] = []

    def check(name: str, passed: bool, detail: str = "") -> None:
        failure_detail = "" if passed else detail
        checks.append({"name": name, "passed": bool(passed), "detail": failure_detail})
        if failure_detail:
            issues.append(failure_detail)

    if directory.is_symlink() or not resolved.is_dir():
        return {
            "format": FORMAT,
            "passed": False,
            "directory": str(resolved),
            "checks": [],
            "issues": ["evidence directory is missing, not a directory, or a symbolic link"],
        }

    marker = resolved / OUTPUT_MARKER
    marker_payload = _read_json(marker)
    marker_ok = (
        marker.is_file()
        and not marker.is_symlink()
        and marker_payload.get("format") == OUTPUT_MARKER_FORMAT
        and isinstance(marker_payload.get("canonical_path"), str)
    )
    check("collector_output_marker", marker_ok, "collector output marker is missing or invalid")

    entries, manifest_issues = _load_manifest(resolved / "SHA256SUMS.txt")
    issues.extend(manifest_issues)
    actual: dict[str, Path] = {}
    symlinks: list[str] = []
    for path in sorted(resolved.rglob("*")):
        if path == resolved / "SHA256SUMS.txt":
            continue
        relative = path.relative_to(resolved).as_posix()
        if path.is_symlink():
            symlinks.append(relative)
        elif path.is_file():
            actual[relative] = path
    check("no_symbolic_links", not symlinks, "evidence contains symbolic links: " + ", ".join(symlinks))
    missing = sorted(set(entries) - set(actual))
    unlisted = sorted(set(actual) - set(entries))
    check("manifest_inventory", not missing and not unlisted, f"manifest inventory mismatch; missing={missing}, unlisted={unlisted}")
    mismatched = sorted(
        relative for relative, digest in entries.items()
        if relative in actual and _sha256(actual[relative]) != digest
    )
    check("manifest_hashes", not mismatched and not manifest_issues, "manifest hash mismatch: " + ", ".join(mismatched))

    aggregate_path = resolved / "external-validation-report.json"
    aggregate = _read_json(aggregate_path)
    aggregate_basic = (
        aggregate_path.is_file()
        and not aggregate_path.is_symlink()
        and aggregate.get("format") == GATE_FORMAT
        and isinstance(aggregate.get("checks"), list)
    )
    check("aggregate_report_format", aggregate_basic, "external-validation-report.json is missing or has the wrong format")

    if aggregate_basic:
        items = [item for item in aggregate["checks"] if isinstance(item, dict)]
        names = Counter(str(item.get("name") or "") for item in items)
        missing_checks = [name for name in REQUIRED_CHECKS if names[name] == 0]
        duplicate_checks = sorted(name for name, count in names.items() if name and count > 1)
        contract_issues = _aggregate_contract_issues(items)
        expected_counts = dict(Counter(str(item.get("status") or "failed") for item in items))
        required_pass = (
            not missing_checks
            and not duplicate_checks
            and not contract_issues
            and all(
                item.get("status") == "passed" and item.get("passed") is True
                for item in items
                if item.get("required") is True
            )
        )
        aggregate_consistent = (
            aggregate.get("missing_checks") == missing_checks
            and aggregate.get("duplicate_checks") == duplicate_checks
            and aggregate.get("contract_issues") == contract_issues
            and aggregate.get("status_counts") == expected_counts
            and aggregate.get("passed") is required_pass
            and aggregate.get("complete") is required_pass
        )
        check("aggregate_contract", aggregate_consistent, "aggregate status or required-check contract is inconsistent")

        binding_issues: list[str] = []
        for item in items:
            name = str(item.get("name") or "unnamed")
            report_name = item.get("report")
            report_digest = str(item.get("report_sha256") or "")
            report: dict[str, Any] = {}
            report_error = ""
            report_contract_issues: list[str] = []
            if name in REPORT_REQUIRED_CHECKS and not isinstance(report_name, str):
                binding_issues.append(f"{name}: required report path missing")
            if report_name:
                if not isinstance(report_name, str) or not _safe_relative(report_name):
                    binding_issues.append(f"{name}: unsafe report path")
                    report_error = "unsafe report path"
                else:
                    report_file = resolved / report_name
                    report, report_error, actual_report_digest = _load_required_report(report_file)
                    if report_error:
                        binding_issues.append(f"{name}: {report_error}")
                    if not report_digest or actual_report_digest != report_digest:
                        binding_issues.append(f"{name}: report digest mismatch")
                    if report:
                        report_contract_issues = _report_contract_issues(report)
                        binding_issues.extend(
                            f"{name}: {issue}" for issue in report_contract_issues
                        )

            execution = item.get("execution")
            execution_ok = False
            if name in EXECUTION_REQUIRED_CHECKS and not isinstance(execution, dict):
                binding_issues.append(f"{name}: required execution record missing")
            if isinstance(execution, dict):
                log_name = execution.get("log")
                log_digest = str(execution.get("log_sha256") or "")
                if not isinstance(log_name, str) or not _safe_relative(log_name):
                    binding_issues.append(f"{name}: unsafe execution log path")
                else:
                    log_file = resolved / log_name
                    if not log_file.is_file() or log_file.is_symlink():
                        binding_issues.append(f"{name}: execution log missing")
                    elif not log_digest or _sha256(log_file) != log_digest:
                        binding_issues.append(f"{name}: execution log digest mismatch")
                execution_ok = (
                    execution.get("exit_code") == 0
                    and not execution.get("timed_out")
                    and not execution.get("error")
                )
            if name == "customer_scanner_corpus" and isinstance(execution, dict):
                binding_issues.append(f"{name}: unexpected execution record")

            if name in REPORT_REQUIRED_CHECKS:
                if name in EXECUTION_REQUIRED_CHECKS and not execution_ok:
                    expected_status = "failed"
                    expected_consistent = False
                elif report_error or report_contract_issues or not report:
                    expected_status = "failed"
                    expected_consistent = False
                else:
                    expected_status = _status_from_report(report)
                    expected_consistent = True
            else:
                expected_status = "passed" if execution_ok else "failed"
                expected_consistent = execution_ok
            if item.get("status") != expected_status:
                binding_issues.append(
                    f"{name}: aggregate status {item.get('status')!r} does not match "
                    f"evidence-derived status {expected_status!r}"
                )
            if item.get("passed") is not (expected_status == "passed"):
                binding_issues.append(f"{name}: aggregate passed flag is not evidence-derived")
            if item.get("execution_report_consistent") is not expected_consistent:
                binding_issues.append(f"{name}: execution_report_consistent is not evidence-derived")
        check("execution_report_binding", not binding_issues, "; ".join(binding_issues))

        version_ok = True
        schema_ok = True
        source_ok = True
        if source_root is not None:
            root = source_root.resolve()
            try:
                expected_version = (root / "VERSION").read_text(encoding="utf-8").strip()
            except (OSError, UnicodeError):
                expected_version = ""
            version_ok = aggregate.get("version") == expected_version
            schema_ok = aggregate.get("schema_version") == CURRENT_SCHEMA_VERSION
            source_manifest = root / "SHA256SUMS.txt"
            expected_manifest_hash = _sha256(source_manifest) if source_manifest.is_file() else ""
            source_ok = (
                aggregate.get("source_identity", {}).get("public_manifest_sha256")
                == expected_manifest_hash
            )
        check("source_version_binding", version_ok and schema_ok, "aggregate version or schema does not match the source tree")
        check("source_manifest_binding", source_ok, "aggregate source manifest digest does not match the source tree")

    return {
        "format": FORMAT,
        "passed": bool(checks) and all(item["passed"] for item in checks),
        "directory": str(resolved),
        "checks": checks,
        "issues": list(dict.fromkeys(issue for issue in issues if issue)),
        "files": len(actual),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--json-output", type=Path)
    parser.add_argument(
        "--without-source-binding",
        action="store_true",
        help="Verify internal evidence integrity without comparing it to the current source tree.",
    )
    args = parser.parse_args()
    report = verify_evidence_directory(
        args.directory,
        source_root=None if args.without_source_binding else ROOT,
    )
    rendered = json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    print(rendered, end="")
    if args.json_output:
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        args.json_output.write_text(rendered, encoding="utf-8")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
