from __future__ import annotations

"""Collect external release evidence without converting blocked checks into passes.

The gate separates product failures from missing tools, managed browser policy,
missing customer scanner exports, and a genuinely successful rehearsal. In
``collect`` mode it always writes evidence and exits zero unless the collector
itself crashes. In ``release`` mode every required check must pass.

Version 2 binds a reported result to the subprocess exit status and the exact
JSON report bytes. Missing, malformed, contradictory, or stale-looking reports
can never become passes merely because a child command returned zero.
"""

import argparse
from collections import Counter
import hashlib
import json
import os
import platform
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
FORMAT = "vulnflow-external-validation-gate/3"
REQUEST_BINDING_FORMAT = "vulnflow-external-validation-request-binding/2"
OUTPUT_MARKER = ".vulnflow-external-validation-evidence"
OUTPUT_MARKER_FORMAT = "vulnflow-external-validation-output/1"
SUPPORTED_SCANNER_SUFFIXES = {".csv", ".xlsx", ".nessus", ".xml"}
TERMINAL_STATUSES = {
    "passed",
    "failed",
    "blocked",
    "unavailable",
    "not-provided",
    "insufficient",
    "needs-review",
}
REQUIRED_CHECKS = (
    "public_manifest",
    "dependency_wheelhouse",
    "production_compose",
    "browser_e2e",
    "synthetic_scanner_matrix",
    "customer_scanner_corpus",
    "runtime_soak",
)
REPORT_REQUIRED_CHECKS = frozenset({
    "dependency_wheelhouse",
    "production_compose",
    "browser_e2e",
    "synthetic_scanner_matrix",
    "customer_scanner_corpus",
    "runtime_soak",
})
EXECUTION_REQUIRED_CHECKS = frozenset(set(REQUIRED_CHECKS) - {"customer_scanner_corpus"})


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )


def _read_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _valid_hex(value: object, length: int) -> bool:
    text = str(value or "")
    return len(text) == length and all(char in "0123456789abcdef" for char in text)


def _validate_request_binding(payload: dict[str, Any]) -> dict[str, Any]:
    if payload.get("format") != REQUEST_BINDING_FORMAT:
        raise ValueError("request binding has the wrong format")
    if not _valid_hex(payload.get("request_id"), 32):
        raise ValueError("request binding request_id is invalid")
    if not _valid_hex(payload.get("challenge_nonce_sha256"), 64):
        raise ValueError("request binding challenge nonce digest is invalid")
    if not _valid_hex(payload.get("request_sha256"), 64):
        raise ValueError("request binding request digest is invalid")
    if not _valid_hex(payload.get("request_signature_sha256"), 64):
        raise ValueError("request binding signature digest is invalid")
    target = str(payload.get("target_name") or "")
    if not target or len(target) > 64:
        raise ValueError("request binding target_name is invalid")
    for name in ("request_created_at", "request_expires_at"):
        value = payload.get(name)
        if not isinstance(value, str) or not value:
            raise ValueError(f"request binding {name} is invalid")
        try:
            datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError(f"request binding {name} is invalid") from exc
    source_identity = payload.get("source_identity")
    if not isinstance(source_identity, dict) or not source_identity:
        raise ValueError("request binding source identity is invalid")
    authorized_operator = payload.get("authorized_operator")
    if not isinstance(authorized_operator, dict):
        raise ValueError("request binding authorized operator identity is invalid")
    if authorized_operator.get("algorithm") != "Ed25519":
        raise ValueError("request binding authorized operator algorithm is invalid")
    operator_key_id = str(authorized_operator.get("key_id") or "")
    operator_fingerprint = str(authorized_operator.get("public_key_fingerprint") or "")
    if not operator_key_id or len(operator_key_id) > 128:
        raise ValueError("request binding authorized operator key_id is invalid")
    if not operator_fingerprint.startswith("sha256:") or not _valid_hex(operator_fingerprint[7:], 64):
        raise ValueError("request binding authorized operator fingerprint is invalid")
    return dict(payload)


def _load_request_binding(path: Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    if path.is_symlink() or not path.is_file():
        raise ValueError("request binding file must be a regular file")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("request binding file must be valid UTF-8 JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError("request binding file must contain a JSON object")
    return _validate_request_binding(payload)


def _load_required_report(path: Path) -> tuple[dict[str, Any], str, str]:
    """Read one mandatory JSON object and return payload, error, and digest."""

    if path.is_symlink():
        return {}, "required report is a symbolic link", ""
    if not path.exists():
        return {}, "required report was not created", ""
    if not path.is_file():
        return {}, "required report is not a regular file", ""
    try:
        raw = path.read_bytes()
    except OSError as exc:
        return {}, f"required report could not be read: {exc.__class__.__name__}", ""
    digest = _sha256_bytes(raw)
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        return {}, "required report is not valid UTF-8 JSON", digest
    if not isinstance(payload, dict) or not payload:
        return {}, "required report must be a non-empty JSON object", digest
    return payload, "", digest


def _normalized_explicit_status(report: dict[str, Any]) -> str:
    explicit = str(report.get("status") or "").strip().lower()
    if explicit == "index-unavailable":
        return "unavailable"
    return explicit


def _report_contract_issues(report: dict[str, Any]) -> list[str]:
    issues: list[str] = []
    explicit = _normalized_explicit_status(report)
    passed = report.get("passed")
    available = report.get("available")
    if explicit and explicit not in TERMINAL_STATUSES:
        issues.append(f"unsupported report status: {explicit}")
    if explicit == "passed" and passed is not True:
        issues.append("status=passed requires passed=true")
    if explicit in TERMINAL_STATUSES - {"passed"} and passed is True:
        issues.append(f"status={explicit} contradicts passed=true")
    if available is False and passed is True:
        issues.append("available=false contradicts passed=true")
    if passed is not None and not isinstance(passed, bool):
        issues.append("passed must be true, false, or null")
    return issues


def _status_from_report(report: dict[str, Any]) -> str:
    if _report_contract_issues(report):
        return "failed"
    explicit = _normalized_explicit_status(report)
    if explicit in TERMINAL_STATUSES:
        return explicit
    if report.get("available") is False:
        return "unavailable"
    if report.get("passed") is True:
        return "passed"
    return "failed"


def _terminate_command_process_group(
    process: subprocess.Popen[str],
    *,
    grace_seconds: float = 1.0,
) -> None:
    """Bound shutdown for the wrapper and every descendant in its process group."""

    if os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        except OSError:
            return
        deadline = time.monotonic() + max(0.0, grace_seconds)
        while time.monotonic() < deadline:
            try:
                os.killpg(process.pid, 0)
            except OSError:
                return
            time.sleep(0.05)
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except OSError:
            pass
        return

    if process.poll() is None:
        try:
            process.terminate()
            process.wait(timeout=max(0.1, grace_seconds))
            return
        except (OSError, subprocess.TimeoutExpired):
            pass
        try:
            process.kill()
        except OSError:
            pass


def _cleanup_residual_command_group(process: subprocess.Popen[str]) -> None:
    """Reap descendants that survive a successful wrapper exit.

    stdout is written directly to the evidence log rather than captured through
    a pipe. A grandchild that inherits a pipe can otherwise keep communicate()
    blocked long after the verified wrapper has exited.
    """

    if os.name == "posix":
        _terminate_command_process_group(process, grace_seconds=0.1)


def _run_command(
    *,
    name: str,
    command: list[str],
    output_dir: Path,
    timeout_seconds: int,
) -> dict[str, Any]:
    log_path = output_dir / f"{name}.log"
    started = time.monotonic()
    process: subprocess.Popen[str] | None = None
    timed_out = False
    return_code: int | None = None
    error = ""
    creationflags = 0
    if os.name == "nt":
        creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    try:
        with log_path.open("w", encoding="utf-8", errors="replace") as log_handle:
            process = subprocess.Popen(
                command,
                cwd=ROOT,
                env=os.environ.copy(),
                text=True,
                stdout=log_handle,
                stderr=subprocess.STDOUT,
                start_new_session=(os.name == "posix"),
                creationflags=creationflags,
            )
            try:
                return_code = process.wait(timeout=max(30, int(timeout_seconds)))
            except subprocess.TimeoutExpired:
                timed_out = True
                _terminate_command_process_group(process)
                try:
                    return_code = process.wait(timeout=2.0)
                except subprocess.TimeoutExpired:
                    return_code = 124
            finally:
                _cleanup_residual_command_group(process)
    except OSError as exc:
        error = str(exc)
        log_path.write_text(
            f"{exc.__class__.__name__}: {exc}\n",
            encoding="utf-8",
        )
    if timed_out:
        return_code = 124
    result: dict[str, Any] = {
        "exit_code": return_code,
        "duration_seconds": round(time.monotonic() - started, 3),
        "log": log_path.name,
        "log_sha256": _sha256(log_path),
        "command": [Path(command[0]).name, *command[1:]],
    }
    if timed_out:
        result["timed_out"] = True
    if error:
        result["error"] = error
    return result


def _command_check(
    *,
    name: str,
    command: list[str],
    output_dir: Path,
    timeout_seconds: int,
    report_path: Path | None = None,
) -> dict[str, Any]:
    execution = _run_command(
        name=name,
        command=command,
        output_dir=output_dir,
        timeout_seconds=timeout_seconds,
    )
    execution_ok = (
        execution.get("exit_code") == 0
        and not execution.get("timed_out")
        and not execution.get("error")
    )
    report: dict[str, Any] = {}
    report_error = ""
    report_sha256 = ""
    contract_issues: list[str] = []
    if report_path is not None:
        report, report_error, report_sha256 = _load_required_report(report_path)
        if report:
            contract_issues = _report_contract_issues(report)

    if report_path is None:
        status = "passed" if execution_ok else "failed"
    elif not execution_ok or report_error or contract_issues:
        status = "failed"
    else:
        status = _status_from_report(report)

    reason_parts: list[str] = []
    if not execution_ok:
        if execution.get("timed_out"):
            reason_parts.append("child command timed out")
        elif execution.get("error"):
            reason_parts.append("child command could not be executed")
        else:
            reason_parts.append(f"child command exited {execution.get('exit_code')}")
    if report_error:
        reason_parts.append(report_error)
    reason_parts.extend(contract_issues)
    report_reason = str(report.get("reason") or report.get("error") or "")
    if report_reason:
        reason_parts.append(report_reason)
    if not report_reason and str(report.get("status") or "") == "index-unavailable":
        reason_parts.append("configured package index did not provide the exact pinned artifacts")
    if not report_reason and report.get("available") is False:
        reason_parts.append("required runtime is unavailable")

    return {
        "name": name,
        "required": True,
        "status": status,
        "passed": status == "passed",
        "execution": execution,
        "report": report_path.name if report_path and report_path.exists() else None,
        "report_sha256": report_sha256,
        "execution_report_consistent": not (
            not execution_ok or report_error or contract_issues
        ),
        "report_contract_issues": contract_issues,
        "reason": "; ".join(dict.fromkeys(part for part in reason_parts if part)),
    }


def scanner_corpus_evidence(
    scanner_dir: Path | None,
    *,
    minimum_files: int = 20,
    maximum_files: int = 200,
    maximum_total_bytes: int = 512 * 1024 * 1024,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Inspect customer exports without copying their names or contents."""

    if scanner_dir is None:
        report = {
            "format": "vulnflow-customer-scanner-corpus/2",
            "status": "not-provided",
            "passed": False,
            "minimum_files": minimum_files,
            "maximum_files": maximum_files,
            "maximum_total_bytes": maximum_total_bytes,
            "files": 0,
            "results": [],
            "reason": "no customer scanner directory was provided",
        }
        return report, _scanner_check(report)
    directory = scanner_dir.resolve()
    if not directory.is_dir():
        report = {
            "format": "vulnflow-customer-scanner-corpus/2",
            "status": "not-provided",
            "passed": False,
            "minimum_files": minimum_files,
            "maximum_files": maximum_files,
            "maximum_total_bytes": maximum_total_bytes,
            "files": 0,
            "results": [],
            "reason": "customer scanner directory does not exist",
        }
        return report, _scanner_check(report)

    from scripts.scanner_compatibility_report import inspect_content

    candidates = sorted(
        path
        for path in directory.rglob("*")
        if path.suffix.lower() in SUPPORTED_SCANNER_SUFFIXES
        and (path.is_file() or path.is_symlink())
    )
    if len(candidates) > maximum_files:
        report = {
            "format": "vulnflow-customer-scanner-corpus/2",
            "status": "failed",
            "passed": False,
            "minimum_files": minimum_files,
            "maximum_files": maximum_files,
            "maximum_total_bytes": maximum_total_bytes,
            "files": len(candidates),
            "results": [],
            "failures": [],
            "reason": f"supported file count exceeds safety limit {maximum_files}",
        }
        return report, _scanner_check(report)

    regular_paths = [path for path in candidates if not path.is_symlink()]
    try:
        total_bytes = sum(path.stat().st_size for path in regular_paths)
    except OSError:
        total_bytes = maximum_total_bytes + 1
    if total_bytes > maximum_total_bytes:
        report = {
            "format": "vulnflow-customer-scanner-corpus/2",
            "status": "failed",
            "passed": False,
            "minimum_files": minimum_files,
            "maximum_files": maximum_files,
            "maximum_total_bytes": maximum_total_bytes,
            "files": len(candidates),
            "total_bytes": total_bytes,
            "results": [],
            "failures": [],
            "reason": "scanner corpus exceeds configured total byte limit",
        }
        return report, _scanner_check(report)

    results: list[dict[str, Any]] = []
    failures: list[dict[str, str]] = []
    for index, path in enumerate(candidates, 1):
        file_id = f"scanner-{index:03d}"
        if path.is_symlink():
            failures.append(
                {
                    "file_id": file_id,
                    "suffix": path.suffix.lower(),
                    "error_code": "symbolic-link-not-allowed",
                }
            )
            continue
        try:
            content = path.read_bytes()
            item = inspect_content(content, filename=path.name)
            results.append(
                {
                    "file_id": file_id,
                    "suffix": path.suffix.lower(),
                    "bytes": len(content),
                    "sha256": _sha256_bytes(content),
                    "detected_format": item.get("detected_format"),
                    "status": item.get("status"),
                    "source_items": item.get("source_items"),
                    "importable_rows": item.get("importable_rows"),
                    "unsupported_source_items": item.get("unsupported_source_items"),
                    "error_count": item.get("error_count"),
                }
            )
        except Exception as exc:  # isolate one untrusted export from the collector
            failures.append(
                {
                    "file_id": file_id,
                    "suffix": path.suffix.lower(),
                    "error_code": "scanner-inspection-failed",
                    "error_type": exc.__class__.__name__,
                }
            )

    ready = sum(1 for item in results if item.get("status") == "READY")
    review = sum(1 for item in results if item.get("status") == "REVIEW")
    blocked = sum(1 for item in results if item.get("status") == "BLOCKED") + len(failures)
    unique_hashes = len({str(item.get("sha256") or "") for item in results})
    if blocked:
        status = "failed"
        reason = "one or more scanner exports were blocked or unreadable"
    elif len(candidates) < minimum_files or unique_hashes < minimum_files:
        status = "insufficient"
        reason = (
            f"{len(candidates)} supported files and {unique_hashes} unique contents provided; "
            f"{minimum_files} unique files required"
        )
    elif review:
        status = "needs-review"
        reason = f"{review} scanner exports require manual compatibility review"
    else:
        status = "passed"
        reason = ""
    report = {
        "format": "vulnflow-customer-scanner-corpus/2",
        "status": status,
        "passed": status == "passed",
        "minimum_files": minimum_files,
        "maximum_files": maximum_files,
        "maximum_total_bytes": maximum_total_bytes,
        "files": len(candidates),
        "total_bytes": total_bytes,
        "unique_contents": unique_hashes,
        "summary": {"ready": ready, "review": review, "blocked": blocked},
        "results": results,
        "failures": failures,
        "reason": reason,
        "privacy": (
            "file contents and filenames are not copied; evidence contains opaque IDs, "
            "suffixes, sizes, hashes, parser outcomes, and sanitized error classes only"
        ),
    }
    return report, _scanner_check(report)


def _scanner_check(report: dict[str, Any]) -> dict[str, Any]:
    status = _status_from_report(report)
    return {
        "name": "customer_scanner_corpus",
        "required": True,
        "status": status,
        "passed": status == "passed",
        "report": "customer-scanner-corpus.json",
        "report_sha256": "",
        "execution_report_consistent": True,
        "report_contract_issues": _report_contract_issues(report),
        "reason": str(report.get("reason") or ""),
    }


def _aggregate_contract_issues(items: list[dict[str, Any]]) -> list[str]:
    issues: list[str] = []
    for index, item in enumerate(items):
        name = str(item.get("name") or "")
        status = str(item.get("status") or "")
        passed = item.get("passed")
        if not name:
            issues.append(f"check[{index}] has no name")
        if status not in TERMINAL_STATUSES:
            issues.append(f"check {name or index} has unsupported status {status!r}")
        if passed != (status == "passed"):
            issues.append(f"check {name or index} has inconsistent passed/status values")
        if item.get("execution_report_consistent") is False and status == "passed":
            issues.append(f"check {name or index} passed with inconsistent execution/report evidence")
        if name in REPORT_REQUIRED_CHECKS and not isinstance(item.get("report"), str):
            issues.append(f"check {name} is missing its required JSON report")
        if name in EXECUTION_REQUIRED_CHECKS and not isinstance(item.get("execution"), dict):
            issues.append(f"check {name} is missing its required execution record")
        if name == "customer_scanner_corpus" and isinstance(item.get("execution"), dict):
            issues.append("check customer_scanner_corpus must not claim a child execution")
    return issues


def aggregate_report(
    *,
    checks: Iterable[dict[str, Any]],
    mode: str,
    version: str,
    schema_version: int,
    output_dir: Path,
    request_binding: dict[str, Any] | None = None,
    collection_started_at: str | None = None,
    collection_completed_at: str | None = None,
) -> dict[str, Any]:
    items = list(checks)
    counts_by_name = Counter(str(item.get("name") or "") for item in items)
    missing = [name for name in REQUIRED_CHECKS if counts_by_name[name] == 0]
    duplicates = sorted(name for name, count in counts_by_name.items() if name and count > 1)
    contract_issues = _aggregate_contract_issues(items)
    passed = (
        not missing
        and not duplicates
        and not contract_issues
        and all(
            item.get("status") == "passed" and item.get("passed") is True
            for item in items
            if item.get("required") is True
        )
    )
    counts: dict[str, int] = {}
    for item in items:
        status = str(item.get("status") or "failed")
        counts[status] = counts.get(status, 0) + 1
    public_manifest = ROOT / "SHA256SUMS.txt"
    completed_at = collection_completed_at or datetime.now(timezone.utc).isoformat()
    started_at = collection_started_at or completed_at
    return {
        "format": FORMAT,
        "created_at": completed_at,
        "collection_window": {
            "started_at": started_at,
            "completed_at": completed_at,
        },
        "request_binding": request_binding,
        "mode": mode,
        "version": version,
        "schema_version": schema_version,
        "passed": passed,
        "complete": passed,
        "evidence_collected": not missing and not duplicates,
        "checks": items,
        "status_counts": counts,
        "missing_checks": missing,
        "duplicate_checks": duplicates,
        "contract_issues": contract_issues,
        "source_identity": {
            "public_manifest_sha256": _sha256(public_manifest) if public_manifest.exists() else "",
            "git_metadata_available": (ROOT / ".git").exists(),
        },
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "docker": shutil.which("docker") or "",
            "chromium": shutil.which("chromium") or shutil.which("chromium-browser") or "",
        },
        "evidence_directory": output_dir.name,
        "exit_contract": {
            "collect": "writes a non-passing report without converting blocked checks into passes",
            "release": "returns non-zero unless every required check passes",
        },
    }


def write_evidence_manifest(output_dir: Path) -> Path:
    manifest = output_dir / "SHA256SUMS.txt"
    lines: list[str] = []
    for path in sorted(output_dir.rglob("*")):
        if path == manifest:
            continue
        if path.is_symlink():
            raise ValueError(f"evidence directory contains a symbolic link: {path}")
        if path.is_file():
            relative = path.relative_to(output_dir).as_posix()
            lines.append(f"{_sha256(path)}  {relative}")
    manifest.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return manifest


def _output_marker_payload(path: Path) -> dict[str, str]:
    return {"format": OUTPUT_MARKER_FORMAT, "canonical_path": str(path)}


def _valid_output_marker(path: Path, marker: Path) -> bool:
    payload = _read_json(marker)
    return (
        payload.get("format") == OUTPUT_MARKER_FORMAT
        and payload.get("canonical_path") == str(path)
    )


def prepare_output_directory(output_dir: Path, *, overwrite: bool) -> Path:
    raw = output_dir.expanduser()
    if raw.is_symlink():
        raise ValueError("evidence output directory must not be a symbolic link")
    resolved = raw.resolve()
    filesystem_root = Path(resolved.anchor)
    if resolved == filesystem_root or resolved == ROOT or resolved in ROOT.parents:
        raise ValueError(f"unsafe evidence output directory: {resolved}")
    marker = resolved / OUTPUT_MARKER
    if resolved.exists() and any(resolved.iterdir()):
        if not overwrite:
            raise ValueError(
                f"evidence directory is not empty: {resolved}; use --overwrite to replace it"
            )
        if not marker.is_file() or marker.is_symlink() or not _valid_output_marker(resolved, marker):
            raise ValueError(
                "refusing to overwrite a non-empty directory that is not owned by the "
                "VulnFlow external validation collector"
            )
        shutil.rmtree(resolved)
    resolved.mkdir(parents=True, exist_ok=True)
    _write_json(resolved / OUTPUT_MARKER, _output_marker_payload(resolved))
    return resolved


def run_gate(args: argparse.Namespace) -> dict[str, Any]:
    collection_started_at = datetime.now(timezone.utc).isoformat()
    output_dir = prepare_output_directory(args.output_dir, overwrite=args.overwrite)
    request_binding = _load_request_binding(getattr(args, "request_binding_file", None))
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    from app.core.schema_versions import CURRENT_SCHEMA_VERSION

    checks: list[dict[str, Any]] = []

    checks.append(
        _command_check(
            name="public_manifest",
            command=[sys.executable, "scripts/verify_public_manifest.py"],
            output_dir=output_dir,
            timeout_seconds=args.command_timeout_seconds,
        )
    )

    wheelhouse_report = output_dir / "dependency-wheelhouse.json"
    checks.append(
        _command_check(
            name="dependency_wheelhouse",
            command=[
                sys.executable,
                "scripts/dependency_wheelhouse_rehearsal.py",
                "--allow-index-unavailable",
                "--timeout-seconds",
                str(args.wheelhouse_timeout_seconds),
                "--json-output",
                str(wheelhouse_report),
            ],
            output_dir=output_dir,
            timeout_seconds=args.wheelhouse_timeout_seconds + 60,
            report_path=wheelhouse_report,
        )
    )

    compose_report = output_dir / "production-compose.json"
    checks.append(
        _command_check(
            name="production_compose",
            command=[
                sys.executable,
                "scripts/production_compose_rehearsal.py",
                "--json-output",
                str(compose_report),
            ],
            output_dir=output_dir,
            timeout_seconds=args.compose_timeout_seconds,
            report_path=compose_report,
        )
    )

    browser_report = output_dir / "browser-e2e.json"
    browser_command = [
        sys.executable,
        "scripts/run_browser_e2e.py",
        "--allow-environment-blocked",
        "--timeout-seconds",
        str(args.browser_timeout_seconds),
        "--json-output",
        str(browser_report),
    ]
    if args.chromium:
        browser_command.extend(["--chromium", args.chromium])
    checks.append(
        _command_check(
            name="browser_e2e",
            command=browser_command,
            output_dir=output_dir,
            timeout_seconds=args.browser_timeout_seconds + 60,
            report_path=browser_report,
        )
    )

    scanner_fixture_report = output_dir / "synthetic-scanner-matrix.json"
    checks.append(
        _command_check(
            name="synthetic_scanner_matrix",
            command=[
                sys.executable,
                "scripts/scanner_fixture_matrix.py",
                "--json-output",
                str(scanner_fixture_report),
            ],
            output_dir=output_dir,
            timeout_seconds=args.command_timeout_seconds,
            report_path=scanner_fixture_report,
        )
    )

    customer_report, customer_check = scanner_corpus_evidence(
        args.scanner_dir,
        minimum_files=args.minimum_scanner_files,
        maximum_files=args.maximum_scanner_files,
        maximum_total_bytes=args.maximum_scanner_total_bytes,
    )
    customer_report_path = output_dir / "customer-scanner-corpus.json"
    _write_json(customer_report_path, customer_report)
    customer_check["report_sha256"] = _sha256(customer_report_path)
    checks.append(customer_check)

    soak_report = output_dir / "runtime-soak.json"
    soak_text = output_dir / "runtime-soak.txt"
    checks.append(
        _command_check(
            name="runtime_soak",
            command=[
                sys.executable,
                "scripts/runtime_stability_soak.py",
                "--iterations",
                str(args.soak_iterations),
                "--json-output",
                str(soak_report),
                "--text-output",
                str(soak_text),
            ],
            output_dir=output_dir,
            timeout_seconds=args.soak_timeout_seconds,
            report_path=soak_report,
        )
    )

    report = aggregate_report(
        checks=checks,
        mode=args.mode,
        version=version,
        schema_version=CURRENT_SCHEMA_VERSION,
        output_dir=output_dir,
        request_binding=request_binding,
        collection_started_at=collection_started_at,
        collection_completed_at=datetime.now(timezone.utc).isoformat(),
    )
    _write_json(output_dir / "external-validation-report.json", report)
    write_evidence_manifest(output_dir)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("collect", "release"), default="collect")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "reports" / "external-validation")
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument("--scanner-dir", type=Path)
    parser.add_argument("--request-binding-file", type=Path)
    parser.add_argument("--minimum-scanner-files", type=int, default=20)
    parser.add_argument("--maximum-scanner-files", type=int, default=200)
    parser.add_argument("--maximum-scanner-total-bytes", type=int, default=512 * 1024 * 1024)
    parser.add_argument("--soak-iterations", type=int, default=12)
    parser.add_argument("--chromium", default="")
    parser.add_argument("--command-timeout-seconds", type=int, default=300)
    parser.add_argument("--wheelhouse-timeout-seconds", type=int, default=900)
    parser.add_argument("--compose-timeout-seconds", type=int, default=1200)
    parser.add_argument("--browser-timeout-seconds", type=int, default=900)
    parser.add_argument("--soak-timeout-seconds", type=int, default=900)
    args = parser.parse_args()
    if (
        args.minimum_scanner_files < 1
        or args.maximum_scanner_files < args.minimum_scanner_files
        or args.maximum_scanner_total_bytes < 1
        or args.soak_iterations < 2
    ):
        parser.error(
            "scanner minimum must be >=1, maximum >= minimum, total bytes >=1, "
            "and soak iterations >=2"
        )

    try:
        report = run_gate(args)
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
        print(f"external validation collector failed: {exc}", file=sys.stderr)
        return 2
    print(
        f"external validation: {'PASS' if report['passed'] else 'INCOMPLETE'} "
        f"({report['status_counts']})"
    )
    if args.mode == "release" and not report["passed"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
