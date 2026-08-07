from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from scripts.external_validation_gate import (
    EXECUTION_REQUIRED_CHECKS,
    REPORT_REQUIRED_CHECKS,
    REQUIRED_CHECKS,
    _status_from_report,
    aggregate_report,
    prepare_output_directory,
    scanner_corpus_evidence,
    write_evidence_manifest,
)
from scripts.run_browser_e2e import find_blocking_browser_policies, run_browser_e2e

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "scanners"


def _check(name: str, status: str = "passed") -> dict[str, object]:
    item: dict[str, object] = {
        "name": name,
        "required": True,
        "status": status,
        "passed": status == "passed",
        "execution_report_consistent": True,
    }
    if name in REPORT_REQUIRED_CHECKS:
        item["report"] = f"{name}.json"
    if name in EXECUTION_REQUIRED_CHECKS:
        item["execution"] = {"exit_code": 0}
    return item


def test_browser_policy_preflight_detects_global_url_block(tmp_path: Path) -> None:
    policy = tmp_path / "managed" / "policy.json"
    policy.parent.mkdir()
    policy.write_text(json.dumps({"URLBlocklist": ["*", "example.invalid"]}), encoding="utf-8")

    assert find_blocking_browser_policies([tmp_path]) == [str(policy)]


def test_browser_report_is_blocked_before_launch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"URLBlocklist": ["*"]}), encoding="utf-8")

    def forbidden(*args: object, **kwargs: object) -> object:
        raise AssertionError("pytest must not launch when managed policy blocks every URL")

    monkeypatch.setattr("scripts.run_browser_e2e.subprocess.run", forbidden)
    report = run_browser_e2e(policy_roots=[tmp_path])

    assert report["status"] == "blocked"
    assert report["passed"] is False
    assert report["blocking_policy_files"] == [str(policy)]


def test_index_unavailable_is_never_classified_as_passed() -> None:
    assert _status_from_report({"status": "index-unavailable", "passed": False}) == "unavailable"
    assert _status_from_report({"passed": True}) == "passed"


def test_customer_scanner_corpus_requires_explicit_input() -> None:
    report, check = scanner_corpus_evidence(None, minimum_files=2)

    assert report["status"] == "not-provided"
    assert check["passed"] is False


def test_customer_scanner_corpus_requires_unique_file_contents(tmp_path: Path) -> None:
    source = FIXTURES / "generic-korean-cp949.csv"
    (tmp_path / "customer-a.csv").write_bytes(source.read_bytes())
    (tmp_path / "customer-b.csv").write_bytes(source.read_bytes())

    report, check = scanner_corpus_evidence(tmp_path, minimum_files=2)

    assert report["files"] == 2
    assert report["unique_contents"] == 1
    assert report["status"] == "insufficient"
    assert check["passed"] is False


def test_customer_scanner_evidence_passes_unique_ready_exports_without_names(
    tmp_path: Path,
) -> None:
    secret_names = ("ACME-prod-export.csv", "ACME-internal-assets.xlsx")
    (tmp_path / secret_names[0]).write_bytes((FIXTURES / "generic-korean-cp949.csv").read_bytes())
    (tmp_path / secret_names[1]).write_bytes((FIXTURES / "generic.xlsx").read_bytes())

    report, check = scanner_corpus_evidence(tmp_path, minimum_files=2)
    rendered = json.dumps(report, ensure_ascii=False)

    assert report["status"] == "passed"
    assert report["unique_contents"] == 2
    assert check["passed"] is True
    assert all(item["status"] == "READY" for item in report["results"])
    assert all(name not in rendered for name in secret_names)
    assert {item["file_id"] for item in report["results"]} == {"scanner-001", "scanner-002"}


def test_aggregate_report_rejects_missing_required_check(tmp_path: Path) -> None:
    checks = [_check(name) for name in REQUIRED_CHECKS[:-1]]
    report = aggregate_report(
        checks=checks,
        mode="release",
        version="72.0.50",
        schema_version=46,
        output_dir=tmp_path,
    )

    assert report["passed"] is False
    assert report["missing_checks"] == [REQUIRED_CHECKS[-1]]


def test_aggregate_report_requires_all_required_checks_to_pass(tmp_path: Path) -> None:
    checks = [_check(name) for name in REQUIRED_CHECKS]
    checks[2] = _check(REQUIRED_CHECKS[2], "unavailable")
    failed = aggregate_report(
        checks=checks,
        mode="release",
        version="72.0.50",
        schema_version=46,
        output_dir=tmp_path,
    )
    passed = aggregate_report(
        checks=[_check(name) for name in REQUIRED_CHECKS],
        mode="release",
        version="72.0.50",
        schema_version=46,
        output_dir=tmp_path,
    )

    assert failed["passed"] is False
    assert passed["passed"] is True
    assert passed["status_counts"] == {"passed": len(REQUIRED_CHECKS)}


def test_output_directory_needs_explicit_overwrite(tmp_path: Path) -> None:
    output = prepare_output_directory(tmp_path / "evidence", overwrite=False)
    (output / "old.json").write_text("{}\n", encoding="utf-8")

    with pytest.raises(ValueError, match="not empty"):
        prepare_output_directory(output, overwrite=False)
    prepared = prepare_output_directory(output, overwrite=True)

    assert prepared == output.resolve()
    assert [path.name for path in prepared.iterdir()] == [
        ".vulnflow-external-validation-evidence"
    ]


def test_evidence_manifest_records_file_hashes(tmp_path: Path) -> None:
    first = tmp_path / "a.json"
    second = tmp_path / "b.log"
    first.write_text('{"passed": false}\n', encoding="utf-8")
    second.write_text("blocked\n", encoding="utf-8")

    manifest = write_evidence_manifest(tmp_path)
    lines = manifest.read_text(encoding="utf-8").splitlines()

    assert lines == [
        f"{hashlib.sha256(first.read_bytes()).hexdigest()}  a.json",
        f"{hashlib.sha256(second.read_bytes()).hexdigest()}  b.log",
    ]
