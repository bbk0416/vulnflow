from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import scripts.external_validation_gate as gate
from scripts.external_validation_gate import (
    REQUIRED_CHECKS,
    _command_check,
    aggregate_report,
    prepare_output_directory,
    scanner_corpus_evidence,
    write_evidence_manifest,
)
from scripts.verify_external_validation_evidence import verify_evidence_directory

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "scanners"


def _execution(output_dir: Path, *, exit_code: int = 0) -> dict[str, object]:
    log = output_dir / "check.log"
    log.write_text("executed\n", encoding="utf-8")
    return {
        "exit_code": exit_code,
        "duration_seconds": 0.01,
        "log": log.name,
        "log_sha256": hashlib.sha256(log.read_bytes()).hexdigest(),
        "command": ["python", "check.py"],
    }


def test_nonzero_child_exit_cannot_be_overridden_by_pass_report(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = tmp_path / "report.json"
    report.write_text('{"passed": true}\n', encoding="utf-8")
    monkeypatch.setattr(gate, "_run_command", lambda **kwargs: _execution(tmp_path, exit_code=9))

    result = _command_check(
        name="check",
        command=["python", "check.py"],
        output_dir=tmp_path,
        timeout_seconds=30,
        report_path=report,
    )

    assert result["status"] == "failed"
    assert result["passed"] is False
    assert result["execution_report_consistent"] is False
    assert "exited 9" in result["reason"]


def test_missing_or_invalid_required_report_never_passes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(gate, "_run_command", lambda **kwargs: _execution(tmp_path))
    missing = tmp_path / "missing.json"
    invalid = tmp_path / "invalid.json"
    invalid.write_text("not-json\n", encoding="utf-8")

    missing_result = _command_check(
        name="missing",
        command=["python"],
        output_dir=tmp_path,
        timeout_seconds=30,
        report_path=missing,
    )
    invalid_result = _command_check(
        name="invalid",
        command=["python"],
        output_dir=tmp_path,
        timeout_seconds=30,
        report_path=invalid,
    )

    assert missing_result["status"] == "failed"
    assert "was not created" in missing_result["reason"]
    assert invalid_result["status"] == "failed"
    assert "valid UTF-8 JSON" in invalid_result["reason"]


def test_contradictory_report_contract_is_failed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = tmp_path / "report.json"
    report.write_text('{"status": "blocked", "passed": true}\n', encoding="utf-8")
    monkeypatch.setattr(gate, "_run_command", lambda **kwargs: _execution(tmp_path))

    result = _command_check(
        name="check",
        command=["python"],
        output_dir=tmp_path,
        timeout_seconds=30,
        report_path=report,
    )

    assert result["status"] == "failed"
    assert result["report_contract_issues"] == ["status=blocked contradicts passed=true"]


def test_required_report_digest_is_bound_to_check(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = tmp_path / "report.json"
    report.write_text('{"passed": true}\n', encoding="utf-8")
    monkeypatch.setattr(gate, "_run_command", lambda **kwargs: _execution(tmp_path))

    result = _command_check(
        name="check",
        command=["python"],
        output_dir=tmp_path,
        timeout_seconds=30,
        report_path=report,
    )

    assert result["status"] == "passed"
    assert result["report_sha256"] == hashlib.sha256(report.read_bytes()).hexdigest()
    assert result["execution_report_consistent"] is True


def test_aggregate_rejects_duplicate_and_inconsistent_checks(tmp_path: Path) -> None:
    checks = [
        {"name": name, "required": True, "status": "passed", "passed": True}
        for name in REQUIRED_CHECKS
    ]
    checks.append({"name": REQUIRED_CHECKS[0], "required": True, "status": "passed", "passed": True})
    checks[1]["passed"] = False

    report = aggregate_report(
        checks=checks,
        mode="release",
        version="72.0.50",
        schema_version=46,
        output_dir=tmp_path,
    )

    assert report["passed"] is False
    assert report["duplicate_checks"] == [REQUIRED_CHECKS[0]]
    assert report["contract_issues"]


def test_overwrite_requires_owned_output_marker(tmp_path: Path) -> None:
    unowned = tmp_path / "unowned"
    unowned.mkdir()
    (unowned / "important.txt").write_text("do not delete\n", encoding="utf-8")

    with pytest.raises(ValueError, match="not owned"):
        prepare_output_directory(unowned, overwrite=True)

    owned = tmp_path / "owned"
    first = prepare_output_directory(owned, overwrite=False)
    (first / "old.json").write_text("{}\n", encoding="utf-8")
    second = prepare_output_directory(owned, overwrite=True)

    assert second == owned.resolve()
    assert sorted(path.name for path in second.iterdir()) == [gate.OUTPUT_MARKER]


def test_output_directory_symlink_is_rejected(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("symbolic links are not available")

    with pytest.raises(ValueError, match="symbolic link"):
        prepare_output_directory(link, overwrite=True)


def test_scanner_corpus_rejects_symlink_without_leaking_target_name(tmp_path: Path) -> None:
    secret = tmp_path / "customer-secret-name.csv"
    secret.write_bytes((FIXTURES / "generic-korean-cp949.csv").read_bytes())
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    link = corpus / "innocent.csv"
    try:
        link.symlink_to(secret)
    except OSError:
        pytest.skip("symbolic links are not available")

    report, check = scanner_corpus_evidence(corpus, minimum_files=1)
    rendered = json.dumps(report, ensure_ascii=False)

    assert report["status"] == "failed"
    assert check["passed"] is False
    assert report["failures"][0]["error_code"] == "symbolic-link-not-allowed"
    assert secret.name not in rendered
    assert str(secret) not in rendered


def test_scanner_exception_is_sanitized(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret_name = "ACME-secret-prod.csv"
    (tmp_path / secret_name).write_bytes(b"bad")

    def fail(*args: object, **kwargs: object) -> object:
        raise RuntimeError(f"parser exploded for {secret_name}")

    monkeypatch.setattr("scripts.scanner_compatibility_report.inspect_content", fail)
    report, _ = scanner_corpus_evidence(tmp_path, minimum_files=1)
    rendered = json.dumps(report, ensure_ascii=False)

    assert report["status"] == "failed"
    assert report["failures"] == [{
        "file_id": "scanner-001",
        "suffix": ".csv",
        "error_code": "scanner-inspection-failed",
        "error_type": "RuntimeError",
    }]
    assert secret_name not in rendered
    assert "parser exploded" not in rendered


def test_scanner_corpus_enforces_file_and_total_byte_limits(tmp_path: Path) -> None:
    (tmp_path / "a.csv").write_bytes(b"a")
    (tmp_path / "b.csv").write_bytes(b"b")

    file_limited, _ = scanner_corpus_evidence(
        tmp_path,
        minimum_files=1,
        maximum_files=1,
    )
    byte_limited, _ = scanner_corpus_evidence(
        tmp_path,
        minimum_files=1,
        maximum_files=2,
        maximum_total_bytes=1,
    )

    assert file_limited["status"] == "failed"
    assert "file count" in file_limited["reason"]
    assert byte_limited["status"] == "failed"
    assert "byte limit" in byte_limited["reason"]


def _build_valid_evidence(tmp_path: Path) -> Path:
    output = prepare_output_directory(tmp_path / "evidence", overwrite=False)
    checks: list[dict[str, object]] = []
    for index, name in enumerate(REQUIRED_CHECKS, 1):
        log = output / f"{name}.log"
        log.write_text(f"{name} executed\n", encoding="utf-8")
        item: dict[str, object] = {
            "name": name,
            "required": True,
            "status": "passed",
            "passed": True,
            "execution_report_consistent": True,
            "report_contract_issues": [],
            "reason": "",
        }
        if name != "customer_scanner_corpus":
            item["execution"] = {
                "exit_code": 0,
                "log": log.name,
                "log_sha256": hashlib.sha256(log.read_bytes()).hexdigest(),
            }
        if name != "public_manifest":
            report = output / f"report-{index}.json"
            report.write_text('{"passed": true}\n', encoding="utf-8")
            item["report"] = report.name
            item["report_sha256"] = hashlib.sha256(report.read_bytes()).hexdigest()
        checks.append(item)
    aggregate = aggregate_report(
        checks=checks,
        mode="release",
        version=(ROOT / "VERSION").read_text(encoding="utf-8").strip(),
        schema_version=46,
        output_dir=output,
    )
    (output / "external-validation-report.json").write_text(
        json.dumps(aggregate, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    write_evidence_manifest(output)
    return output


def test_independent_evidence_verifier_accepts_bound_directory(tmp_path: Path) -> None:
    output = _build_valid_evidence(tmp_path)

    report = verify_evidence_directory(output)

    assert report["passed"] is True
    assert report["issues"] == []
    assert all(item["detail"] == "" for item in report["checks"])




def test_independent_evidence_verifier_accepts_relocated_archive(tmp_path: Path) -> None:
    output = _build_valid_evidence(tmp_path)
    relocated = tmp_path / "relocated"
    import shutil
    shutil.copytree(output, relocated)

    report = verify_evidence_directory(relocated)

    assert report["passed"] is True

def test_independent_evidence_verifier_detects_tampering(tmp_path: Path) -> None:
    output = _build_valid_evidence(tmp_path)
    (output / "report-2.json").write_text('{"passed": false}\n', encoding="utf-8")

    report = verify_evidence_directory(output)

    assert report["passed"] is False
    assert any("manifest hash mismatch" in issue for issue in report["issues"])


def test_evidence_manifest_is_recursive_and_rejects_symlinks(tmp_path: Path) -> None:
    nested = tmp_path / "nested"
    nested.mkdir()
    content = nested / "result.json"
    content.write_text("{}\n", encoding="utf-8")

    manifest = write_evidence_manifest(tmp_path)
    assert "nested/result.json" in manifest.read_text(encoding="utf-8")

    target = tmp_path / "target.txt"
    target.write_text("secret\n", encoding="utf-8")
    link = tmp_path / "link.txt"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symbolic links are not available")
    with pytest.raises(ValueError, match="symbolic link"):
        write_evidence_manifest(tmp_path)
