from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from app.core.schema_versions import CURRENT_SCHEMA_VERSION
from scripts.external_validation_exchange import (
    OPERATOR_PUBLIC_KEY,
    PAYLOAD_MANIFEST,
    REQUEST_JSON,
    REQUEST_SIGNATURE,
    RESPONSE_JSON,
    RESPONSE_SIGNATURE,
    create_request_bundle,
    evidence_request_binding,
    generate_keypair,
    sign_response_bundle,
    verify_request_bundle,
    verify_response_bundle,
)
from scripts.external_validation_gate import (
    EXECUTION_REQUIRED_CHECKS,
    REPORT_REQUIRED_CHECKS,
    REQUIRED_CHECKS,
    _sha256,
    _write_json,
    aggregate_report,
    prepare_output_directory,
    write_evidence_manifest,
)
from scripts.verify_external_validation_evidence import verify_evidence_directory
from scripts.external_validation_source_attestation import require_public_source

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 8, 4, 3, 0, tzinfo=timezone.utc)


def _write_keypair(base: Path, key_id: str) -> tuple[Path, Path]:
    private, public = generate_keypair(key_id=key_id)
    private_path = base / f"{key_id}-private.json"
    public_path = base / f"{key_id}-public.json"
    private_path.write_text(json.dumps(private), encoding="utf-8")
    public_path.write_text(json.dumps(public), encoding="utf-8")
    private_path.chmod(0o600)
    return private_path, public_path


def _valid_evidence(base: Path, *, request: Path | None = None, all_passed: bool = False) -> Path:
    output = prepare_output_directory(base / "evidence", overwrite=False)
    checks = []
    for index, name in enumerate(REQUIRED_CHECKS):
        status = "passed"
        if not all_passed and name == "dependency_wheelhouse":
            status = "unavailable"
        item = {
            "name": name,
            "required": True,
            "status": status,
            "passed": status == "passed",
            "execution_report_consistent": True,
            "report_contract_issues": [],
            "reason": "runtime unavailable" if status == "unavailable" else "",
        }
        if name in EXECUTION_REQUIRED_CHECKS:
            log = output / f"{name}.log"
            log.write_text(f"{name}\n", encoding="utf-8")
            item["execution"] = {
                "exit_code": 0,
                "duration_seconds": 0.001,
                "log": log.name,
                "log_sha256": _sha256(log),
                "command": ["python", name],
            }
        if name in REPORT_REQUIRED_CHECKS:
            report = {
                "format": f"test-{name}/1",
                "status": status,
                "passed": status == "passed",
                "available": status != "unavailable",
                "reason": item["reason"],
            }
            report_path = output / f"{name}.json"
            _write_json(report_path, report)
            item["report"] = report_path.name
            item["report_sha256"] = _sha256(report_path)
        checks.append(item)
    request_binding = None
    if request is not None:
        request_payload = json.loads((request / REQUEST_JSON).read_text(encoding="utf-8"))
        request_binding = evidence_request_binding(request, request_payload)
    report = aggregate_report(
        checks=checks,
        mode="collect",
        version=(ROOT / "VERSION").read_text(encoding="utf-8").strip(),
        schema_version=CURRENT_SCHEMA_VERSION,
        output_dir=output,
        request_binding=request_binding,
        collection_started_at=(NOW + timedelta(minutes=1)).isoformat(),
        collection_completed_at=(NOW + timedelta(minutes=5)).isoformat(),
    )
    _write_json(output / "external-validation-report.json", report)
    write_evidence_manifest(output)
    assert verify_evidence_directory(output, source_root=ROOT)["passed"] is True
    return output


def _request(base: Path, private_key: Path, *, target: str = "lab-a", nonce: str = "n" * 32) -> Path:
    output = base / f"request-{target}"
    operator_public = base / "operator-v1-public.json"
    if not operator_public.exists():
        _write_keypair(base, "operator-v1")
    create_request_bundle(
        output_dir=output,
        private_key_file=private_key,
        operator_public_key_file=operator_public,
        target_name=target,
        lifetime_seconds=3600,
        now=NOW,
        nonce=nonce,
    )
    return output


def test_signed_request_round_trip_and_no_private_material(tmp_path: Path) -> None:
    private, public = _write_keypair(tmp_path, "requester-v1")
    request = _request(tmp_path, private)
    statement = verify_request_bundle(
        request,
        requester_public_key_file=public,
        source_root=ROOT,
        now=NOW + timedelta(minutes=1),
    )
    assert statement["target_name"] == "lab-a"
    assert set(path.name for path in request.iterdir()) == {REQUEST_JSON, REQUEST_SIGNATURE}
    assert "private" not in (request / REQUEST_JSON).read_text(encoding="utf-8")


def test_tampered_request_and_wrong_key_are_rejected(tmp_path: Path) -> None:
    private, public = _write_keypair(tmp_path, "requester-v1")
    _, wrong_public = _write_keypair(tmp_path, "requester-v2")
    request = _request(tmp_path, private)
    with pytest.raises(ValueError, match="key_id"):
        verify_request_bundle(request, requester_public_key_file=wrong_public, now=NOW)
    payload = json.loads((request / REQUEST_JSON).read_text(encoding="utf-8"))
    payload["target_name"] = "changed"
    (request / REQUEST_JSON).write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="signature"):
        verify_request_bundle(request, requester_public_key_file=public, now=NOW)


def test_expired_request_and_source_mismatch_are_rejected(tmp_path: Path) -> None:
    private, public = _write_keypair(tmp_path, "requester-v1")
    request = _request(tmp_path, private)
    with pytest.raises(ValueError, match="expired"):
        verify_request_bundle(
            request,
            requester_public_key_file=public,
            now=NOW + timedelta(hours=2),
        )
    other = tmp_path / "other-source"
    other.mkdir()
    (other / "VERSION").write_text("0.0.0\n", encoding="utf-8")
    (other / "SHA256SUMS.txt").write_text("", encoding="utf-8")
    with pytest.raises(ValueError, match="source"):
        verify_request_bundle(
            request,
            requester_public_key_file=public,
            source_root=other,
            now=NOW,
        )


def test_signed_response_authenticates_incomplete_validation_without_promoting_it(tmp_path: Path) -> None:
    requester_private, requester_public = _write_keypair(tmp_path, "requester-v1")
    operator_private, operator_public = _write_keypair(tmp_path, "operator-v1")
    request = _request(tmp_path, requester_private)
    evidence = _valid_evidence(tmp_path, request=request)
    response = tmp_path / "response"
    statement = sign_response_bundle(
        request_dir=request,
        requester_public_key_file=requester_public,
        evidence_dir=evidence,
        operator_private_key_file=operator_private,
        output_dir=response,
        runner_label="authorized-lab-1",
        now=NOW + timedelta(minutes=10),
    )
    assert statement["validation_passed"] is False
    report = verify_response_bundle(
        response,
        expected_request_dir=request,
        requester_public_key_file=requester_public,
        operator_public_key_file=operator_public,
        source_root=ROOT,
    )
    assert report["integrity_passed"] is True
    assert report["execution_source_attested"] is False
    assert report["validation_passed"] is False
    assert {path.name for path in response.iterdir()} == {
        "request",
        "evidence",
        OPERATOR_PUBLIC_KEY,
        PAYLOAD_MANIFEST,
        RESPONSE_JSON,
        RESPONSE_SIGNATURE,
    }
    assert "private_key" not in "\n".join(
        path.read_text(encoding="utf-8", errors="ignore")
        for path in response.rglob("*")
        if path.is_file()
    )


def test_complete_validation_remains_separate_from_exchange_integrity(tmp_path: Path) -> None:
    requester_private, requester_public = _write_keypair(tmp_path, "requester-v1")
    operator_private, operator_public = _write_keypair(tmp_path, "operator-v1")
    request = _request(tmp_path, requester_private)
    evidence = _valid_evidence(tmp_path, request=request, all_passed=True)
    response = tmp_path / "response"
    source_attestation = require_public_source(ROOT)
    sign_response_bundle(
        request_dir=request,
        requester_public_key_file=requester_public,
        evidence_dir=evidence,
        operator_private_key_file=operator_private,
        output_dir=response,
        runner_label="authorized-lab-1",
        now=NOW + timedelta(minutes=10),
        source_attestation_before=source_attestation,
        source_attestation_after=source_attestation,
    )
    report = verify_response_bundle(
        response,
        expected_request_dir=request,
        requester_public_key_file=requester_public,
        operator_public_key_file=operator_public,
        source_root=ROOT,
    )
    assert report["integrity_passed"] is True
    assert report["execution_source_attested"] is True
    assert report["validation_passed"] is True
    assert report["validation_complete"] is True


def test_response_tampering_wrong_operator_and_wrong_expected_request_fail(tmp_path: Path) -> None:
    requester_private, requester_public = _write_keypair(tmp_path, "requester-v1")
    operator_private, operator_public = _write_keypair(tmp_path, "operator-v1")
    _, wrong_operator_public = _write_keypair(tmp_path, "operator-v2")
    request = _request(tmp_path, requester_private, target="lab-a", nonce="a" * 32)
    other_request = _request(tmp_path, requester_private, target="lab-b", nonce="b" * 32)
    evidence = _valid_evidence(tmp_path, request=request)
    response = tmp_path / "response"
    sign_response_bundle(
        request_dir=request,
        requester_public_key_file=requester_public,
        evidence_dir=evidence,
        operator_private_key_file=operator_private,
        output_dir=response,
        runner_label="authorized-lab-1",
        now=NOW + timedelta(minutes=10),
    )
    wrong_key = verify_response_bundle(
        response,
        expected_request_dir=request,
        requester_public_key_file=requester_public,
        operator_public_key_file=wrong_operator_public,
        source_root=ROOT,
    )
    assert wrong_key["integrity_passed"] is False
    wrong_request = verify_response_bundle(
        response,
        expected_request_dir=other_request,
        requester_public_key_file=requester_public,
        operator_public_key_file=operator_public,
        source_root=ROOT,
    )
    assert wrong_request["integrity_passed"] is False
    aggregate = response / "evidence" / "external-validation-report.json"
    aggregate.write_text(aggregate.read_text(encoding="utf-8") + " ", encoding="utf-8")
    tampered = verify_response_bundle(
        response,
        expected_request_dir=request,
        requester_public_key_file=requester_public,
        operator_public_key_file=operator_public,
        source_root=ROOT,
    )
    assert tampered["integrity_passed"] is False


def test_response_statement_tampering_and_extra_payload_fail(tmp_path: Path) -> None:
    requester_private, requester_public = _write_keypair(tmp_path, "requester-v1")
    operator_private, operator_public = _write_keypair(tmp_path, "operator-v1")
    request = _request(tmp_path, requester_private)
    evidence = _valid_evidence(tmp_path, request=request)
    response = tmp_path / "response"
    sign_response_bundle(
        request_dir=request,
        requester_public_key_file=requester_public,
        evidence_dir=evidence,
        operator_private_key_file=operator_private,
        output_dir=response,
        runner_label="authorized-lab-1",
        now=NOW + timedelta(minutes=10),
    )
    statement = json.loads((response / RESPONSE_JSON).read_text(encoding="utf-8"))
    statement["validation_passed"] = True
    (response / RESPONSE_JSON).write_text(json.dumps(statement), encoding="utf-8")
    report = verify_response_bundle(
        response,
        expected_request_dir=request,
        requester_public_key_file=requester_public,
        operator_public_key_file=operator_public,
        source_root=ROOT,
    )
    assert report["integrity_passed"] is False
    (response / "unexpected.txt").write_text("extra", encoding="utf-8")
    report = verify_response_bundle(
        response,
        expected_request_dir=request,
        requester_public_key_file=requester_public,
        operator_public_key_file=operator_public,
        source_root=ROOT,
    )
    assert report["integrity_passed"] is False


def test_sign_response_rejects_invalid_internal_evidence(tmp_path: Path) -> None:
    requester_private, requester_public = _write_keypair(tmp_path, "requester-v1")
    operator_private, _ = _write_keypair(tmp_path, "operator-v1")
    request = _request(tmp_path, requester_private)
    evidence = _valid_evidence(tmp_path, request=request)
    (evidence / "SHA256SUMS.txt").write_text("bad\n", encoding="utf-8")
    with pytest.raises(ValueError, match="independent integrity"):
        sign_response_bundle(
            request_dir=request,
            requester_public_key_file=requester_public,
            evidence_dir=evidence,
            operator_private_key_file=operator_private,
            output_dir=tmp_path / "response",
            runner_label="authorized-lab-1",
            now=NOW + timedelta(minutes=10),
        )


def test_evidence_verifier_rejects_missing_required_report(tmp_path: Path) -> None:
    evidence = _valid_evidence(tmp_path)
    aggregate_path = evidence / "external-validation-report.json"
    aggregate = json.loads(aggregate_path.read_text(encoding="utf-8"))
    item = next(item for item in aggregate["checks"] if item["name"] == "browser_e2e")
    report_name = item.pop("report")
    item.pop("report_sha256")
    (evidence / report_name).unlink()
    aggregate["contract_issues"] = []
    aggregate_path.write_text(json.dumps(aggregate), encoding="utf-8")
    write_evidence_manifest(evidence)
    report = verify_evidence_directory(evidence, source_root=ROOT)
    assert report["passed"] is False
    assert any("required report" in issue for issue in report["issues"])


def test_evidence_verifier_recomputes_report_status(tmp_path: Path) -> None:
    evidence = _valid_evidence(tmp_path)
    aggregate_path = evidence / "external-validation-report.json"
    aggregate = json.loads(aggregate_path.read_text(encoding="utf-8"))
    item = next(item for item in aggregate["checks"] if item["name"] == "runtime_soak")
    report_path = evidence / item["report"]
    report_payload = json.loads(report_path.read_text(encoding="utf-8"))
    report_payload["status"] = "failed"
    report_payload["passed"] = False
    report_path.write_text(json.dumps(report_payload), encoding="utf-8")
    item["report_sha256"] = _sha256(report_path)
    aggregate_path.write_text(json.dumps(aggregate), encoding="utf-8")
    write_evidence_manifest(evidence)
    report = verify_evidence_directory(evidence, source_root=ROOT)
    assert report["passed"] is False
    assert any("evidence-derived status" in issue for issue in report["issues"])


def test_private_key_permissions_and_output_overlap_are_rejected(tmp_path: Path) -> None:
    requester_private, requester_public = _write_keypair(tmp_path, "requester-v1")
    operator_private, _ = _write_keypair(tmp_path, "operator-v1")
    if __import__("os").name == "posix":
        requester_private.chmod(0o644)
        with pytest.raises(ValueError, match="permissions"):
            _request(tmp_path, requester_private)
        requester_private.chmod(0o600)
    request = _request(tmp_path, requester_private)
    evidence = _valid_evidence(tmp_path, request=request)
    with pytest.raises(ValueError, match="must not overlap"):
        sign_response_bundle(
            request_dir=request,
            requester_public_key_file=requester_public,
            evidence_dir=evidence,
            operator_private_key_file=operator_private,
            output_dir=evidence / "response",
            runner_label="authorized-lab-1",
            now=NOW + timedelta(minutes=10),
        )


def test_malformed_operator_statement_fails_without_crashing(tmp_path: Path) -> None:
    requester_private, requester_public = _write_keypair(tmp_path, "requester-v1")
    operator_private, operator_public = _write_keypair(tmp_path, "operator-v1")
    request = _request(tmp_path, requester_private)
    evidence = _valid_evidence(tmp_path, request=request)
    response = tmp_path / "response"
    sign_response_bundle(
        request_dir=request,
        requester_public_key_file=requester_public,
        evidence_dir=evidence,
        operator_private_key_file=operator_private,
        output_dir=response,
        runner_label="authorized-lab-1",
        now=NOW + timedelta(minutes=10),
    )
    statement = json.loads((response / RESPONSE_JSON).read_text(encoding="utf-8"))
    statement["operator"] = []
    (response / RESPONSE_JSON).write_text(json.dumps(statement), encoding="utf-8")
    report = verify_response_bundle(
        response,
        expected_request_dir=request,
        requester_public_key_file=requester_public,
        operator_public_key_file=operator_public,
        source_root=ROOT,
    )
    assert report["integrity_passed"] is False
    assert any(item["name"] == "operator_identity" and not item["passed"] for item in report["checks"])


def test_evidence_verifier_rejects_missing_required_execution(tmp_path: Path) -> None:
    evidence = _valid_evidence(tmp_path)
    aggregate_path = evidence / "external-validation-report.json"
    aggregate = json.loads(aggregate_path.read_text(encoding="utf-8"))
    item = next(item for item in aggregate["checks"] if item["name"] == "public_manifest")
    log_name = item.pop("execution")["log"]
    (evidence / log_name).unlink()
    aggregate["contract_issues"] = []
    aggregate_path.write_text(json.dumps(aggregate), encoding="utf-8")
    write_evidence_manifest(evidence)
    report = verify_evidence_directory(evidence, source_root=ROOT)
    assert report["passed"] is False
    assert any("execution" in issue for issue in report["issues"])
