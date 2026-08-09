from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from app.core.schema_versions import CURRENT_SCHEMA_VERSION
from scripts.external_validation_acceptance import (
    RECEIPTS_DIR,
    accept_response_bundle,
    verify_acceptance_ledger,
)
from scripts.external_validation_exchange import (
    REQUEST_JSON,
    create_request_bundle,
    evidence_request_binding,
    generate_keypair,
    sign_response_bundle,
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
from scripts.external_validation_source_attestation import require_public_source

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime.now(timezone.utc) - timedelta(minutes=2)


def _keypair(base: Path, key_id: str) -> tuple[Path, Path]:
    private, public = generate_keypair(key_id=key_id)
    private_path = base / f"{key_id}-private.json"
    public_path = base / f"{key_id}-public.json"
    private_path.write_text(json.dumps(private), encoding="utf-8")
    public_path.write_text(json.dumps(public), encoding="utf-8")
    private_path.chmod(0o600)
    return private_path, public_path


def _request(base: Path, requester_private: Path, operator_public: Path, *, name: str = "request") -> Path:
    output = base / name
    create_request_bundle(
        output_dir=output,
        private_key_file=requester_private,
        operator_public_key_file=operator_public,
        target_name="acceptance-lab",
        lifetime_seconds=3600,
        minimum_scanner_files=2,
        soak_iterations=2,
        now=NOW,
        nonce=f"acceptance-ledger-{name}-0000000000000000",
    )
    return output


def _evidence(base: Path, request: Path, *, name: str = "evidence") -> Path:
    output = prepare_output_directory(base / name, overwrite=False)
    checks: list[dict[str, object]] = []
    for check_name in REQUIRED_CHECKS:
        item: dict[str, object] = {
            "name": check_name,
            "required": True,
            "status": "passed",
            "passed": True,
            "execution_report_consistent": True,
            "report_contract_issues": [],
            "reason": "",
        }
        if check_name in EXECUTION_REQUIRED_CHECKS:
            log = output / f"{check_name}.log"
            log.write_text(f"{check_name}\n", encoding="utf-8")
            item["execution"] = {
                "exit_code": 0,
                "duration_seconds": 0.001,
                "log": log.name,
                "log_sha256": _sha256(log),
                "command": ["python", check_name],
            }
        if check_name in REPORT_REQUIRED_CHECKS:
            report_path = output / f"{check_name}.json"
            _write_json(
                report_path,
                {
                    "format": f"test-{check_name}/1",
                    "status": "passed",
                    "passed": True,
                    "available": True,
                    "reason": "",
                },
            )
            item["report"] = report_path.name
            item["report_sha256"] = _sha256(report_path)
        checks.append(item)
    request_payload = json.loads((request / REQUEST_JSON).read_text(encoding="utf-8"))
    report = aggregate_report(
        checks=checks,
        mode="collect",
        version=(ROOT / "VERSION").read_text(encoding="utf-8").strip(),
        schema_version=CURRENT_SCHEMA_VERSION,
        output_dir=output,
        request_binding=evidence_request_binding(request, request_payload),
        collection_started_at=(NOW + timedelta(minutes=1)).isoformat(),
        collection_completed_at=(NOW + timedelta(minutes=1, seconds=10)).isoformat(),
    )
    _write_json(output / "external-validation-report.json", report)
    write_evidence_manifest(output)
    return output


def _response(
    base: Path,
    request: Path,
    requester_public: Path,
    operator_private: Path,
    evidence: Path,
    *,
    name: str,
    runner_label: str,
    seconds: int,
) -> Path:
    output = base / name
    attestation = require_public_source(ROOT)
    sign_response_bundle(
        request_dir=request,
        requester_public_key_file=requester_public,
        evidence_dir=evidence,
        operator_private_key_file=operator_private,
        output_dir=output,
        runner_label=runner_label,
        now=NOW + timedelta(minutes=1, seconds=seconds),
        source_attestation_before=attestation,
        source_attestation_after=attestation,
    )
    return output


def _fixture(tmp_path: Path):
    requester_private, requester_public = _keypair(tmp_path, "requester-v112")
    operator_private, operator_public = _keypair(tmp_path, "operator-v112")
    request = _request(tmp_path, requester_private, operator_public)
    evidence = _evidence(tmp_path, request)
    response = _response(
        tmp_path,
        request,
        requester_public,
        operator_private,
        evidence,
        name="response-a",
        runner_label="acceptance-runner-a",
        seconds=20,
    )
    return requester_private, requester_public, operator_private, operator_public, request, evidence, response


def test_acceptance_receipt_is_requester_signed_and_ledger_verifies(tmp_path: Path) -> None:
    requester_private, requester_public, _, operator_public, request, _, response = _fixture(tmp_path)
    ledger = tmp_path / "acceptance-ledger"
    result = accept_response_bundle(
        response_dir=response,
        expected_request_dir=request,
        requester_private_key_file=requester_private,
        requester_public_key_file=requester_public,
        operator_public_key_file=operator_public,
        ledger_dir=ledger,
        source_root=ROOT,
        now=NOW + timedelta(minutes=2),
    )
    assert result["accepted"] is True
    report = verify_acceptance_ledger(ledger, requester_public_key_file=requester_public)
    assert report["passed"] is True
    assert report["receipt_count"] == 1
    assert report["entries"][0]["integrity_passed"] is True
    assert report["entries"][0]["validation_passed"] is True


def test_same_response_replay_is_rejected_without_second_receipt(tmp_path: Path) -> None:
    requester_private, requester_public, _, operator_public, request, _, response = _fixture(tmp_path)
    ledger = tmp_path / "acceptance-ledger"
    kwargs = dict(
        response_dir=response,
        expected_request_dir=request,
        requester_private_key_file=requester_private,
        requester_public_key_file=requester_public,
        operator_public_key_file=operator_public,
        ledger_dir=ledger,
        source_root=ROOT,
        now=NOW + timedelta(minutes=2),
    )
    accept_response_bundle(**kwargs)
    with pytest.raises(ValueError, match="replay"):
        accept_response_bundle(**kwargs)
    assert len(list((ledger / RECEIPTS_DIR).iterdir())) == 1


def test_conflicting_second_response_is_rejected_as_operator_equivocation(tmp_path: Path) -> None:
    requester_private, requester_public, operator_private, operator_public, request, evidence, response_a = _fixture(tmp_path)
    response_b = _response(
        tmp_path,
        request,
        requester_public,
        operator_private,
        evidence,
        name="response-b",
        runner_label="acceptance-runner-b",
        seconds=25,
    )
    ledger = tmp_path / "acceptance-ledger"
    accept_response_bundle(
        response_dir=response_a,
        expected_request_dir=request,
        requester_private_key_file=requester_private,
        requester_public_key_file=requester_public,
        operator_public_key_file=operator_public,
        ledger_dir=ledger,
        source_root=ROOT,
        now=NOW + timedelta(minutes=2),
    )
    with pytest.raises(ValueError, match="equivocation"):
        accept_response_bundle(
            response_dir=response_b,
            expected_request_dir=request,
            requester_private_key_file=requester_private,
            requester_public_key_file=requester_public,
            operator_public_key_file=operator_public,
            ledger_dir=ledger,
            source_root=ROOT,
            now=NOW + timedelta(minutes=2),
        )
    assert len(list((ledger / RECEIPTS_DIR).iterdir())) == 1


def test_receipt_tampering_breaks_ledger_verification(tmp_path: Path) -> None:
    requester_private, requester_public, _, operator_public, request, _, response = _fixture(tmp_path)
    ledger = tmp_path / "acceptance-ledger"
    accept_response_bundle(
        response_dir=response,
        expected_request_dir=request,
        requester_private_key_file=requester_private,
        requester_public_key_file=requester_public,
        operator_public_key_file=operator_public,
        ledger_dir=ledger,
        source_root=ROOT,
    )
    receipt = next((ledger / RECEIPTS_DIR).iterdir())
    payload = json.loads(receipt.read_text(encoding="utf-8"))
    payload["statement"]["validation_passed"] = False
    receipt.write_text(json.dumps(payload), encoding="utf-8")
    report = verify_acceptance_ledger(ledger, requester_public_key_file=requester_public)
    assert report["passed"] is False
    assert any("signature" in issue for issue in report["issues"])


def test_wrong_requester_private_key_cannot_append(tmp_path: Path) -> None:
    requester_private, requester_public, _, operator_public, request, _, response = _fixture(tmp_path)
    wrong_private, _ = _keypair(tmp_path, "requester-wrong-v112")
    ledger = tmp_path / "acceptance-ledger"
    with pytest.raises(ValueError, match="does not match"):
        accept_response_bundle(
            response_dir=response,
            expected_request_dir=request,
            requester_private_key_file=wrong_private,
            requester_public_key_file=requester_public,
            operator_public_key_file=operator_public,
            ledger_dir=ledger,
            source_root=ROOT,
        )
    assert not ledger.exists()


def test_ledger_rejects_unlisted_or_symbolic_receipt_entries(tmp_path: Path) -> None:
    requester_private, requester_public, _, operator_public, request, _, response = _fixture(tmp_path)
    ledger = tmp_path / "acceptance-ledger"
    accept_response_bundle(
        response_dir=response,
        expected_request_dir=request,
        requester_private_key_file=requester_private,
        requester_public_key_file=requester_public,
        operator_public_key_file=operator_public,
        ledger_dir=ledger,
        source_root=ROOT,
    )
    (ledger / RECEIPTS_DIR / "unexpected.txt").write_text("x", encoding="utf-8")
    report = verify_acceptance_ledger(ledger, requester_public_key_file=requester_public)
    assert report["passed"] is False
    assert any("unexpected" in issue for issue in report["issues"])
