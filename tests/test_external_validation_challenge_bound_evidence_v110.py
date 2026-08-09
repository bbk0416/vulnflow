from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from app.core.schema_versions import CURRENT_SCHEMA_VERSION
from scripts.external_validation_exchange import (
    REQUEST_JSON,
    create_request_bundle,
    evidence_request_binding,
    generate_keypair,
    sign_response_bundle,
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

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 8, 4, 5, 0, tzinfo=timezone.utc)


def _keypair(base: Path, key_id: str) -> tuple[Path, Path]:
    private, public = generate_keypair(key_id=key_id)
    private_path = base / f"{key_id}-private.json"
    public_path = base / f"{key_id}-public.json"
    private_path.write_text(json.dumps(private), encoding="utf-8")
    public_path.write_text(json.dumps(public), encoding="utf-8")
    private_path.chmod(0o600)
    return private_path, public_path


def _request(base: Path, private: Path, *, name: str, nonce: str) -> Path:
    output = base / name
    operator_public = base / "operator-v1-public.json"
    if not operator_public.exists():
        _keypair(base, "operator-v1")
    create_request_bundle(
        output_dir=output,
        private_key_file=private,
        operator_public_key_file=operator_public,
        target_name="authorized-lab",
        lifetime_seconds=3600,
        now=NOW,
        nonce=nonce,
    )
    return output


def _evidence(
    base: Path,
    *,
    request: Path | None,
    started: datetime | None = None,
    completed: datetime | None = None,
) -> Path:
    output = prepare_output_directory(base, overwrite=False)
    checks: list[dict[str, object]] = []
    for name in REQUIRED_CHECKS:
        item: dict[str, object] = {
            "name": name,
            "required": True,
            "status": "passed",
            "passed": True,
            "execution_report_consistent": True,
            "report_contract_issues": [],
            "reason": "",
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
            report_path = output / f"{name}.json"
            _write_json(
                report_path,
                {
                    "format": f"test-{name}/1",
                    "status": "passed",
                    "passed": True,
                    "available": True,
                    "reason": "",
                },
            )
            item["report"] = report_path.name
            item["report_sha256"] = _sha256(report_path)
        checks.append(item)

    binding = None
    if request is not None:
        request_payload = json.loads((request / REQUEST_JSON).read_text(encoding="utf-8"))
        binding = evidence_request_binding(request, request_payload)
    report = aggregate_report(
        checks=checks,
        mode="collect",
        version=(ROOT / "VERSION").read_text(encoding="utf-8").strip(),
        schema_version=CURRENT_SCHEMA_VERSION,
        output_dir=output,
        request_binding=binding,
        collection_started_at=(started or NOW + timedelta(minutes=1)).isoformat(),
        collection_completed_at=(completed or NOW + timedelta(minutes=2)).isoformat(),
    )
    _write_json(output / "external-validation-report.json", report)
    write_evidence_manifest(output)
    assert verify_evidence_directory(output, source_root=ROOT)["passed"] is True
    return output


def test_evidence_from_another_signed_challenge_cannot_be_reused(tmp_path: Path) -> None:
    requester_private, requester_public = _keypair(tmp_path, "requester-v1")
    operator_private, _ = _keypair(tmp_path, "operator-v1")
    request_a = _request(tmp_path, requester_private, name="request-a", nonce="a" * 32)
    request_b = _request(tmp_path, requester_private, name="request-b", nonce="b" * 32)
    evidence = _evidence(tmp_path / "evidence-a", request=request_a)

    sign_response_bundle(
        request_dir=request_a,
        requester_public_key_file=requester_public,
        evidence_dir=evidence,
        operator_private_key_file=operator_private,
        output_dir=tmp_path / "response-a",
        runner_label="authorized-lab",
        now=NOW + timedelta(minutes=3),
    )
    with pytest.raises(ValueError, match="not bound"):
        sign_response_bundle(
            request_dir=request_b,
            requester_public_key_file=requester_public,
            evidence_dir=evidence,
            operator_private_key_file=operator_private,
            output_dir=tmp_path / "response-b",
            runner_label="authorized-lab",
            now=NOW + timedelta(minutes=3),
        )


def test_unbound_evidence_cannot_be_signed_as_challenge_response(tmp_path: Path) -> None:
    requester_private, requester_public = _keypair(tmp_path, "requester-v1")
    operator_private, _ = _keypair(tmp_path, "operator-v1")
    request = _request(tmp_path, requester_private, name="request", nonce="n" * 32)
    evidence = _evidence(tmp_path / "evidence", request=None)
    with pytest.raises(ValueError, match="not bound"):
        sign_response_bundle(
            request_dir=request,
            requester_public_key_file=requester_public,
            evidence_dir=evidence,
            operator_private_key_file=operator_private,
            output_dir=tmp_path / "response",
            runner_label="authorized-lab",
            now=NOW + timedelta(minutes=3),
        )


@pytest.mark.parametrize(
    ("started", "completed", "message"),
    [
        (NOW - timedelta(minutes=10), NOW - timedelta(minutes=9), "predates"),
        (NOW + timedelta(minutes=59), NOW + timedelta(hours=1, seconds=1), "after request expiry"),
        (NOW + timedelta(minutes=4), NOW + timedelta(minutes=5), "after response creation"),
    ],
)
def test_evidence_collection_window_must_fit_request_and_response(
    tmp_path: Path,
    started: datetime,
    completed: datetime,
    message: str,
) -> None:
    requester_private, requester_public = _keypair(tmp_path, "requester-v1")
    operator_private, _ = _keypair(tmp_path, "operator-v1")
    request = _request(tmp_path, requester_private, name="request", nonce="n" * 32)
    evidence = _evidence(
        tmp_path / "evidence",
        request=request,
        started=started,
        completed=completed,
    )
    with pytest.raises(ValueError, match=message):
        sign_response_bundle(
            request_dir=request,
            requester_public_key_file=requester_public,
            evidence_dir=evidence,
            operator_private_key_file=operator_private,
            output_dir=tmp_path / "response",
            runner_label="authorized-lab",
            now=NOW + timedelta(minutes=3),
        )


def test_response_verifier_reports_challenge_bound_collection(tmp_path: Path) -> None:
    requester_private, requester_public = _keypair(tmp_path, "requester-v1")
    operator_private, operator_public = _keypair(tmp_path, "operator-v1")
    request = _request(tmp_path, requester_private, name="request", nonce="n" * 32)
    evidence = _evidence(tmp_path / "evidence", request=request)
    response = tmp_path / "response"
    statement = sign_response_bundle(
        request_dir=request,
        requester_public_key_file=requester_public,
        evidence_dir=evidence,
        operator_private_key_file=operator_private,
        output_dir=response,
        runner_label="authorized-lab",
        now=NOW + timedelta(minutes=3),
    )
    assert len(statement["evidence_request_binding_sha256"]) == 64
    report = verify_response_bundle(
        response,
        expected_request_dir=request,
        requester_public_key_file=requester_public,
        operator_public_key_file=operator_public,
        source_root=ROOT,
    )
    assert report["integrity_passed"] is True
    checks = {item["name"]: item["passed"] for item in report["checks"]}
    assert checks["evidence_request_binding"] is True
    assert checks["evidence_collection_window"] is True
