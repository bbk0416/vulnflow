from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

import scripts.external_validation_runner_kit as kit
from app.core.schema_versions import CURRENT_SCHEMA_VERSION
from scripts.external_validation_exchange import (
    REQUEST_JSON,
    REQUEST_SIGNATURE,
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
from scripts.external_validation_source_attestation import require_public_source

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime.now(timezone.utc) - timedelta(minutes=1)


def _keypair(base: Path, key_id: str) -> tuple[Path, Path]:
    private, public = generate_keypair(key_id=key_id)
    private_path = base / f"{key_id}-private.json"
    public_path = base / f"{key_id}-public.json"
    private_path.write_text(json.dumps(private), encoding="utf-8")
    public_path.write_text(json.dumps(public), encoding="utf-8")
    private_path.chmod(0o600)
    return private_path, public_path


def _request(base: Path, requester_private: Path, operator_public: Path) -> Path:
    output = base / "request"
    create_request_bundle(
        output_dir=output,
        private_key_file=requester_private,
        operator_public_key_file=operator_public,
        target_name="authorized-lab",
        lifetime_seconds=3600,
        minimum_scanner_files=2,
        soak_iterations=2,
        now=NOW,
        nonce="operator-bound-nonce-0000000000000000",
    )
    return output


def _evidence(base: Path, request: Path) -> Path:
    output = prepare_output_directory(base / "evidence", overwrite=False)
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
    request_payload = json.loads((request / REQUEST_JSON).read_text(encoding="utf-8"))
    report = aggregate_report(
        checks=checks,
        mode="collect",
        version=(ROOT / "VERSION").read_text(encoding="utf-8").strip(),
        schema_version=CURRENT_SCHEMA_VERSION,
        output_dir=output,
        request_binding=evidence_request_binding(request, request_payload),
        collection_started_at=(NOW + timedelta(minutes=1)).isoformat(),
        collection_completed_at=(NOW + timedelta(minutes=2)).isoformat(),
    )
    _write_json(output / "external-validation-report.json", report)
    write_evidence_manifest(output)
    return output


def test_request_pins_authorized_operator_without_private_material(tmp_path: Path) -> None:
    requester_private, requester_public = _keypair(tmp_path, "requester-v111")
    _, operator_public = _keypair(tmp_path, "operator-v111")
    request = _request(tmp_path, requester_private, operator_public)
    statement = verify_request_bundle(
        request,
        requester_public_key_file=requester_public,
        source_root=ROOT,
        now=NOW + timedelta(minutes=1),
    )
    operator_payload = json.loads(operator_public.read_text(encoding="utf-8"))
    assert statement["authorized_operator"] == {
        "algorithm": "Ed25519",
        "key_id": operator_payload["key_id"],
        "public_key_fingerprint": operator_payload["public_key_fingerprint"],
    }
    request_text = (request / REQUEST_JSON).read_text(encoding="utf-8")
    assert "private_key_base64" not in request_text


def test_operator_substitution_is_rejected_before_response_output(tmp_path: Path) -> None:
    requester_private, requester_public = _keypair(tmp_path, "requester-v111")
    operator_private, operator_public = _keypair(tmp_path, "operator-authorized")
    wrong_operator_private, _ = _keypair(tmp_path, "operator-substitute")
    request = _request(tmp_path, requester_private, operator_public)
    evidence = _evidence(tmp_path, request)

    with pytest.raises(ValueError, match="not authorized"):
        sign_response_bundle(
            request_dir=request,
            requester_public_key_file=requester_public,
            evidence_dir=evidence,
            operator_private_key_file=wrong_operator_private,
            output_dir=tmp_path / "wrong-response",
            runner_label="substitute-lab",
            now=NOW + timedelta(minutes=3),
        )
    assert not (tmp_path / "wrong-response").exists()

    sign_response_bundle(
        request_dir=request,
        requester_public_key_file=requester_public,
        evidence_dir=evidence,
        operator_private_key_file=operator_private,
        output_dir=tmp_path / "response",
        runner_label="authorized-lab",
        now=NOW + timedelta(minutes=3),
    )


def test_tampering_authorized_operator_invalidates_request_signature(tmp_path: Path) -> None:
    requester_private, requester_public = _keypair(tmp_path, "requester-v111")
    _, operator_public = _keypair(tmp_path, "operator-authorized")
    _, other_public = _keypair(tmp_path, "operator-other")
    request = _request(tmp_path, requester_private, operator_public)
    payload = json.loads((request / REQUEST_JSON).read_text(encoding="utf-8"))
    other_payload = json.loads(other_public.read_text(encoding="utf-8"))
    payload["authorized_operator"]["key_id"] = other_payload["key_id"]
    payload["authorized_operator"]["public_key_fingerprint"] = other_payload["public_key_fingerprint"]
    (request / REQUEST_JSON).write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="signature"):
        verify_request_bundle(
            request,
            requester_public_key_file=requester_public,
            source_root=ROOT,
            now=NOW + timedelta(minutes=1),
        )


def test_response_verifier_requires_request_authorized_operator(tmp_path: Path) -> None:
    requester_private, requester_public = _keypair(tmp_path, "requester-v111")
    operator_private, operator_public = _keypair(tmp_path, "operator-authorized")
    _, other_operator_public = _keypair(tmp_path, "operator-other")
    request = _request(tmp_path, requester_private, operator_public)
    evidence = _evidence(tmp_path, request)
    response = tmp_path / "response"
    source_attestation = require_public_source(ROOT)
    sign_response_bundle(
        request_dir=request,
        requester_public_key_file=requester_public,
        evidence_dir=evidence,
        operator_private_key_file=operator_private,
        output_dir=response,
        runner_label="authorized-lab",
        now=NOW + timedelta(minutes=3),
        source_attestation_before=source_attestation,
        source_attestation_after=source_attestation,
    )
    valid = verify_response_bundle(
        response,
        expected_request_dir=request,
        requester_public_key_file=requester_public,
        operator_public_key_file=operator_public,
        source_root=ROOT,
    )
    assert valid["integrity_passed"] is True
    substituted = verify_response_bundle(
        response,
        expected_request_dir=request,
        requester_public_key_file=requester_public,
        operator_public_key_file=other_operator_public,
        source_root=ROOT,
    )
    assert substituted["integrity_passed"] is False
    assert any(item["name"] == "operator_identity" and not item["passed"] for item in substituted["checks"])


def test_runner_kit_binds_operator_identity_and_rejects_wrong_private_key_before_child(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requester_private, requester_public = _keypair(tmp_path, "requester-v111")
    operator_private, operator_public = _keypair(tmp_path, "operator-authorized")
    wrong_operator_private, _ = _keypair(tmp_path, "operator-other")
    request = _request(tmp_path, requester_private, operator_public)
    archive = tmp_path / "runner-kit.zip"
    result = kit.build_runner_kit(
        output_zip=archive,
        request_dir=request,
        requester_private_key_file=requester_private,
        requester_public_key_file=requester_public,
        source_root=ROOT,
    )
    assert result["verified"] is True
    extracted = kit.extract_runner_kit(
        archive,
        requester_public_key_file=requester_public,
        output_dir=tmp_path / "extracted",
    )
    root = Path(extracted["output"])
    called = False

    def fake_run(*args, **kwargs):
        nonlocal called
        called = True
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(kit.subprocess, "run", fake_run)
    with pytest.raises(ValueError, match="not authorized"):
        kit.run_extracted_kit(
            kit_root=root,
            requester_public_key_file=requester_public,
            operator_private_key_file=wrong_operator_private,
            output_dir=tmp_path / "response-wrong",
            evidence_output_dir=tmp_path / "evidence-wrong",
            runner_label="wrong-lab",
            scanner_dir=None,
            chromium="",
            timeout_seconds=300,
        )
    assert called is False

    report = kit.verify_runner_kit_archive(archive, requester_public_key_file=requester_public)
    assert report["passed"] is True
    report, exit_code = kit.run_extracted_kit(
        kit_root=root,
        requester_public_key_file=requester_public,
        operator_private_key_file=operator_private,
        output_dir=tmp_path / "response-authorized",
        evidence_output_dir=tmp_path / "evidence-authorized",
        runner_label="authorized-lab",
        scanner_dir=None,
        chromium="",
        timeout_seconds=300,
    )
    assert exit_code == 0
    assert report["kit_verification"]["passed"] is True
    assert called is True


def test_request_format_rejects_missing_authorized_operator(tmp_path: Path) -> None:
    requester_private, requester_public = _keypair(tmp_path, "requester-v111")
    _, operator_public = _keypair(tmp_path, "operator-authorized")
    request = _request(tmp_path, requester_private, operator_public)
    payload = json.loads((request / REQUEST_JSON).read_text(encoding="utf-8"))
    del payload["authorized_operator"]
    (request / REQUEST_JSON).write_text(json.dumps(payload), encoding="utf-8")
    # Preserve the original signature to prove the altered request cannot be accepted.
    assert (request / REQUEST_SIGNATURE).is_file()
    with pytest.raises(ValueError, match="authorized operator"):
        verify_request_bundle(
            request,
            requester_public_key_file=requester_public,
            source_root=ROOT,
            now=NOW + timedelta(minutes=1),
        )
