from __future__ import annotations

import importlib.util
import json
from datetime import timedelta
from pathlib import Path

import pytest

from scripts.external_validation_acceptance import (
    RECEIPTS_DIR,
    accept_response_bundle,
    create_acceptance_checkpoint,
    verify_acceptance_checkpoint,
    verify_acceptance_ledger,
)

_HELPER_PATH = Path(__file__).with_name("test_external_validation_acceptance_ledger_v112.py")
_SPEC = importlib.util.spec_from_file_location("v112_acceptance_helpers", _HELPER_PATH)
assert _SPEC is not None and _SPEC.loader is not None
_HELPERS = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_HELPERS)

NOW = _HELPERS.NOW
ROOT = _HELPERS.ROOT


def _two_receipt_fixture(tmp_path: Path):
    requester_private, requester_public, operator_private, operator_public, request_a, _, response_a = _HELPERS._fixture(tmp_path)
    request_b = _HELPERS._request(tmp_path, requester_private, operator_public, name="request-b")
    evidence_b = _HELPERS._evidence(tmp_path, request_b, name="evidence-b")
    response_b = _HELPERS._response(
        tmp_path,
        request_b,
        requester_public,
        operator_private,
        evidence_b,
        name="response-b",
        runner_label="acceptance-runner-b",
        seconds=30,
    )
    ledger = tmp_path / "acceptance-ledger"
    common = {
        "requester_private_key_file": requester_private,
        "requester_public_key_file": requester_public,
        "operator_public_key_file": operator_public,
        "ledger_dir": ledger,
        "source_root": ROOT,
        "now": NOW + timedelta(minutes=2),
    }
    accept_response_bundle(response_dir=response_a, expected_request_dir=request_a, **common)
    accept_response_bundle(response_dir=response_b, expected_request_dir=request_b, **common)
    return requester_private, requester_public, operator_public, request_b, response_b, ledger


def test_signed_checkpoint_verifies_and_binds_current_head(tmp_path: Path) -> None:
    requester_private, requester_public, _, _, _, ledger = _two_receipt_fixture(tmp_path)
    checkpoint = tmp_path / "trusted" / "minimum-checkpoint.json"
    created = create_acceptance_checkpoint(
        ledger,
        requester_private_key_file=requester_private,
        requester_public_key_file=requester_public,
        output_file=checkpoint,
        now=NOW + timedelta(minutes=3),
    )
    assert created["passed"] is True
    assert created["statement"]["receipt_count"] == 2
    report = verify_acceptance_ledger(
        ledger,
        requester_public_key_file=requester_public,
        minimum_checkpoint_file=checkpoint,
    )
    assert report["passed"] is True
    assert report["minimum_checkpoint"]["head_receipt_sha256"] == report["head_receipt_sha256"]


def test_valid_prefix_rollback_is_detected_by_minimum_checkpoint(tmp_path: Path) -> None:
    requester_private, requester_public, _, _, _, ledger = _two_receipt_fixture(tmp_path)
    checkpoint = tmp_path / "minimum-checkpoint.json"
    create_acceptance_checkpoint(
        ledger,
        requester_private_key_file=requester_private,
        requester_public_key_file=requester_public,
        output_file=checkpoint,
    )
    (ledger / RECEIPTS_DIR / "00000002.receipt.json").unlink()
    legacy_report = verify_acceptance_ledger(ledger, requester_public_key_file=requester_public)
    assert legacy_report["passed"] is True
    assert legacy_report["receipt_count"] == 1
    guarded_report = verify_acceptance_ledger(
        ledger,
        requester_public_key_file=requester_public,
        minimum_checkpoint_file=checkpoint,
    )
    assert guarded_report["passed"] is False
    assert any("older than the minimum checkpoint" in issue for issue in guarded_report["issues"])


def test_rolled_back_ledger_cannot_reaccept_when_checkpoint_is_required(tmp_path: Path) -> None:
    requester_private, requester_public, operator_public, request_b, response_b, ledger = _two_receipt_fixture(tmp_path)
    checkpoint = tmp_path / "minimum-checkpoint.json"
    create_acceptance_checkpoint(
        ledger,
        requester_private_key_file=requester_private,
        requester_public_key_file=requester_public,
        output_file=checkpoint,
    )
    (ledger / RECEIPTS_DIR / "00000002.receipt.json").unlink()
    with pytest.raises(ValueError, match="ledger failed integrity"):
        accept_response_bundle(
            response_dir=response_b,
            expected_request_dir=request_b,
            requester_private_key_file=requester_private,
            requester_public_key_file=requester_public,
            operator_public_key_file=operator_public,
            ledger_dir=ledger,
            minimum_checkpoint_file=checkpoint,
            source_root=ROOT,
            now=NOW + timedelta(minutes=4),
        )
    assert len(list((ledger / RECEIPTS_DIR).iterdir())) == 1


def test_ledger_may_extend_beyond_a_valid_minimum_checkpoint(tmp_path: Path) -> None:
    requester_private, requester_public, operator_private, operator_public, request_a, _, response_a = _HELPERS._fixture(tmp_path)
    ledger = tmp_path / "acceptance-ledger"
    common = {
        "requester_private_key_file": requester_private,
        "requester_public_key_file": requester_public,
        "operator_public_key_file": operator_public,
        "ledger_dir": ledger,
        "source_root": ROOT,
        "now": NOW + timedelta(minutes=2),
    }
    accept_response_bundle(response_dir=response_a, expected_request_dir=request_a, **common)
    checkpoint = tmp_path / "minimum-checkpoint.json"
    create_acceptance_checkpoint(
        ledger,
        requester_private_key_file=requester_private,
        requester_public_key_file=requester_public,
        output_file=checkpoint,
    )
    request_b = _HELPERS._request(tmp_path, requester_private, operator_public, name="request-extension")
    evidence_b = _HELPERS._evidence(tmp_path, request_b, name="evidence-extension")
    response_b = _HELPERS._response(
        tmp_path,
        request_b,
        requester_public,
        operator_private,
        evidence_b,
        name="response-extension",
        runner_label="acceptance-extension",
        seconds=35,
    )
    accept_response_bundle(
        response_dir=response_b,
        expected_request_dir=request_b,
        minimum_checkpoint_file=checkpoint,
        **common,
    )
    report = verify_acceptance_ledger(
        ledger,
        requester_public_key_file=requester_public,
        minimum_checkpoint_file=checkpoint,
    )
    assert report["passed"] is True
    assert report["receipt_count"] == 2


def test_checkpoint_tampering_is_rejected(tmp_path: Path) -> None:
    requester_private, requester_public, _, _, _, ledger = _two_receipt_fixture(tmp_path)
    checkpoint = tmp_path / "minimum-checkpoint.json"
    create_acceptance_checkpoint(
        ledger,
        requester_private_key_file=requester_private,
        requester_public_key_file=requester_public,
        output_file=checkpoint,
    )
    payload = json.loads(checkpoint.read_text(encoding="utf-8"))
    payload["statement"]["receipt_count"] = 1
    checkpoint.write_text(json.dumps(payload), encoding="utf-8")
    report = verify_acceptance_checkpoint(checkpoint, requester_public_key_file=requester_public)
    assert report["passed"] is False
    assert any("signature" in issue for issue in report["issues"])


def test_checkpoint_is_rejected_under_a_different_requester_key(tmp_path: Path) -> None:
    requester_private, requester_public, _, _, _, ledger = _two_receipt_fixture(tmp_path)
    checkpoint = tmp_path / "minimum-checkpoint.json"
    create_acceptance_checkpoint(
        ledger,
        requester_private_key_file=requester_private,
        requester_public_key_file=requester_public,
        output_file=checkpoint,
    )
    _, wrong_public = _HELPERS._keypair(tmp_path, "checkpoint-wrong-requester-v113")
    report = verify_acceptance_checkpoint(checkpoint, requester_public_key_file=wrong_public)
    assert report["passed"] is False
    assert any("requester identity" in issue or "signature" in issue for issue in report["issues"])
