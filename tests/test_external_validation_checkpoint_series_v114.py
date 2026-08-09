from __future__ import annotations

import importlib.util
import json
import shutil
from datetime import timedelta
from pathlib import Path

import pytest

from scripts.external_validation_acceptance import (
    CHECKPOINTS_DIR,
    RECEIPTS_DIR,
    accept_response_bundle,
    append_acceptance_checkpoint_series,
    verify_acceptance_checkpoint_series,
    verify_acceptance_ledger,
)

_HELPER_PATH = Path(__file__).with_name("test_external_validation_acceptance_ledger_v112.py")
_SPEC = importlib.util.spec_from_file_location("v112_acceptance_helpers", _HELPER_PATH)
assert _SPEC is not None and _SPEC.loader is not None
_HELPERS = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_HELPERS)

NOW = _HELPERS.NOW
ROOT = _HELPERS.ROOT


def _accept_new(
    tmp_path: Path,
    *,
    requester_private: Path,
    requester_public: Path,
    operator_private: Path,
    operator_public: Path,
    ledger: Path,
    suffix: str,
    series: Path | None = None,
) -> tuple[Path, Path]:
    request = _HELPERS._request(tmp_path, requester_private, operator_public, name=f"request-{suffix}")
    evidence = _HELPERS._evidence(tmp_path, request, name=f"evidence-{suffix}")
    response = _HELPERS._response(
        tmp_path,
        request,
        requester_public,
        operator_private,
        evidence,
        name=f"response-{suffix}",
        runner_label=f"runner-{suffix}",
        seconds=20 + len(suffix),
    )
    accept_response_bundle(
        response_dir=response,
        expected_request_dir=request,
        requester_private_key_file=requester_private,
        requester_public_key_file=requester_public,
        operator_public_key_file=operator_public,
        ledger_dir=ledger,
        minimum_checkpoint_series_dir=series,
        source_root=ROOT,
        now=NOW + timedelta(minutes=2),
    )
    return request, response


def _base(tmp_path: Path):
    requester_private, requester_public = _HELPERS._keypair(tmp_path, "requester-v114")
    operator_private, operator_public = _HELPERS._keypair(tmp_path, "operator-v114")
    ledger = tmp_path / "ledger"
    series = tmp_path / "trusted-checkpoint-series"
    return requester_private, requester_public, operator_private, operator_public, ledger, series


def test_checkpoint_series_appends_monotonic_signed_heads(tmp_path: Path) -> None:
    requester_private, requester_public, operator_private, operator_public, ledger, series = _base(tmp_path)
    _accept_new(tmp_path, requester_private=requester_private, requester_public=requester_public, operator_private=operator_private, operator_public=operator_public, ledger=ledger, suffix="a")
    first = append_acceptance_checkpoint_series(ledger, series_dir=series, requester_private_key_file=requester_private, requester_public_key_file=requester_public, now=NOW + timedelta(minutes=3))
    _accept_new(tmp_path, requester_private=requester_private, requester_public=requester_public, operator_private=operator_private, operator_public=operator_public, ledger=ledger, suffix="b", series=series)
    second = append_acceptance_checkpoint_series(ledger, series_dir=series, requester_private_key_file=requester_private, requester_public_key_file=requester_public, now=NOW + timedelta(minutes=4))
    report = verify_acceptance_checkpoint_series(series, requester_public_key_file=requester_public)
    assert report["passed"] is True
    assert report["checkpoint_count"] == 2
    assert report["entries"][0]["generation"] == 1
    assert report["entries"][1]["generation"] == 2
    assert report["entries"][1]["previous_checkpoint_sha256"] == first["checkpoint_sha256"]
    assert second["series"]["head_checkpoint_sha256"] == report["head_checkpoint_sha256"]


def test_series_latest_head_blocks_rollback_even_if_old_checkpoint_is_available(tmp_path: Path) -> None:
    requester_private, requester_public, operator_private, operator_public, ledger, series = _base(tmp_path)
    _accept_new(tmp_path, requester_private=requester_private, requester_public=requester_public, operator_private=operator_private, operator_public=operator_public, ledger=ledger, suffix="a")
    append_acceptance_checkpoint_series(ledger, series_dir=series, requester_private_key_file=requester_private, requester_public_key_file=requester_public)
    old_checkpoint = tmp_path / "old-checkpoint.json"
    shutil.copy2(series / CHECKPOINTS_DIR / "00000001.checkpoint.json", old_checkpoint)
    _accept_new(tmp_path, requester_private=requester_private, requester_public=requester_public, operator_private=operator_private, operator_public=operator_public, ledger=ledger, suffix="b", series=series)
    append_acceptance_checkpoint_series(ledger, series_dir=series, requester_private_key_file=requester_private, requester_public_key_file=requester_public)
    (ledger / RECEIPTS_DIR / "00000002.receipt.json").unlink()
    legacy = verify_acceptance_ledger(ledger, requester_public_key_file=requester_public)
    assert legacy["passed"] is True and legacy["receipt_count"] == 1
    guarded = verify_acceptance_ledger(ledger, requester_public_key_file=requester_public, minimum_checkpoint_series_dir=series)
    assert guarded["passed"] is False
    assert any("older than the minimum checkpoint" in issue for issue in guarded["issues"])


def test_rolled_back_or_divergent_ledger_cannot_advance_series(tmp_path: Path) -> None:
    requester_private, requester_public, operator_private, operator_public, ledger, series = _base(tmp_path)
    _accept_new(tmp_path, requester_private=requester_private, requester_public=requester_public, operator_private=operator_private, operator_public=operator_public, ledger=ledger, suffix="a")
    append_acceptance_checkpoint_series(ledger, series_dir=series, requester_private_key_file=requester_private, requester_public_key_file=requester_public)
    _accept_new(tmp_path, requester_private=requester_private, requester_public=requester_public, operator_private=operator_private, operator_public=operator_public, ledger=ledger, suffix="b", series=series)
    append_acceptance_checkpoint_series(ledger, series_dir=series, requester_private_key_file=requester_private, requester_public_key_file=requester_public)
    (ledger / RECEIPTS_DIR / "00000002.receipt.json").unlink()
    with pytest.raises(ValueError, match="does not extend"):
        append_acceptance_checkpoint_series(ledger, series_dir=series, requester_private_key_file=requester_private, requester_public_key_file=requester_public)
    assert len(list((series / CHECKPOINTS_DIR).iterdir())) == 2


def test_series_rejects_deleted_generation_or_hash_chain_tampering(tmp_path: Path) -> None:
    requester_private, requester_public, operator_private, operator_public, ledger, series = _base(tmp_path)
    _accept_new(tmp_path, requester_private=requester_private, requester_public=requester_public, operator_private=operator_private, operator_public=operator_public, ledger=ledger, suffix="a")
    append_acceptance_checkpoint_series(ledger, series_dir=series, requester_private_key_file=requester_private, requester_public_key_file=requester_public)
    _accept_new(tmp_path, requester_private=requester_private, requester_public=requester_public, operator_private=operator_private, operator_public=operator_public, ledger=ledger, suffix="b", series=series)
    append_acceptance_checkpoint_series(ledger, series_dir=series, requester_private_key_file=requester_private, requester_public_key_file=requester_public)
    second = series / CHECKPOINTS_DIR / "00000002.checkpoint.json"
    payload = json.loads(second.read_text(encoding="utf-8"))
    payload["statement"]["previous_checkpoint_sha256"] = "f" * 64
    second.write_text(json.dumps(payload), encoding="utf-8")
    report = verify_acceptance_checkpoint_series(series, requester_public_key_file=requester_public)
    assert report["passed"] is False
    assert any("hash chain" in issue or "signature" in issue for issue in report["issues"])


def test_series_refuses_duplicate_checkpoint_without_new_receipt(tmp_path: Path) -> None:
    requester_private, requester_public, operator_private, operator_public, ledger, series = _base(tmp_path)
    _accept_new(tmp_path, requester_private=requester_private, requester_public=requester_public, operator_private=operator_private, operator_public=operator_public, ledger=ledger, suffix="a")
    append_acceptance_checkpoint_series(ledger, series_dir=series, requester_private_key_file=requester_private, requester_public_key_file=requester_public)
    with pytest.raises(ValueError, match="no new receipt"):
        append_acceptance_checkpoint_series(ledger, series_dir=series, requester_private_key_file=requester_private, requester_public_key_file=requester_public)
    assert len(list((series / CHECKPOINTS_DIR).iterdir())) == 1


def test_series_is_bound_to_requester_and_rejects_unexpected_inventory(tmp_path: Path) -> None:
    requester_private, requester_public, operator_private, operator_public, ledger, series = _base(tmp_path)
    _accept_new(tmp_path, requester_private=requester_private, requester_public=requester_public, operator_private=operator_private, operator_public=operator_public, ledger=ledger, suffix="a")
    append_acceptance_checkpoint_series(ledger, series_dir=series, requester_private_key_file=requester_private, requester_public_key_file=requester_public)
    _, wrong_public = _HELPERS._keypair(tmp_path, "wrong-requester-v114")
    wrong = verify_acceptance_checkpoint_series(series, requester_public_key_file=wrong_public)
    assert wrong["passed"] is False
    (series / CHECKPOINTS_DIR / "unexpected.txt").write_text("x", encoding="utf-8")
    report = verify_acceptance_checkpoint_series(series, requester_public_key_file=requester_public)
    assert report["passed"] is False
    assert any("unexpected" in issue for issue in report["issues"])
