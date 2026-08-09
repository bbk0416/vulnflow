from __future__ import annotations

import importlib.util
import json
import shutil
import zipfile
from pathlib import Path

import pytest

from scripts.external_validation_acceptance import CHECKPOINTS_DIR
from scripts.external_validation_checkpoint_transfer import (
    build_checkpoint_series_transfer,
    install_checkpoint_series_transfer,
    verify_checkpoint_series_transfer,
)

_HELPER_PATH = Path(__file__).with_name("test_external_validation_checkpoint_series_v114.py")
_SPEC = importlib.util.spec_from_file_location("v114_checkpoint_helpers", _HELPER_PATH)
assert _SPEC is not None and _SPEC.loader is not None
_HELPERS = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_HELPERS)


def _two_generation_state(tmp_path: Path):
    requester_private, requester_public, operator_private, operator_public, ledger, series = _HELPERS._base(tmp_path)
    _HELPERS._accept_new(
        tmp_path,
        requester_private=requester_private,
        requester_public=requester_public,
        operator_private=operator_private,
        operator_public=operator_public,
        ledger=ledger,
        suffix="a",
    )
    from scripts.external_validation_acceptance import append_acceptance_checkpoint_series

    append_acceptance_checkpoint_series(
        ledger,
        series_dir=series,
        requester_private_key_file=requester_private,
        requester_public_key_file=requester_public,
    )
    bundle_one = tmp_path / "series-one.zip"
    build_checkpoint_series_transfer(
        series,
        requester_private_key_file=requester_private,
        requester_public_key_file=requester_public,
        output_zip=bundle_one,
    )
    _HELPERS._accept_new(
        tmp_path,
        requester_private=requester_private,
        requester_public=requester_public,
        operator_private=operator_private,
        operator_public=operator_public,
        ledger=ledger,
        suffix="b",
        series=series,
    )
    append_acceptance_checkpoint_series(
        ledger,
        series_dir=series,
        requester_private_key_file=requester_private,
        requester_public_key_file=requester_public,
    )
    bundle_two = tmp_path / "series-two.zip"
    build_checkpoint_series_transfer(
        series,
        requester_private_key_file=requester_private,
        requester_public_key_file=requester_public,
        output_zip=bundle_two,
    )
    return requester_private, requester_public, operator_private, operator_public, ledger, series, bundle_one, bundle_two


def test_transfer_bundle_is_deterministic_and_contains_no_private_key(tmp_path: Path) -> None:
    requester_private, requester_public, _, _, _, series, _, _ = _two_generation_state(tmp_path)
    first = tmp_path / "deterministic-a.zip"
    second = tmp_path / "deterministic-b.zip"
    build_checkpoint_series_transfer(series, requester_private_key_file=requester_private, requester_public_key_file=requester_public, output_zip=first)
    build_checkpoint_series_transfer(series, requester_private_key_file=requester_private, requester_public_key_file=requester_public, output_zip=second)
    assert first.read_bytes() == second.read_bytes()
    with zipfile.ZipFile(first) as archive:
        combined = b"\n".join(archive.read(info) for info in archive.infolist() if not info.is_dir())
    assert b"private_key_base64" not in combined


def test_transfer_installs_exact_head_and_is_idempotent(tmp_path: Path) -> None:
    _, requester_public, _, _, _, _, _, bundle_two = _two_generation_state(tmp_path)
    destination = tmp_path / "independent-store"
    first = install_checkpoint_series_transfer(bundle_two, series_dir=destination, requester_public_key_file=requester_public)
    assert first["passed"] is True
    assert first["incoming_checkpoint_count"] == 2
    assert first["checkpoints_added"] == 2
    second = install_checkpoint_series_transfer(bundle_two, series_dir=destination, requester_public_key_file=requester_public)
    assert second["idempotent"] is True
    assert second["checkpoints_added"] == 0


def test_interrupted_prefix_copy_resumes_to_signed_head(tmp_path: Path) -> None:
    _, requester_public, _, _, _, series, _, bundle_two = _two_generation_state(tmp_path)
    destination = tmp_path / "partial-store"
    shutil.copytree(series, destination)
    (destination / CHECKPOINTS_DIR / "00000002.checkpoint.json").unlink()
    from scripts.external_validation_acceptance import verify_acceptance_checkpoint_series

    assert verify_acceptance_checkpoint_series(destination, requester_public_key_file=requester_public)["passed"] is True
    report = install_checkpoint_series_transfer(bundle_two, series_dir=destination, requester_public_key_file=requester_public)
    assert report["checkpoints_added"] == 1
    assert report["installed_checkpoint_count"] == 2


def test_stale_transfer_cannot_roll_back_newer_destination(tmp_path: Path) -> None:
    _, requester_public, _, _, _, _, bundle_one, bundle_two = _two_generation_state(tmp_path)
    destination = tmp_path / "store"
    install_checkpoint_series_transfer(bundle_two, series_dir=destination, requester_public_key_file=requester_public)
    with pytest.raises(ValueError, match="older than"):
        install_checkpoint_series_transfer(bundle_one, series_dir=destination, requester_public_key_file=requester_public)
    assert len(list((destination / CHECKPOINTS_DIR).glob("*.checkpoint.json"))) == 2


def test_forked_transfer_cannot_extend_installed_series(tmp_path: Path) -> None:
    requester_private, requester_public, operator_private, operator_public, ledger, series = _HELPERS._base(tmp_path)
    from scripts.external_validation_acceptance import append_acceptance_checkpoint_series

    _HELPERS._accept_new(tmp_path, requester_private=requester_private, requester_public=requester_public, operator_private=operator_private, operator_public=operator_public, ledger=ledger, suffix="base")
    append_acceptance_checkpoint_series(ledger, series_dir=series, requester_private_key_file=requester_private, requester_public_key_file=requester_public)
    ledger_fork = tmp_path / "ledger-fork"
    series_fork = tmp_path / "series-fork"
    shutil.copytree(ledger, ledger_fork)
    shutil.copytree(series, series_fork)

    _HELPERS._accept_new(tmp_path, requester_private=requester_private, requester_public=requester_public, operator_private=operator_private, operator_public=operator_public, ledger=ledger, suffix="left", series=series)
    append_acceptance_checkpoint_series(ledger, series_dir=series, requester_private_key_file=requester_private, requester_public_key_file=requester_public)
    left = tmp_path / "left.zip"
    build_checkpoint_series_transfer(series, requester_private_key_file=requester_private, requester_public_key_file=requester_public, output_zip=left)

    _HELPERS._accept_new(tmp_path, requester_private=requester_private, requester_public=requester_public, operator_private=operator_private, operator_public=operator_public, ledger=ledger_fork, suffix="right", series=series_fork)
    append_acceptance_checkpoint_series(ledger_fork, series_dir=series_fork, requester_private_key_file=requester_private, requester_public_key_file=requester_public)
    right = tmp_path / "right.zip"
    build_checkpoint_series_transfer(series_fork, requester_private_key_file=requester_private, requester_public_key_file=requester_public, output_zip=right)

    destination = tmp_path / "store"
    install_checkpoint_series_transfer(left, series_dir=destination, requester_public_key_file=requester_public)
    with pytest.raises(ValueError, match="does not extend"):
        install_checkpoint_series_transfer(right, series_dir=destination, requester_public_key_file=requester_public)


def test_truncated_or_path_traversal_transfer_is_rejected(tmp_path: Path) -> None:
    _, requester_public, _, _, _, _, _, bundle_two = _two_generation_state(tmp_path)
    truncated = tmp_path / "truncated.zip"
    truncated.write_bytes(bundle_two.read_bytes()[: max(1, bundle_two.stat().st_size // 2)])
    assert verify_checkpoint_series_transfer(truncated, requester_public_key_file=requester_public)["passed"] is False

    malicious = tmp_path / "malicious.zip"
    with zipfile.ZipFile(malicious, "w") as archive:
        archive.writestr("root/../escape", b"x")
    report = verify_checkpoint_series_transfer(malicious, requester_public_key_file=requester_public)
    assert report["passed"] is False
    assert any("unsafe" in issue for issue in report["issues"])


def test_signed_inventory_tampering_is_rejected(tmp_path: Path) -> None:
    _, requester_public, _, _, _, _, _, bundle_two = _two_generation_state(tmp_path)
    tampered = tmp_path / "tampered.zip"
    with zipfile.ZipFile(bundle_two) as source, zipfile.ZipFile(tampered, "w") as target:
        changed = False
        for info in source.infolist():
            data = source.read(info)
            if not info.is_dir() and info.filename.endswith("00000002.checkpoint.json") and not changed:
                payload = json.loads(data.decode("utf-8"))
                payload["statement"]["receipt_count"] += 1
                data = json.dumps(payload, sort_keys=True).encode("utf-8")
                changed = True
            target.writestr(info, data)
    report = verify_checkpoint_series_transfer(tampered, requester_public_key_file=requester_public)
    assert report["passed"] is False
