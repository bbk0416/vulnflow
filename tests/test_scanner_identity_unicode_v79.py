from __future__ import annotations

import unicodedata
from pathlib import Path

import pytest

from app.core.storage import apply_import_batch, init_db, list_assets, list_findings
from app.main import normalize_row, score_row
from app.services.request_processing import prepare_findings_rows


def _raw(finding_id: str = "", *, component: str = "openssl", product: str = "Round5") -> dict:
    return {
        "finding_id": finding_id,
        "product": product,
        "product_version": "1.0",
        "asset_id": "",
        "asset_name": "host.example",
        "fqdn": "host.example",
        "environment": "prod",
        "cve_id": "CVE-2026-79001",
        "component": component,
        "component_version": "3.0",
        "cvss": 7.0,
        "epss": 0.1,
        "epss_percentile": 0.2,
        "kev": 0,
        "internet_exposed": 0,
        "asset_criticality": 3,
        "data_sensitivity": 3,
        "patch_available": 1,
        "compensating_control": 0,
        "status": "OPEN",
        "owner": "",
        "due_date": "",
        "notes": "",
    }


def _normalized(raw: dict, scanner_source: str, index: int = 0) -> dict:
    return normalize_row(dict(raw), index, scanner_source=scanner_source)


def test_unicode_nfc_nfd_component_names_share_one_canonical_finding(tmp_path: Path):
    nfc = "café-lib"
    nfd = unicodedata.normalize("NFD", nfc)
    assert nfc != nfd

    db = tmp_path / "component-normalization.sqlite3"
    init_db(db)
    first = apply_import_batch(
        db, [_normalized(_raw("CMP-A", component=nfc), "scanner-a")],
        scanner_source="scanner-a", filename="a.csv",
    )
    second = apply_import_batch(
        db, [_normalized(_raw("CMP-B", component=nfd), "scanner-b")],
        scanner_source="scanner-b", filename="b.csv",
    )

    findings = list_findings(db)
    assert first["inserted"] == 1
    assert second["inserted"] == 0
    assert second["updated"] == 1
    assert len(findings) == 1
    assert findings[0]["source_count"] == 2


def test_auto_finding_id_is_stable_across_scanner_source_nfc_nfd():
    nfc = _normalized(_raw(), "Néssus")
    nfd = _normalized(_raw(), "Ne\u0301ssus")
    assert nfc["finding_id"] == nfd["finding_id"]


def test_auto_finding_id_is_stable_across_identity_field_nfc_nfd():
    nfc_component = "café-lib"
    nfd_component = unicodedata.normalize("NFD", nfc_component)
    first = _normalized(_raw(component=nfc_component), "scanner-a")
    second = _normalized(_raw(component=nfd_component), "scanner-a")
    assert first["finding_id"] == second["finding_id"]


def test_ascii_auto_finding_id_remains_compatible_with_72_0_78():
    assert _normalized(_raw(product="P"), "scanner")["finding_id"] == "AUTO-BB1E91637B96B4B8"


def test_preview_rejects_source_record_equivalent_finding_ids(tmp_path: Path):
    db = tmp_path / "preview-parity.sqlite3"
    init_db(db)
    prepared = prepare_findings_rows(
        [_raw("ABC-1"), _raw("abc-1")],
        scanner_source="scanner-x",
        allow_empty=False,
        db_path=db,
        list_findings_fn=list_findings,
        list_assets_fn=list_assets,
        normalize_callback=lambda raw, idx, source: normalize_row(raw, idx, scanner_source=source),
        rescore_callback=score_row,
        collect_errors=True,
    )
    assert len(prepared["rows"]) == 1
    assert len(prepared["errors"]) == 1
    assert "finding_id 중복" in prepared["errors"][0]["message"]


def test_apply_rejects_source_record_equivalent_finding_ids_before_writes(tmp_path: Path):
    db = tmp_path / "apply-parity.sqlite3"
    init_db(db)
    rows = [
        _normalized(_raw("ABC-1"), "scanner-x", 0),
        _normalized(_raw("abc-1"), "scanner-x", 1),
    ]
    with pytest.raises(ValueError, match="중복 finding_id"):
        apply_import_batch(db, rows, scanner_source="scanner-x", filename="x.csv")
    assert list_findings(db) == []
