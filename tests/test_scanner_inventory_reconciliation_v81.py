from __future__ import annotations

import unicodedata
from pathlib import Path

import pytest

from app.core.storage import (
    apply_asset_inventory,
    apply_import_batch,
    get_finding,
    get_source_reconciliation,
    init_db,
    list_assets,
    resolve_source_conflict,
)
from app.services.request_processing import parse_assets_csv


def _row(
    fid: str,
    *,
    asset_id: str = "ASSET-81",
    asset_name: str = "portal.example",
    product_version: str = "5.0",
    component_version: str = "1.0",
    cvss: float = 7.5,
) -> dict:
    return {
        "finding_id": fid,
        "product": "Portal",
        "product_version": product_version,
        "asset_id": asset_id,
        "asset_name": asset_name,
        "environment": "prod",
        "cve_id": "CVE-2026-81001",
        "component": "demo-lib",
        "component_version": component_version,
        "cvss": cvss,
        "epss": 0.2,
        "epss_percentile": 0.7,
        "kev": 0,
        "internet_exposed": 0,
        "asset_criticality": 2,
        "data_sensitivity": 2,
        "patch_available": 0,
        "compensating_control": 0,
        "status": "OPEN",
        "owner": "",
        "due_date": "",
        "notes": "",
        "score": 70,
        "threat_score": 30,
        "asset_context_score": 30,
        "remediation_urgency_score": 10,
        "decision": "URGENT_REVIEW",
        "decision_label": "긴급 검토",
        "sla_days": 7,
        "target_date": "2026-09-01",
        "mitigation_required": 0,
        "reasons": "test",
        "policy_version": "test",
        "first_seen_at": "2026-08-01",
        "first_scored_at": "2026-08-01",
        "last_scored_at": "2026-08-01",
        "record_state": "ACTIVE",
        "row_version": 1,
    }


def _nfd(value: str) -> str:
    return unicodedata.normalize("NFD", value)


def test_single_source_version_observation_updates_canonical_values(tmp_path: Path):
    db = tmp_path / "versions.sqlite3"
    init_db(db)
    apply_import_batch(
        db,
        [_row("V-81", product_version="5.0", component_version="1.0")],
        scanner_source="scanner-a",
        filename="first.csv",
    )

    apply_import_batch(
        db,
        [_row("V-81", product_version="5.1", component_version="2.0")],
        scanner_source="scanner-a",
        filename="second.csv",
    )

    finding = get_finding(db, "V-81")
    assert finding["product_version"] == "5.1"
    assert finding["component_version"] == "2.0"


def test_reconciliation_decision_is_ineffective_while_chosen_present_source_omits_field(tmp_path: Path):
    db = tmp_path / "decision-empty.sqlite3"
    init_db(db)
    apply_import_batch(
        db, [_row("A-81", component_version="1.0")],
        scanner_source="scanner-a", filename="a.csv",
    )
    apply_import_batch(
        db, [_row("B-81", component_version="2.0")],
        scanner_source="scanner-b", filename="b.csv",
    )
    detail = get_source_reconciliation(db, "A-81")
    scanner_a = next(item for item in detail["records"] if item["scanner_source"] == "scanner-a")
    resolve_source_conflict(
        db,
        "A-81",
        field_name="component_version",
        chosen_source_record_id=scanner_a["source_record_id"],
        reason="trusted source",
        actor="ops",
    )
    assert get_finding(db, "A-81")["component_version"] == "1.0"

    apply_import_batch(
        db, [_row("A-81", component_version="")],
        scanner_source="scanner-a", filename="a-empty-version.csv",
    )

    finding = get_finding(db, "A-81")
    after = get_source_reconciliation(db, "A-81")
    decision = next(item for item in after["decisions"] if item["field_name"] == "component_version")
    assert finding["component_version"] == "2.0"
    assert decision["status"] == "ACTIVE"
    assert decision["observed_state"] == "PRESENT"
    assert all(item["active_decision"] is None for item in after["conflicts"] if item["field_name"] == "component_version")

    apply_import_batch(
        db, [_row("A-81", component_version="1.5")],
        scanner_source="scanner-a", filename="a-version-return.csv",
    )
    assert get_finding(db, "A-81")["component_version"] == "1.5"
    returned = get_source_reconciliation(db, "A-81")
    conflict = next(item for item in returned["conflicts"] if item["field_name"] == "component_version")
    assert conflict["resolved"] is True
    assert conflict["active_decision"]["chosen_source_record_id"] == scanner_a["source_record_id"]


def test_inventory_link_reuses_scanner_asset_and_allows_future_reimport(tmp_path: Path):
    db = tmp_path / "inventory-reimport.sqlite3"
    init_db(db)
    apply_import_batch(
        db, [_row("INV-81", asset_id="api-81", asset_name="billing-api")],
        scanner_source="scanner-a", filename="scan.csv",
    )
    before = get_finding(db, "INV-81")

    result = apply_asset_inventory(
        db,
        [{
            "asset_id": "api-81",
            "asset_name": "billing-api",
            "service_name": "Billing",
            "business_unit": "Payments",
            "owner": "platform",
            "environment": "prod",
            "criticality": 5,
            "data_sensitivity": 5,
            "internet_exposed": 1,
        }],
        actor="asset-owner",
    )

    linked = get_finding(db, "INV-81")
    assert result["linked_findings"] == 1
    assert linked["asset_ref_id"] == before["asset_ref_id"]
    assert linked["asset_criticality"] == 5
    assert linked["internet_exposed"] == 1
    assert len([item for item in list_assets(db) if item["status"] == "ACTIVE"]) == 1

    replay = apply_import_batch(
        db, [_row("INV-81", asset_id="api-81", asset_name="billing-api")],
        scanner_source="scanner-a", filename="scan-next.csv",
    )
    assert replay["updated"] == 1
    assert get_finding(db, "INV-81")["asset_ref_id"] == before["asset_ref_id"]


def test_inventory_external_id_nfc_nfd_links_existing_scanner_asset(tmp_path: Path):
    db = tmp_path / "inventory-unicode.sqlite3"
    init_db(db)
    nfc = "Café-Asset-81"
    nfd = _nfd(nfc)
    apply_import_batch(
        db, [_row("UNI-INV-81", asset_id=nfd, asset_name="unicode-api")],
        scanner_source="scanner-a", filename="unicode.csv",
    )
    before = get_finding(db, "UNI-INV-81")

    result = apply_asset_inventory(
        db,
        [{
            "asset_id": nfc,
            "asset_name": "unicode-api",
            "environment": "prod",
            "criticality": 5,
            "data_sensitivity": 4,
            "internet_exposed": 1,
        }],
        actor="asset-owner",
    )

    after = get_finding(db, "UNI-INV-81")
    assert result["linked_findings"] == 1
    assert after["asset_ref_id"] == before["asset_ref_id"]
    assert after["asset_criticality"] == 5
    assert after["internet_exposed"] == 1

    replay = apply_import_batch(
        db, [_row("UNI-INV-81", asset_id=nfc, asset_name="unicode-api")],
        scanner_source="scanner-a", filename="unicode-next.csv",
    )
    assert replay["updated"] == 1



def test_inventory_first_unicode_external_id_matches_later_scanner_observation(tmp_path: Path):
    db = tmp_path / "inventory-first.sqlite3"
    init_db(db)
    nfc = "Café-First-81"
    nfd = _nfd(nfc)
    apply_asset_inventory(
        db,
        [{
            "asset_id": nfc,
            "asset_name": "inventory-first",
            "environment": "prod",
            "criticality": 5,
            "data_sensitivity": 4,
            "internet_exposed": 1,
        }],
        actor="asset-owner",
    )
    inventory_ref = list_assets(db)[0]["asset_ref_id"]

    apply_import_batch(
        db, [_row("INV-FIRST-81", asset_id=nfd, asset_name="inventory-first")],
        scanner_source="scanner-a", filename="first-scan.csv",
    )

    finding = get_finding(db, "INV-FIRST-81")
    assert finding["asset_ref_id"] == inventory_ref
    assert finding["asset_criticality"] == 5
    assert finding["data_sensitivity"] == 4
    assert finding["internet_exposed"] == 1


def test_inventory_apply_rejects_unicode_canonical_duplicate_authoritative_ids(tmp_path: Path):
    db = tmp_path / "inventory-duplicate.sqlite3"
    init_db(db)
    nfc = "Café-Duplicate-81"
    nfd = _nfd(nfc)
    rows = [
        {"asset_id": nfc, "asset_name": "one", "environment": "prod"},
        {"asset_id": nfd, "asset_name": "two", "environment": "prod"},
    ]

    with pytest.raises(ValueError, match="중복 권위 식별자"):
        apply_asset_inventory(db, rows, actor="asset-owner")
    assert list_assets(db) == []

def test_asset_csv_rejects_unicode_canonical_duplicate_external_ids():
    nfc = "Café-Asset-81"
    nfd = _nfd(nfc)
    content = (
        "asset_id,asset_name,environment\n"
        f"{nfc},one,prod\n"
        f"{nfd},two,prod\n"
    ).encode("utf-8")

    with pytest.raises(ValueError, match="자산 CSV 중복"):
        parse_assets_csv(content)
