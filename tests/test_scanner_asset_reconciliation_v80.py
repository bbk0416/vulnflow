from __future__ import annotations

import unicodedata
from pathlib import Path

from app.core.storage import (
    apply_import_batch,
    get_finding,
    get_source_reconciliation,
    init_db,
    list_findings,
    resolve_source_conflict,
)
from app.services.asset_identity import identifier_scope, normalize_asset_identifier


def _row(
    fid: str,
    *,
    cvss: float = 7.5,
    asset_id: str = "ASSET-80",
    asset_name: str = "portal.example",
    environment: str = "prod",
) -> dict:
    return {
        "finding_id": fid,
        "product": "Portal",
        "product_version": "5.0",
        "asset_id": asset_id,
        "asset_name": asset_name,
        "environment": environment,
        "cve_id": "CVE-2026-80001",
        "component": "demo-lib",
        "component_version": "1.0",
        "cvss": cvss,
        "epss": 0.2,
        "epss_percentile": 0.7,
        "kev": 0,
        "internet_exposed": 1,
        "asset_criticality": 5,
        "data_sensitivity": 4,
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
        "target_date": "2026-08-01",
        "mitigation_required": 0,
        "reasons": "test",
        "policy_version": "test",
        "first_seen_at": "2026-07-20",
        "first_scored_at": "2026-07-20",
        "last_scored_at": "2026-07-20",
        "record_state": "ACTIVE",
        "row_version": 1,
    }


def _nfd(value: str) -> str:
    return unicodedata.normalize("NFD", value)


def test_absent_authoritative_source_no_longer_overrides_present_source(tmp_path: Path):
    db = tmp_path / "absent-resolution.sqlite3"
    init_db(db)
    apply_import_batch(db, [_row("A-80", cvss=7.5)], scanner_source="scanner-a", filename="a.csv", reconcile_missing=True)
    apply_import_batch(db, [_row("B-80", cvss=9.1)], scanner_source="scanner-b", filename="b.csv", reconcile_missing=True)
    detail = get_source_reconciliation(db, "A-80")
    scanner_a = next(item for item in detail["records"] if item["scanner_source"] == "scanner-a")
    resolve_source_conflict(
        db,
        "A-80",
        field_name="cvss",
        chosen_source_record_id=scanner_a["source_record_id"],
        reason="trusted source",
        actor="ops",
    )
    assert get_finding(db, "A-80")["cvss"] == 7.5

    apply_import_batch(db, [], scanner_source="scanner-a", filename="a-empty.csv", reconcile_missing=True)

    assert get_finding(db, "A-80")["cvss"] == 9.1
    after = get_source_reconciliation(db, "A-80")
    decision = next(item for item in after["decisions"] if item["field_name"] == "cvss")
    assert decision["status"] == "ACTIVE"
    assert decision["observed_state"] == "ABSENT"


def test_absent_authoritative_source_does_not_resolve_remaining_present_conflict(tmp_path: Path):
    db = tmp_path / "remaining-conflict.sqlite3"
    init_db(db)
    apply_import_batch(db, [_row("A-80", cvss=7.5)], scanner_source="scanner-a", filename="a.csv", reconcile_missing=True)
    apply_import_batch(db, [_row("B-80", cvss=8.0)], scanner_source="scanner-b", filename="b.csv", reconcile_missing=True)
    apply_import_batch(db, [_row("C-80", cvss=9.1)], scanner_source="scanner-c", filename="c.csv", reconcile_missing=True)
    detail = get_source_reconciliation(db, "A-80")
    scanner_a = next(item for item in detail["records"] if item["scanner_source"] == "scanner-a")
    resolve_source_conflict(
        db,
        "A-80",
        field_name="cvss",
        chosen_source_record_id=scanner_a["source_record_id"],
        reason="trusted source",
        actor="ops",
    )

    apply_import_batch(db, [], scanner_source="scanner-a", filename="a-empty.csv", reconcile_missing=True)

    after = get_source_reconciliation(db, "A-80")
    cvss_conflict = next(item for item in after["conflicts"] if item["field_name"] == "cvss")
    assert cvss_conflict["values"] == [8.0, 9.1]
    assert cvss_conflict["resolved"] is False
    assert cvss_conflict["active_decision"] is None
    assert after["unresolved_count"] >= 1
    assert get_finding(db, "A-80")["cvss"] == 9.1


def test_authoritative_source_decision_becomes_effective_again_after_source_returns(tmp_path: Path):
    db = tmp_path / "resolution-return.sqlite3"
    init_db(db)
    apply_import_batch(db, [_row("A-80", cvss=7.5)], scanner_source="scanner-a", filename="a.csv", reconcile_missing=True)
    apply_import_batch(db, [_row("B-80", cvss=9.1)], scanner_source="scanner-b", filename="b.csv", reconcile_missing=True)
    detail = get_source_reconciliation(db, "A-80")
    scanner_a = next(item for item in detail["records"] if item["scanner_source"] == "scanner-a")
    resolve_source_conflict(
        db,
        "A-80",
        field_name="cvss",
        chosen_source_record_id=scanner_a["source_record_id"],
        reason="trusted source",
        actor="ops",
    )
    apply_import_batch(db, [], scanner_source="scanner-a", filename="a-empty.csv", reconcile_missing=True)
    assert get_finding(db, "A-80")["cvss"] == 9.1

    apply_import_batch(db, [_row("A-80", cvss=8.2)], scanner_source="scanner-a", filename="a-return.csv", reconcile_missing=True)

    assert get_finding(db, "A-80")["cvss"] == 8.2
    after = get_source_reconciliation(db, "A-80")
    cvss_conflict = next(item for item in after["conflicts"] if item["field_name"] == "cvss")
    assert cvss_conflict["resolved"] is True
    assert cvss_conflict["active_decision"]["observed_state"] == "PRESENT"


def test_scanner_asset_id_nfc_nfd_reimport_keeps_same_asset_and_source_record(tmp_path: Path):
    db = tmp_path / "asset-id.sqlite3"
    init_db(db)
    nfc = "Café-Asset-80"
    nfd = _nfd(nfc)
    apply_import_batch(db, [_row("A-80", asset_id=nfc)], scanner_source="scanner-a", filename="one.csv")
    before = get_finding(db, "A-80")

    result = apply_import_batch(db, [_row("A-80", asset_id=nfd)], scanner_source="scanner-a", filename="two.csv")

    after = get_finding(db, "A-80")
    detail = get_source_reconciliation(db, "A-80")
    assert result["updated"] == 1
    assert after["asset_ref_id"] == before["asset_ref_id"]
    assert len(detail["records"]) == 1
    assert detail["records"][0]["observed_state"] == "PRESENT"


def test_hostname_nfc_nfd_across_scanners_merge_into_one_canonical_asset(tmp_path: Path):
    db = tmp_path / "hostname.sqlite3"
    init_db(db)
    nfc = "CaféHost"
    nfd = _nfd(nfc)
    apply_import_batch(db, [_row("A-80", asset_id="", asset_name=nfc)], scanner_source="scanner-a", filename="a.csv")
    apply_import_batch(db, [_row("B-80", asset_id="", asset_name=nfd)], scanner_source="scanner-b", filename="b.csv")

    findings = list_findings(db)
    assert len(findings) == 1
    assert findings[0]["finding_id"] == "A-80"
    assert findings[0]["source_count"] == 2
    records = get_source_reconciliation(db, "A-80")["records"]
    assert {item["scanner_source"] for item in records} == {"scanner-a", "scanner-b"}


def test_generic_asset_identifier_and_hostname_scope_use_unicode_nfc():
    nfc_id = "Café-Asset-80"
    nfd_id = _nfd(nfc_id)
    assert normalize_asset_identifier("SCANNER_ASSET_ID", nfc_id) == normalize_asset_identifier("SCANNER_ASSET_ID", nfd_id)
    assert normalize_asset_identifier("EXTERNAL_ASSET_ID", nfc_id) == normalize_asset_identifier("EXTERNAL_ASSET_ID", nfd_id)

    nfc_env = "Prod-Café"
    nfd_env = _nfd(nfc_env)
    assert identifier_scope("HOSTNAME", environment=nfc_env) == identifier_scope("HOSTNAME", environment=nfd_env)
