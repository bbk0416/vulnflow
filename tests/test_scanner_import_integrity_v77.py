from __future__ import annotations

from pathlib import Path

from app.core.storage import (
    apply_import_batch,
    get_finding,
    get_source_reconciliation,
    init_db,
    list_asset_identity_candidates,
    list_findings,
)
from app.services.asset_identity import fqdn_equivalent_values


def _row(finding_id: str, *, asset_id: str = "asset-1", asset_name: str = "host1", fqdn: str = "") -> dict:
    return {
        "finding_id": finding_id,
        "product": "Scanner integrity",
        "product_version": "1.0",
        "asset_id": asset_id,
        "asset_name": asset_name,
        "fqdn": fqdn,
        "environment": "prod",
        "cve_id": "CVE-2026-79001",
        "component": "openssl",
        "component_version": "3.0",
        "cvss": 8.0,
        "epss": 0.2,
        "epss_percentile": 0.4,
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
        "score": 60,
        "threat_score": 25,
        "asset_context_score": 20,
        "remediation_urgency_score": 15,
        "decision": "REVIEW",
        "decision_label": "검토",
        "sla_days": 30,
        "target_date": "2026-09-01",
        "mitigation_required": 0,
        "reasons": "test",
        "policy_version": "test",
        "first_seen_at": "2026-08-12",
        "first_scored_at": "2026-08-12",
        "last_scored_at": "2026-08-12",
        "record_state": "ACTIVE",
        "row_version": 1,
    }


def test_unicode_scanner_source_casefold_snapshot_marks_missing(tmp_path: Path):
    db = tmp_path / "unicode-source.sqlite3"
    init_db(db)
    apply_import_batch(
        db, [_row("UNI-1")], scanner_source="NÉSSUS", filename="full.csv", reconcile_missing=True
    )
    result = apply_import_batch(
        db, [], scanner_source="néssus", filename="empty.csv", reconcile_missing=True
    )
    detail = get_source_reconciliation(db, "UNI-1")
    assert result["stale"] == 1
    assert detail["records"][0]["observed_state"] == "ABSENT"
    assert detail["records"][0]["consecutive_absent_scans"] == 1
    assert get_finding(db, "UNI-1")["record_state"] == "STALE"


def test_casefold_equivalent_source_names_count_as_one_logical_source(tmp_path: Path):
    db = tmp_path / "source-count.sqlite3"
    init_db(db)
    apply_import_batch(db, [_row("SRC-A")], scanner_source="NÉSSUS", filename="a.csv")
    apply_import_batch(db, [_row("SRC-B")], scanner_source="néssus", filename="b.csv")
    finding = list_findings(db)[0]
    assert finding["source_count"] == 1
    assert finding["scanner_source"].casefold() == "néssus".casefold()
    records = get_source_reconciliation(db, finding["finding_id"])["records"]
    assert len(records) == 2


def test_idn_unicode_and_stable_punycode_resolve_to_same_fqdn_identity(tmp_path: Path):
    assert set(fqdn_equivalent_values("bücher.example")) == {
        "bücher.example", "xn--bcher-kva.example"
    }
    assert set(fqdn_equivalent_values("xn--bcher-kva.example")) == {
        "bücher.example", "xn--bcher-kva.example"
    }

    db = tmp_path / "idn.sqlite3"
    init_db(db)
    apply_import_batch(
        db,
        [_row("IDN-A", asset_id="", asset_name="bücher.example", fqdn="bücher.example")],
        scanner_source="scanner-a",
        filename="a.csv",
    )
    second = apply_import_batch(
        db,
        [_row("IDN-B", asset_id="", asset_name="xn--bcher-kva.example", fqdn="xn--bcher-kva.example")],
        scanner_source="scanner-b",
        filename="b.csv",
    )
    active = [row for row in list_findings(db) if row["record_state"] != "ARCHIVED"]
    assert second["inserted"] == 0
    assert second["updated"] == 1
    assert len(active) == 1
    assert active[0]["source_count"] == 2


def test_idn_equivalence_does_not_override_authoritative_scanner_asset_ids(tmp_path: Path):
    db = tmp_path / "idn-authoritative.sqlite3"
    init_db(db)
    apply_import_batch(
        db,
        [_row("AUTH-A", asset_id="scanner-a-1", asset_name="bücher.example", fqdn="bücher.example")],
        scanner_source="scanner-a",
        filename="a.csv",
    )
    apply_import_batch(
        db,
        [_row("AUTH-B", asset_id="scanner-b-2", asset_name="xn--bcher-kva.example", fqdn="xn--bcher-kva.example")],
        scanner_source="scanner-b",
        filename="b.csv",
    )
    active = [row for row in list_findings(db) if row["record_state"] != "ARCHIVED"]
    assert len(active) == 2
    candidates = list_asset_identity_candidates(db, status="PENDING")
    assert any(
        item["reasons"][0]["identifier_type"] == "FQDN"
        for item in candidates
    )
