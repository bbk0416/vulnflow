from __future__ import annotations

from pathlib import Path

import idna

from app.core.storage import (
    apply_import_batch,
    get_finding,
    get_source_reconciliation,
    init_db,
    list_findings,
)
from app.services.asset_identity import fqdn_equivalent_values, normalize_asset_identifier


def _row(finding_id: str, *, fqdn: str) -> dict:
    return {
        "finding_id": finding_id,
        "product": "Scanner identity round 4",
        "product_version": "1.0",
        "asset_id": "",
        "asset_name": fqdn,
        "fqdn": fqdn,
        "environment": "prod",
        "cve_id": "CVE-2026-78001",
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


def test_idna2008_sharp_s_domain_does_not_merge_with_ascii_ss(tmp_path: Path):
    assert idna.encode("faß.de").decode("ascii") == "xn--fa-hia.de"
    assert idna.encode("fass.de").decode("ascii") == "fass.de"
    assert normalize_asset_identifier("FQDN", "faß.de") != normalize_asset_identifier("FQDN", "fass.de")

    db = tmp_path / "sharp-s.sqlite3"
    init_db(db)
    apply_import_batch(db, [_row("IDN-SS-A", fqdn="faß.de")], scanner_source="scanner-a", filename="a.csv")
    second = apply_import_batch(db, [_row("IDN-SS-B", fqdn="fass.de")], scanner_source="scanner-b", filename="b.csv")

    assert second["inserted"] == 1
    assert len(list_findings(db)) == 2


def test_idna2008_sigma_and_final_sigma_remain_distinct(tmp_path: Path):
    assert idna.encode("σ.example").decode("ascii") == "xn--4xa.example"
    assert idna.encode("ς.example").decode("ascii") == "xn--3xa.example"
    assert normalize_asset_identifier("FQDN", "σ.example") != normalize_asset_identifier("FQDN", "ς.example")

    db = tmp_path / "sigma.sqlite3"
    init_db(db)
    apply_import_batch(db, [_row("IDN-SIG-A", fqdn="σ.example")], scanner_source="scanner-a", filename="a.csv")
    second = apply_import_batch(db, [_row("IDN-SIG-B", fqdn="ς.example")], scanner_source="scanner-b", filename="b.csv")

    assert second["inserted"] == 1
    assert len(list_findings(db)) == 2


def test_stable_unicode_and_alabel_fqdn_equivalence_is_preserved(tmp_path: Path):
    assert set(fqdn_equivalent_values("bücher.example")) == {
        "bücher.example",
        "xn--bcher-kva.example",
    }
    db = tmp_path / "u-label-a-label.sqlite3"
    init_db(db)
    apply_import_batch(db, [_row("IDN-UA-A", fqdn="bücher.example")], scanner_source="scanner-a", filename="a.csv")
    second = apply_import_batch(
        db,
        [_row("IDN-UA-B", fqdn="xn--bcher-kva.example")],
        scanner_source="scanner-b",
        filename="b.csv",
    )
    findings = list_findings(db)
    assert second["inserted"] == 0
    assert second["updated"] == 1
    assert len(findings) == 1
    assert findings[0]["source_count"] == 2


def test_scanner_source_nfc_nfd_snapshot_equivalence_marks_missing(tmp_path: Path):
    db = tmp_path / "source-normalization.sqlite3"
    init_db(db)
    apply_import_batch(
        db,
        [_row("SRC-NORM-1", fqdn="host.example")],
        scanner_source="Néssus",
        filename="full.csv",
        reconcile_missing=True,
    )
    result = apply_import_batch(
        db,
        [],
        scanner_source="Ne\u0301ssus",
        filename="empty.csv",
        reconcile_missing=True,
    )
    detail = get_source_reconciliation(db, "SRC-NORM-1")
    assert result["stale"] == 1
    assert detail["records"][0]["observed_state"] == "ABSENT"
    assert get_finding(db, "SRC-NORM-1")["record_state"] == "STALE"


def test_scanner_source_nfc_nfd_variants_count_as_one_logical_source(tmp_path: Path):
    db = tmp_path / "source-count-normalization.sqlite3"
    init_db(db)
    apply_import_batch(
        db,
        [_row("SRC-NORM-A", fqdn="host.example")],
        scanner_source="Néssus",
        filename="a.csv",
    )
    apply_import_batch(
        db,
        [_row("SRC-NORM-B", fqdn="host.example")],
        scanner_source="Ne\u0301ssus",
        filename="b.csv",
    )
    finding = list_findings(db)[0]
    assert finding["source_count"] == 1
    assert len(get_source_reconciliation(db, finding["finding_id"])["records"]) == 2
