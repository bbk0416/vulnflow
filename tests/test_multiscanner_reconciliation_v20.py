from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from app.core.storage import (
    CURRENT_SCHEMA_VERSION,
    apply_import_batch,
    get_finding,
    get_source_reconciliation,
    init_db,
    list_findings,
    list_reconciliation_findings,
    resolve_source_conflict,
    retire_source_conflict_resolution,
)


def _row(fid: str, *, cvss: float = 7.5, version: str = "1.0", patch: int = 0) -> dict:
    return {
        "finding_id": fid,
        "product": "Portal",
        "product_version": "5.0",
        "asset_id": "ASSET-20",
        "asset_name": "portal.example",
        "environment": "prod",
        "cve_id": "CVE-2026-20001",
        "component": "demo-lib",
        "component_version": version,
        "cvss": cvss,
        "epss": 0.2,
        "epss_percentile": 0.7,
        "kev": 0,
        "internet_exposed": 1,
        "asset_criticality": 5,
        "data_sensitivity": 4,
        "patch_available": patch,
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


def test_schema_v20_has_multiscanner_tables(tmp_path: Path):
    db = tmp_path / "schema.sqlite3"
    init_db(db)
    with sqlite3.connect(db) as conn:
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        columns = {r[1] for r in conn.execute("PRAGMA table_info(findings)")}
        version = conn.execute("PRAGMA user_version").fetchone()[0]
    assert version == CURRENT_SCHEMA_VERSION == 40
    assert {"source_finding_records", "finding_reconciliation_decisions"} <= tables
    assert {"canonical_key", "source_count", "source_conflict_count"} <= columns


def test_two_scanners_merge_into_one_canonical_finding(tmp_path: Path):
    db = tmp_path / "merge.sqlite3"
    init_db(db)
    first = apply_import_batch(db, [_row("A-100", cvss=7.5)], scanner_source="scanner-a", filename="a.csv")
    second = apply_import_batch(db, [_row("B-900", cvss=9.1)], scanner_source="scanner-b", filename="b.csv")
    rows = list_findings(db)
    assert first["inserted"] == 1
    assert second["inserted"] == 0
    assert second["merged"] == 1
    assert len(rows) == 1
    finding = rows[0]
    assert finding["finding_id"] == "A-100"
    assert finding["source_count"] == 2
    assert finding["cvss"] == 9.1
    detail = get_source_reconciliation(db, "A-100")
    assert {r["scanner_source"] for r in detail["records"]} == {"scanner-a", "scanner-b"}


def test_one_scanner_missing_does_not_stale_canonical(tmp_path: Path):
    db = tmp_path / "lifecycle.sqlite3"
    init_db(db)
    apply_import_batch(db, [_row("A-100")], scanner_source="scanner-a", filename="a.csv", reconcile_missing=True)
    apply_import_batch(db, [_row("B-900")], scanner_source="scanner-b", filename="b.csv", reconcile_missing=True)
    apply_import_batch(db, [], scanner_source="scanner-a", filename="a-empty.csv", reconcile_missing=True)
    finding = get_finding(db, "A-100")
    assert finding["record_state"] == "ACTIVE"
    assert finding["source_count"] == 1
    records = get_source_reconciliation(db, "A-100")["records"]
    states = {r["scanner_source"]: r["observed_state"] for r in records}
    assert states == {"scanner-a": "ABSENT", "scanner-b": "PRESENT"}


def test_all_scanners_missing_marks_canonical_stale(tmp_path: Path):
    db = tmp_path / "all-missing.sqlite3"
    init_db(db)
    apply_import_batch(db, [_row("A-100")], scanner_source="scanner-a", filename="a.csv", reconcile_missing=True)
    apply_import_batch(db, [_row("B-900")], scanner_source="scanner-b", filename="b.csv", reconcile_missing=True)
    apply_import_batch(db, [], scanner_source="scanner-a", filename="a-empty.csv", reconcile_missing=True)
    result = apply_import_batch(db, [], scanner_source="scanner-b", filename="b-empty.csv", reconcile_missing=True)
    finding = get_finding(db, "A-100")
    assert result["stale"] == 1
    assert finding["record_state"] == "STALE"
    assert finding["source_count"] == 0
    assert finding["consecutive_absent_scans"] == 1


def test_conflicts_are_exposed_and_operator_can_select_authoritative_source(tmp_path: Path):
    db = tmp_path / "conflict.sqlite3"
    init_db(db)
    apply_import_batch(db, [_row("A-100", cvss=7.5, version="1.0", patch=0)], scanner_source="scanner-a", filename="a.csv")
    apply_import_batch(db, [_row("B-900", cvss=9.1, version="1.1", patch=1)], scanner_source="scanner-b", filename="b.csv")
    detail = get_source_reconciliation(db, "A-100")
    fields = {item["field_name"] for item in detail["conflicts"]}
    assert {"cvss", "component_version", "patch_available"} <= fields
    scanner_a = next(r for r in detail["records"] if r["scanner_source"] == "scanner-a")
    resolved = resolve_source_conflict(
        db, "A-100", field_name="cvss", chosen_source_record_id=scanner_a["source_record_id"],
        reason="Scanner A is the authenticated infrastructure scanner", actor="ops1",
    )
    assert get_finding(db, "A-100")["cvss"] == 7.5
    assert resolved["unresolved_count"] == 2
    assert any(item["field_name"] == "cvss" and item["resolved"] for item in resolved["conflicts"])


def test_authoritative_source_decision_follows_future_source_value(tmp_path: Path):
    db = tmp_path / "follow.sqlite3"
    init_db(db)
    apply_import_batch(db, [_row("A-100", cvss=7.5)], scanner_source="scanner-a", filename="a.csv")
    apply_import_batch(db, [_row("B-900", cvss=9.1)], scanner_source="scanner-b", filename="b.csv")
    detail = get_source_reconciliation(db, "A-100")
    scanner_a = next(r for r in detail["records"] if r["scanner_source"] == "scanner-a")
    resolve_source_conflict(
        db, "A-100", field_name="cvss", chosen_source_record_id=scanner_a["source_record_id"],
        reason="trusted source", actor="ops1",
    )
    apply_import_batch(db, [_row("A-100", cvss=8.2)], scanner_source="scanner-a", filename="a2.csv")
    assert get_finding(db, "A-100")["cvss"] == 8.2


def test_retiring_resolution_restores_conservative_aggregate(tmp_path: Path):
    db = tmp_path / "retire.sqlite3"
    init_db(db)
    apply_import_batch(db, [_row("A-100", cvss=7.5)], scanner_source="scanner-a", filename="a.csv")
    apply_import_batch(db, [_row("B-900", cvss=9.1)], scanner_source="scanner-b", filename="b.csv")
    detail = get_source_reconciliation(db, "A-100")
    scanner_a = next(r for r in detail["records"] if r["scanner_source"] == "scanner-a")
    resolve_source_conflict(db, "A-100", field_name="cvss", chosen_source_record_id=scanner_a["source_record_id"], reason="test", actor="ops1")
    retire_source_conflict_resolution(db, "A-100", field_name="cvss", actor="ops1")
    assert get_finding(db, "A-100")["cvss"] == 9.1


def test_reconciliation_queue_lists_multisource_findings(tmp_path: Path):
    db = tmp_path / "queue.sqlite3"
    init_db(db)
    apply_import_batch(db, [_row("A-100", version="1.0")], scanner_source="scanner-a", filename="a.csv")
    apply_import_batch(db, [_row("B-900", version="1.1")], scanner_source="scanner-b", filename="b.csv")
    items = list_reconciliation_findings(db, unresolved_only=True)
    assert len(items) == 1
    assert items[0]["finding_id"] == "A-100"
    assert items[0]["unresolved_count"] >= 1


def test_same_source_native_id_cannot_move_to_different_canonical(tmp_path: Path):
    db = tmp_path / "identity.sqlite3"
    init_db(db)
    apply_import_batch(db, [_row("A-100")], scanner_source="scanner-a", filename="a.csv")
    changed = _row("A-100")
    changed["asset_id"] = "OTHER-ASSET"
    with pytest.raises(ValueError, match="다른 canonical finding"):
        apply_import_batch(db, [changed], scanner_source="scanner-a", filename="changed.csv")


def test_reconciliation_template_renders_conflict_value_list():
    from types import SimpleNamespace
    from jinja2 import Environment, FileSystemLoader, select_autoescape

    templates = Path(__file__).resolve().parents[1] / "app" / "templates"
    env = Environment(
        loader=FileSystemLoader(str(templates)),
        autoescape=select_autoescape(["html"]),
    )
    template = env.get_template("reconciliation.html")
    request = SimpleNamespace(state=SimpleNamespace(role="admin", actor="tester"))
    rendered = template.render(
        request=request,
        unresolved_only=True,
        items=[{
            "finding_id": "A-100", "asset_name": "portal", "cve_id": "CVE-2026-20001",
            "component": "demo-lib", "component_version": "1.1", "source_count": 2,
            "source_records": [
                {"scanner_source": "scanner-a", "source_finding_id": "A-100", "observed_state": "PRESENT"},
                {"scanner_source": "scanner-b", "source_finding_id": "B-900", "observed_state": "PRESENT"},
            ],
            "unresolved_count": 1,
            "conflicts": [{"field_name": "cvss", "values": [7.5, 9.1], "resolved": False}],
            "record_state": "ACTIVE", "status": "OPEN", "score": 91,
            "decision_label": "즉시 조치",
        }],
    )
    assert "7.5 / 9.1" in rendered
    assert "scanner-a:A-100" in rendered
