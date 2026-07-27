from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

import app.main as main
from app.core.storage import (
    CURRENT_SCHEMA_VERSION,
    add_asset_identifier,
    apply_import_batch,
    get_asset,
    get_asset_identity_candidate,
    get_finding,
    get_source_reconciliation,
    init_db,
    list_asset_identity_candidates,
    list_asset_merge_history,
    list_assets,
    list_findings,
    merge_assets,
    reject_asset_identity_candidate,
)


def _row(
    finding_id: str,
    *,
    asset_id: str,
    asset_name: str,
    cve_id: str = "CVE-2026-21001",
    component: str = "openssl",
    environment: str = "prod",
    **identity,
) -> dict:
    return {
        "finding_id": finding_id,
        "product": "Identity API",
        "product_version": "1.0",
        "asset_id": asset_id,
        "asset_name": asset_name,
        "environment": environment,
        "cve_id": cve_id,
        "component": component,
        "component_version": "3.0",
        "cvss": 8.1,
        "epss": 0.5,
        "epss_percentile": 0.8,
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
        "score": 75,
        "threat_score": 35,
        "asset_context_score": 25,
        "remediation_urgency_score": 15,
        "decision": "URGENT_REVIEW",
        "decision_label": "긴급 검토",
        "sla_days": 7,
        "target_date": "2026-08-01",
        "mitigation_required": 0,
        "reasons": "test",
        "policy_version": "test",
        "first_seen_at": "2026-07-21",
        "first_scored_at": "2026-07-21",
        "last_scored_at": "2026-07-21",
        "record_state": "ACTIVE",
        "row_version": 1,
        **identity,
    }


def _two_weak_assets(db: Path) -> tuple[dict, dict, dict]:
    apply_import_batch(
        db, [_row("IDA-1", asset_id="scanner-a-100", asset_name="shared-host")],
        scanner_source="scanner-a", filename="a.csv",
    )
    apply_import_batch(
        db, [_row("IDB-1", asset_id="scanner-b-900", asset_name="shared-host")],
        scanner_source="scanner-b", filename="b.csv",
    )
    a = get_finding(db, "IDA-1")
    b = get_finding(db, "IDB-1")
    candidate = list_asset_identity_candidates(db, status="PENDING")[0]
    return a, b, candidate


def test_schema_v21_has_asset_identity_tables_and_merge_columns(tmp_path: Path):
    db = tmp_path / "schema.sqlite3"
    init_db(db)
    with sqlite3.connect(db) as conn:
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        asset_columns = {row[1] for row in conn.execute("PRAGMA table_info(assets)")}
        finding_columns = {row[1] for row in conn.execute("PRAGMA table_info(findings)")}
        version = conn.execute("PRAGMA user_version").fetchone()[0]
    assert version == CURRENT_SCHEMA_VERSION == 40
    assert {"asset_identifiers", "asset_identity_candidates", "asset_merge_history"} <= tables
    assert "merged_into_asset_ref_id" in asset_columns
    assert "merged_into_finding_id" in finding_columns


def test_two_independent_signals_auto_resolve_cross_scanner_asset(tmp_path: Path):
    db = tmp_path / "strong-match.sqlite3"
    init_db(db)
    first = apply_import_batch(
        db, [_row("A-1", asset_id="asset-21", asset_name="api.example.com")],
        scanner_source="scanner-a", filename="a.csv",
    )
    second = apply_import_batch(
        db, [_row("B-1", asset_id="asset-21", asset_name="api.example.com")],
        scanner_source="scanner-b", filename="b.csv",
    )
    active = [row for row in list_findings(db) if row["record_state"] != "ARCHIVED"]
    assert first["inserted"] == 1
    assert second["inserted"] == 0
    assert len(active) == 1
    assert active[0]["source_count"] == 2
    assert list_asset_identity_candidates(db, status="PENDING") == []


def test_weak_hostname_match_creates_candidate_without_silent_merge(tmp_path: Path):
    db = tmp_path / "candidate.sqlite3"
    init_db(db)
    a, b, candidate = _two_weak_assets(db)
    assert a["asset_ref_id"] != b["asset_ref_id"]
    assert candidate["score"] == 50
    assert candidate["status"] == "PENDING"
    assert candidate["reasons"][0]["identifier_type"] == "HOSTNAME"
    assert len(list_assets(db, status="ACTIVE")) == 2


def test_same_hostname_in_different_environments_does_not_create_candidate(tmp_path: Path):
    db = tmp_path / "scope.sqlite3"
    init_db(db)
    apply_import_batch(
        db, [_row("P-1", asset_id="prod-1", asset_name="app01", environment="prod")],
        scanner_source="scanner-a", filename="prod.csv",
    )
    apply_import_batch(
        db, [_row("D-1", asset_id="dev-1", asset_name="app01", environment="dev")],
        scanner_source="scanner-b", filename="dev.csv",
    )
    assert list_asset_identity_candidates(db, status="PENDING") == []
    assert len(list_assets(db, status="ACTIVE")) == 2


def test_manual_identifier_collision_creates_reusable_candidate_and_can_be_rejected(tmp_path: Path):
    db = tmp_path / "manual.sqlite3"
    init_db(db)
    apply_import_batch(
        db, [_row("A-1", asset_id="a-1", asset_name="alpha")],
        scanner_source="scanner-a", filename="a.csv",
    )
    apply_import_batch(
        db, [_row("B-1", asset_id="b-1", asset_name="beta", cve_id="CVE-2026-21002")],
        scanner_source="scanner-b", filename="b.csv",
    )
    a = get_finding(db, "A-1")
    b = get_finding(db, "B-1")
    assert add_asset_identifier(db, a["asset_ref_id"], identifier_type="CMDB_ID", value="CI-2100")["status"] == "ACTIVE"
    collision = add_asset_identifier(db, b["asset_ref_id"], identifier_type="CMDB_ID", value="CI-2100")
    assert collision["status"] == "CANDIDATE"
    candidate_id = collision["candidate"]["candidate_id"]
    repeated = add_asset_identifier(db, b["asset_ref_id"], identifier_type="CMDB_ID", value="CI-2100")
    assert repeated["candidate"]["candidate_id"] == candidate_id
    rejected = reject_asset_identity_candidate(db, candidate_id, reason="동일 CMDB 표기지만 별도 테스트 자산", actor="ops")
    assert rejected["status"] == "REJECTED"
    assert get_asset_identity_candidate(db, candidate_id)["status"] == "REJECTED"


def test_asset_merge_consolidates_duplicate_canonical_findings_and_future_updates(tmp_path: Path):
    db = tmp_path / "merge.sqlite3"
    init_db(db)
    a, b, candidate = _two_weak_assets(db)
    result = merge_assets(
        db,
        source_asset_ref_id=b["asset_ref_id"],
        target_asset_ref_id=a["asset_ref_id"],
        candidate_id=candidate["candidate_id"],
        reason="두 스캐너의 동일 운영 서버임을 CMDB에서 확인",
        actor="asset-owner",
    )
    assert result["consolidated_findings"] == 1
    archived = get_finding(db, "IDB-1")
    target = get_finding(db, "IDA-1")
    assert archived["record_state"] == "ARCHIVED"
    assert archived["merged_into_finding_id"] == "IDA-1"
    assert target["source_count"] == 2
    assert get_asset(db, b["asset_ref_id"])["merged_into_asset_ref_id"] == a["asset_ref_id"]
    records = get_source_reconciliation(db, "IDA-1")["records"]
    assert {row["scanner_source"] for row in records} == {"scanner-a", "scanner-b"}

    # The moved scanner-native identifier must continue resolving to the target asset.
    apply_import_batch(
        db, [_row("IDB-1", asset_id="scanner-b-900", asset_name="shared-host", component="openssl") | {"cvss": 9.4}],
        scanner_source="scanner-b", filename="b-next.csv",
    )
    assert get_finding(db, "IDA-1")["cvss"] == 9.4
    assert get_finding(db, "IDB-1")["record_state"] == "ARCHIVED"


def test_asset_merge_moves_nonduplicate_finding_without_archiving(tmp_path: Path):
    db = tmp_path / "move.sqlite3"
    init_db(db)
    apply_import_batch(
        db, [_row("A-1", asset_id="a-1", asset_name="node-a", cve_id="CVE-2026-21001")],
        scanner_source="scanner-a", filename="a.csv",
    )
    apply_import_batch(
        db, [_row("B-1", asset_id="b-1", asset_name="node-b", cve_id="CVE-2026-21002")],
        scanner_source="scanner-b", filename="b.csv",
    )
    a = get_finding(db, "A-1")
    b = get_finding(db, "B-1")
    result = merge_assets(
        db, source_asset_ref_id=b["asset_ref_id"], target_asset_ref_id=a["asset_ref_id"],
        reason="운영 자산 재식별", actor="ops",
    )
    assert result["moved_findings"] == 1
    moved = get_finding(db, "B-1")
    assert moved["asset_ref_id"] == a["asset_ref_id"]
    assert moved["record_state"] == "ACTIVE"
    assert moved["merged_into_finding_id"] in (None, "")
    assert list_asset_merge_history(db, asset_ref_id=a["asset_ref_id"])[0]["merge_id"] == result["merge_id"]


def test_duplicate_merge_is_blocked_while_approval_is_pending(tmp_path: Path):
    db = tmp_path / "pending.sqlite3"
    init_db(db)
    a, b, candidate = _two_weak_assets(db)
    with sqlite3.connect(db) as conn:
        conn.execute(
            """INSERT INTO risk_approval_requests(
                   request_id,finding_id,requested_by,reason,exception_expiry,status,finding_row_version,requested_at
               ) VALUES(?,?,?,?,?,'PENDING',1,?)""",
            ("RAR-21", "IDB-1", "ops", "pending", "2026-12-31", "2026-07-21T00:00:00+00:00"),
        )
        conn.commit()
    with pytest.raises(ValueError, match="대기 중인"):
        merge_assets(
            db, source_asset_ref_id=b["asset_ref_id"], target_asset_ref_id=a["asset_ref_id"],
            candidate_id=candidate["candidate_id"], reason="merge after review", actor="ops",
        )
    assert get_asset_identity_candidate(db, candidate["candidate_id"])["status"] == "PENDING"


def test_asset_identity_page_and_api_render(client):
    apply_import_batch(
        main.DB_PATH, [_row("UI-A", asset_id="ui-a", asset_name="ui-shared")],
        scanner_source="scanner-a", filename="a.csv",
    )
    apply_import_batch(
        main.DB_PATH, [_row("UI-B", asset_id="ui-b", asset_name="ui-shared")],
        scanner_source="scanner-b", filename="b.csv",
    )
    page = client.get("/asset-identities")
    assert page.status_code == 200
    assert "자산 식별 후보" in page.text
    api = client.get("/api/v1/asset-identities/candidates")
    assert api.status_code == 200
    assert api.json()["count"] == 1
    asset_ref = get_finding(main.DB_PATH, "UI-A")["asset_ref_id"]
    detail = client.get(f"/asset/{asset_ref}")
    assert detail.status_code == 200
    assert "자산 식별자" in detail.text


def test_merge_remaps_unrelated_pending_identity_candidates(tmp_path: Path):
    db = tmp_path / "remap.sqlite3"
    init_db(db)
    apply_import_batch(
        db, [_row("A-1", asset_id="a-id", asset_name="shared-node")],
        scanner_source="scanner-a", filename="a.csv",
    )
    apply_import_batch(
        db, [_row("B-1", asset_id="b-id", asset_name="shared-node")],
        scanner_source="scanner-b", filename="b.csv",
    )
    apply_import_batch(
        db, [_row("C-1", asset_id="c-id", asset_name="shared-node", cve_id="CVE-2026-21003")],
        scanner_source="scanner-c", filename="c.csv",
    )
    a = get_finding(db, "A-1")
    b = get_finding(db, "B-1")
    c = get_finding(db, "C-1")
    candidates = list_asset_identity_candidates(db, status="PENDING")
    ab = next(item for item in candidates if {item["asset_ref_id_a"], item["asset_ref_id_b"]} == {a["asset_ref_id"], b["asset_ref_id"]})
    merge_assets(
        db, source_asset_ref_id=a["asset_ref_id"], target_asset_ref_id=b["asset_ref_id"],
        candidate_id=ab["candidate_id"], reason="대표 자산 B로 통합", actor="ops",
    )
    remaining = list_asset_identity_candidates(db, status="PENDING")
    assert len(remaining) == 1
    assert {remaining[0]["asset_ref_id_a"], remaining[0]["asset_ref_id_b"]} == {b["asset_ref_id"], c["asset_ref_id"]}


def test_asset_identity_core_records_are_tamper_resistant(tmp_path: Path):
    db = tmp_path / "immutable.sqlite3"
    init_db(db)
    a, b, candidate = _two_weak_assets(db)
    with sqlite3.connect(db) as conn:
        identifier_id = conn.execute(
            "SELECT identifier_id FROM asset_identifiers WHERE asset_ref_id=? AND status='ACTIVE' LIMIT 1",
            (a["asset_ref_id"],),
        ).fetchone()[0]
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("UPDATE asset_identifiers SET normalized_value='tampered' WHERE identifier_id=?", (identifier_id,))
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("UPDATE asset_identity_candidates SET score=1 WHERE candidate_id=?", (candidate["candidate_id"],))
    merge = merge_assets(
        db, source_asset_ref_id=b["asset_ref_id"], target_asset_ref_id=a["asset_ref_id"],
        candidate_id=candidate["candidate_id"], reason="immutable merge history test", actor="ops",
    )
    with sqlite3.connect(db) as conn:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("UPDATE asset_merge_history SET reason='tampered' WHERE merge_id=?", (merge["merge_id"],))
