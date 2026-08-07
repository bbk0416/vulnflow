from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from app.core.storage import (
    CURRENT_SCHEMA_VERSION,
    add_asset_identifier,
    analyze_asset_merge_rollback,
    apply_import_batch,
    approve_asset_merge_rollback_request,
    create_asset_merge_rollback_request,
    create_campaign,
    get_asset,
    get_asset_merge_rollback_request,
    get_finding,
    init_db,
    list_asset_identity_candidates,
    list_asset_merge_history,
    list_asset_merge_rollback_requests,
    merge_assets,
    reject_asset_merge_rollback_request,
)


def _row(finding_id: str, *, asset_id: str, asset_name: str, cve_id: str = "CVE-2026-23001") -> dict:
    return {
        "finding_id": finding_id,
        "product": "Merge Rollback API",
        "product_version": "1.0",
        "asset_id": asset_id,
        "asset_name": asset_name,
        "environment": "prod",
        "cve_id": cve_id,
        "component": "openssl",
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
    }


def _merged_pair(db: Path) -> tuple[dict, dict, dict, dict]:
    apply_import_batch(
        db, [_row("V23-A", asset_id="scanner-a-2300", asset_name="rollback-host")],
        scanner_source="scanner-a", filename="a.csv",
    )
    apply_import_batch(
        db, [_row("V23-B", asset_id="scanner-b-2300", asset_name="rollback-host")],
        scanner_source="scanner-b", filename="b.csv",
    )
    a = get_finding(db, "V23-A")
    b = get_finding(db, "V23-B")
    candidate = list_asset_identity_candidates(db, status="PENDING")[0]
    result = merge_assets(
        db,
        source_asset_ref_id=b["asset_ref_id"],
        target_asset_ref_id=a["asset_ref_id"],
        candidate_id=candidate["candidate_id"],
        reason="동일 서버 식별자 검증 완료",
        actor="approver-a",
    )
    return a, b, candidate, result


def test_schema_v23_has_scoped_rollback_tables_and_triggers(tmp_path: Path):
    db = tmp_path / "schema.sqlite3"
    init_db(db)
    with sqlite3.connect(db) as conn:
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        triggers = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='trigger'")}
        version = int(conn.execute("PRAGMA user_version").fetchone()[0])
    assert version == CURRENT_SCHEMA_VERSION == 46
    assert {"asset_merge_rollback_journals", "asset_merge_rollback_requests"} <= tables
    assert {
        "asset_merge_rollback_journals_immutable_update",
        "asset_merge_rollback_journals_immutable_delete",
        "asset_merge_rollback_requests_core_immutable",
        "asset_merge_rollback_requests_no_delete",
    } <= triggers


def test_scoped_rollback_restores_assets_findings_identifiers_and_candidates(tmp_path: Path):
    db = tmp_path / "rollback.sqlite3"
    init_db(db)
    a, b, candidate, merge = _merged_pair(db)
    impact = analyze_asset_merge_rollback(db, merge["merge_id"])
    assert impact["can_request"] is True
    assert impact["summary"]["finding_count"] == 2
    assert impact["summary"]["asset_count"] == 2

    request = create_asset_merge_rollback_request(
        db, merge_id=merge["merge_id"], reason="잘못된 자산 동일성 판정 확인", requested_by="operator-a",
    )
    assert request["status"] == "PENDING"
    approved = approve_asset_merge_rollback_request(
        db, request["rollback_request_id"], decided_by="approver-b", decision_note="후속 변경 없음 확인",
    )
    assert approved["status"] == "APPROVED"
    assert get_asset(db, b["asset_ref_id"])["status"] == "ACTIVE"
    assert get_asset(db, b["asset_ref_id"])["merged_into_asset_ref_id"] is None
    assert get_finding(db, "V23-B")["record_state"] == "ACTIVE"
    assert get_finding(db, "V23-B")["merged_into_finding_id"] is None
    candidates = list_asset_identity_candidates(db, status="PENDING")
    assert any(item["candidate_id"] == candidate["candidate_id"] for item in candidates)
    assert analyze_asset_merge_rollback(db, merge["merge_id"])["can_request"] is False
    assert list_asset_merge_history(db)[0]["rollback_status"] == "APPROVED"


def test_post_merge_change_blocks_rollback_request(tmp_path: Path):
    db = tmp_path / "changed.sqlite3"
    init_db(db)
    a, _b, _candidate, merge = _merged_pair(db)
    add_asset_identifier(
        db, a["asset_ref_id"], identifier_type="IP_ADDRESS", value="192.0.2.230", actor="inventory-sync",
    )
    impact = analyze_asset_merge_rollback(db, merge["merge_id"])
    assert impact["can_request"] is False
    assert any(item["code"] == "POST_MERGE_STATE_CHANGED" for item in impact["blockers"])
    with pytest.raises(ValueError, match="변경"):
        create_asset_merge_rollback_request(
            db, merge_id=merge["merge_id"], reason="변경 후 롤백 시도", requested_by="operator-a",
        )


def test_rollback_request_can_be_rejected_and_is_immutable(tmp_path: Path):
    db = tmp_path / "rejected.sqlite3"
    init_db(db)
    _a, _b, _candidate, merge = _merged_pair(db)
    request = create_asset_merge_rollback_request(
        db, merge_id=merge["merge_id"], reason="롤백 검토", requested_by="operator-a",
    )
    rejected = reject_asset_merge_rollback_request(
        db, request["rollback_request_id"], decided_by="approver-a", decision_note="병합 유지가 타당함",
    )
    assert rejected["status"] == "REJECTED"
    assert list_asset_merge_rollback_requests(db, status="PENDING") == []
    with sqlite3.connect(db) as conn:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "UPDATE asset_merge_rollback_requests SET impact_sha256='tampered' WHERE rollback_request_id=?",
                (request["rollback_request_id"],),
            )
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "DELETE FROM asset_merge_rollback_requests WHERE rollback_request_id=?",
                (request["rollback_request_id"],),
            )


def test_schema_22_database_migrates_but_old_merge_has_no_scoped_journal(tmp_path: Path):
    db = tmp_path / "migration.sqlite3"
    init_db(db)
    _a, _b, _candidate, merge = _merged_pair(db)
    with sqlite3.connect(db) as conn:
        conn.execute("DROP TRIGGER IF EXISTS asset_merge_rollback_journals_immutable_update")
        conn.execute("DROP TRIGGER IF EXISTS asset_merge_rollback_journals_immutable_delete")
        conn.execute("DROP TRIGGER IF EXISTS asset_merge_rollback_requests_core_immutable")
        conn.execute("DROP TRIGGER IF EXISTS asset_merge_rollback_requests_no_delete")
        conn.execute("DROP TABLE asset_merge_rollback_requests")
        conn.execute("DROP TABLE asset_merge_rollback_journals")
        conn.execute("DELETE FROM schema_migrations WHERE version=23")
        conn.execute("PRAGMA user_version=22")
        conn.commit()
    init_db(db)
    with sqlite3.connect(db) as conn:
        version = int(conn.execute("PRAGMA user_version").fetchone()[0])
        migration = conn.execute(
            "SELECT name,app_version FROM schema_migrations WHERE version=23"
        ).fetchone()
    assert version == CURRENT_SCHEMA_VERSION == 46
    assert migration == ("asset_merge_scoped_rollback", "23.0.0")
    impact = analyze_asset_merge_rollback(db, merge["merge_id"])
    assert impact["can_request"] is False
    assert impact["blockers"][0]["code"] == "ROLLBACK_JOURNAL_UNAVAILABLE"



def test_scoped_rollback_restores_moved_finding_and_campaign_link(tmp_path: Path):
    db = tmp_path / "moved.sqlite3"
    init_db(db)
    apply_import_batch(
        db, [_row("V23-MOVE-A", asset_id="move-a", asset_name="move-host", cve_id="CVE-2026-23011")],
        scanner_source="scanner-a", filename="a.csv",
    )
    apply_import_batch(
        db, [_row("V23-MOVE-B", asset_id="move-b", asset_name="move-host", cve_id="CVE-2026-23012")],
        scanner_source="scanner-b", filename="b.csv",
    )
    a = get_finding(db, "V23-MOVE-A")
    b = get_finding(db, "V23-MOVE-B")
    create_campaign(
        db, title="rollback campaign", description="", owner="ops", due_date="2026-08-31",
        finding_ids=["V23-MOVE-B"], actor="operator-a",
    )
    candidate = list_asset_identity_candidates(db, status="PENDING")[0]
    merge = merge_assets(
        db, source_asset_ref_id=b["asset_ref_id"], target_asset_ref_id=a["asset_ref_id"],
        candidate_id=candidate["candidate_id"], reason="동일 자산 검토", actor="approver-a",
    )
    assert get_finding(db, "V23-MOVE-B")["asset_ref_id"] == a["asset_ref_id"]
    request = create_asset_merge_rollback_request(
        db, merge_id=merge["merge_id"], reason="비중복 finding 이동 취소", requested_by="operator-a",
    )
    approve_asset_merge_rollback_request(
        db, request["rollback_request_id"], decided_by="approver-b", decision_note="영향 없음",
    )
    assert get_finding(db, "V23-MOVE-B")["asset_ref_id"] == b["asset_ref_id"]
    with sqlite3.connect(db) as conn:
        campaign_links = conn.execute(
            "SELECT COUNT(*) FROM campaign_findings WHERE finding_id='V23-MOVE-B'"
        ).fetchone()[0]
    assert campaign_links == 1


def test_change_after_rollback_request_blocks_approval(tmp_path: Path):
    db = tmp_path / "approval-race.sqlite3"
    init_db(db)
    a, _b, _candidate, merge = _merged_pair(db)
    request = create_asset_merge_rollback_request(
        db, merge_id=merge["merge_id"], reason="롤백 승인 대기", requested_by="operator-a",
    )
    add_asset_identifier(
        db, a["asset_ref_id"], identifier_type="IP_ADDRESS", value="198.51.100.23", actor="inventory-sync",
    )
    with pytest.raises(Exception, match="변경|조건"):
        approve_asset_merge_rollback_request(
            db, request["rollback_request_id"], decided_by="approver-a", decision_note="",
        )
    assert get_asset_merge_rollback_request(db, request["rollback_request_id"])["status"] == "PENDING"

def test_ui_scoped_rollback_request_and_approval(client):
    import app.main as main

    apply_import_batch(
        main.DB_PATH, [_row("UI23-A", asset_id="ui23-a", asset_name="ui23-host")],
        scanner_source="scanner-a", filename="a.csv",
    )
    apply_import_batch(
        main.DB_PATH, [_row("UI23-B", asset_id="ui23-b", asset_name="ui23-host")],
        scanner_source="scanner-b", filename="b.csv",
    )
    a = get_finding(main.DB_PATH, "UI23-A")
    b = get_finding(main.DB_PATH, "UI23-B")
    candidate = list_asset_identity_candidates(main.DB_PATH, status="PENDING")[0]

    page = client.get("/asset-identities")
    assert page.status_code == 200
    csrf = client.cookies.get("vulnflow_csrf")
    created = client.post(
        f"/asset-identities/{candidate['candidate_id']}/request-merge",
        data={"target_asset_ref_id": a["asset_ref_id"], "reason": "동일 자산 확인", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert created.status_code == 303
    approvals = client.get("/approvals")
    assert approvals.status_code == 200
    csrf = client.cookies.get("vulnflow_csrf")
    merge_request_id = approvals.text.split("AMR-")[1].split("<")[0]
    merge_request_id = "AMR-" + merge_request_id
    approved = client.post(
        f"/asset-merge-requests/{merge_request_id}/decision",
        data={"decision": "APPROVED", "decision_note": "복구점 확인", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert approved.status_code == 303
    merge = list_asset_merge_history(main.DB_PATH)[0]
    impact = client.get(f"/asset-merges/{merge['merge_id']}/rollback-impact")
    assert impact.status_code == 200
    assert impact.json()["can_request"] is True

    csrf = client.cookies.get("vulnflow_csrf")
    requested = client.post(
        f"/asset-merges/{merge['merge_id']}/request-rollback",
        data={"reason": "자산 동일성 오판 확인", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert requested.status_code == 303
    rollback = list_asset_merge_rollback_requests(main.DB_PATH, status="PENDING")[0]
    approvals = client.get("/approvals")
    assert approvals.status_code == 200
    assert rollback["rollback_request_id"] in approvals.text
    csrf = client.cookies.get("vulnflow_csrf")
    decided = client.post(
        f"/asset-merge-rollback-requests/{rollback['rollback_request_id']}/decision",
        data={"decision": "APPROVED", "decision_note": "후속 변경 없음", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert decided.status_code == 303
    assert get_asset(main.DB_PATH, b["asset_ref_id"])["status"] == "ACTIVE"
