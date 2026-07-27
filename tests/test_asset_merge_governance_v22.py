from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path

import pytest

from app.core.storage import (
    CURRENT_SCHEMA_VERSION,
    ConcurrencyError,
    add_asset_identifier,
    analyze_asset_merge,
    apply_import_batch,
    approve_asset_merge_request,
    create_asset_merge_request,
    get_asset,
    get_asset_merge_request,
    get_finding,
    init_db,
    list_asset_identity_candidates,
    list_asset_merge_requests,
    reject_asset_merge_request,
)


def _row(finding_id: str, *, asset_id: str, asset_name: str, cve_id: str = "CVE-2026-22001") -> dict:
    return {
        "finding_id": finding_id,
        "product": "Merge Governance API",
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


def _candidate_pair(db: Path) -> tuple[dict, dict, dict]:
    apply_import_batch(
        db, [_row("V22-A", asset_id="scanner-a-2200", asset_name="merge-host")],
        scanner_source="scanner-a", filename="a.csv",
    )
    apply_import_batch(
        db, [_row("V22-B", asset_id="scanner-b-2200", asset_name="merge-host")],
        scanner_source="scanner-b", filename="b.csv",
    )
    a = get_finding(db, "V22-A")
    b = get_finding(db, "V22-B")
    candidate = list_asset_identity_candidates(db, status="PENDING")[0]
    return a, b, candidate


def _recovery_file(tmp_path: Path) -> tuple[str, str]:
    path = tmp_path / "asset-merge-recovery.zip"
    path.write_bytes(b"vulnflow-v22-recovery-point")
    return str(path), hashlib.sha256(path.read_bytes()).hexdigest()


def test_schema_v22_has_merge_governance_table_and_triggers(tmp_path: Path):
    db = tmp_path / "schema.sqlite3"
    init_db(db)
    with sqlite3.connect(db) as conn:
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        triggers = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='trigger'")}
        version = int(conn.execute("PRAGMA user_version").fetchone()[0])
    assert version == CURRENT_SCHEMA_VERSION == 40
    assert "asset_merge_requests" in tables
    assert {"asset_merge_requests_core_immutable", "asset_merge_requests_no_delete"} <= triggers


def test_dry_run_request_approval_and_recovery_point(tmp_path: Path):
    db = tmp_path / "approved.sqlite3"
    init_db(db)
    a, b, candidate = _candidate_pair(db)
    impact = analyze_asset_merge(
        db, source_asset_ref_id=b["asset_ref_id"], target_asset_ref_id=a["asset_ref_id"],
        candidate_id=candidate["candidate_id"],
    )
    assert impact["can_request"] is True
    assert impact["summary"]["consolidated_finding_count"] == 1
    assert impact["summary"]["moved_finding_count"] == 0
    assert len(impact["impact_sha256"]) == 64

    request = create_asset_merge_request(
        db, source_asset_ref_id=b["asset_ref_id"], target_asset_ref_id=a["asset_ref_id"],
        candidate_id=candidate["candidate_id"], reason="CMDB와 운영 담당자가 동일 서버임을 확인",
        requested_by="operator-a",
    )
    assert request["status"] == "PENDING"
    assert request["impact_sha256"] == impact["impact_sha256"]

    bundle_path, bundle_sha = _recovery_file(tmp_path)
    approved = approve_asset_merge_request(
        db, request["request_id"], decided_by="approver-a", decision_note="영향범위와 복구점 확인",
        recovery_bundle_path=bundle_path, recovery_bundle_sha256=bundle_sha,
    )
    assert approved["status"] == "APPROVED"
    assert approved["merge_id"]
    assert approved["recovery_bundle_sha256"] == bundle_sha
    assert get_asset(db, b["asset_ref_id"])["merged_into_asset_ref_id"] == a["asset_ref_id"]
    assert get_finding(db, "V22-B")["record_state"] == "ARCHIVED"


def test_request_is_blocked_when_impact_changes_after_dry_run(tmp_path: Path):
    db = tmp_path / "changed.sqlite3"
    init_db(db)
    a, b, candidate = _candidate_pair(db)
    request = create_asset_merge_request(
        db, source_asset_ref_id=b["asset_ref_id"], target_asset_ref_id=a["asset_ref_id"],
        candidate_id=candidate["candidate_id"], reason="병합 전 영향분석 고정",
        requested_by="operator-a",
    )
    add_asset_identifier(
        db, b["asset_ref_id"], identifier_type="IP_ADDRESS", value="192.0.2.22",
        actor="inventory-sync",
    )
    bundle_path, bundle_sha = _recovery_file(tmp_path)
    with pytest.raises(ConcurrencyError, match="영향 범위"):
        approve_asset_merge_request(
            db, request["request_id"], decided_by="approver-a", decision_note="",
            recovery_bundle_path=bundle_path, recovery_bundle_sha256=bundle_sha,
        )
    assert get_asset_merge_request(db, request["request_id"])["status"] == "PENDING"
    assert get_asset(db, b["asset_ref_id"])["status"] == "ACTIVE"


def test_authoritative_identifier_conflict_blocks_merge_request(tmp_path: Path):
    db = tmp_path / "conflict.sqlite3"
    init_db(db)
    apply_import_batch(
        db, [_row("C-A", asset_id="a", asset_name="alpha", cve_id="CVE-2026-22002")],
        scanner_source="scanner-a", filename="a.csv",
    )
    apply_import_batch(
        db, [_row("C-B", asset_id="b", asset_name="beta", cve_id="CVE-2026-22003")],
        scanner_source="scanner-b", filename="b.csv",
    )
    a = get_finding(db, "C-A")
    b = get_finding(db, "C-B")
    add_asset_identifier(db, a["asset_ref_id"], identifier_type="CMDB_ID", value="CI-220-A")
    add_asset_identifier(db, b["asset_ref_id"], identifier_type="CMDB_ID", value="CI-220-B")
    impact = analyze_asset_merge(
        db, source_asset_ref_id=b["asset_ref_id"], target_asset_ref_id=a["asset_ref_id"],
    )
    assert impact["can_request"] is False
    assert any(item["code"] == "AUTHORITATIVE_IDENTIFIER_CONFLICT" for item in impact["blockers"])
    with pytest.raises(ValueError, match="권위 식별자"):
        create_asset_merge_request(
            db, source_asset_ref_id=b["asset_ref_id"], target_asset_ref_id=a["asset_ref_id"],
            reason="conflicting identifiers", requested_by="operator-a",
        )


def test_merge_request_can_be_rejected_and_records_are_immutable(tmp_path: Path):
    db = tmp_path / "rejected.sqlite3"
    init_db(db)
    a, b, candidate = _candidate_pair(db)
    request = create_asset_merge_request(
        db, source_asset_ref_id=b["asset_ref_id"], target_asset_ref_id=a["asset_ref_id"],
        candidate_id=candidate["candidate_id"], reason="중복 가능성 검토",
        requested_by="operator-a",
    )
    rejected = reject_asset_merge_request(
        db, request["request_id"], decided_by="approver-a", decision_note="서로 다른 운영 소유자 확인",
    )
    assert rejected["status"] == "REJECTED"
    assert list_asset_merge_requests(db, status="PENDING") == []
    with sqlite3.connect(db) as conn:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "UPDATE asset_merge_requests SET impact_sha256='tampered' WHERE request_id=?",
                (request["request_id"],),
            )
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("DELETE FROM asset_merge_requests WHERE request_id=?", (request["request_id"],))


def test_ui_merge_request_approval_creates_real_recovery_bundle(client):
    import app.main as main

    apply_import_batch(
        main.DB_PATH, [_row("UI22-A", asset_id="ui22-a", asset_name="ui22-host")],
        scanner_source="scanner-a", filename="a.csv",
    )
    apply_import_batch(
        main.DB_PATH, [_row("UI22-B", asset_id="ui22-b", asset_name="ui22-host")],
        scanner_source="scanner-b", filename="b.csv",
    )
    a = get_finding(main.DB_PATH, "UI22-A")
    b = get_finding(main.DB_PATH, "UI22-B")
    candidate = list_asset_identity_candidates(main.DB_PATH, status="PENDING")[0]

    page = client.get("/asset-identities")
    assert page.status_code == 200
    csrf = client.cookies.get("vulnflow_csrf")
    assert csrf
    created = client.post(
        f"/asset-identities/{candidate['candidate_id']}/request-merge",
        data={
            "target_asset_ref_id": a["asset_ref_id"],
            "reason": "UI에서 영향분석 후 승인 요청",
            "csrf_token": csrf,
        },
        follow_redirects=False,
    )
    assert created.status_code == 303
    request_row = list_asset_merge_requests(main.DB_PATH, status="PENDING")[0]
    assert get_asset(main.DB_PATH, b["asset_ref_id"])["status"] == "ACTIVE"

    approvals = client.get("/approvals")
    assert approvals.status_code == 200
    assert request_row["request_id"] in approvals.text
    csrf = client.cookies.get("vulnflow_csrf")
    approved = client.post(
        f"/asset-merge-requests/{request_row['request_id']}/decision",
        data={"decision": "APPROVED", "decision_note": "복구점과 영향범위 확인", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert approved.status_code == 303
    final = get_asset_merge_request(main.DB_PATH, request_row["request_id"])
    assert final["status"] == "APPROVED"
    bundle = Path(final["recovery_bundle_path"])
    assert bundle.is_file()
    assert hashlib.sha256(bundle.read_bytes()).hexdigest() == final["recovery_bundle_sha256"]
    assert get_asset(main.DB_PATH, b["asset_ref_id"])["merged_into_asset_ref_id"] == a["asset_ref_id"]


def test_schema_21_database_migrates_to_asset_merge_governance(tmp_path: Path):
    db = tmp_path / "migration.sqlite3"
    init_db(db)
    with sqlite3.connect(db) as conn:
        conn.execute("DROP TRIGGER IF EXISTS asset_merge_requests_core_immutable")
        conn.execute("DROP TRIGGER IF EXISTS asset_merge_requests_no_delete")
        conn.execute("DROP INDEX IF EXISTS idx_asset_merge_requests_status")
        conn.execute("DROP INDEX IF EXISTS idx_asset_merge_requests_assets")
        conn.execute("DROP INDEX IF EXISTS idx_asset_merge_requests_pending_candidate")
        conn.execute("DROP TABLE asset_merge_requests")
        conn.execute("DELETE FROM schema_migrations WHERE version=22")
        conn.execute("PRAGMA user_version=21")
        conn.commit()

    init_db(db)
    with sqlite3.connect(db) as conn:
        version = int(conn.execute("PRAGMA user_version").fetchone()[0])
        table = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='asset_merge_requests'"
        ).fetchone()
        migration = conn.execute(
            "SELECT name,app_version FROM schema_migrations WHERE version=23"
        ).fetchone()
    assert version == 40
    assert table is not None
    assert migration == ("asset_merge_scoped_rollback", "23.0.0")
