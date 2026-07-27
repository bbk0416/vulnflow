from pathlib import Path
import sqlite3

import pytest
from fastapi.testclient import TestClient

import app.main as main
from app.core.storage import (
    ConcurrencyError,
    apply_import_batch,
    create_remediation_verification_request,
    decide_remediation_verification_request,
    get_finding,
    init_db,
    list_finding_observations,
    list_remediation_verification_requests,
    update_workflow,
)


def _row(fid: str, cve: str, source: str = "scanner-v14") -> dict:
    return {
        "finding_id": fid,
        "product": "Demo",
        "asset_name": "demo-asset",
        "cve_id": cve,
        "status": "OPEN",
        "scanner_source": source,
        "record_state": "ACTIVE",
        "row_version": 1,
        "score": 50,
        "first_seen_at": "2026-07-01",
        "first_scored_at": "2026-07-01",
    }


def _mitigate(db: Path, fid: str) -> None:
    current = get_finding(db, fid)
    update_workflow(
        db,
        fid,
        status="MITIGATED",
        owner="operator",
        due_date="",
        exception_expiry="",
        risk_acceptance_reason="",
        risk_acceptance_approver="",
        notes="patch applied",
        actor="operator",
        expected_version=current["row_version"],
    )


def test_schema_v15_contains_verification_tables_and_columns(tmp_path: Path):
    db = tmp_path / "schema.sqlite3"
    init_db(db)
    with sqlite3.connect(db) as conn:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(findings)")}
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        version = conn.execute("PRAGMA user_version").fetchone()[0]
    assert version == 40
    assert {
        "resolution_state",
        "resolution_requested_at",
        "verified_at",
        "verified_by",
        "verification_method",
        "consecutive_absent_scans",
        "reopen_count",
    } <= columns
    assert {"finding_observations", "remediation_verification_requests", "verification_evidence_artifacts"} <= tables


def test_two_snapshot_absences_make_mitigated_finding_ready(tmp_path: Path):
    db = tmp_path / "absence.sqlite3"
    init_db(db)
    apply_import_batch(db, [_row("F-1", "CVE-2026-14001"), _row("F-2", "CVE-2026-14002")], scanner_source="scanner-v14", filename="one.csv", reconcile_missing=True)
    _mitigate(db, "F-1")

    first = apply_import_batch(db, [_row("F-2", "CVE-2026-14002")], scanner_source="scanner-v14", filename="two.csv", reconcile_missing=True)
    item = get_finding(db, "F-1")
    assert first["verification_ready"] == 0
    assert item["record_state"] == "STALE"
    assert item["consecutive_absent_scans"] == 1

    second = apply_import_batch(db, [_row("F-2", "CVE-2026-14002")], scanner_source="scanner-v14", filename="three.csv", reconcile_missing=True)
    item = get_finding(db, "F-1")
    assert second["verification_ready"] == 1
    assert item["consecutive_absent_scans"] == 2
    assert item["resolution_state"] == "READY_FOR_VERIFICATION"
    observations = list_finding_observations(db, "F-1")
    assert [row["observation"] for row in observations[:2]] == ["ABSENT", "ABSENT"]


def test_scan_absence_request_approval_closes_and_reappearance_reopens(tmp_path: Path):
    db = tmp_path / "approve.sqlite3"
    init_db(db)
    apply_import_batch(db, [_row("F-1", "CVE-2026-14001"), _row("F-2", "CVE-2026-14002")], scanner_source="scanner-v14", filename="one.csv", reconcile_missing=True)
    _mitigate(db, "F-1")
    apply_import_batch(db, [_row("F-2", "CVE-2026-14002")], scanner_source="scanner-v14", filename="two.csv", reconcile_missing=True)
    apply_import_batch(db, [_row("F-2", "CVE-2026-14002")], scanner_source="scanner-v14", filename="three.csv", reconcile_missing=True)

    current = get_finding(db, "F-1")
    request = create_remediation_verification_request(
        db,
        "F-1",
        method="SCAN_ABSENCE",
        evidence_note="",
        actor="operator",
        expected_version=current["row_version"],
        absence_threshold=2,
    )
    pending = get_finding(db, "F-1")
    assert request["status"] == "PENDING"
    assert pending["resolution_state"] == "PENDING"

    decided = decide_remediation_verification_request(
        db, request["verification_id"], decision="APPROVE", decision_note="two clean snapshots", actor="approver"
    )
    closed = get_finding(db, "F-1")
    assert decided["status"] == "APPROVED"
    assert closed["status"] == "CLOSED"
    assert closed["resolution_state"] == "VERIFIED"
    assert closed["verified_by"] == "approver"

    result = apply_import_batch(
        db,
        [_row("F-1", "CVE-2026-14001"), _row("F-2", "CVE-2026-14002")],
        scanner_source="scanner-v14",
        filename="four.csv",
        reconcile_missing=True,
    )
    reopened = get_finding(db, "F-1")
    assert result["reopened"] == 1
    assert reopened["status"] == "OPEN"
    assert reopened["resolution_state"] == "REOPENED"
    assert reopened["reopen_count"] == 1
    assert reopened["record_state"] == "ACTIVE"


def test_reject_returns_to_in_progress(tmp_path: Path):
    db = tmp_path / "reject.sqlite3"
    init_db(db)
    apply_import_batch(db, [_row("F-1", "CVE-2026-14001")], scanner_source="scanner-v14", filename="one.csv")
    _mitigate(db, "F-1")
    current = get_finding(db, "F-1")
    request = create_remediation_verification_request(
        db,
        "F-1",
        method="RETEST",
        evidence_note="service retest attached",
        actor="operator",
        expected_version=current["row_version"],
    )
    decide_remediation_verification_request(
        db, request["verification_id"], decision="REJECT", decision_note="still reproducible", actor="approver"
    )
    item = get_finding(db, "F-1")
    assert item["status"] == "IN_PROGRESS"
    assert item["resolution_state"] == "REJECTED"
    assert not item["resolved_at"]


def test_request_becomes_stale_after_workflow_change(tmp_path: Path):
    db = tmp_path / "stale-request.sqlite3"
    init_db(db)
    apply_import_batch(db, [_row("F-1", "CVE-2026-14001")], scanner_source="scanner-v14", filename="one.csv")
    _mitigate(db, "F-1")
    current = get_finding(db, "F-1")
    request = create_remediation_verification_request(
        db,
        "F-1",
        method="MANUAL_EVIDENCE",
        evidence_note="change ticket CHG-14",
        actor="operator",
        expected_version=current["row_version"],
    )
    changed = get_finding(db, "F-1")
    update_workflow(
        db,
        "F-1",
        status="IN_PROGRESS",
        owner="operator",
        due_date="",
        exception_expiry="",
        risk_acceptance_reason="",
        risk_acceptance_approver="",
        notes="additional fix required",
        actor="operator",
        expected_version=changed["row_version"],
    )
    records = list_remediation_verification_requests(db, finding_id="F-1")
    assert records[0]["status"] == "CANCELLED"
    with pytest.raises(ValueError, match="이미 처리된"):
        decide_remediation_verification_request(
            db, request["verification_id"], decision="APPROVE", decision_note="late", actor="approver"
        )


def test_web_routes_and_direct_close_restriction(client: TestClient):
    token = client.get("/").cookies.get(main.CSRF_COOKIE) or client.cookies.get(main.CSRF_COOKIE)
    current = client.get("/api/v1/findings/F-0001").json()
    close = client.post(
        "/finding/F-0001",
        data={
            "csrf_token": token,
            "row_version": current["row_version"],
            "status": "CLOSED",
            "owner": "",
            "due_date": "",
            "exception_expiry": "",
            "risk_acceptance_reason": "",
            "risk_acceptance_approver": "",
            "notes": "manual close",
        },
    )
    assert close.status_code == 400
    assert client.get("/verifications").status_code == 200
    assert client.get("/api/v1/verifications").status_code == 200
