from pathlib import Path
import sqlite3

import pytest
from fastapi.testclient import TestClient

import app.main as main
from app.core.storage import (
    ConcurrencyError,
    apply_import_batch,
    get_finding,
    init_db,
    list_import_batches,
    update_record_state,
    update_workflow,
)


def _row(fid: str, cve: str, *, source: str = "scanner-a") -> dict:
    return {
        "finding_id": fid,
        "product": "Demo",
        "cve_id": cve,
        "status": "OPEN",
        "scanner_source": source,
        "record_state": "ACTIVE",
        "row_version": 1,
        "score": 10,
        "first_seen_at": "2026-07-01",
        "first_scored_at": "2026-07-01",
    }


def _csrf(client: TestClient) -> str:
    assert client.get("/").status_code == 200
    return client.cookies.get(main.CSRF_COOKIE)


def test_snapshot_marks_missing_stale_and_reappearance_active(tmp_path: Path):
    db = tmp_path / "scan.sqlite3"
    init_db(db)
    apply_import_batch(
        db,
        [_row("F-1", "CVE-2026-10001"), _row("F-2", "CVE-2026-10002")],
        scanner_source="scanner-a",
        filename="first.csv",
        reconcile_missing=True,
        actor="tester",
    )
    second = apply_import_batch(
        db,
        [_row("F-1", "CVE-2026-10001")],
        scanner_source="scanner-a",
        filename="second.csv",
        reconcile_missing=True,
        actor="tester",
    )
    assert second["stale"] == 1
    assert get_finding(db, "F-2")["record_state"] == "STALE"
    assert get_finding(db, "F-2")["stale_since"]

    third = apply_import_batch(
        db,
        [_row("F-1", "CVE-2026-10001"), _row("F-2", "CVE-2026-10002")],
        scanner_source="scanner-a",
        filename="third.csv",
        reconcile_missing=True,
        actor="tester",
    )
    assert third["stale"] == 0
    revived = get_finding(db, "F-2")
    assert revived["record_state"] == "ACTIVE"
    assert not revived["stale_since"]


def test_incremental_import_does_not_mark_missing_stale(tmp_path: Path):
    db = tmp_path / "incremental.sqlite3"
    init_db(db)
    apply_import_batch(
        db,
        [_row("F-1", "CVE-2026-10001"), _row("F-2", "CVE-2026-10002")],
        scanner_source="scanner-a",
        filename="first.csv",
        reconcile_missing=False,
    )
    result = apply_import_batch(
        db,
        [_row("F-1", "CVE-2026-10001")],
        scanner_source="scanner-a",
        filename="delta.csv",
        reconcile_missing=False,
    )
    assert result["stale"] == 0
    assert get_finding(db, "F-2")["record_state"] == "ACTIVE"


def test_import_batches_are_recorded(tmp_path: Path):
    db = tmp_path / "history.sqlite3"
    init_db(db)
    result = apply_import_batch(
        db,
        [_row("F-1", "CVE-2026-10001")],
        scanner_source="nessus-lab",
        filename="scan.csv",
        reconcile_missing=True,
        actor="operator",
    )
    batches = list_import_batches(db)
    assert batches[0]["batch_id"] == result["batch_id"]
    assert batches[0]["scanner_source"] == "nessus-lab"
    assert batches[0]["import_mode"] == "snapshot"
    assert batches[0]["actor"] == "operator"


def test_record_state_archive_and_restore_with_optimistic_lock(tmp_path: Path):
    db = tmp_path / "state.sqlite3"
    init_db(db)
    apply_import_batch(
        db,
        [_row("F-1", "CVE-2026-10001")],
        scanner_source="scanner-a",
        filename="scan.csv",
    )
    current = get_finding(db, "F-1")
    archived = update_record_state(
        db, "F-1", record_state="ARCHIVED", actor="tester", expected_version=current["row_version"]
    )
    assert archived["record_state"] == "ARCHIVED"
    assert archived["archived_at"]
    with pytest.raises(ConcurrencyError):
        update_record_state(
            db, "F-1", record_state="ACTIVE", actor="stale-tab", expected_version=current["row_version"]
        )
    restored = update_record_state(
        db, "F-1", record_state="ACTIVE", actor="tester", expected_version=archived["row_version"]
    )
    assert restored["record_state"] == "ACTIVE"
    assert not restored["archived_at"]


def test_workflow_optimistic_lock_rejects_stale_version(tmp_path: Path):
    db = tmp_path / "concurrency.sqlite3"
    init_db(db)
    apply_import_batch(
        db,
        [_row("F-1", "CVE-2026-10001")],
        scanner_source="scanner-a",
        filename="scan.csv",
    )
    version = get_finding(db, "F-1")["row_version"]
    update_workflow(
        db, "F-1", status="IN_PROGRESS", owner="a", due_date="", exception_expiry="",
        risk_acceptance_reason="", risk_acceptance_approver="", notes="first", expected_version=version,
    )
    with pytest.raises(ConcurrencyError):
        update_workflow(
            db, "F-1", status="IN_PROGRESS", owner="b", due_date="", exception_expiry="",
            risk_acceptance_reason="", risk_acceptance_approver="", notes="stale", expected_version=version,
        )


def test_upload_snapshot_route_and_import_history(client: TestClient):
    token = _csrf(client)
    csv_bytes = (
        b"finding_id,product,cve_id,cvss\n"
        b"V4-1,Scanner Product,CVE-2026-20001,8.1\n"
    )
    response = client.post(
        "/upload/findings",
        data={"csrf_token": token, "scanner_source": "scanner-v4", "import_mode": "snapshot"},
        files={"file": ("snapshot.csv", csv_bytes, "text/csv")},
        follow_redirects=False,
    )
    assert response.status_code == 303
    item = client.get("/api/v1/findings/V4-1").json()
    assert item["scanner_source"] == "scanner-v4"
    assert item["record_state"] == "ACTIVE"
    history = client.get("/api/v1/imports").json()["items"]
    assert any(batch["scanner_source"] == "scanner-v4" for batch in history)
    assert client.get("/imports").status_code == 200


def test_record_state_route_detects_conflict(client: TestClient):
    token = _csrf(client)
    current = client.get("/api/v1/findings/F-0001").json()
    first = client.post(
        "/finding/F-0001/record-state",
        data={"csrf_token": token, "record_state": "ARCHIVED", "row_version": current["row_version"]},
        follow_redirects=False,
    )
    assert first.status_code == 303
    conflict = client.post(
        "/finding/F-0001/record-state",
        data={"csrf_token": token, "record_state": "ACTIVE", "row_version": current["row_version"]},
    )
    assert conflict.status_code == 409


def test_v3_database_migrates_without_source_index_failure(tmp_path: Path):
    legacy_db = tmp_path / "legacy.sqlite3"
    schema = (Path(__file__).parent / "fixtures" / "v3_schema.sql").read_text(encoding="utf-8")
    with sqlite3.connect(legacy_db) as conn:
        conn.executescript(schema)
    init_db(legacy_db)
    with sqlite3.connect(legacy_db) as conn:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(findings)")}
        indexes = {row[1] for row in conn.execute("PRAGMA index_list(findings)")}
    assert {"scanner_source", "record_state", "row_version"} <= columns
    assert "idx_findings_source_state" in indexes


def test_rescore_does_not_bump_unrelated_versions(client: TestClient):
    before_1 = client.get("/api/v1/findings/F-0001").json()["row_version"]
    before_2 = client.get("/api/v1/findings/F-0002").json()["row_version"]
    token = _csrf(client)
    changed = client.post(
        "/finding/F-0001",
        data={
            "csrf_token": token,
            "row_version": before_1,
            "status": "IN_PROGRESS",
            "owner": "operator",
            "due_date": "",
            "exception_expiry": "",
            "risk_acceptance_reason": "",
            "risk_acceptance_approver": "",
            "notes": "concurrency check",
        },
        follow_redirects=False,
    )
    assert changed.status_code == 303
    after_2 = client.get("/api/v1/findings/F-0002").json()["row_version"]
    assert after_2 == before_2


def test_archived_finding_rejects_workflow_update(client: TestClient):
    token = _csrf(client)
    current = client.get("/api/v1/findings/F-0001").json()
    archived = client.post(
        "/finding/F-0001/record-state",
        data={"csrf_token": token, "record_state": "ARCHIVED", "row_version": current["row_version"]},
        follow_redirects=False,
    )
    assert archived.status_code == 303
    item = client.get("/api/v1/findings/F-0001").json()
    response = client.post(
        "/finding/F-0001",
        data={
            "csrf_token": token,
            "row_version": item["row_version"],
            "status": "IN_PROGRESS",
            "owner": "should-fail",
            "due_date": "",
            "exception_expiry": "",
            "risk_acceptance_reason": "",
            "risk_acceptance_approver": "",
            "notes": "",
        },
    )
    assert response.status_code == 400
    assert "ACTIVE로 복원" in response.text


def test_health_remains_available_in_explicit_demo_mode(client: TestClient):
    assert client.get("/health").status_code == 200
    assert client.get("/").status_code == 200


def test_html_report_excludes_archived_records(tmp_path: Path):
    from app.services.report import generate_html_report
    db = tmp_path / "report.sqlite3"
    init_db(db)
    apply_import_batch(
        db,
        [_row("F-1", "CVE-2026-10001"), _row("F-2", "CVE-2026-10002")],
        scanner_source="scanner-a",
        filename="scan.csv",
    )
    item = get_finding(db, "F-2")
    update_record_state(db, "F-2", record_state="ARCHIVED", expected_version=item["row_version"])
    from app.core.storage import list_findings
    html = generate_html_report(list_findings(db))
    assert "F-1" in html
    assert "F-2" not in html


def test_dashboard_hides_archived_by_default_and_can_filter_it(client: TestClient):
    token = _csrf(client)
    current = client.get("/api/v1/findings/F-0001").json()
    response = client.post(
        "/finding/F-0001/record-state",
        data={"csrf_token": token, "record_state": "ARCHIVED", "row_version": current["row_version"]},
        follow_redirects=False,
    )
    assert response.status_code == 303
    default_page = client.get("/")
    assert b"F-0001" not in default_page.content
    archived_page = client.get("/?record_state=ARCHIVED")
    assert b"F-0001" in archived_page.content
