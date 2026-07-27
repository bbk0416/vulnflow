from pathlib import Path
import sqlite3

from fastapi.testclient import TestClient
import pytest

import app.main as main
from app.core.storage import (
    bulk_update_workflow,
    get_finding,
    init_db,
    list_audit_events,
    restore_database,
    upsert_findings,
    validate_database_file,
)



def csrf(client: TestClient) -> str:
    response = client.get("/")
    assert response.status_code == 200
    return client.cookies.get(main.CSRF_COOKIE)


def row(fid: str, status: str = "OPEN") -> dict:
    return {
        "finding_id": fid,
        "product": "Demo",
        "cve_id": f"CVE-2026-{10000 + int(fid.split('-')[-1])}",
        "status": status,
        "score": 10,
        "policy_version": "2.0.0",
        "first_seen_at": "2026-07-01",
        "first_scored_at": "2026-07-01",
    }


def test_bulk_update_endpoint_changes_multiple_findings(client: TestClient):
    token = csrf(client)
    response = client.post(
        "/bulk-update",
        data={
            "csrf_token": token,
            "finding_ids": ["F-0001", "F-0002"],
            "bulk_status": "IN_PROGRESS",
            "owner_mode": "set",
            "bulk_owner": "vm-team",
            "due_date_mode": "set",
            "bulk_due_date": "2026-08-15",
            "bulk_notes": "weekly triage",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    for fid in ("F-0001", "F-0002"):
        item = client.get(f"/api/v1/findings/{fid}").json()
        assert item["status"] == "IN_PROGRESS"
        assert item["owner"] == "vm-team"
        assert item["due_date"] == "2026-08-15"
        assert "weekly triage" in item["notes"]
        assert any(event["event_type"] == "bulk_workflow_update" for event in item["audit_events"])


def test_bulk_update_rejects_risk_acceptance(client: TestClient):
    token = csrf(client)
    response = client.post(
        "/bulk-update",
        data={
            "csrf_token": token,
            "finding_ids": ["F-0001"],
            "bulk_status": "RISK_ACCEPTED",
            "owner_mode": "keep",
            "due_date_mode": "keep",
        },
    )
    assert response.status_code == 400
    assert "개별 처리" in response.text


def test_audit_export_and_api(client: TestClient):
    exported = client.get("/export/audit.csv")
    assert exported.status_code == 200
    assert exported.content.startswith(b"\xef\xbb\xbf")
    assert b"event_type" in exported.content
    api = client.get("/api/v1/audit?limit=5")
    assert api.status_code == 200
    assert len(api.json()["items"]) <= 5


def test_backup_restore_endpoint_reverts_state(client: TestClient):
    backup = client.get("/export/backup.sqlite3")
    assert backup.status_code == 200
    token = csrf(client)
    changed = client.post(
        "/finding/F-0001",
        data={
            "csrf_token": token,
            "status": "IN_PROGRESS",
            "owner": "changed-owner",
            "due_date": "2026-08-01",
            "exception_expiry": "",
            "risk_acceptance_reason": "",
            "risk_acceptance_approver": "",
            "notes": "changed after backup",
        },
        follow_redirects=False,
    )
    assert changed.status_code == 303
    assert client.get("/api/v1/findings/F-0001").json()["owner"] == "changed-owner"

    restored = client.post(
        "/restore-backup",
        data={"csrf_token": token, "confirmation": "RESTORE"},
        files={"file": ("backup.sqlite3", backup.content, "application/vnd.sqlite3")},
        follow_redirects=False,
    )
    assert restored.status_code == 303
    item = client.get("/api/v1/findings/F-0001").json()
    assert item["owner"] != "changed-owner"
    audit = client.get("/api/v1/audit?limit=20").json()["items"]
    assert any(event["event_type"] == "database_restore" for event in audit)


def test_restore_rejects_non_sqlite(client: TestClient):
    token = csrf(client)
    response = client.post(
        "/restore-backup",
        data={"csrf_token": token, "confirmation": "RESTORE"},
        files={"file": ("fake.sqlite3", b"not sqlite", "application/octet-stream")},
    )
    assert response.status_code == 400


def test_storage_restore_creates_safety_backup(tmp_path: Path):
    live = tmp_path / "live.sqlite3"
    source = tmp_path / "source.sqlite3"
    init_db(live)
    init_db(source)
    upsert_findings(live, [row("F-1")], audit=False)
    upsert_findings(source, [row("F-2")], audit=False)
    summary = validate_database_file(source)
    assert summary["finding_count"] == 1
    restored = restore_database(live, source, actor="tester")
    assert restored["finding_count"] == 1
    assert get_finding(live, "F-2") is not None
    assert Path(restored["safety_backup"]).exists()
    assert any(event["event_type"] == "database_restore" for event in list_audit_events(live))


def test_validate_database_rejects_wrong_schema(tmp_path: Path):
    bad = tmp_path / "bad.sqlite3"
    with sqlite3.connect(bad) as conn:
        conn.execute("CREATE TABLE other(id INTEGER)")
    with pytest.raises(ValueError):
        validate_database_file(bad)


def test_storage_bulk_update_is_atomic_and_audited(tmp_path: Path):
    db = tmp_path / "bulk.sqlite3"
    init_db(db)
    upsert_findings(db, [row("F-1"), row("F-2")], audit=False)
    count = bulk_update_workflow(
        db,
        ["F-1", "F-2"],
        status="IN_PROGRESS",
        owner_mode="set",
        owner="team-a",
        due_date_mode="set",
        due_date="2026-09-01",
        notes_append="bulk note",
        actor="tester",
    )
    assert count == 2
    assert get_finding(db, "F-1")["owner"] == "team-a"
    events = list_audit_events(db, limit=20)
    assert sum(event["event_type"] == "bulk_workflow_update" for event in events) == 3


def test_bulk_no_selection_returns_friendly_error(client: TestClient):
    token = csrf(client)
    response = client.post(
        "/bulk-update",
        data={
            "csrf_token": token,
            "bulk_status": "IN_PROGRESS",
            "owner_mode": "keep",
            "due_date_mode": "keep",
        },
    )
    assert response.status_code == 400
    assert "선택된 취약점" in response.text


def test_bulk_reopen_clears_risk_acceptance_fields(tmp_path: Path):
    db = tmp_path / "risk.sqlite3"
    init_db(db)
    accepted = row("F-1", status="RISK_ACCEPTED") | {
        "exception_expiry": "2027-01-01",
        "risk_acceptance_reason": "temporary",
        "risk_acceptance_approver": "CISO",
    }
    upsert_findings(db, [accepted], audit=False)
    bulk_update_workflow(db, ["F-1"], status="OPEN", actor="tester")
    saved = get_finding(db, "F-1")
    assert saved["status"] == "OPEN"
    assert not saved["exception_expiry"]
    assert not saved["risk_acceptance_reason"]
    assert not saved["risk_acceptance_approver"]


def test_reimport_with_blank_workflow_columns_does_not_wipe_state(client: TestClient):
    token = csrf(client)
    changed = client.post(
        "/finding/F-0001",
        data={
            "csrf_token": token,
            "status": "IN_PROGRESS",
            "owner": "workflow-owner",
            "due_date": "2026-08-10",
            "exception_expiry": "",
            "risk_acceptance_reason": "",
            "risk_acceptance_approver": "",
            "notes": "managed in VulnFlow",
        },
        follow_redirects=False,
    )
    assert changed.status_code == 303
    csv_bytes = (
        b"finding_id,product,cve_id,cvss,status,owner,due_date,notes,epss,kev\n"
        b"F-0001,EdgeConnect Gateway,CVE-2024-3400,9.6,,,,,0,0\n"
    )
    uploaded = client.post(
        "/upload/findings",
        data={"csrf_token": token},
        files={"file": ("scanner-refresh.csv", csv_bytes, "text/csv")},
        follow_redirects=False,
    )
    assert uploaded.status_code == 303
    item = client.get("/api/v1/findings/F-0001").json()
    assert item["status"] == "IN_PROGRESS"
    assert item["owner"] == "workflow-owner"
    assert item["due_date"] == "2026-08-10"
    assert item["notes"] == "managed in VulnFlow"
    assert item["cvss"] == 9.6
    assert item["epss"] != 0 or item["kev"] != 0


def test_validate_database_rejects_triggers(tmp_path: Path):
    db = tmp_path / "trigger.sqlite3"
    init_db(db)
    with sqlite3.connect(db) as conn:
        conn.execute("CREATE TRIGGER bad_trigger AFTER INSERT ON findings BEGIN DELETE FROM findings; END")
    with pytest.raises(ValueError, match="트리거"):
        validate_database_file(db)
