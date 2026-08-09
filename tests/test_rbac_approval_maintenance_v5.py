from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

import app.main as main
from app.core.storage import add_audit_event, connect, get_finding, list_maintenance_runs


TOKENS = {
    "viewer": "viewer-token-123456789012",
    "operator": "operator-token-1234567890",
    "approver": "approver-token-1234567890",
    "admin": "admin-token-12345678901234",
}


def tokens_json() -> str:
    return json.dumps({
        name: {"token": token, "role": name, "projects": "*"}
        for name, token in TOKENS.items()
    })


def auth_headers(role: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {TOKENS[role]}"}


def make_client(tmp_path: Path, monkeypatch) -> TestClient:
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "v5.sqlite3")
    monkeypatch.setattr(main, "AUTH_USERS_JSON", "")
    monkeypatch.setattr(main, "AUTH_USER", "")
    monkeypatch.setattr(main, "AUTH_PASSWORD", "")
    monkeypatch.setattr(main, "AUTH_API_TOKENS_JSON", tokens_json())
    monkeypatch.setattr(main, "DEMO_MODE", True)
    monkeypatch.setattr(main, "MAINTENANCE_INTERVAL_MINUTES", 0)
    return TestClient(main.app)


def csrf(client: TestClient, headers: dict[str, str], path: str = "/") -> str:
    response = client.get(path, headers=headers)
    assert response.status_code == 200
    token = client.cookies.get(main.CSRF_COOKIE)
    assert token
    return token


def test_role_permissions(tmp_path: Path, monkeypatch):
    with make_client(tmp_path, monkeypatch) as client:
        viewer = auth_headers("viewer")
        token = csrf(client, viewer)
        assert client.get("/", headers=viewer).status_code == 200
        assert client.get("/upload", headers=viewer).status_code == 403
        assert client.get("/export/backup.sqlite3", headers=viewer).status_code == 403
        assert client.post("/rescore", headers=viewer, data={"csrf_token": token}).status_code == 403

        operator = auth_headers("operator")
        assert client.get("/upload", headers=operator).status_code == 200
        assert client.get("/maintenance", headers=operator).status_code == 403

        admin = auth_headers("admin")
        assert client.get("/maintenance", headers=admin).status_code == 200
        assert client.get("/export/backup.sqlite3", headers=admin).status_code == 200


def test_operator_requests_and_approver_approves(tmp_path: Path, monkeypatch):
    with make_client(tmp_path, monkeypatch) as client:
        operator = auth_headers("operator")
        token = csrf(client, operator, "/finding/F-0001")
        requested = client.post(
            "/finding/F-0001",
            headers=operator,
            data={
                "csrf_token": token,
                "status": "RISK_ACCEPTED",
                "owner": "vm-team",
                "due_date": "",
                "exception_expiry": "2027-01-31",
                "risk_acceptance_reason": "vendor patch unavailable",
                "risk_acceptance_approver": "ignored-free-text",
                "notes": "monitor weekly",
                "row_version": "1",
            },
            follow_redirects=False,
        )
        assert requested.status_code == 303
        assert "approval_requested" in requested.headers["location"]
        before = client.get("/api/v1/findings/F-0001", headers=operator).json()
        assert before["status"] != "RISK_ACCEPTED"
        pending = client.get("/api/v1/approvals?status=PENDING", headers=operator).json()["items"]
        assert len(pending) == 1
        request_id = pending[0]["request_id"]

        approver = auth_headers("approver")
        approve_token = csrf(client, approver, "/approvals")
        decided = client.post(
            f"/approvals/{request_id}/decision",
            headers=approver,
            data={"csrf_token": approve_token, "decision": "APPROVED", "decision_note": "compensating control verified"},
            follow_redirects=False,
        )
        assert decided.status_code == 303
        saved = client.get("/api/v1/findings/F-0001", headers=approver).json()
        assert saved["status"] == "RISK_ACCEPTED"
        assert saved["risk_acceptance_approver"] == "api:approver"
        assert saved["exception_expiry"] == "2027-01-31"


def test_approval_detects_changed_finding(tmp_path: Path, monkeypatch):
    with make_client(tmp_path, monkeypatch) as client:
        operator = auth_headers("operator")
        token = csrf(client, operator, "/finding/F-0001")
        requested = client.post(
            "/finding/F-0001", headers=operator,
            data={
                "csrf_token": token, "status": "RISK_ACCEPTED", "owner": "", "due_date": "",
                "exception_expiry": "2027-02-01", "risk_acceptance_reason": "temporary",
                "risk_acceptance_approver": "", "notes": "request", "row_version": "1",
            }, follow_redirects=False,
        )
        assert requested.status_code == 303
        request_id = client.get("/api/v1/approvals?status=PENDING", headers=operator).json()["items"][0]["request_id"]

        admin = auth_headers("admin")
        admin_token = csrf(client, admin, "/finding/F-0001")
        current = client.get("/api/v1/findings/F-0001", headers=admin).json()
        changed = client.post(
            "/finding/F-0001", headers=admin,
            data={
                "csrf_token": admin_token, "status": "IN_PROGRESS", "owner": "admin-owner",
                "due_date": "2026-09-01", "exception_expiry": "", "risk_acceptance_reason": "",
                "risk_acceptance_approver": "", "notes": "changed after request",
                "row_version": str(current["row_version"]),
            }, follow_redirects=False,
        )
        assert changed.status_code == 303

        approver = auth_headers("approver")
        approve_token = csrf(client, approver, "/approvals")
        conflict = client.post(
            f"/approvals/{request_id}/decision", headers=approver,
            data={"csrf_token": approve_token, "decision": "APPROVED", "decision_note": ""},
        )
        assert conflict.status_code == 409
        assert client.get("/api/v1/findings/F-0001", headers=approver).json()["status"] == "IN_PROGRESS"


def test_maintenance_reopens_exceptions_archives_stale_and_prunes(tmp_path: Path, monkeypatch):
    with make_client(tmp_path, monkeypatch) as client:
        monkeypatch.setattr(main, "AUDIT_RETENTION_DAYS", 30)
        monkeypatch.setattr(main, "IMPORT_RETENTION_DAYS", 30)
        monkeypatch.setattr(main, "AUTO_ARCHIVE_STALE_DAYS", 30)
        with connect(main.DB_PATH) as conn:
            conn.execute(
                """UPDATE findings SET status='RISK_ACCEPTED', exception_expiry='2020-01-01',
                risk_acceptance_reason='old risk', risk_acceptance_approver='legacy' WHERE finding_id='F-0001'"""
            )
            conn.execute(
                """UPDATE findings SET record_state='STALE', stale_since='2020-01-01T00:00:00+00:00'
                WHERE finding_id='F-0002'"""
            )
            add_audit_event(
                main.DB_PATH, finding_id=None, event_type="old", actor="test",
                summary="old event", details={"fixture": True},
                created_at="2020-01-01T00:00:00+00:00", conn=conn,
            )
            conn.execute(
                """INSERT INTO import_batches(batch_id,scanner_source,filename,import_mode,row_count,inserted_count,updated_count,stale_count,actor,created_at)
                VALUES('OLD-BATCH','old','old.csv','incremental',1,1,0,0,'test','2020-01-01T00:00:00+00:00')"""
            )
            conn.commit()

        admin = auth_headers("admin")
        token = csrf(client, admin, "/maintenance")
        response = client.post("/maintenance/run", headers=admin, data={"csrf_token": token}, follow_redirects=False)
        assert response.status_code == 303
        assert get_finding(main.DB_PATH, "F-0001")["status"] == "OPEN"
        assert get_finding(main.DB_PATH, "F-0002")["record_state"] == "ARCHIVED"
        runs = list_maintenance_runs(main.DB_PATH)
        assert runs and runs[0]["details"]["expired_reopened"] == 1
        assert runs[0]["details"]["stale_archived"] == 1
        with connect(main.DB_PATH) as conn:
            assert conn.execute("SELECT COUNT(*) FROM import_batches WHERE batch_id='OLD-BATCH'").fetchone()[0] == 0
            # Hash-chain retention only removes a contiguous old prefix. This synthetic
            # event was appended after current events, so it is intentionally retained.
            assert conn.execute("SELECT COUNT(*) FROM audit_events WHERE event_type='old'").fetchone()[0] == 1
            assert runs[0]["details"]["audit_deleted"] == 0


def test_viewer_cannot_access_approval_api(tmp_path: Path, monkeypatch):
    with make_client(tmp_path, monkeypatch) as client:
        assert client.get("/api/v1/approvals", headers=auth_headers("viewer")).status_code == 403
        assert client.get("/api/v1/maintenance-runs", headers=auth_headers("approver")).status_code == 403


def test_maintenance_cancels_obsolete_pending_approval(tmp_path: Path, monkeypatch):
    from app.core.storage import create_risk_approval_request, list_risk_approval_requests, update_workflow
    from app.services.maintenance import run_maintenance

    with make_client(tmp_path, monkeypatch) as client:
        finding = get_finding(main.DB_PATH, "F-0001")
        request = create_risk_approval_request(
            main.DB_PATH,
            "F-0001",
            requested_by="operator",
            reason="temporary",
            exception_expiry="2027-03-01",
            expected_version=finding["row_version"],
        )
        update_workflow(
            main.DB_PATH,
            "F-0001",
            status="IN_PROGRESS",
            owner="team",
            due_date="2026-09-01",
            exception_expiry="",
            risk_acceptance_reason="",
            risk_acceptance_approver="",
            notes="changed",
            actor="admin",
            expected_version=finding["row_version"],
        )
        summary = run_maintenance(main.DB_PATH, actor="admin")
        assert summary["approval_cancelled"] == 1
        saved = [x for x in list_risk_approval_requests(main.DB_PATH) if x["request_id"] == request["request_id"]][0]
        assert saved["status"] == "CANCELLED"
        assert "변경" in saved["decision_note"]


def test_expired_pending_approval_cannot_be_approved_and_is_cancelled(tmp_path: Path, monkeypatch):
    from app.core.storage import create_risk_approval_request, decide_risk_approval_request, list_risk_approval_requests
    from app.services.maintenance import run_maintenance
    import pytest

    with make_client(tmp_path, monkeypatch):
        finding = get_finding(main.DB_PATH, "F-0001")
        request = create_risk_approval_request(
            main.DB_PATH, "F-0001", requested_by="operator", reason="expired",
            exception_expiry="2020-01-01", expected_version=finding["row_version"],
        )
        with pytest.raises(ValueError, match="만료일"):
            decide_risk_approval_request(
                main.DB_PATH, request["request_id"], decision="APPROVED", decided_by="approver"
            )
        summary = run_maintenance(main.DB_PATH, actor="admin")
        assert summary["approval_cancelled"] == 1
        saved = [x for x in list_risk_approval_requests(main.DB_PATH) if x["request_id"] == request["request_id"]][0]
        assert saved["status"] == "CANCELLED"
        assert saved["decision_note"] == "요청 만료"


def test_reset_demo_deletes_pending_approvals_without_fk_failure(tmp_path: Path, monkeypatch):
    from app.core.storage import create_risk_approval_request

    with make_client(tmp_path, monkeypatch) as client:
        finding = get_finding(main.DB_PATH, "F-0001")
        create_risk_approval_request(
            main.DB_PATH, "F-0001", requested_by="operator", reason="temporary",
            exception_expiry="2027-04-01", expected_version=finding["row_version"],
        )
        admin = auth_headers("admin")
        token = csrf(client, admin)
        response = client.post(
            "/reset-demo", headers=admin,
            data={"csrf_token": token, "confirmation": "RESET"},
            follow_redirects=False,
        )
        assert response.status_code == 303
        assert client.get("/api/v1/approvals", headers=admin).json()["items"] == []


def test_legacy_schema_migration_adds_v5_tables(tmp_path: Path):
    import sqlite3
    from app.core.storage import init_db

    db = tmp_path / "legacy-v5.sqlite3"
    fixture = Path(__file__).parent / "fixtures" / "v3_schema.sql"
    with sqlite3.connect(db) as conn:
        conn.executescript(fixture.read_text(encoding="utf-8"))
    init_db(db)
    with sqlite3.connect(db) as conn:
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        approval_columns = {row[1] for row in conn.execute("PRAGMA table_info(risk_approval_requests)")}
    assert {"risk_approval_requests", "maintenance_runs", "import_batches"} <= tables
    assert {"request_id", "finding_id", "finding_row_version", "status"} <= approval_columns


def test_legacy_plaintext_user_configuration_fails_startup(tmp_path: Path, monkeypatch):
    import pytest

    monkeypatch.setattr(main, "DB_PATH", tmp_path / "bad-auth.sqlite3")
    monkeypatch.setattr(main, "AUTH_USERS_JSON", "{not-json}")
    monkeypatch.setattr(main, "AUTH_API_TOKENS_JSON", tokens_json())
    with pytest.raises(RuntimeError, match="평문 환경변수 사용자"):
        with TestClient(main.app):
            pass
