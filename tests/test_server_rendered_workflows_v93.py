from __future__ import annotations

import json
import re
from pathlib import Path

from fastapi.testclient import TestClient

import app.main as main

TOKENS = {
    "operator": "server-e2e-operator-token-12345",
    "approver": "server-e2e-approver-token-12345",
    "admin": "server-e2e-admin-token-123456789",
}


def _headers(role: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {TOKENS[role]}"}


def _csrf(client: TestClient, headers: dict[str, str], path: str) -> str:
    response = client.get(path, headers=headers)
    assert response.status_code == 200
    token = client.cookies.get(main.CSRF_COOKIE)
    assert token
    return token


def _client(tmp_path: Path, monkeypatch) -> TestClient:
    token_config = json.dumps(
        {name: {"token": token, "role": name, "projects": "*"} for name, token in TOKENS.items()}
    )
    overrides = {
        "DB_PATH": tmp_path / "server-e2e.sqlite3",
        "AUTH_API_TOKENS_JSON": token_config,
        "AUTH_USERS_JSON": "",
        "AUTH_USER": "",
        "AUTH_PASSWORD": "",
        "DEMO_MODE": True,
        "ALLOW_LOCAL_ADMIN_FALLBACK": False,
        "JOB_WORKER_ENABLED": False,
        "CLUSTER_COORDINATION_ENABLED": False,
        "WEBHOOK_INTERVAL_SECONDS": 0,
        "MAINTENANCE_INTERVAL_MINUTES": 0,
        "BACKUP_INTERVAL_HOURS": 0,
    }
    for name, value in overrides.items():
        monkeypatch.setattr(main, name, value, raising=False)
    monkeypatch.setattr(
        main.APPLICATION_CONTEXT,
        "settings",
        main.APPLICATION_CONTEXT.settings.with_overrides(overrides),
    )
    return TestClient(main.app)


def test_dashboard_and_finding_forms_keep_browser_contract(tmp_path: Path, monkeypatch):
    with _client(tmp_path, monkeypatch) as client:
        admin = _headers("admin")
        dashboard = client.get("/", headers=admin)
        assert dashboard.status_code == 200
        assert 'id="findings"' in dashboard.text
        assert 'href="/finding/F-0001"' in dashboard.text
        assert "전체 조치 항목" in dashboard.text

        detail = client.get("/finding/F-0001", headers=admin)
        assert detail.status_code == 200
        for contract in (
            'select name="status"',
            'input name="owner"',
            'textarea name="notes"',
            "저장하고 반영",
        ):
            assert contract in detail.text

        token = client.cookies.get(main.CSRF_COOKIE)
        current = client.get("/api/v1/findings/F-0001", headers=admin).json()
        changed = client.post(
            "/finding/F-0001",
            headers=admin,
            data={
                "csrf_token": token,
                "status": "IN_PROGRESS",
                "owner": "server-rendered-owner",
                "due_date": "",
                "exception_expiry": "",
                "risk_acceptance_reason": "",
                "risk_acceptance_approver": "",
                "notes": "server-rendered workflow update",
                "row_version": str(current["row_version"]),
            },
            follow_redirects=False,
        )
        assert changed.status_code == 303
        refreshed = client.get("/finding/F-0001", headers=admin)
        assert "server-rendered-owner" in refreshed.text
        assert "server-rendered workflow update" in refreshed.text


def test_import_preview_apply_and_search_form_contract(tmp_path: Path, monkeypatch):
    with _client(tmp_path, monkeypatch) as client:
        admin = _headers("admin")
        token = _csrf(client, admin, "/upload")
        upload_page = client.get("/upload", headers=admin)
        assert 'action="/upload/findings/preview"' in upload_page.text
        assert 'input type="file" name="file"' in upload_page.text
        assert "파일 분석하고 미리보기" in upload_page.text

        csv_content = (
            "finding_id,product,cve_id,asset_name,cvss,status,notes\n"
            "SRV-E2E-1,Server E2E,CVE-2099-7777,Server Rendered Asset,9.2,OPEN,HTTP contract\n"
        ).encode()
        preview = client.post(
            "/upload/findings/preview",
            headers=admin,
            data={
                "csrf_token": token,
                "scanner_source": "server-e2e",
                "format_hint": "auto",
                "import_mode": "incremental",
            },
            files={"file": ("server-e2e.csv", csv_content, "text/csv")},
        )
        assert preview.status_code == 200
        assert "반영 전에 결과를 확인하세요." in preview.text
        match = re.search(r'name="token" value="([A-Za-z0-9_-]+)"', preview.text)
        assert match
        assert "1건 목록에 반영" in preview.text

        applied = client.post(
            "/upload/findings/apply",
            headers=admin,
            data={
                "csrf_token": token,
                "token": match.group(1),
                "scanner_source": "server-e2e",
                "import_mode": "incremental",
            },
            follow_redirects=False,
        )
        assert applied.status_code == 303
        search = client.get("/?query=CVE-2099-7777", headers=admin)
        assert search.status_code == 200
        assert "CVE-2099-7777" in search.text
        assert "Server Rendered Asset" in search.text


def test_operator_request_and_approver_decision_preserve_role_separation(tmp_path: Path, monkeypatch):
    with _client(tmp_path, monkeypatch) as client:
        operator = _headers("operator")
        token = _csrf(client, operator, "/finding/F-0004")
        current = client.get("/api/v1/findings/F-0004", headers=operator).json()
        requested = client.post(
            "/finding/F-0004",
            headers=operator,
            data={
                "csrf_token": token,
                "status": "RISK_ACCEPTED",
                "owner": "server-e2e-operator",
                "due_date": "",
                "exception_expiry": "2099-12-31",
                "risk_acceptance_reason": "server-rendered role separation",
                "risk_acceptance_approver": "",
                "notes": "pending browser-equivalent approval",
                "row_version": str(current["row_version"]),
            },
            follow_redirects=False,
        )
        assert requested.status_code == 303
        assert "approval_requested" in requested.headers["location"]
        pending = client.get("/api/v1/approvals?status=PENDING", headers=operator).json()["items"]
        assert len(pending) == 1
        request_id = pending[0]["request_id"]

        approver = _headers("approver")
        approvals_page = client.get("/approvals?status=PENDING", headers=approver)
        assert approvals_page.status_code == 200
        assert f'action="/approvals/{request_id}/decision"' in approvals_page.text
        assert 'textarea name="decision_note"' in approvals_page.text
        assert 'value="APPROVED"' in approvals_page.text

        approve_token = client.cookies.get(main.CSRF_COOKIE)
        decided = client.post(
            f"/approvals/{request_id}/decision",
            headers=approver,
            data={
                "csrf_token": approve_token,
                "decision": "APPROVED",
                "decision_note": "server-rendered approval",
            },
            follow_redirects=False,
        )
        assert decided.status_code == 303
        saved = client.get("/api/v1/findings/F-0004", headers=approver).json()
        assert saved["status"] == "RISK_ACCEPTED"
        assert saved["risk_acceptance_approver"] == "api:approver"
