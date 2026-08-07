from pathlib import Path

import pytest

from fastapi.testclient import TestClient
import app.main as main


def csrf(client: TestClient) -> str:
    response = client.get("/")
    assert response.status_code == 200
    return client.cookies.get(main.CSRF_COOKIE)


def test_security_headers_and_health(client: TestClient):
    response = client.get("/")
    assert response.headers["x-frame-options"] == "DENY"
    assert "default-src 'self'" in response.headers["content-security-policy"]
    health = client.get("/health")
    assert health.status_code == 200 and health.json()["database"] == "ready"
    assert "finding_count" not in health.json()


def test_post_requires_csrf(client: TestClient):
    response = client.post("/rescore", data={"csrf_token": "wrong"})
    assert response.status_code == 403


def test_dashboard_filter_and_api(client: TestClient):
    response = client.get("/?status=OPEN&page_size=25")
    assert response.status_code == 200 and "검색 결과" in response.text
    api = client.get("/api/v1/findings?status=OPEN&limit=5")
    assert api.status_code == 200
    assert len(api.json()["items"]) <= 5


def test_workflow_requires_risk_acceptance_governance(client: TestClient):
    token = csrf(client)
    response = client.post(
        "/finding/F-0001",
        data={
            "csrf_token": token,
            "status": "RISK_ACCEPTED",
            "owner": "owner",
            "due_date": "",
            "exception_expiry": "",
            "risk_acceptance_reason": "",
            "risk_acceptance_approver": "",
            "notes": "",
        },
    )
    assert response.status_code == 400


def test_workflow_update_and_audit(client: TestClient):
    token = csrf(client)
    response = client.post(
        "/finding/F-0001",
        data={
            "csrf_token": token,
            "status": "IN_PROGRESS",
            "owner": "owner",
            "due_date": "2026-08-01",
            "exception_expiry": "",
            "risk_acceptance_reason": "",
            "risk_acceptance_approver": "",
            "notes": "triage started",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    detail = client.get("/finding/F-0001")
    assert "triage started" in detail.text and "워크플로 변경" in detail.text


def test_csv_upload_validation_and_export(client: TestClient):
    token = csrf(client)
    bad = client.post(
        "/upload/findings",
        data={"csrf_token": token},
        files={"file": ("bad.csv", b"product,cve_id\nDemo,NOT-CVE\n", "text/csv")},
    )
    assert bad.status_code == 400
    exported = client.get("/export/findings.csv")
    assert exported.status_code == 200 and exported.content.startswith(b"\xef\xbb\xbf")


def test_backup_and_reset(client: TestClient):
    backup = client.get("/export/backup.sqlite3")
    assert backup.status_code == 200 and backup.content.startswith(b"SQLite format 3")
    token = csrf(client)
    bad = client.post("/reset-demo", data={"csrf_token": token, "confirmation": "NO"})
    assert bad.status_code == 400
    ok = client.post("/reset-demo", data={"csrf_token": token, "confirmation": "RESET"}, follow_redirects=False)
    assert ok.status_code == 303


def test_plaintext_basic_auth_configuration_is_rejected(tmp_path: Path):
    application = main.create_app(
        setting_overrides={
            "DB_PATH": tmp_path / "auth.db",
            "EVIDENCE_DIR": tmp_path / "evidence",
            "EXPORT_DIR": tmp_path / "exports",
            "RECOVERY_DIR": tmp_path / "recovery",
            "AUTH_USERS_JSON": "",
            "AUTH_API_TOKENS_JSON": "",
            "AUTH_USER": "demo",
            "AUTH_PASSWORD": "secret",
            "DEMO_MODE": False,
            "ALLOW_LOCAL_ADMIN_FALLBACK": False,
            "JOB_WORKER_ENABLED": False,
            "CLUSTER_COORDINATION_ENABLED": False,
        }
    )
    with pytest.raises(RuntimeError, match="평문 환경변수 사용자 인증은 제거"):
        with TestClient(application):
            pass


def test_sbom_compare_route(client: TestClient):
    token = csrf(client)
    before = (main.DATA_DIR / "sample_sbom.cdx.json").read_bytes()
    after = (main.DATA_DIR / "sample_sbom_v2.cdx.json").read_bytes()
    response = client.post(
        "/upload/sbom-compare",
        data={"csrf_token": token},
        files={
            "before_file": ("before.cdx.json", before, "application/json"),
            "after_file": ("after.cdx.json", after, "application/json"),
        },
    )
    assert response.status_code == 200 and "추가 구성요소" in response.text


def test_valid_risk_acceptance_and_exception_filter(client: TestClient):
    token = csrf(client)
    response = client.post(
        "/finding/F-0001",
        data={
            "csrf_token": token,
            "status": "RISK_ACCEPTED",
            "owner": "owner",
            "due_date": "",
            "exception_expiry": "2026-12-31",
            "risk_acceptance_reason": "temporary business constraint",
            "risk_acceptance_approver": "CISO",
            "notes": "accepted with monitoring",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    filtered = client.get("/api/v1/findings?exception=active")
    assert any(item["finding_id"] == "F-0001" for item in filtered.json()["items"])


def test_reimport_without_workflow_columns_preserves_workflow(client: TestClient):
    token = csrf(client)
    update = client.post(
        "/finding/F-0001",
        data={
            "csrf_token": token,
            "status": "IN_PROGRESS",
            "owner": "workflow-owner",
            "due_date": "2026-08-10",
            "exception_expiry": "",
            "risk_acceptance_reason": "",
            "risk_acceptance_approver": "",
            "notes": "preserve me",
        },
        follow_redirects=False,
    )
    assert update.status_code == 303
    csv_bytes = b"finding_id,product,cve_id,cvss\nF-0001,EdgeConnect Gateway,CVE-2024-3400,9.5\n"
    uploaded = client.post(
        "/upload/findings",
        data={"csrf_token": token},
        files={"file": ("refresh.csv", csv_bytes, "text/csv")},
        follow_redirects=False,
    )
    assert uploaded.status_code == 303
    item = client.get("/api/v1/findings?query=F-0001").json()["items"][0]
    assert item["status"] == "IN_PROGRESS"
    assert item["owner"] == "workflow-owner"
    assert item["notes"] == "preserve me"
    assert item["cvss"] == 9.5


def test_intel_refresh_supports_partial_success(client: TestClient, monkeypatch):
    token = csrf(client)
    monkeypatch.setattr(main, "fetch_kev_catalog", lambda: {"CVE-2024-3400"})
    def fail_epss(_):
        raise main.IntelligenceError("offline")
    monkeypatch.setattr(main, "fetch_epss", fail_epss)
    response = client.post("/refresh-intel", data={"csrf_token": token}, follow_redirects=False)
    assert response.status_code == 303
    assert "intel_partial" in response.headers["location"]
    item = client.get("/api/v1/findings?query=F-0001").json()["items"][0]
    assert item["kev"] == 1
    assert item["intel_source"] == "CISA KEV"
