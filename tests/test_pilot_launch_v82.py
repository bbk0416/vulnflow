from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import app.main as main
from app.core.database_schema import CURRENT_SCHEMA_VERSION, init_db
from app.repositories.pilot import get_pilot_profile, save_pilot_profile
from app.services.accounts import create_user
from app.services.pilot_readiness import build_pilot_readiness
from app.services.projects import create_project

PASSWORD = "Correct-Horse-42!"


def _settings(tmp_path: Path, db: Path) -> dict:
    default_root = tmp_path / "runtime-projects" / "default"
    return {
        "DATA_DIR": tmp_path / "runtime-data",
        "LEGACY_DB_PATH": db,
        "CONTROL_DB_PATH": tmp_path / "runtime-control.db",
        "DEFAULT_PROJECT_ROOT": default_root,
        "DEFAULT_PROJECT_DB_PATH": default_root / "vulnflow.db",
        "DB_PATH": default_root / "vulnflow.db",
        "EVIDENCE_DIR": default_root / "evidence",
        "EXPORT_DIR": default_root / "exports",
        "RECOVERY_DIR": default_root / "backups" / "recovery",
        "LEGACY_EVIDENCE_DIR": tmp_path / "evidence",
        "LEGACY_EXPORT_DIR": tmp_path / "exports",
        "LEGACY_IMPORT_PREVIEW_DIR": tmp_path / "previews",
        "LEGACY_RECOVERY_DIR": tmp_path / "recovery",
        "IMPORT_PREVIEW_DIR": default_root / "import-previews",
        "PROJECTS_DIR": tmp_path / "projects",
        "AUTH_USERS_JSON": "",
        "AUTH_API_TOKENS_JSON": "",
        "AUTH_USER": "",
        "AUTH_PASSWORD": "",
        "AUTH_SESSION_COOKIE": "vulnflow_session",
        "AUTH_SESSION_MINUTES": 60,
        "AUTH_MAX_ACTIVE_SESSIONS": 10,
        "AUTH_LOCK_THRESHOLD": 5,
        "AUTH_LOCK_MINUTES": 15,
        "COOKIE_SECURE": False,
        "DEMO_MODE": False,
        "ALLOW_LOCAL_ADMIN_FALLBACK": False,
        "JOB_WORKER_ENABLED": False,
        "CLUSTER_COORDINATION_ENABLED": False,
        "PUBLIC_BASE_URL": "",
    }


def _login(client: TestClient) -> str:
    assert client.get("/login").status_code == 200
    csrf = str(client.cookies.get("vulnflow_csrf"))
    response = client.post(
        "/login",
        data={"username": "admin", "password": PASSWORD, "csrf_token": csrf, "next": "/"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    return str(client.cookies.get("vulnflow_csrf"))


def test_pilot_profile_validation_persistence_and_audit(tmp_path: Path):
    db = tmp_path / "vulnflow.db"
    init_db(db)
    with pytest.raises(ValueError, match="고객사"):
        save_pilot_profile(db, customer_name="", engagement_name="진단", actor="admin")
    with pytest.raises(ValueError, match="이메일"):
        save_pilot_profile(
            db, customer_name="A사", engagement_name="진단", contact_email="broken", actor="admin"
        )
    profile = save_pilot_profile(
        db,
        customer_name="A사",
        engagement_name="2026 정기 진단",
        contact_name="홍길동",
        contact_email="security@example.com",
        scope_notes="외부 공개 서비스",
        default_due_days=14,
        report_footer="대외비",
        actor="admin",
    )
    assert profile["customer_name"] == "A사"
    assert profile["default_due_days"] == 14
    assert get_pilot_profile(db)["report_footer"] == "대외비"
    with sqlite3.connect(db) as conn:
        assert conn.execute(
            "SELECT COUNT(*) FROM audit_events WHERE event_type='PILOT_PROFILE_UPDATED'"
        ).fetchone()[0] == 1


def test_pilot_readiness_separates_required_and_recommended():
    readiness = build_pilot_readiness(
        profile={"customer_name": "A사", "engagement_name": "파일럿"},
        finding_count=0,
        import_count=0,
        member_count=1,
        integrity_status="HEALTHY",
        backup_count=1,
        recovery_drill_passed=False,
        integrations=[],
        cookie_secure=False,
        public_base_url="http://127.0.0.1:8000",
    )
    assert readiness["launch_ready"] is False
    assert readiness["required_passed"] == 4
    assert readiness["required_total"] == 5
    assert readiness["recommended_passed"] == 0
    assert {item["key"] for item in readiness["checks"] if not item["passed"]} == {
        "scanner_data", "recovery_drill", "collaboration", "transport"
    }
    assert next(item for item in readiness["checks"] if item["key"] == "scanner_data")["required"] is True


def test_pilot_ui_profile_api_and_executive_report(tmp_path: Path):
    db = tmp_path / "vulnflow.db"
    init_db(db)
    create_user(db, username="admin", password=PASSWORD, role="admin", actor="test")
    app = main.create_app(setting_overrides=_settings(tmp_path, db))
    with TestClient(app) as client:
        csrf = _login(client)
        page = client.get("/pilot")
        assert page.status_code == 200
        assert "파일럿 시작 센터" in page.text
        saved = client.post(
            "/pilot/profile",
            data={
                "customer_name": "A사",
                "engagement_name": "2026 상반기 파일럿",
                "contact_name": "홍길동",
                "contact_email": "security@example.com",
                "scope_notes": "인터넷 서비스 10대",
                "default_due_days": "21",
                "report_footer": "대외비",
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )
        assert saved.status_code == 303
        api = client.get("/api/v1/pilot-readiness")
        assert api.status_code == 200
        payload = api.json()
        assert payload["profile"]["customer_name"] == "A사"
        report = client.get("/export/executive-report.html")
        assert report.status_code == 200
        assert "A사" in report.text
        assert "2026 상반기 파일럿" in report.text
        assert "대외비" in report.text
        assert report.headers["cache-control"] == "no-store"


def test_pilot_profile_is_isolated_per_project(tmp_path: Path):
    db = tmp_path / "vulnflow.db"
    init_db(db)
    create_user(db, username="admin", password=PASSWORD, role="admin", actor="test")
    project = create_project(
        db,
        name="B사 파일럿",
        actor="admin",
        projects_dir=tmp_path / "projects",
        default_database_path=db,
        default_evidence_dir=tmp_path / "evidence",
        default_export_dir=tmp_path / "exports",
        default_import_preview_dir=tmp_path / "previews",
        default_recovery_dir=tmp_path / "recovery",
        init_db_fn=init_db,
    )
    child_db = Path(project["database"])
    save_pilot_profile(db, customer_name="A사", engagement_name="기본", actor="admin")
    save_pilot_profile(child_db, customer_name="B사", engagement_name="분리", actor="admin")
    assert get_pilot_profile(db)["customer_name"] == "A사"
    assert get_pilot_profile(child_db)["customer_name"] == "B사"


def test_schema43_upgrade_adds_pilot_profile(tmp_path: Path):
    db = tmp_path / "vulnflow.db"
    init_db(db)
    with sqlite3.connect(db) as conn:
        conn.execute("DROP TABLE pilot_project_profile")
        conn.execute("DELETE FROM schema_migrations WHERE version=44")
        conn.execute("PRAGMA user_version=43")
        conn.commit()
    init_db(db)
    with sqlite3.connect(db) as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == CURRENT_SCHEMA_VERSION == 46
        assert conn.execute(
            "SELECT COUNT(*) FROM schema_migrations WHERE version=44"
        ).fetchone()[0] == 1
        assert conn.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='pilot_project_profile'"
        ).fetchone()[0] == 1
