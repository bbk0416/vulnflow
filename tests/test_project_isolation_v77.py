from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

from fastapi.testclient import TestClient
import pytest

import app.main as main
from app.core.database_schema import CURRENT_SCHEMA_VERSION, init_db
from app.services.accounts import create_user
from app.services.projects import (
    create_project,
    get_project,
    list_projects,
    project_selection,
    set_project_membership,
)
from app.repositories.finding_ingestion import upsert_findings
from app.core.storage import create_background_job, get_background_job

PASSWORD = "Correct-Horse-42!"


def _settings(tmp_path: Path, db: Path, *, tokens: dict | None = None) -> dict:
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
        "IMPORT_PREVIEW_DIR": default_root / "import-previews",
        "PROJECTS_DIR": tmp_path / "projects",
        "LEGACY_EVIDENCE_DIR": tmp_path / "evidence",
        "LEGACY_EXPORT_DIR": tmp_path / "exports",
        "LEGACY_IMPORT_PREVIEW_DIR": tmp_path / "previews",
        "LEGACY_RECOVERY_DIR": tmp_path / "recovery",
        "AUTH_USERS_JSON": "",
        "AUTH_API_TOKENS_JSON": json.dumps(tokens or {}),
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
    }


def _finding(finding_id: str, cve_id: str) -> dict:
    return {
        "finding_id": finding_id,
        "product": "Demo Product",
        "cve_id": cve_id,
        "cvss": 9.1,
        "status": "OPEN",
        "record_state": "ACTIVE",
        "scanner_source": "test",
    }


def _login(client: TestClient, username: str = "admin") -> None:
    page = client.get("/login")
    assert page.status_code == 200
    csrf = client.cookies.get("vulnflow_csrf")
    response = client.post(
        "/login",
        data={"username": username, "password": PASSWORD, "csrf_token": csrf, "next": "/"},
        follow_redirects=False,
    )
    assert response.status_code == 303


def _create_isolated_project(tmp_path: Path, db: Path, *, actor: str = "admin") -> dict:
    return create_project(
        db,
        name="A사 2026 정기진단",
        actor=actor,
        projects_dir=tmp_path / "projects",
        default_database_path=db,
        default_evidence_dir=tmp_path / "evidence",
        default_export_dir=tmp_path / "exports",
        default_import_preview_dir=tmp_path / "previews",
        default_recovery_dir=tmp_path / "recovery",
        init_db_fn=init_db,
    )


def test_schema_42_backfills_default_project_and_memberships(tmp_path: Path):
    db = tmp_path / "vulnflow.db"
    init_db(db)
    create_user(db, username="admin", password=PASSWORD, role="admin", actor="test")
    with sqlite3.connect(db) as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == CURRENT_SCHEMA_VERSION == 46
        default = conn.execute(
            "SELECT project_id,name,is_default,status FROM projects WHERE is_default=1"
        ).fetchone()
        membership = conn.execute(
            "SELECT project_id,username FROM project_memberships WHERE username='admin'"
        ).fetchone()
    assert default == ("default", "기본 프로젝트", 1, "ACTIVE")
    assert membership == ("default", "admin")


def test_project_creation_uses_separate_database_and_storage(tmp_path: Path):
    db = tmp_path / "vulnflow.db"
    init_db(db)
    project = _create_isolated_project(tmp_path, db, actor="system")
    selection = project_selection(
        db,
        project["project_id"],
        projects_dir=tmp_path / "projects",
        default_database_path=db,
        default_evidence_dir=tmp_path / "evidence",
        default_export_dir=tmp_path / "exports",
        default_import_preview_dir=tmp_path / "previews",
        default_recovery_dir=tmp_path / "recovery",
    )
    assert selection.database != db
    assert selection.database.is_file()
    assert selection.evidence.is_dir()
    assert selection.exports.is_dir()
    assert selection.import_previews.is_dir()
    assert selection.recovery.is_dir()
    with sqlite3.connect(selection.database) as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == CURRENT_SCHEMA_VERSION
        assert conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 0


def test_browser_switch_physically_isolates_findings(tmp_path: Path):
    db = tmp_path / "vulnflow.db"
    init_db(db)
    create_user(db, username="admin", password=PASSWORD, role="admin", actor="test")
    project = _create_isolated_project(tmp_path, db)
    child = Path(project["database"])
    upsert_findings(db, [_finding("DEFAULT-FINDING", "CVE-2026-77001")], actor="test")
    upsert_findings(child, [_finding("CHILD-FINDING", "CVE-2026-77002")], actor="test")

    application = main.create_app(setting_overrides=_settings(tmp_path, db))
    with TestClient(application) as client:
        _login(client)
        default_response = client.get("/api/v1/findings")
        assert default_response.status_code == 200
        default_ids = {item["finding_id"] for item in default_response.json()["items"]}
        assert default_ids == {"DEFAULT-FINDING"}
        assert default_response.headers["X-VulnFlow-Project"] == "default"

        csrf = client.cookies.get("vulnflow_csrf")
        switched = client.post(
            "/projects/switch",
            data={"project_id": project["project_id"], "csrf_token": csrf},
            follow_redirects=False,
        )
        assert switched.status_code == 303
        child_response = client.get("/api/v1/findings")
        assert child_response.status_code == 200
        child_ids = {item["finding_id"] for item in child_response.json()["items"]}
        assert child_ids == {"CHILD-FINDING"}
        assert child_response.headers["X-VulnFlow-Project"] == project["project_id"]


def test_unassigned_browser_cookie_falls_back_to_accessible_project(tmp_path: Path):
    db = tmp_path / "vulnflow.db"
    init_db(db)
    create_user(db, username="operator", password=PASSWORD, role="operator", actor="test")
    project = _create_isolated_project(tmp_path, db, actor="system")
    assert get_project(db, project["project_id"])
    application = main.create_app(setting_overrides=_settings(tmp_path, db))
    with TestClient(application) as client:
        _login(client, "operator")
        client.cookies.set("vulnflow_project", project["project_id"], domain="testserver.local", path="/")
        response = client.get("/")
        assert response.status_code == 200
        assert response.headers["X-VulnFlow-Project"] == "default"
        assert "vulnflow_project=default" in response.headers.get("set-cookie", "")


def test_project_membership_grants_browser_access(tmp_path: Path):
    db = tmp_path / "vulnflow.db"
    init_db(db)
    create_user(db, username="operator", password=PASSWORD, role="operator", actor="test")
    project = _create_isolated_project(tmp_path, db, actor="system")
    set_project_membership(
        db,
        project_id=project["project_id"],
        username="operator",
        member=True,
        actor="admin",
    )
    rows = list_projects(db, username="operator")
    assert {item["project_id"] for item in rows} == {"default", project["project_id"]}


def test_bearer_project_scope_defaults_closed_and_can_be_explicit(tmp_path: Path):
    db = tmp_path / "vulnflow.db"
    init_db(db)
    project = _create_isolated_project(tmp_path, db, actor="system")
    token_default = "default-project-token-1234567890"
    token_all = "all-project-token-123456789012345"
    application = main.create_app(
        setting_overrides=_settings(
            tmp_path,
            db,
            tokens={
                "default-ci": {"token": token_default, "role": "viewer"},
                "all-ci": {"token": token_all, "role": "viewer", "projects": "*"},
            },
        )
    )
    with TestClient(application) as client:
        denied = client.get(
            "/api/v1/findings",
            headers={"Authorization": f"Bearer {token_default}", "X-VulnFlow-Project": project["project_id"]},
        )
        assert denied.status_code == 403
        allowed = client.get(
            "/api/v1/findings",
            headers={"Authorization": f"Bearer {token_all}", "X-VulnFlow-Project": project["project_id"]},
        )
        assert allowed.status_code == 200
        assert allowed.headers["X-VulnFlow-Project"] == project["project_id"]


def test_background_worker_processes_child_project_queue(tmp_path: Path):
    db = tmp_path / "vulnflow.db"
    init_db(db)
    create_user(db, username="admin", password=PASSWORD, role="admin", actor="test")
    project = _create_isolated_project(tmp_path, db, actor="admin")
    child = Path(project["database"])
    created = create_background_job(child, job_type="RESCORE_ALL", requested_by="test")
    settings = _settings(tmp_path, db)
    settings.update({"JOB_WORKER_ENABLED": True, "JOB_WORKER_INTERVAL_SECONDS": 1})
    application = main.create_app(setting_overrides=settings)
    with TestClient(application):
        deadline = time.time() + 6
        current = created
        while time.time() < deadline:
            current = get_background_job(child, created["job_id"]) or {}
            if current.get("status") == "SUCCEEDED":
                break
            time.sleep(0.1)
    assert current.get("status") == "SUCCEEDED"


def test_logout_clears_project_cookie(tmp_path: Path):
    db = tmp_path / "vulnflow.db"
    init_db(db)
    create_user(db, username="admin", password=PASSWORD, role="admin", actor="test")
    application = main.create_app(setting_overrides=_settings(tmp_path, db))
    with TestClient(application) as client:
        _login(client)
        client.cookies.set("vulnflow_project", "default", domain="testserver.local", path="/")
        csrf = client.cookies.get("vulnflow_csrf")
        response = client.post("/logout", data={"csrf_token": csrf}, follow_redirects=False)
        assert response.status_code == 303
        cookies = response.headers.get_list("set-cookie")
        assert any("vulnflow_session=" in value and "Max-Age=0" in value for value in cookies)
        assert any("vulnflow_project=" in value and "Max-Age=0" in value for value in cookies)


def test_schema_41_upgrade_creates_default_project_and_backfills_users(tmp_path: Path):
    db = tmp_path / "upgrade.db"
    init_db(db)
    create_user(db, username="operator", password=PASSWORD, role="operator", actor="test")
    with sqlite3.connect(db) as conn:
        conn.execute("DROP TABLE project_memberships")
        conn.execute("DROP TABLE projects")
        conn.execute("DELETE FROM schema_migrations WHERE version=42")
        conn.execute("PRAGMA user_version=41")
        conn.commit()
    init_db(db)
    with sqlite3.connect(db) as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == CURRENT_SCHEMA_VERSION
        assert conn.execute(
            "SELECT project_id FROM projects WHERE is_default=1"
        ).fetchone() == ("default",)
        assert conn.execute(
            "SELECT project_id,username FROM project_memberships WHERE username='operator'"
        ).fetchone() == ("default", "operator")


def test_admin_project_access_is_global_not_membership_toggle(tmp_path: Path):
    db = tmp_path / "vulnflow.db"
    init_db(db)
    create_user(db, username="admin", password=PASSWORD, role="admin", actor="test")
    project = _create_isolated_project(tmp_path, db, actor="admin")
    with pytest.raises(ValueError, match="모든 활성 프로젝트"):
        set_project_membership(
            db, project_id=project["project_id"], username="admin", member=False, actor="admin"
        )
