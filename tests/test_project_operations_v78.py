from __future__ import annotations

import sqlite3
import time
from pathlib import Path

from fastapi.testclient import TestClient

import app.main as main
from app.core.database_schema import init_db
from app.core.storage import create_background_job, get_background_job, list_background_jobs
from app.repositories.audit import add_audit_event
from app.repositories.webhook_queue import enqueue_webhook_events
from app.services.accounts import create_user
from app.services.lifecycle_runtime import (
    schedule_all_project_backups,
    schedule_all_project_maintenance,
    schedule_all_project_webhooks,
)
from app.services.projects import create_project, project_selection

PASSWORD = "Correct-Horse-42!"


def _settings(tmp_path: Path, db: Path, *, worker: bool = False) -> dict:
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
        "JOB_WORKER_ENABLED": worker,
        "JOB_WORKER_INTERVAL_SECONDS": 1,
        "CLUSTER_COORDINATION_ENABLED": False,
        "BACKUP_INTERVAL_HOURS": 1,
        "BACKUP_RETENTION_COUNT": 3,
    }


def _project(tmp_path: Path, db: Path) -> tuple[dict, Path]:
    project = create_project(
        db,
        name="격리 운영 프로젝트",
        actor="admin",
        projects_dir=tmp_path / "projects",
        default_database_path=db,
        default_evidence_dir=tmp_path / "evidence",
        default_export_dir=tmp_path / "exports",
        default_import_preview_dir=tmp_path / "previews",
        default_recovery_dir=tmp_path / "recovery",
        init_db_fn=init_db,
    )
    return project, Path(project["database"])


def _selection(tmp_path: Path, db: Path, project_id: str):
    return project_selection(
        db,
        project_id,
        projects_dir=tmp_path / "projects",
        default_database_path=db,
        default_evidence_dir=tmp_path / "evidence",
        default_export_dir=tmp_path / "exports",
        default_import_preview_dir=tmp_path / "previews",
        default_recovery_dir=tmp_path / "recovery",
    )


def _tamper_audit(db: Path) -> None:
    add_audit_event(
        db,
        finding_id=None,
        event_type="TEST_EVENT",
        summary="original",
        details={"source": "test"},
        actor="test",
    )
    with sqlite3.connect(db) as conn:
        conn.execute("DROP TRIGGER audit_events_immutable")
        conn.execute("UPDATE audit_events SET summary='tampered' WHERE chain_seq=1")
        conn.commit()


def _login(client: TestClient) -> str:
    page = client.get("/login")
    assert page.status_code == 200
    csrf = client.cookies.get("vulnflow_csrf")
    response = client.post(
        "/login",
        data={"username": "admin", "password": PASSWORD, "csrf_token": csrf, "next": "/"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    return str(client.cookies.get("vulnflow_csrf"))


def test_damaged_child_project_is_isolated_without_blocking_default(tmp_path: Path):
    db = tmp_path / "vulnflow.db"
    init_db(db)
    create_user(db, username="admin", password=PASSWORD, role="admin", actor="test")
    project, child = _project(tmp_path, db)
    with sqlite3.connect(child) as conn:
        conn.execute("PRAGMA user_version=42")
        conn.execute("DELETE FROM schema_migrations WHERE version=43")
        conn.commit()
    _tamper_audit(child)

    application = main.create_app(setting_overrides=_settings(tmp_path, db))
    with TestClient(application) as client:
        csrf = _login(client)
        context = application.state.vulnflow_context
        modes = context.get("PROJECT_RECOVERY_MODES")
        assert modes["default"]["active"] is False
        assert modes[project["project_id"]]["active"] is True
        with sqlite3.connect(child) as conn:
            assert conn.execute("PRAGMA user_version").fetchone()[0] == 46
            assert conn.execute(
                "SELECT COUNT(*) FROM schema_migrations WHERE version=43"
            ).fetchone()[0] == 1

        default_write = client.post("/rescore", data={"csrf_token": csrf}, follow_redirects=False)
        assert default_write.status_code == 303

        switched = client.post(
            "/projects/switch",
            data={"project_id": project["project_id"], "csrf_token": csrf},
            follow_redirects=False,
        )
        assert switched.status_code == 303
        degraded = client.get("/health")
        assert degraded.status_code == 200
        assert degraded.json()["status"] == "degraded"
        blocked = client.post("/rescore", data={"csrf_token": csrf}, follow_redirects=False)
        assert blocked.status_code == 503
        assert blocked.headers["x-vulnflow-recovery-mode"] == "active"

        escaped = client.post(
            "/projects/switch",
            data={"project_id": "default", "csrf_token": csrf},
            follow_redirects=False,
        )
        assert escaped.status_code == 303


def test_backup_scheduler_fans_out_and_skips_read_only_project(tmp_path: Path):
    db = tmp_path / "vulnflow.db"
    init_db(db)
    create_user(db, username="admin", password=PASSWORD, role="admin", actor="test")
    project, child = _project(tmp_path, db)
    application = main.create_app(setting_overrides=_settings(tmp_path, db))

    with TestClient(application):
        context = application.state.vulnflow_context
        runtime_default = Path(context.get("DEFAULT_PROJECT_DB_PATH"))
        first = schedule_all_project_backups(context, now=3600)
        assert {item["project_id"] for item in first["scheduled"]} == {
            "default",
            project["project_id"],
        }
        maintenance = schedule_all_project_maintenance(context, now=3600)
        assert {item["project_id"] for item in maintenance["scheduled"]} == {
            "default",
            project["project_id"],
        }
        enqueue_webhook_events(
            runtime_default, endpoint_names=["ops"], event_type="test", payload={"project": "default"}
        )
        enqueue_webhook_events(
            child, endpoint_names=["ops"], event_type="test", payload={"project": "child"}
        )
        webhooks = schedule_all_project_webhooks(context, now=3600)
        assert {item["project_id"] for item in webhooks["scheduled"]} == {
            "default",
            project["project_id"],
        }
        assert {job["job_type"] for job in list_background_jobs(runtime_default)} == {
            "RECOVERY_BACKUP",
            "MAINTENANCE",
            "WEBHOOK_DELIVERY",
        }
        assert {job["job_type"] for job in list_background_jobs(child)} == {
            "RECOVERY_BACKUP",
            "MAINTENANCE",
            "WEBHOOK_DELIVERY",
        }

        modes = dict(context.get("PROJECT_RECOVERY_MODES"))
        modes[project["project_id"]] = {
            **modes[project["project_id"]],
            "active": True,
            "read_only": True,
            "status": "READ_ONLY",
            "reasons": ["test isolation"],
        }
        context.set("PROJECT_RECOVERY_MODES", modes)
        second = schedule_all_project_backups(context, now=7200)
        assert [item["project_id"] for item in second["scheduled"]] == ["default"]
        assert second["skipped"] == [project["project_id"]]


def test_worker_leaves_degraded_project_job_queued(tmp_path: Path):
    db = tmp_path / "vulnflow.db"
    init_db(db)
    create_user(db, username="admin", password=PASSWORD, role="admin", actor="test")
    project, child = _project(tmp_path, db)
    default_job = create_background_job(db, job_type="RESCORE_ALL", requested_by="test")
    child_job = create_background_job(child, job_type="RESCORE_ALL", requested_by="test")
    _tamper_audit(child)

    application = main.create_app(setting_overrides=_settings(tmp_path, db, worker=True))
    with TestClient(application):
        runtime_default = Path(application.state.vulnflow_context.get("DEFAULT_PROJECT_DB_PATH"))
        deadline = time.time() + 6
        current_default = default_job
        while time.time() < deadline:
            current_default = get_background_job(runtime_default, default_job["job_id"]) or {}
            if current_default.get("status") == "SUCCEEDED":
                break
            time.sleep(0.1)
        current_child = get_background_job(child, child_job["job_id"]) or {}
    assert current_default.get("status") == "SUCCEEDED"
    assert current_child.get("status") == "PENDING"


def test_admin_can_recheck_and_queue_project_backup(tmp_path: Path):
    db = tmp_path / "vulnflow.db"
    init_db(db)
    create_user(db, username="admin", password=PASSWORD, role="admin", actor="test")
    project, child = _project(tmp_path, db)
    selection = _selection(tmp_path, db, project["project_id"])
    application = main.create_app(setting_overrides=_settings(tmp_path, db, worker=True))

    with TestClient(application) as client:
        csrf = _login(client)
        with sqlite3.connect(child) as conn:
            conn.execute("PRAGMA user_version=42")
            conn.execute("DELETE FROM schema_migrations WHERE version=43")
            conn.commit()
        checked = client.post(
            "/admin/projects/integrity-check",
            data={"project_id": project["project_id"], "csrf_token": csrf},
            follow_redirects=False,
        )
        assert checked.status_code == 303
        assert "notice=integrity_ok" in checked.headers["location"]
        with sqlite3.connect(child) as conn:
            assert conn.execute("PRAGMA user_version").fetchone()[0] == 46

        queued = client.post(
            "/admin/projects/backup",
            data={"project_id": project["project_id"], "csrf_token": csrf},
            follow_redirects=False,
        )
        assert queued.status_code == 303
        assert "notice=backup_queued" in queued.headers["location"]

        deadline = time.time() + 10
        bundles: list[Path] = []
        while time.time() < deadline:
            bundles = list(selection.recovery.glob("vulnflow_recovery_*.zip"))
            if bundles:
                break
            time.sleep(0.1)
        page = client.get(f"/projects?selected={project['project_id']}")
        assert page.status_code == 200
        assert "무결성 상태" in page.text
        assert "최근 복구 번들" in page.text
    assert len(bundles) == 1
    assert bundles[0].stat().st_size > 0
    assert get_background_job(child, list_background_jobs(child)[0]["job_id"])["status"] == "SUCCEEDED"


def test_integrity_recheck_restarts_lifecycle_after_all_projects_were_read_only(tmp_path: Path):
    db = tmp_path / "vulnflow.db"
    init_db(db)
    create_user(db, username="admin", password=PASSWORD, role="admin", actor="test")
    state = {"healthy": False}

    def audit_result(*_args, **_kwargs):
        if state["healthy"]:
            return {"valid": True, "issues": [], "last_seq": 0, "checkpoints": []}
        return {
            "valid": False,
            "issues": ["temporary audit verification failure"],
            "last_seq": 0,
            "checkpoints": [],
        }

    application = main.create_app(
        setting_overrides=_settings(tmp_path, db),
        service_overrides={"verify_audit_integrity": audit_result},
    )
    with TestClient(application) as client:
        context = application.state.vulnflow_context
        supervisor = context.get("LIFECYCLE_SUPERVISOR")
        assert supervisor.snapshot()["state"] == "NEW"
        csrf = _login(client)

        state["healthy"] = True
        checked = client.post(
            "/admin/projects/integrity-check",
            data={"project_id": "default", "csrf_token": csrf},
            follow_redirects=False,
        )
        assert checked.status_code == 303
        assert "notice=integrity_ok" in checked.headers["location"]
        assert context.get("PROJECT_RECOVERY_MODES")["default"]["active"] is False
        assert supervisor.snapshot()["state"] == "RUNNING"
