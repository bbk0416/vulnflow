from __future__ import annotations

import json
import os
import stat
import time
from pathlib import Path

from fastapi.testclient import TestClient

import app.main as main
from app.core.database_schema import CURRENT_SCHEMA_VERSION, init_db
from app.core.storage import create_background_job, get_background_job
from app.repositories.audit import list_audit_events
from app.repositories.finding_ingestion import upsert_findings
from app.services.accounts import create_user
from app.services.projects import create_project, project_selection
from app.services.recovery import create_scheduled_recovery_bundle
from app.services.recovery_operations import (
    list_external_recovery_bundles,
    list_recovery_drills,
    mirror_recovery_bundle,
    resolve_stored_recovery_bundle,
    run_recovery_drill,
)

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
        "EXTERNAL_BACKUP_DIR": tmp_path / "external-backups",
        "EXTERNAL_BACKUP_RETENTION_COUNT": 5,
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
        "BACKUP_INTERVAL_HOURS": 0,
        "BACKUP_RETENTION_COUNT": 3,
        "BACKUP_REQUIRE_SIGNATURE": False,
    }


def _finding() -> dict:
    return {
        "finding_id": "DRILL-FINDING",
        "product": "Recovery Demo",
        "cve_id": "CVE-2026-79001",
        "cvss": 9.1,
        "status": "OPEN",
        "record_state": "ACTIVE",
        "scanner_source": "test",
    }


def _project(tmp_path: Path, db: Path):
    created = create_project(
        db,
        name="복구 리허설 프로젝트",
        actor="admin",
        projects_dir=tmp_path / "projects",
        default_database_path=db,
        default_evidence_dir=tmp_path / "evidence",
        default_export_dir=tmp_path / "exports",
        default_import_preview_dir=tmp_path / "previews",
        default_recovery_dir=tmp_path / "recovery",
        init_db_fn=init_db,
    )
    selection = project_selection(
        db,
        created["project_id"],
        projects_dir=tmp_path / "projects",
        default_database_path=db,
        default_evidence_dir=tmp_path / "evidence",
        default_export_dir=tmp_path / "exports",
        default_import_preview_dir=tmp_path / "previews",
        default_recovery_dir=tmp_path / "recovery",
    )
    return created, selection


def _bundle(
    db: Path, recovery: Path, evidence: Path, *, project_id: str = "default", project_name: str = ""
) -> dict:
    return create_scheduled_recovery_bundle(
        db,
        recovery,
        signing_key="",
        retention_count=10,
        actor="test",
        evidence_dir=evidence,
        project_id=project_id,
        project_name=project_name,
    )


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


def test_external_backup_copy_is_atomic_verified_and_pruned(tmp_path: Path):
    db = tmp_path / "vulnflow.db"
    init_db(db)
    upsert_findings(db, [_finding()], actor="test")
    recovery = tmp_path / "recovery"
    evidence = tmp_path / "evidence"
    external = tmp_path / "mounted-backup"

    created = []
    for _index in range(3):
        result = _bundle(db, recovery, evidence)
        source = Path(result["bundle_path"])
        mirrored = mirror_recovery_bundle(
            source,
            external_root=external,
            project_id="default",
            retention_count=2,
        )
        assert mirrored["copied"] is True
        assert Path(mirrored["bundle_path"]).is_file()
        assert Path(mirrored["bundle_path"] + ".sha256").is_file()
        created.append(source.name)
        time.sleep(0.01)

    items = list_external_recovery_bundles(external, project_id="default")
    assert len(items) == 2
    assert {item["filename"] for item in items} == set(created[-2:])
    assert not list((external / "default").glob("*.partial"))
    if os.name != "nt":
        project_mode = stat.S_IMODE((external / "default").stat().st_mode)
        assert project_mode == 0o700
        for item in items:
            bundle_path = external / "default" / item["filename"]
            assert stat.S_IMODE(bundle_path.stat().st_mode) == 0o600
            sidecar = bundle_path.with_suffix(bundle_path.suffix + ".sha256")
            assert stat.S_IMODE(sidecar.stat().st_mode) == 0o600


def test_recovery_drill_restores_and_rechecks_without_touching_live_db(tmp_path: Path):
    db = tmp_path / "vulnflow.db"
    init_db(db)
    upsert_findings(db, [_finding()], actor="test")
    recovery = tmp_path / "recovery"
    evidence = tmp_path / "evidence"
    result = _bundle(db, recovery, evidence)
    live_before = db.read_bytes()

    report = run_recovery_drill(
        result["bundle_path"],
        report_dir=recovery / "drills",
        actor="admin",
        project_id="default",
        current_schema_version=CURRENT_SCHEMA_VERSION,
    )

    assert report["status"] == "PASSED"
    assert report["database"]["finding_count"] == 1
    assert report["audit_integrity"]["valid"] is True
    assert report["evidence_integrity"]["valid"] is True
    assert db.read_bytes() == live_before
    if os.name != "nt":
        report_path = Path(report["report_path"])
        assert stat.S_IMODE(report_path.parent.stat().st_mode) == 0o700
        assert stat.S_IMODE(report_path.stat().st_mode) == 0o600
    drills = list_recovery_drills(recovery / "drills")
    assert drills[0]["status"] == "PASSED"
    assert drills[0]["bundle_filename"] == Path(result["bundle_path"]).name


def test_external_bundle_tampering_is_rejected_before_drill(tmp_path: Path):
    db = tmp_path / "vulnflow.db"
    init_db(db)
    result = _bundle(db, tmp_path / "recovery", tmp_path / "evidence")
    mirrored = mirror_recovery_bundle(
        result["bundle_path"],
        external_root=tmp_path / "external",
        project_id="default",
        retention_count=3,
    )
    external_file = Path(mirrored["bundle_path"])
    external_file.write_bytes(external_file.read_bytes() + b"tampered")

    try:
        resolve_stored_recovery_bundle(
            recovery_dir=tmp_path / "recovery",
            external_root=tmp_path / "external",
            project_id="default",
            location="external",
            filename=external_file.name,
        )
    except ValueError as exc:
        assert "SHA-256 검증" in str(exc)
    else:
        raise AssertionError("tampered external bundle must be rejected")


def test_failed_recovery_drill_persists_failure_report(tmp_path: Path):
    recovery = tmp_path / "recovery"
    recovery.mkdir(parents=True)
    broken = recovery / "vulnflow_recovery_20260802T010203000000Z.zip"
    broken.write_bytes(b"not-a-zip")

    try:
        run_recovery_drill(
            broken,
            report_dir=recovery / "drills",
            actor="admin",
            project_id="default",
            current_schema_version=CURRENT_SCHEMA_VERSION,
        )
    except ValueError as exc:
        assert "복구 리허설 실패" in str(exc)
    else:
        raise AssertionError("broken recovery bundle must fail")

    drills = list_recovery_drills(recovery / "drills")
    assert drills[0]["status"] == "FAILED"
    assert drills[0]["error_type"] in {"BadZipFile", "ValueError"}


def test_project_recovery_drill_route_accepts_external_copy(tmp_path: Path):
    db = tmp_path / "vulnflow.db"
    init_db(db)
    create_user(db, username="admin", password=PASSWORD, role="admin", actor="test")
    project, selection = _project(tmp_path, db)
    upsert_findings(selection.database, [_finding()], actor="test")
    bundle = _bundle(
        selection.database,
        selection.recovery,
        selection.evidence,
        project_id=project["project_id"],
        project_name=project["name"],
    )
    mirrored = mirror_recovery_bundle(
        bundle["bundle_path"],
        external_root=tmp_path / "external-backups",
        project_id=project["project_id"],
        retention_count=5,
    )

    application = main.create_app(setting_overrides=_settings(tmp_path, db))
    with TestClient(application) as client:
        csrf = _login(client)
        response = client.post(
            "/admin/projects/recovery-drill",
            data={
                "project_id": project["project_id"],
                "location": "external",
                "filename": mirrored["filename"],
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )
        assert response.status_code == 303
        assert "notice=drill_ok" in response.headers["location"]
        page = client.get(f"/projects?selected={project['project_id']}")
        assert page.status_code == 200
        assert "최근 복구 리허설" in page.text
        assert "성공" in page.text
        runtime_control = Path(application.state.vulnflow_context.get("CONTROL_DB_PATH"))

    events = list_audit_events(runtime_control, limit=100)
    assert any(event["event_type"] == "PROJECT_RECOVERY_DRILL_COMPLETED" for event in events)


def test_child_project_backup_job_mirrors_to_project_external_directory(tmp_path: Path):
    db = tmp_path / "vulnflow.db"
    init_db(db)
    create_user(db, username="admin", password=PASSWORD, role="admin", actor="test")
    project, selection = _project(tmp_path, db)
    upsert_findings(selection.database, [_finding()], actor="test")
    job = create_background_job(
        selection.database,
        job_type="RECOVERY_BACKUP",
        requested_by="admin",
    )
    application = main.create_app(setting_overrides=_settings(tmp_path, db, worker=True))

    with TestClient(application):
        deadline = time.time() + 8
        current = job
        while time.time() < deadline:
            current = get_background_job(selection.database, job["job_id"]) or {}
            if current.get("status") in {"SUCCEEDED", "FAILED"}:
                break
            time.sleep(0.1)

    assert current.get("status") == "SUCCEEDED", json.dumps(current, ensure_ascii=False)
    external = tmp_path / "external-backups" / project["project_id"]
    bundles = list(external.glob("vulnflow_recovery_*.zip"))
    assert len(bundles) == 1
    assert bundles[0].with_suffix(bundles[0].suffix + ".sha256").is_file()
