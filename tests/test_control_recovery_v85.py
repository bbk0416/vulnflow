from __future__ import annotations

import sqlite3
from pathlib import Path
import zipfile

import pytest

from app.core.database_schema import CURRENT_SCHEMA_VERSION, init_db
from app.core.project_scope import ProjectScopedPath, ProjectSelection, project_scope
from app.services.accounts import (
    authenticate_session,
    authenticate_user_password,
    create_session,
    create_user,
    list_users,
)
from app.services.control_recovery import (
    CONTROL_DATABASE_FILENAME,
    create_control_recovery_bundle,
    restore_control_recovery_bundle,
    validate_control_recovery_bundle,
)
from app.services.database_identity import (
    CONTROL_DATABASE_ROLE,
    PROJECT_DATABASE_ROLE,
    set_database_identity,
)
from app.services.projects import create_project, list_projects

PASSWORD = "Correct-Horse-42!"


def _control(tmp_path: Path) -> tuple[Path, Path, Path]:
    control = tmp_path / "data" / "control.db"
    projects_dir = tmp_path / "data" / "projects"
    default_root = projects_dir / "default"
    default_db = default_root / "vulnflow.db"
    init_db(control)
    set_database_identity(
        control,
        database_role=CONTROL_DATABASE_ROLE,
        project_id="control",
        project_name="제어 DB",
    )
    init_db(default_db)
    set_database_identity(
        default_db,
        database_role=PROJECT_DATABASE_ROLE,
        project_id="default",
        project_name="기본 프로젝트",
    )
    create_user(control, username="admin", password=PASSWORD, role="admin", actor="test")
    return control, projects_dir, default_db


def _project(control: Path, projects_dir: Path, default_db: Path, name: str) -> dict:
    default_root = default_db.parent
    return create_project(
        control,
        name=name,
        actor="admin",
        projects_dir=projects_dir,
        default_database_path=default_db,
        default_evidence_dir=default_root / "evidence",
        default_export_dir=default_root / "exports",
        default_import_preview_dir=default_root / "import-previews",
        default_recovery_dir=default_root / "backups" / "recovery",
        init_db_fn=init_db,
    )


def test_control_bundle_excludes_sessions_and_login_attempts(tmp_path: Path):
    control, projects_dir, default_db = _control(tmp_path)
    _project(control, projects_dir, default_db, "Before Backup")
    create_session(control, username="admin")
    authenticate_user_password(
        control,
        username="admin",
        password="Wrong-Password-42!",
        client_key="198.51.100.5",
    )
    bundle = tmp_path / "control-recovery.zip"
    result = create_control_recovery_bundle(
        control, bundle, created_by="admin", signing_key="test-signing-key", signing_key_id="control-v1"
    )
    assert result["database"]["sessions_included"] is False
    validated = validate_control_recovery_bundle(
        bundle, signing_key="test-signing-key", require_signature=True
    )
    assert validated["valid"] is True
    assert validated["database"]["schema_version"] == CURRENT_SCHEMA_VERSION
    with zipfile.ZipFile(bundle) as archive:
        extracted = tmp_path / CONTROL_DATABASE_FILENAME
        extracted.write_bytes(archive.read(CONTROL_DATABASE_FILENAME))
    with sqlite3.connect(extracted) as conn:
        assert conn.execute("SELECT COUNT(*) FROM auth_sessions").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM auth_login_attempts").fetchone()[0] == 0


def test_control_restore_revokes_sessions_and_preserves_live_project_databases(tmp_path: Path):
    control, projects_dir, default_db = _control(tmp_path)
    before = _project(control, projects_dir, default_db, "Before Backup")
    bundle = tmp_path / "control-recovery.zip"
    create_control_recovery_bundle(control, bundle, created_by="admin")

    after = _project(control, projects_dir, default_db, "Created After Backup")
    create_user(control, username="temporary", password=PASSWORD, role="viewer", actor="admin")
    raw_session, _ = create_session(control, username="admin")
    assert authenticate_session(control, raw_session) is not None

    restored = restore_control_recovery_bundle(
        control,
        bundle,
        actor="offline-admin",
        projects_dir=projects_dir,
    )
    assert authenticate_session(control, raw_session) is None
    assert {item["username"] for item in list_users(control)} == {"admin"}
    project_ids = {item["project_id"] for item in list_projects(control, admin=True)}
    assert {"default", before["project_id"], after["project_id"]} <= project_ids
    assert restored["restore"]["preserved"]["projects"] >= 1
    assert Path(restored["restore"]["safety_backup"]).is_file()


def test_control_recovery_rejects_project_database_role(tmp_path: Path):
    control, _projects_dir, default_db = _control(tmp_path)
    with pytest.raises(ValueError, match="control 역할"):
        create_control_recovery_bundle(default_db, tmp_path / "bad.zip", created_by="admin")


def test_project_scoped_path_fails_closed_without_explicit_scope(tmp_path: Path):
    fallback = tmp_path / "default" / "vulnflow.db"
    scoped = ProjectScopedPath("database", fallback, require_scope=True)
    with pytest.raises(RuntimeError, match="프로젝트 범위 없이"):
        Path(scoped)
    selection = ProjectSelection(
        project_id="customer-a",
        name="Customer A",
        slug="customer-a",
        database=tmp_path / "customer-a" / "vulnflow.db",
        evidence=tmp_path / "customer-a" / "evidence",
        exports=tmp_path / "customer-a" / "exports",
        import_previews=tmp_path / "customer-a" / "previews",
        recovery=tmp_path / "customer-a" / "recovery",
    )
    with project_scope(selection):
        assert Path(scoped) == selection.database
