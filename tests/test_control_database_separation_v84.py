from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from app.core.database_schema import CURRENT_SCHEMA_VERSION, init_db
from app.repositories.finding_ingestion import upsert_findings
from app.repositories.findings import list_findings
from app.services.accounts import create_user, list_users
from app.services.projects import create_project, list_projects
from app.services.database_identity import get_database_identity
from app.services.database_lifecycle import validate_database_file
from app.services.recovery import (
    create_recovery_bundle,
    restore_recovery_bundle,
    validate_recovery_bundle,
)
from app.services.storage_layout import prepare_split_storage
from scripts.run_public_tests import _run_group

PASSWORD = "Correct-Horse-42!"


def _finding(finding_id: str, cve_id: str) -> dict:
    return {
        "finding_id": finding_id,
        "product": "Control Boundary Demo",
        "cve_id": cve_id,
        "cvss": 9.0,
        "status": "OPEN",
        "record_state": "ACTIVE",
        "scanner_source": "test",
    }


def _prepare(tmp_path: Path):
    legacy = tmp_path / "vulnflow.db"
    control = tmp_path / "control.db"
    default_root = tmp_path / "projects" / "default"
    default = default_root / "vulnflow.db"
    init_db(legacy)
    create_user(legacy, username="admin", password=PASSWORD, role="admin", actor="test")
    upsert_findings(legacy, [_finding("BASELINE", "CVE-2026-84001")], actor="test")
    legacy_evidence = tmp_path / "evidence"
    legacy_evidence.mkdir()
    (legacy_evidence / "legacy.txt").write_text("legacy", encoding="utf-8")
    result = prepare_split_storage(
        control_database=control,
        default_project_database=default,
        legacy_database=legacy,
        data_directory=tmp_path,
        directory_migrations=((legacy_evidence, default_root / "evidence"),),
        init_db_fn=init_db,
    )
    return legacy, control, default_root, default, result


def test_legacy_store_is_split_without_deleting_source_or_recopying_directories(tmp_path: Path):
    legacy, control, default_root, default, result = _prepare(tmp_path)
    assert result.migrated_legacy_database is True
    assert legacy.is_file()
    assert control.is_file() and default.is_file()
    assert control.resolve() != default.resolve()
    assert {item["username"] for item in list_users(control)} == {"admin"}
    assert list_findings(control) == []
    assert list_users(default) == []
    assert {item["finding_id"] for item in list_findings(default)} == {"BASELINE"}
    assert get_database_identity(control)["database_role"] == "control"
    assert get_database_identity(default) == {
        "database_role": "project-data",
        "project_id": "default",
        "project_name": "기본 프로젝트",
    }
    copied = default_root / "evidence" / "legacy.txt"
    assert copied.read_text(encoding="utf-8") == "legacy"

    # A completed split must not replay stale legacy directories on every boot.
    copied.unlink()
    (default_root / "evidence" / "current.txt").write_text("current", encoding="utf-8")
    second = prepare_split_storage(
        control_database=control,
        default_project_database=default,
        legacy_database=legacy,
        data_directory=tmp_path,
        directory_migrations=((tmp_path / "evidence", default_root / "evidence"),),
        init_db_fn=init_db,
    )
    assert second.migrated_legacy_database is False
    assert not copied.exists()
    assert (default_root / "evidence" / "current.txt").is_file()
    assert Path(second.marker_path).name == "split-storage-v1.json"


def test_default_project_restore_cannot_roll_back_users_or_project_registry(tmp_path: Path):
    _legacy, control, default_root, default, _result = _prepare(tmp_path)
    bundle = tmp_path / "default-recovery.zip"
    create_recovery_bundle(
        default,
        bundle,
        created_by="admin",
        evidence_dir=default_root / "evidence",
        project_id="default",
        project_name="기본 프로젝트",
    )

    create_user(control, username="analyst", password=PASSWORD, role="operator", actor="admin")
    child = create_project(
        control,
        name="Customer A",
        actor="admin",
        projects_dir=tmp_path / "projects",
        default_database_path=default,
        default_evidence_dir=default_root / "evidence",
        default_export_dir=default_root / "exports",
        default_import_preview_dir=default_root / "import-previews",
        default_recovery_dir=default_root / "backups" / "recovery",
        init_db_fn=init_db,
    )
    upsert_findings(default, [_finding("AFTER-BACKUP", "CVE-2026-84002")], actor="test")

    restore_recovery_bundle(
        default,
        bundle,
        actor="admin",
        current_schema_version=CURRENT_SCHEMA_VERSION,
        evidence_dir=default_root / "evidence",
        expected_project_id="default",
    )

    assert {item["username"] for item in list_users(control)} == {"admin", "analyst"}
    assert child["project_id"] in {item["project_id"] for item in list_projects(control, admin=True)}
    assert {item["finding_id"] for item in list_findings(default)} == {"BASELINE"}
    assert Path(child["database"]).is_file()


def test_recovery_bundle_is_bound_to_its_project_identity(tmp_path: Path):
    _legacy, control, default_root, default, _result = _prepare(tmp_path)
    child = create_project(
        control,
        name="Customer B",
        actor="admin",
        projects_dir=tmp_path / "projects",
        default_database_path=default,
        default_evidence_dir=default_root / "evidence",
        default_export_dir=default_root / "exports",
        default_import_preview_dir=default_root / "import-previews",
        default_recovery_dir=default_root / "backups" / "recovery",
        init_db_fn=init_db,
    )
    bundle = tmp_path / "child-recovery.zip"
    create_recovery_bundle(
        child["database"],
        bundle,
        created_by="admin",
        project_id=child["project_id"],
        project_name=child["name"],
    )
    validated = validate_recovery_bundle(
        bundle,
        current_schema_version=CURRENT_SCHEMA_VERSION,
        expected_project_id=child["project_id"],
    )
    assert validated["project"]["project_id"] == child["project_id"]
    assert get_database_identity(child["database"])["project_id"] == child["project_id"]
    with pytest.raises(ValueError, match="다른 프로젝트"):
        validate_database_file(
            child["database"],
            expected_project_id="default",
        )
    with pytest.raises(ValueError, match="다른 프로젝트"):
        validate_recovery_bundle(
            bundle,
            current_schema_version=CURRENT_SCHEMA_VERSION,
            expected_project_id="default",
        )
    with pytest.raises(ValueError, match="다른 프로젝트"):
        restore_recovery_bundle(
            default,
            bundle,
            actor="admin",
            current_schema_version=CURRENT_SCHEMA_VERSION,
            expected_project_id="default",
        )


def test_public_runner_never_accepts_failure_text_as_success(tmp_path: Path):
    script = tmp_path / "fake_pytest.py"
    script.write_text(
        "import sys, time\nprint('1 failed, 73 passed in 0.01s', flush=True)\ntime.sleep(0.05)\nsys.exit(1)\n",
        encoding="utf-8",
    )
    code = _run_group(
        [sys.executable, str(script)],
        root=tmp_path,
        env={},
        timeout_seconds=5,
    )
    assert code == 1


def test_docker_build_context_excludes_runtime_secrets_and_data():
    dockerignore = Path(".dockerignore").read_text(encoding="utf-8")
    dockerfile = Path("Dockerfile").read_text(encoding="utf-8")
    for required in (".env", "data/**", "*.db", "*.sqlite", "*.key", "INITIAL_CREDENTIALS.json"):
        assert required in dockerignore
    assert "COPY . ." not in dockerfile
    assert "COPY app ./app" in dockerfile
