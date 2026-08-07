from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from app.core.database_schema import CURRENT_SCHEMA_VERSION, init_db
from app.services.database_lifecycle import backup_database, validate_database_file
from scripts.runtime_fault_rehearsal import run_rehearsal
from scripts.runtime_stability_soak import _settings, run_soak


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_backup_database_publishes_atomically_and_preserves_previous_snapshot(tmp_path: Path):
    source = tmp_path / "source.db"
    destination = tmp_path / "backup.db"
    invalid = tmp_path / "invalid.db"
    init_db(source)
    backup_database(source, destination)
    before = _sha256(destination)
    invalid.write_bytes(b"not-a-sqlite-database")

    with pytest.raises(Exception):
        backup_database(invalid, destination)
    with pytest.raises(FileNotFoundError):
        backup_database(tmp_path / "missing.db", destination)

    assert _sha256(destination) == before
    assert not list(tmp_path.glob(f".{destination.name}.*.partial"))
    assert not (tmp_path / "missing.db").exists()
    assert validate_database_file(destination)["schema_version"] == CURRENT_SCHEMA_VERSION


def test_backup_database_rejects_source_destination_alias(tmp_path: Path):
    database = tmp_path / "project.db"
    init_db(database)
    with pytest.raises(ValueError, match="서로 달라야"):
        backup_database(database, database)


def test_runtime_soak_settings_are_fully_isolated(tmp_path: Path):
    settings = _settings(tmp_path, port=12345)
    assert Path(settings["DATA_DIR"]) == tmp_path
    assert Path(settings["CONTROL_DB_PATH"]).parent == tmp_path
    assert Path(settings["PROJECTS_DIR"]).parent == tmp_path
    assert Path(settings["DEFAULT_PROJECT_DB_PATH"]).is_relative_to(tmp_path)
    assert Path(settings["EVIDENCE_DIR"]).is_relative_to(tmp_path)
    assert Path(settings["RECOVERY_DIR"]).is_relative_to(tmp_path)


def test_short_runtime_soak_passes_without_touching_repository_data(tmp_path: Path):
    root = Path(__file__).resolve().parents[1]
    repository_runtime_files = [
        root / "data" / "control.db",
        root / "data" / "split-storage-v1.json",
        root / "data" / "projects" / "default" / "vulnflow.db",
    ]
    before = {
        path: _sha256(path) if path.is_file() else None
        for path in repository_runtime_files
    }

    result = run_soak(iterations=2, job_timeout_seconds=10, work_root=tmp_path / "soak")

    assert result["passed"] is True
    soak_source = (Path(__file__).resolve().parents[1] / "scripts/runtime_stability_soak.py").read_text(encoding="utf-8")
    assert "os._exit(0 if result[\"passed\"] else 1)" in soak_source
    assert result["iterations"] == 2
    assert result["jobs"]["failed"] == 0
    after = {
        path: _sha256(path) if path.is_file() else None
        for path in repository_runtime_files
    }
    assert after == before


def test_runtime_fault_rehearsal_passes_bounded_profile(tmp_path: Path):
    result = run_rehearsal(
        workers=2,
        writes_per_worker=2,
        work_root=tmp_path / "fault",
    )

    assert result["passed"] is True
    assert result["concurrency"]["completed"] == 4
    assert result["atomic_failure"]["destination_preserved"] is True
    assert result["crash"]["returncode"] == 17
    assert result["crash"]["uncommitted_row_present"] is False
