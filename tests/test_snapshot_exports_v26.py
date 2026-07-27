from __future__ import annotations

import csv
import io
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

import app.main as main
from app.core.storage import (
    CURRENT_SCHEMA_VERSION,
    claim_background_job,
    complete_background_job,
    connect,
    create_background_job,
    get_background_job,
    init_db,
    upsert_findings,
)
from app.services.exports import (
    create_findings_csv_export,
    get_export_artifact,
    list_export_artifacts,
    purge_expired_export_artifacts,
    stream_findings_csv,
    verify_export_artifact,
)


def _seed(db: Path, count: int = 5) -> None:
    init_db(db)
    rows = []
    for idx in range(count):
        rows.append(
            main.normalize_row(
                {
                    "finding_id": f"F-{idx:04d}",
                    "product": "=Danger" if idx == 0 else f"Portal-{idx}",
                    "asset_name": f"web-{idx}",
                    "cve_id": f"CVE-2026-{12000 + idx}",
                    "cvss": str(9.0 - idx * 0.2),
                    "status": "OPEN" if idx % 2 == 0 else "CLOSED",
                    "scanner_source": "scanner-a",
                },
                idx,
                scanner_source="scanner-a",
            )
        )
    upsert_findings(db, rows, actor="test")


def test_v25_database_migrates_export_schema(tmp_path: Path):
    db = tmp_path / "legacy.sqlite3"
    _seed(db, 1)
    with sqlite3.connect(db) as conn:
        conn.execute("DELETE FROM schema_migrations WHERE version=26")
        conn.execute("DROP TABLE export_artifacts")
        conn.execute("PRAGMA user_version=25")
        conn.commit()
    init_db(db)
    with sqlite3.connect(db) as conn:
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        migration = conn.execute(
            "SELECT name,app_version FROM schema_migrations WHERE version=26"
        ).fetchone()
        columns = {row[1] for row in conn.execute("PRAGMA table_info(export_artifacts)")}
    assert version == CURRENT_SCHEMA_VERSION == 40
    assert migration == ("snapshot_export_artifacts", "26.0.0")
    assert {"artifact_id", "sha256", "expires_at", "downloaded_count"} <= columns


def test_stream_findings_csv_uses_bom_header_and_formula_defense(tmp_path: Path):
    db = tmp_path / "vulnflow.db"
    _seed(db, 3)
    payload = b"".join(stream_findings_csv(db, filters={"record_state": "ALL"}, batch_size=2))
    assert payload.startswith(b"\xef\xbb\xbf")
    rows = list(csv.DictReader(io.StringIO(payload.decode("utf-8-sig"))))
    assert len(rows) == 3
    assert rows[0]["product"].startswith("'=")


def test_background_export_creates_verified_snapshot_artifact(tmp_path: Path, monkeypatch):
    db = tmp_path / "vulnflow.db"
    export_dir = tmp_path / "exports"
    monkeypatch.setattr(main, "DB_PATH", db)
    monkeypatch.setattr(main, "EXPORT_DIR", export_dir)
    monkeypatch.setattr(main, "EXPORT_RETENTION_DAYS", 3)
    _seed(db, 6)
    main._ensure_policy_registry()
    created = create_background_job(
        db,
        job_type="FINDINGS_EXPORT",
        payload={"filters": {"status": "OPEN", "record_state": "ALL"}},
        requested_by="operator",
    )
    claimed = claim_background_job(db, worker_id="worker-export")
    result = main._execute_background_job(claimed, worker_id="worker-export")
    completed = complete_background_job(
        db, job_id=created["job_id"], worker_id="worker-export", result=result
    )
    assert completed["status"] == "SUCCEEDED"
    assert result["row_count"] == 3
    assert verify_export_artifact(export_dir, result)["valid"] is True
    assert get_export_artifact(db, result["artifact_id"])["job_id"] == created["job_id"]


def test_export_job_replay_is_idempotent(tmp_path: Path, monkeypatch):
    db = tmp_path / "vulnflow.db"
    export_dir = tmp_path / "exports"
    monkeypatch.setattr(main, "DB_PATH", db)
    monkeypatch.setattr(main, "EXPORT_DIR", export_dir)
    _seed(db, 2)
    main._ensure_policy_registry()
    created = create_background_job(
        db, job_type="FINDINGS_EXPORT", payload={"filters": {}}, requested_by="operator"
    )
    first = create_findings_csv_export(
        db, export_dir, filters={}, actor="operator", job_id=created["job_id"], retention_days=7
    )
    second = create_findings_csv_export(
        db, export_dir, filters={}, actor="operator", job_id=created["job_id"], retention_days=7
    )
    assert first["artifact_id"] == second["artifact_id"]
    assert second["idempotent_replay"] is True
    assert len(list_export_artifacts(db)) == 1


def test_export_artifact_tamper_is_marked_corrupt_on_download(tmp_path: Path, monkeypatch):
    db = tmp_path / "vulnflow.db"
    export_dir = tmp_path / "exports"
    monkeypatch.setattr(main, "DB_PATH", db)
    monkeypatch.setattr(main, "EXPORT_DIR", export_dir)
    monkeypatch.setattr(main, "JOB_WORKER_ENABLED", False)
    _seed(db, 2)
    artifact = create_findings_csv_export(db, export_dir, filters={}, actor="operator", retention_days=7)
    with TestClient(main.app) as client:
        (export_dir / artifact["stored_filename"]).write_bytes(b"tampered")
        response = client.get(f"/exports/{artifact['artifact_id']}/download")
    assert response.status_code == 409
    assert get_export_artifact(db, artifact["artifact_id"])["status"] == "CORRUPT"


def test_expired_export_cleanup_removes_file(tmp_path: Path):
    db = tmp_path / "vulnflow.db"
    export_dir = tmp_path / "exports"
    _seed(db, 1)
    past_now = datetime.now(timezone.utc) - timedelta(days=2)
    with patch("app.services.exports.datetime") as mocked_datetime:
        mocked_datetime.now.return_value = past_now
        artifact = create_findings_csv_export(db, export_dir, filters={}, actor="operator", retention_days=1)
    result = purge_expired_export_artifacts(db, export_dir, actor="maintenance")
    assert result == {"exports_expired": 1, "export_files_removed": 1}
    assert get_export_artifact(db, artifact["artifact_id"])["status"] == "EXPIRED"
    assert not (export_dir / artifact["stored_filename"]).exists()


def test_export_api_queues_job_and_lists_artifacts(tmp_path: Path, monkeypatch):
    db = tmp_path / "vulnflow.db"
    export_dir = tmp_path / "exports"
    monkeypatch.setattr(main, "DB_PATH", db)
    monkeypatch.setattr(main, "EXPORT_DIR", export_dir)
    monkeypatch.setattr(main, "JOB_WORKER_ENABLED", False)
    monkeypatch.setattr(
        main,
        "AUTH_API_TOKENS_JSON",
        '{"automation":{"token":"0123456789abcdef0123456789abcdef","role":"operator"}}',
    )
    headers = {"Authorization": "Bearer 0123456789abcdef0123456789abcdef"}
    with TestClient(main.app) as client:
        queued = client.post(
            "/api/v1/exports/findings",
            headers=headers,
            json={"status": "OPEN", "record_state": "ALL"},
        )
        assert queued.status_code == 200
        assert queued.json()["job_type"] == "FINDINGS_EXPORT"
        listing = client.get("/api/v1/exports", headers=headers)
        assert listing.status_code == 200
        assert listing.json()["count"] == 0


def test_export_page_and_stream_endpoint(tmp_path: Path, monkeypatch):
    db = tmp_path / "vulnflow.db"
    export_dir = tmp_path / "exports"
    monkeypatch.setattr(main, "DB_PATH", db)
    monkeypatch.setattr(main, "EXPORT_DIR", export_dir)
    monkeypatch.setattr(main, "JOB_WORKER_ENABLED", False)
    with TestClient(main.app) as client:
        page = client.get("/exports")
        assert page.status_code == 200
        assert "스냅샷 내보내기" in page.text
        streamed = client.get("/export/findings.csv")
        assert streamed.status_code == 200
        assert streamed.headers["x-vulnflow-export-mode"] == "transactional-stream"
        assert streamed.content.startswith(b"\xef\xbb\xbf")


def test_export_artifact_core_fields_are_immutable(tmp_path: Path):
    db = tmp_path / "vulnflow.db"
    export_dir = tmp_path / "exports"
    _seed(db, 1)
    artifact = create_findings_csv_export(db, export_dir, filters={}, actor="operator", retention_days=7)
    with sqlite3.connect(db) as conn:
        try:
            conn.execute("UPDATE export_artifacts SET sha256='0' WHERE artifact_id=?", (artifact["artifact_id"],))
        except sqlite3.IntegrityError as exc:
            assert "immutable" in str(exc)
        else:
            raise AssertionError("core-field update should be blocked")
        try:
            conn.execute("DELETE FROM export_artifacts WHERE artifact_id=?", (artifact["artifact_id"],))
        except sqlite3.IntegrityError as exc:
            assert "cannot be deleted" in str(exc)
        else:
            raise AssertionError("artifact deletion should be blocked")
