from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi.testclient import TestClient

import app.main as main
from app.core.storage import (
    claim_background_job,
    complete_background_job,
    connect,
    create_background_job,
    fail_background_job,
    get_background_job,
    init_db,
    list_background_jobs,
    request_background_job_cancel,
    retry_background_job,
)


def test_job_create_and_active_dedupe(tmp_path: Path):
    db = tmp_path / "jobs.db"
    init_db(db)
    first = create_background_job(
        db, job_type="RESCORE_ALL", requested_by="tester", dedupe_key="rescore:1"
    )
    second = create_background_job(
        db, job_type="RESCORE_ALL", requested_by="tester", dedupe_key="rescore:1"
    )
    assert first["job_id"] == second["job_id"]
    assert len(list_background_jobs(db)) == 1


def test_job_claim_is_atomic(tmp_path: Path):
    db = tmp_path / "jobs.db"
    init_db(db)
    created = create_background_job(db, job_type="RESCORE_ALL", requested_by="tester")
    claimed = claim_background_job(db, worker_id="worker-a", lease_seconds=30)
    assert claimed and claimed["job_id"] == created["job_id"]
    assert claimed["status"] == "RUNNING"
    assert claim_background_job(db, worker_id="worker-b", lease_seconds=30) is None


def test_expired_job_lease_is_recovered(tmp_path: Path):
    db = tmp_path / "jobs.db"
    init_db(db)
    created = create_background_job(db, job_type="RESCORE_ALL", requested_by="tester")
    claim_background_job(db, worker_id="worker-a", lease_seconds=30)
    expired = (datetime.now(timezone.utc) - timedelta(seconds=5)).replace(microsecond=0).isoformat()
    with connect(db) as conn:
        conn.execute(
            "UPDATE background_jobs SET lease_expires_at=? WHERE job_id=?",
            (expired, created["job_id"]),
        )
        conn.commit()
    recovered = claim_background_job(db, worker_id="worker-b", lease_seconds=30)
    assert recovered and recovered["job_id"] == created["job_id"]
    assert recovered["attempts"] == 2
    assert recovered["lease_owner"] == "worker-b"


def test_job_completion_persists_result(tmp_path: Path):
    db = tmp_path / "jobs.db"
    init_db(db)
    created = create_background_job(db, job_type="RESCORE_ALL", requested_by="tester")
    claim_background_job(db, worker_id="worker-a")
    completed = complete_background_job(
        db, job_id=created["job_id"], worker_id="worker-a", result={"rescored": 10}
    )
    assert completed["status"] == "SUCCEEDED"
    assert completed["result"] == {"rescored": 10}
    assert completed["lease_owner"] is None


def test_job_failure_retries_then_fails(tmp_path: Path):
    db = tmp_path / "jobs.db"
    init_db(db)
    created = create_background_job(
        db, job_type="INTEL_REFRESH", requested_by="tester", max_attempts=2
    )
    claim_background_job(db, worker_id="worker-a")
    retrying = fail_background_job(
        db, job_id=created["job_id"], worker_id="worker-a", error="network"
    )
    assert retrying["status"] == "RETRY"
    with connect(db) as conn:
        conn.execute(
            "UPDATE background_jobs SET next_attempt_at=? WHERE job_id=?",
            ((datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(), created["job_id"]),
        )
        conn.commit()
    claim_background_job(db, worker_id="worker-b")
    failed = fail_background_job(
        db, job_id=created["job_id"], worker_id="worker-b", error="network"
    )
    assert failed["status"] == "FAILED"
    assert failed["attempts"] == 2


def test_pending_job_cancel_and_retry(tmp_path: Path):
    db = tmp_path / "jobs.db"
    init_db(db)
    created = create_background_job(db, job_type="MAINTENANCE", requested_by="tester")
    cancelled = request_background_job_cancel(db, created["job_id"], actor="admin")
    assert cancelled["status"] == "CANCELLED"
    retried = retry_background_job(db, created["job_id"], actor="admin")
    assert retried["status"] == "PENDING"
    assert retried["attempts"] == 0
    assert retried["cancel_requested"] is False


def test_background_csv_import_executor(tmp_path: Path, monkeypatch):
    db = tmp_path / "vulnflow.db"
    monkeypatch.setattr(main, "DB_PATH", db)
    init_db(db)
    main._ensure_policy_registry()
    row = main.normalize_row(
        {"product": "Portal", "cve_id": "CVE-2026-12345", "cvss": "8.1"},
        0,
        scanner_source="scanner-a",
    )
    created = create_background_job(
        db,
        job_type="CSV_IMPORT",
        payload={
            "rows": [row],
            "scanner_source": "scanner-a",
            "filename": "scan.csv",
            "reconcile_missing": False,
        },
        requested_by="operator",
    )
    job = claim_background_job(db, worker_id="worker-test")
    result = main._execute_background_job(job, worker_id="worker-test")
    completed = complete_background_job(
        db, job_id=created["job_id"], worker_id="worker-test", result=result
    )
    assert completed["status"] == "SUCCEEDED"
    assert result["inserted"] == 1
    assert main.count_findings(db) == 1


def test_jobs_page_is_visible(client):
    response = client.get("/jobs")
    assert response.status_code == 200
    assert "백그라운드 작업 큐" in response.text


def test_bearer_can_queue_and_read_job(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "vulnflow.db")
    monkeypatch.setattr(
        main,
        "AUTH_API_TOKENS_JSON",
        '{"automation":{"token":"0123456789abcdef0123456789abcdef","role":"operator","projects":"*"}}',
    )
    monkeypatch.setattr(main, "JOB_WORKER_ENABLED", False)
    headers = {"Authorization": "Bearer 0123456789abcdef0123456789abcdef"}
    with TestClient(main.app) as test_client:
        queued = test_client.post("/api/v1/jobs/queue/RESCORE_ALL", headers=headers)
        assert queued.status_code == 200
        job_id = queued.json()["job_id"]
        detail = test_client.get(f"/api/v1/jobs/{job_id}", headers=headers)
        assert detail.status_code == 200
        assert detail.json()["job_type"] == "RESCORE_ALL"


def test_operator_cannot_queue_admin_job(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "vulnflow.db")
    monkeypatch.setattr(
        main,
        "AUTH_API_TOKENS_JSON",
        '{"automation":{"token":"0123456789abcdef0123456789abcdef","role":"operator","projects":"*"}}',
    )
    monkeypatch.setattr(main, "JOB_WORKER_ENABLED", False)
    headers = {"Authorization": "Bearer 0123456789abcdef0123456789abcdef"}
    with TestClient(main.app) as test_client:
        response = test_client.post("/api/v1/jobs/queue/MAINTENANCE", headers=headers)
        assert response.status_code == 403


def test_background_import_is_idempotent_after_worker_crash(tmp_path: Path, monkeypatch):
    db = tmp_path / "vulnflow.db"
    monkeypatch.setattr(main, "DB_PATH", db)
    init_db(db)
    main._ensure_policy_registry()
    row = main.normalize_row(
        {"product": "Portal", "cve_id": "CVE-2026-54321", "cvss": "7.5"},
        0,
        scanner_source="scanner-a",
    )
    created = create_background_job(
        db,
        job_type="CSV_IMPORT",
        payload={"rows": [row], "scanner_source": "scanner-a", "filename": "scan.csv"},
        requested_by="operator",
    )
    claimed = claim_background_job(db, worker_id="worker-a")
    first = main._execute_background_job(claimed, worker_id="worker-a")
    # Simulate a crash after the import transaction committed but before the job was completed.
    with connect(db) as conn:
        conn.execute(
            "UPDATE background_jobs SET lease_expires_at=? WHERE job_id=?",
            ((datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(), created["job_id"]),
        )
        conn.commit()
    claimed_again = claim_background_job(db, worker_id="worker-b")
    second = main._execute_background_job(claimed_again, worker_id="worker-b")
    assert first["batch_id"] == second["batch_id"]
    assert second["idempotent_replay"] is True
    assert main.count_findings(db) == 1


def test_v7_import_batches_migrate_source_job_id(tmp_path: Path):
    db = tmp_path / "legacy.db"
    import sqlite3

    with sqlite3.connect(db) as conn:
        conn.executescript((Path(__file__).parent / "fixtures" / "v3_schema.sql").read_text(encoding="utf-8"))
        conn.executescript(
            """
            CREATE TABLE import_batches (
                batch_id TEXT PRIMARY KEY, scanner_source TEXT NOT NULL, filename TEXT,
                import_mode TEXT NOT NULL, row_count INTEGER NOT NULL DEFAULT 0,
                inserted_count INTEGER NOT NULL DEFAULT 0, updated_count INTEGER NOT NULL DEFAULT 0,
                stale_count INTEGER NOT NULL DEFAULT 0, actor TEXT DEFAULT 'local-user', created_at TEXT NOT NULL
            );
            """
        )
    init_db(db)
    with connect(db) as conn:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(import_batches)").fetchall()}
    assert "source_job_id" in columns


def test_job_api_redacts_import_rows(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "vulnflow.db")
    monkeypatch.setattr(
        main,
        "AUTH_API_TOKENS_JSON",
        '{"automation":{"token":"0123456789abcdef0123456789abcdef","role":"operator","projects":"*"}}',
    )
    monkeypatch.setattr(main, "JOB_WORKER_ENABLED", False)
    headers = {"Authorization": "Bearer 0123456789abcdef0123456789abcdef"}
    with TestClient(main.app) as test_client:
        job = create_background_job(
            main.DB_PATH,
            job_type="CSV_IMPORT",
            payload={"rows": [{"finding_id": "secret-row"}], "scanner_source": "api"},
            requested_by="automation",
        )
        response = test_client.get(f"/api/v1/jobs/{job['job_id']}", headers=headers)
        assert response.status_code == 200
        payload = response.json()["payload"]
        assert "rows" not in payload
        assert payload["row_count"] == 1


def test_live_worker_completes_queued_job(tmp_path: Path, monkeypatch):
    import time

    monkeypatch.setattr(main, "DB_PATH", tmp_path / "vulnflow.db")
    monkeypatch.setattr(main, "JOB_WORKER_ENABLED", True)
    monkeypatch.setattr(main, "JOB_WORKER_INTERVAL_SECONDS", 1)
    with TestClient(main.app):
        created = create_background_job(
            main.DB_PATH, job_type="RESCORE_ALL", requested_by="operator"
        )
        deadline = time.time() + 5
        current = created
        while time.time() < deadline:
            current = get_background_job(main.DB_PATH, created["job_id"]) or {}
            if current.get("status") == "SUCCEEDED":
                break
            time.sleep(0.1)
        assert current.get("status") == "SUCCEEDED"
        assert current.get("result", {}).get("rescored", 0) >= 1


def test_expired_lease_respects_max_attempts(tmp_path: Path):
    db = tmp_path / "jobs.db"
    init_db(db)
    created = create_background_job(
        db, job_type="RESCORE_ALL", requested_by="tester", max_attempts=1
    )
    claim_background_job(db, worker_id="worker-a", lease_seconds=30)
    with connect(db) as conn:
        conn.execute(
            "UPDATE background_jobs SET lease_expires_at=? WHERE job_id=?",
            ((datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(), created["job_id"]),
        )
        conn.commit()
    assert claim_background_job(db, worker_id="worker-b", lease_seconds=30) is None
    current = get_background_job(db, created["job_id"])
    assert current["status"] == "FAILED"
    assert "maximum attempts" in current["last_error"]
