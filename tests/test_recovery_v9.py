from __future__ import annotations

import json
import sqlite3
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import app.main as main
from app.core.storage import (
    CURRENT_APP_VERSION,
    CURRENT_SCHEMA_VERSION,
    claim_background_job,
    create_background_job,
    get_finding,
    get_schema_info,
    init_db,
    upsert_findings,
    validate_database_file,
)
from app.services.recovery import (
    build_config_audit,
    create_recovery_bundle,
    restore_recovery_bundle,
    validate_recovery_bundle,
)


def _row(fid: str, owner: str = "") -> dict:
    return {
        "finding_id": fid,
        "product": "Recovery Demo",
        "cve_id": "CVE-2026-12345",
        "status": "OPEN",
        "owner": owner,
        "first_seen_at": "2026-07-01",
        "first_scored_at": "2026-07-01",
    }


def test_schema_migration_history_and_metadata(tmp_path: Path):
    db = tmp_path / "schema.sqlite3"
    init_db(db)
    info = get_schema_info(db)
    assert info["schema_version"] == CURRENT_SCHEMA_VERSION
    assert info["app_version"] == CURRENT_APP_VERSION
    assert any(item["version"] == CURRENT_SCHEMA_VERSION for item in info["migrations"])


def test_signed_recovery_bundle_validates_and_redacts_config(tmp_path: Path):
    db = tmp_path / "live.sqlite3"
    bundle = tmp_path / "recovery.zip"
    init_db(db)
    upsert_findings(db, [_row("REC-1")], audit=False)
    env = {
        "VULNFLOW_USERS_JSON": json.dumps({"admin": {"password": "TOP-SECRET", "role": "admin"}}),
        "VULNFLOW_API_TOKENS_JSON": json.dumps({"ci": {"token": "TOKEN-SECRET-123456", "role": "operator", "projects": "*"}}),
        "VULNFLOW_WEBHOOKS_JSON": json.dumps({"ops": {"url": "https://user:pass@example.test/private", "secret": "WEBHOOK-SECRET", "events": ["*"]}}),
        "VULNFLOW_BACKUP_SIGNING_KEY": "signing-key",
        "VULNFLOW_COOKIE_SECURE": "1",
    }
    audit = build_config_audit(env, db_path=db, base_dir=Path(__file__).resolve().parents[1])
    rendered = json.dumps(audit, ensure_ascii=False)
    assert "TOP-SECRET" not in rendered
    assert "TOKEN-SECRET" not in rendered
    assert "WEBHOOK-SECRET" not in rendered
    assert "/private" not in rendered
    assert audit["settings"]["webhooks"]["endpoints"] == [{"name": "ops", "scheme": "https", "event_count": 1}]

    created = create_recovery_bundle(
        db, bundle, config_audit=audit, signing_key="signing-key", created_by="tester",
        base_dir=Path(__file__).resolve().parents[1],
    )
    assert created["signed"] is True
    checked = validate_recovery_bundle(
        bundle, signing_key="signing-key", require_signature=True,
        current_schema_version=CURRENT_SCHEMA_VERSION,
    )
    assert checked["valid"] is True
    assert checked["database"]["finding_count"] == 1
    assert checked["manifest"]["schema"]["schema_version"] == CURRENT_SCHEMA_VERSION


def test_recovery_bundle_tamper_is_rejected(tmp_path: Path):
    db = tmp_path / "live.sqlite3"
    bundle = tmp_path / "recovery.zip"
    init_db(db)
    upsert_findings(db, [_row("REC-1")], audit=False)
    create_recovery_bundle(db, bundle, signing_key="signing-key", base_dir=Path(__file__).resolve().parents[1])

    unpacked = tmp_path / "unpacked"
    with zipfile.ZipFile(bundle) as archive:
        archive.extractall(unpacked)
    with (unpacked / "config-audit.json").open("ab") as handle:
        handle.write(b"tamper")
    tampered = tmp_path / "tampered.zip"
    with zipfile.ZipFile(tampered, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in unpacked.iterdir():
            archive.write(path, arcname=path.name)
    with pytest.raises(ValueError, match="해시 불일치"):
        validate_recovery_bundle(tampered, signing_key="signing-key")



def test_signed_bundle_rejects_rehashed_tampering(tmp_path: Path):
    import hashlib
    db = tmp_path / "live.sqlite3"
    bundle = tmp_path / "recovery.zip"
    init_db(db)
    upsert_findings(db, [_row("REC-SIGNED")], audit=False)
    create_recovery_bundle(db, bundle, signing_key="signing-key", base_dir=Path(__file__).resolve().parents[1])
    unpacked = tmp_path / "signed-unpacked"
    with zipfile.ZipFile(bundle) as archive:
        archive.extractall(unpacked)
    audit_path = unpacked / "config-audit.json"
    audit_path.write_text('{"tampered":true}', encoding="utf-8")
    hashed_files = sorted(path for path in unpacked.iterdir() if path.is_file() and path.name not in {"SHA256SUMS.txt", "manifest.hmac"})
    sums = []
    for path in hashed_files:
        sums.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}")
    (unpacked / "SHA256SUMS.txt").write_text("\n".join(sums) + "\n", encoding="utf-8")
    tampered = tmp_path / "signed-tampered.zip"
    with zipfile.ZipFile(tampered, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in unpacked.iterdir():
            archive.write(path, arcname=path.name)
    with pytest.raises(ValueError, match="HMAC 서명"):
        validate_recovery_bundle(tampered, signing_key="signing-key")

def test_recovery_bundle_restore_reverts_database(tmp_path: Path):
    db = tmp_path / "live.sqlite3"
    bundle = tmp_path / "recovery.zip"
    init_db(db)
    upsert_findings(db, [_row("REC-1", "before")], audit=False)
    create_recovery_bundle(db, bundle, signing_key="signing-key", base_dir=Path(__file__).resolve().parents[1])
    upsert_findings(db, [_row("REC-1", "after")], audit=False)
    assert get_finding(db, "REC-1")["owner"] == "after"
    result = restore_recovery_bundle(
        db, bundle, actor="tester", signing_key="signing-key",
        require_signature=True, current_schema_version=CURRENT_SCHEMA_VERSION,
    )
    assert result["validation"]["valid"] is True
    assert get_finding(db, "REC-1")["owner"] == "before"
    assert Path(result["restore"]["safety_backup"]).exists()


def test_future_schema_database_is_rejected(tmp_path: Path):
    db = tmp_path / "future.sqlite3"
    init_db(db)
    with sqlite3.connect(db) as conn:
        conn.execute(f"PRAGMA user_version={CURRENT_SCHEMA_VERSION + 1}")
    with pytest.raises(ValueError, match="보다 새롭습니다"):
        validate_database_file(db)


def test_configuration_audit_flags_insecure_defaults():
    audit = build_config_audit({}, db_path="vulnflow.db", base_dir=Path(__file__).resolve().parents[1])
    codes = {item["code"] for item in audit["findings"]}
    assert "AUTH_MISSING" in codes
    assert "BACKUP_UNSIGNED" in codes
    assert "SCHEDULED_BACKUP_DISABLED" in codes
    assert audit["posture"] == "attention"


def test_system_ui_and_recovery_export(client: TestClient):
    page = client.get("/system")
    assert page.status_code == 200
    assert "시스템 구성·재해복구" in page.text
    audit = client.get("/export/config-audit.json")
    assert audit.status_code == 200
    assert audit.json()["settings"]["app_version"] == CURRENT_APP_VERSION
    bundle = client.get("/export/recovery-bundle.zip")
    assert bundle.status_code == 200
    assert bundle.content.startswith(b"PK")


def test_recovery_validate_api_requires_admin_bearer(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "api.sqlite3")
    monkeypatch.setattr(main, "AUTH_API_TOKENS_JSON", json.dumps({"admin-api": {"token": "a" * 32, "role": "admin", "projects": "*"}}))
    with TestClient(main.app) as client:
        bundle = client.get("/export/recovery-bundle.zip", headers={"Authorization": "Bearer " + "a" * 32})
        assert bundle.status_code == 200
        response = client.post(
            "/api/v1/recovery/validate",
            headers={"Authorization": "Bearer " + "a" * 32},
            files={"file": ("recovery.zip", bundle.content, "application/zip")},
        )
        assert response.status_code == 200
        assert response.json()["valid"] is True


def test_recovery_backup_background_job(tmp_path: Path, monkeypatch):
    db = tmp_path / "job.sqlite3"
    recovery_dir = tmp_path / "recovery"
    init_db(db)
    upsert_findings(db, [_row("REC-JOB")], audit=False)
    monkeypatch.setattr(main, "DB_PATH", db)
    monkeypatch.setattr(main, "RECOVERY_DIR", recovery_dir)
    monkeypatch.setattr(main, "BACKUP_SIGNING_KEY", "job-signing-key-123")
    monkeypatch.setattr(main, "BACKUP_RETENTION_COUNT", 2)
    create_background_job(
        db, job_type="RECOVERY_BACKUP", payload={}, requested_by="admin", max_attempts=1,
    )
    job = claim_background_job(db, worker_id="worker-test", lease_seconds=60)
    assert job is not None
    result = main._execute_background_job(job, worker_id="worker-test")
    assert Path(result["bundle_path"]).exists()
    assert result["signed"] is True


def test_api_recovery_restore_reverts_workflow(tmp_path: Path, monkeypatch):
    token = "r" * 32
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "api-restore.sqlite3")
    monkeypatch.setattr(main, "AUTH_API_TOKENS_JSON", json.dumps({"admin-api": {"token": token, "role": "admin", "projects": "*"}}))
    monkeypatch.setattr(main, "BACKUP_SIGNING_KEY", "api-restore-signing-key-123")
    monkeypatch.setattr(main, "BACKUP_REQUIRE_SIGNATURE", True)
    headers = {"Authorization": f"Bearer {token}"}
    with TestClient(main.app) as client:
        bundle = client.get("/export/recovery-bundle.zip", headers=headers)
        assert bundle.status_code == 200
        current = client.get("/api/v1/findings/F-0001", headers=headers).json()
        changed = client.post(
            "/api/v1/findings/F-0001/workflow",
            headers=headers,
            json={
                "status": "IN_PROGRESS",
                "owner": "changed-after-bundle",
                "due_date": "2026-12-31",
                "notes": "changed",
                "expected_row_version": current["row_version"],
            },
        )
        assert changed.status_code == 200
        restored = client.post(
            "/api/v1/recovery/restore",
            headers=headers,
            data={"confirmation": "RESTORE-BUNDLE"},
            files={"file": ("recovery.zip", bundle.content, "application/zip")},
        )
        assert restored.status_code == 200
        item = client.get("/api/v1/findings/F-0001", headers=headers).json()
        assert item["owner"] != "changed-after-bundle"


def test_scheduled_bundle_retention_uses_unique_names(tmp_path: Path):
    from app.services.recovery import create_scheduled_recovery_bundle, list_recovery_bundles
    db = tmp_path / "retention.sqlite3"
    directory = tmp_path / "bundles"
    init_db(db)
    upsert_findings(db, [_row("REC-RET")], audit=False)
    for _ in range(4):
        create_scheduled_recovery_bundle(
            db, directory, signing_key="retention-signing-key", retention_count=2,
            actor="scheduler", base_dir=Path(__file__).resolve().parents[1],
        )
    bundles = list_recovery_bundles(directory)
    assert len(bundles) == 2
    assert len({item["filename"] for item in bundles}) == 2


def test_signature_required_startup_without_key_is_rejected(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "bad-config.sqlite3")
    monkeypatch.setattr(main, "BACKUP_REQUIRE_SIGNATURE", True)
    monkeypatch.setattr(main, "BACKUP_SIGNING_KEY", "")
    with pytest.raises(ValueError, match="BACKUP_SIGNING_KEY"):
        with TestClient(main.app):
            pass
