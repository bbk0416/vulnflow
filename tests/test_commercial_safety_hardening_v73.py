from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import app.main as main
from app.core.storage import (
    apply_import_batch,
    create_remediation_verification_request,
    get_finding,
    init_db,
    update_workflow,
)
from app.services import intel
from app.services.evidence import verify_evidence_store


def _settings(tmp_path: Path, **overrides):
    default_root = tmp_path / "projects" / "default"
    values = {
        "DATA_DIR": tmp_path,
        "LEGACY_DB_PATH": tmp_path / "legacy-vulnflow.db",
        "CONTROL_DB_PATH": tmp_path / "control.db",
        "DEFAULT_PROJECT_ROOT": default_root,
        "DEFAULT_PROJECT_DB_PATH": default_root / "vulnflow.db",
        "DB_PATH": default_root / "vulnflow.db",
        "PROJECTS_DIR": tmp_path / "projects",
        "EVIDENCE_DIR": default_root / "evidence",
        "EXPORT_DIR": default_root / "exports",
        "RECOVERY_DIR": default_root / "backups" / "recovery",
        "IMPORT_PREVIEW_DIR": default_root / "import-previews",
        "LEGACY_EVIDENCE_DIR": tmp_path / "legacy-evidence",
        "LEGACY_EXPORT_DIR": tmp_path / "legacy-exports",
        "LEGACY_IMPORT_PREVIEW_DIR": tmp_path / "legacy-previews",
        "LEGACY_RECOVERY_DIR": tmp_path / "legacy-recovery",
        "AUTH_USERS_JSON": "",
        "AUTH_API_TOKENS_JSON": "",
        "AUTH_USER": "",
        "AUTH_PASSWORD": "",
        "DEMO_MODE": False,
        "ALLOW_LOCAL_ADMIN_FALLBACK": False,
        "JOB_WORKER_ENABLED": False,
        "CLUSTER_COORDINATION_ENABLED": False,
    }
    values.update(overrides)
    return values


def test_local_admin_fallback_requires_demo_mode(tmp_path: Path):
    application = main.create_app(
        setting_overrides=_settings(
            tmp_path,
            DEMO_MODE=False,
            ALLOW_LOCAL_ADMIN_FALLBACK=True,
        )
    )
    with pytest.raises(RuntimeError, match="DEMO_MODE=1"):
        with TestClient(application):
            pass


def test_forwarded_request_cannot_use_demo_local_admin_fallback(tmp_path: Path):
    application = main.create_app(
        setting_overrides=_settings(
            tmp_path,
            DEMO_MODE=True,
            ALLOW_LOCAL_ADMIN_FALLBACK=True,
        )
    )
    with TestClient(application) as client:
        response = client.get("/", headers={"X-Forwarded-For": "203.0.113.20"})
    assert response.status_code == 401


def test_production_start_is_empty_and_demo_reset_is_hidden(tmp_path: Path):
    api_token = "production-admin-token-1234567890"
    application = main.create_app(
        setting_overrides=_settings(
            tmp_path,
            AUTH_API_TOKENS_JSON=json.dumps({
                "admin": {"token": api_token, "role": "admin", "projects": "*"}
            }),
        )
    )
    headers = {"Authorization": f"Bearer {api_token}"}
    with TestClient(application) as client:
        findings = client.get("/api/v1/findings", headers=headers)
        assert findings.status_code == 200
        assert findings.json()["count"] == 0

        home = client.get("/upload", headers=headers)
        assert home.status_code == 200
        assert "/reset-demo" not in home.text

        token = home.cookies.get(main.CSRF_COOKIE) or client.cookies.get(main.CSRF_COOKIE)
        reset = client.post(
            "/reset-demo",
            headers=headers,
            data={"csrf_token": token, "confirmation": "RESET"},
        )
        assert reset.status_code == 404


def _pending_verification(db: Path) -> tuple[str, str]:
    init_db(db)
    finding_id = "E-SCALE-1"
    apply_import_batch(
        db,
        [{
            "finding_id": finding_id,
            "product": "Evidence Scale",
            "asset_name": "scale-host",
            "cve_id": "CVE-2026-73001",
            "status": "OPEN",
            "scanner_source": "scale-test",
            "record_state": "ACTIVE",
            "row_version": 1,
            "score": 50,
            "first_seen_at": "2026-07-01",
            "first_scored_at": "2026-07-01",
        }],
        scanner_source="scale-test",
        filename="scale.csv",
    )
    current = get_finding(db, finding_id)
    update_workflow(
        db,
        finding_id,
        status="MITIGATED",
        owner="operator",
        due_date="",
        exception_expiry="",
        risk_acceptance_reason="",
        risk_acceptance_approver="",
        notes="patched",
        actor="operator",
        expected_version=current["row_version"],
    )
    current = get_finding(db, finding_id)
    request = create_remediation_verification_request(
        db,
        finding_id,
        method="RETEST",
        evidence_note="scale verification",
        actor="operator",
        expected_version=current["row_version"],
    )
    return finding_id, str(request["verification_id"])


def test_evidence_integrity_covers_more_than_two_thousand_files(tmp_path: Path):
    db = tmp_path / "scale.sqlite3"
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    finding_id, verification_id = _pending_verification(db)
    content = b"x"
    digest = hashlib.sha256(content).hexdigest()
    rows = []
    for index in range(2001):
        stored = f"evidence-{index:04d}.txt"
        (evidence_dir / stored).write_bytes(content)
        rows.append((
            f"EV-{index:04d}", verification_id, finding_id, stored, stored,
            "text/plain", len(content), digest, "test", "2026-07-31T00:00:00+00:00",
        ))
    with sqlite3.connect(db) as conn:
        conn.executemany(
            """INSERT INTO verification_evidence_artifacts(
                   evidence_id,verification_id,finding_id,stored_filename,original_filename,
                   content_type,size_bytes,sha256,uploaded_by,uploaded_at
               ) VALUES(?,?,?,?,?,?,?,?,?,?)""",
            rows,
        )
        conn.commit()

    result = verify_evidence_store(db, evidence_dir)
    assert result["valid"] is True
    assert result["artifact_count"] == 2001
    assert result["unexpected_file_count"] == 0


class _FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self.payload


class _FakeSession:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def get(self, *_args, **_kwargs):
        return _FakeResponse(self.payload)


def test_empty_kev_response_fails_closed(monkeypatch):
    monkeypatch.setattr(intel, "_fetch_json", lambda *args, **kwargs: {"vulnerabilities": []})
    with pytest.raises(intel.IntelligenceError, match="비어"):
        intel.fetch_kev_catalog()
