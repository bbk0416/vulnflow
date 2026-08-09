from __future__ import annotations

import io
import json
import sqlite3
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import app.main as main
from app.core.storage import (
    CURRENT_SCHEMA_VERSION,
    apply_import_batch,
    create_remediation_verification_request,
    get_finding,
    init_db,
    update_workflow,
)
from app.services.evidence import (
    get_evidence_artifact,
    list_evidence_artifacts,
    retire_evidence_artifact,
    store_verification_evidence,
    validate_evidence_content,
    verify_evidence_artifact,
    verify_evidence_store,
)
from app.services.recovery import create_recovery_bundle, restore_recovery_bundle, validate_recovery_bundle


def _row(fid: str = "E-1") -> dict:
    return {
        "finding_id": fid,
        "product": "Evidence Demo",
        "asset_name": "evidence-host",
        "cve_id": "CVE-2026-15001",
        "status": "OPEN",
        "scanner_source": "evidence-scanner",
        "record_state": "ACTIVE",
        "row_version": 1,
        "score": 50,
        "first_seen_at": "2026-07-01",
        "first_scored_at": "2026-07-01",
    }


def _pending(db: Path, fid: str = "E-1") -> dict:
    init_db(db)
    apply_import_batch(db, [_row(fid)], scanner_source="evidence-scanner", filename="one.csv")
    current = get_finding(db, fid)
    update_workflow(
        db, fid, status="MITIGATED", owner="operator", due_date="", exception_expiry="",
        risk_acceptance_reason="", risk_acceptance_approver="", notes="patch applied",
        actor="operator", expected_version=current["row_version"],
    )
    current = get_finding(db, fid)
    return create_remediation_verification_request(
        db, fid, method="RETEST", evidence_note="retest evidence follows", actor="operator",
        expected_version=current["row_version"],
    )


def test_schema_v15_has_immutable_evidence_table(tmp_path: Path):
    db = tmp_path / "schema.sqlite3"
    init_db(db)
    with sqlite3.connect(db) as conn:
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        columns = {row[1] for row in conn.execute("PRAGMA table_info(verification_evidence_artifacts)")}
        triggers = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='trigger'")}
    assert version == CURRENT_SCHEMA_VERSION == 46
    assert {"evidence_id", "verification_id", "finding_id", "stored_filename", "sha256", "status"} <= columns
    assert {"verification_evidence_core_immutable", "verification_evidence_no_delete"} <= triggers


def test_evidence_validation_rejects_unsafe_content():
    assert validate_evidence_content("result.json", b'{"ok":true}', max_bytes=1024)["content_type"] == "application/json"
    with pytest.raises(ValueError, match="허용되는"):
        validate_evidence_content("payload.exe", b"MZ", max_bytes=1024)
    with pytest.raises(ValueError, match="시그니처"):
        validate_evidence_content("fake.pdf", b"not pdf", max_bytes=1024)
    with pytest.raises(ValueError, match="UTF-8"):
        validate_evidence_content("bad.log", b"\xff\xfe", max_bytes=1024)
    with pytest.raises(ValueError, match="최대"):
        validate_evidence_content("large.txt", b"a" * 11, max_bytes=10)


def test_store_verify_tamper_and_retire(tmp_path: Path):
    db = tmp_path / "evidence.sqlite3"
    evidence_dir = tmp_path / "evidence"
    request = _pending(db)
    item = store_verification_evidence(
        db, evidence_dir, verification_id=request["verification_id"], filename="retest.log",
        content=b"retest passed\n", notes="service retest", actor="operator", max_bytes=1024,
    )
    assert item["status"] == "ACTIVE"
    assert item["sha256"]
    assert verify_evidence_store(db, evidence_dir)["valid"] is True
    with sqlite3.connect(db) as conn:
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            conn.execute("UPDATE verification_evidence_artifacts SET sha256='x' WHERE evidence_id=?", (item["evidence_id"],))
        with pytest.raises(sqlite3.IntegrityError, match="cannot be deleted"):
            conn.execute("DELETE FROM verification_evidence_artifacts WHERE evidence_id=?", (item["evidence_id"],))
    path = evidence_dir / item["stored_filename"]
    path.write_bytes(b"tampered")
    assert verify_evidence_artifact(evidence_dir, item)["valid"] is False
    path.write_bytes(b"retest passed\n")
    retired = retire_evidence_artifact(db, item["evidence_id"], actor="operator", reason="wrong attachment")
    assert retired["status"] == "RETIRED"
    assert path.exists()


def test_completed_verification_evidence_cannot_be_retired(tmp_path: Path):
    from app.core.storage import decide_remediation_verification_request

    db = tmp_path / "complete.sqlite3"
    evidence_dir = tmp_path / "evidence"
    request = _pending(db)
    item = store_verification_evidence(
        db, evidence_dir, verification_id=request["verification_id"], filename="proof.txt",
        content=b"fixed", notes="proof", actor="operator", max_bytes=1024,
    )
    from app.services.evidence import scan_evidence_artifact, waive_evidence_scan
    scan_evidence_artifact(db, evidence_dir, item["evidence_id"], mode="builtin", actor="scanner")
    waive_evidence_scan(db, item["evidence_id"], actor="admin", reason="isolated baseline review")
    decide_remediation_verification_request(
        db, request["verification_id"], decision="APPROVE", decision_note="verified", actor="approver"
    )
    with pytest.raises(ValueError, match="처리 완료"):
        retire_evidence_artifact(db, item["evidence_id"], actor="operator", reason="remove")


def test_recovery_bundle_contains_and_restores_evidence(tmp_path: Path):
    db = tmp_path / "live.sqlite3"
    evidence_dir = tmp_path / "evidence"
    request = _pending(db)
    item = store_verification_evidence(
        db, evidence_dir, verification_id=request["verification_id"], filename="proof.json",
        content=b'{"patched":true}', notes="proof", actor="operator", max_bytes=1024,
    )
    bundle = tmp_path / "bundle.zip"
    create_recovery_bundle(db, bundle, evidence_dir=evidence_dir, created_by="admin", base_dir=Path(__file__).resolve().parents[1])
    checked = validate_recovery_bundle(bundle, current_schema_version=CURRENT_SCHEMA_VERSION)
    assert checked["evidence"]["artifact_count"] == 1
    with zipfile.ZipFile(bundle) as archive:
        names = set(archive.namelist())
        assert "evidence-manifest.json" in names
        assert f"evidence/{item['stored_filename']}" in names

    restored_db = tmp_path / "restored.sqlite3"
    restored_evidence = tmp_path / "restored-evidence"
    result = restore_recovery_bundle(
        restored_db, bundle, actor="admin", current_schema_version=CURRENT_SCHEMA_VERSION, evidence_dir=restored_evidence
    )
    assert result["validation"]["evidence"]["artifact_count"] == 1
    restored = list_evidence_artifacts(restored_db)
    assert len(restored) == 1
    assert verify_evidence_store(restored_db, restored_evidence)["valid"] is True
    assert (restored_evidence / restored[0]["stored_filename"]).read_bytes() == b'{"patched":true}'


def test_recovery_bundle_rejects_tampered_evidence(tmp_path: Path):
    db = tmp_path / "live.sqlite3"
    evidence_dir = tmp_path / "evidence"
    request = _pending(db)
    item = store_verification_evidence(
        db, evidence_dir, verification_id=request["verification_id"], filename="proof.txt",
        content=b"original", notes="", actor="operator", max_bytes=1024,
    )
    bundle = tmp_path / "bundle.zip"
    tampered = tmp_path / "tampered.zip"
    create_recovery_bundle(db, bundle, evidence_dir=evidence_dir, created_by="admin", base_dir=Path(__file__).resolve().parents[1])
    with zipfile.ZipFile(bundle) as src, zipfile.ZipFile(tampered, "w", zipfile.ZIP_DEFLATED) as dst:
        for info in src.infolist():
            data = src.read(info.filename)
            if info.filename == f"evidence/{item['stored_filename']}":
                data = b"changed"
            dst.writestr(info, data)
    with pytest.raises(ValueError, match="해시 불일치"):
        validate_recovery_bundle(tampered, current_schema_version=CURRENT_SCHEMA_VERSION)


def test_web_upload_download_and_integrity_api(client: TestClient):
    token = client.get("/").cookies.get(main.CSRF_COOKIE) or client.cookies.get(main.CSRF_COOKIE)
    finding = client.get("/api/v1/findings/F-0001").json()
    mitigated = client.post(
        "/finding/F-0001",
        data={
            "csrf_token": token, "row_version": finding["row_version"], "status": "MITIGATED",
            "owner": "operator", "due_date": "", "exception_expiry": "",
            "risk_acceptance_reason": "", "risk_acceptance_approver": "", "notes": "patched",
        },
        follow_redirects=False,
    )
    assert mitigated.status_code == 303
    finding = client.get("/api/v1/findings/F-0001").json()
    request = client.post(
        "/finding/F-0001/verification-requests",
        data={"csrf_token": token, "row_version": finding["row_version"], "method": "RETEST", "evidence_note": "manual retest"},
        follow_redirects=False,
    )
    assert request.status_code == 303
    verification_id = client.get("/api/v1/verifications?finding_id=F-0001").json()["items"][0]["verification_id"]
    uploaded = client.post(
        f"/verifications/{verification_id}/evidence",
        data={"csrf_token": token, "notes": "test log"},
        files={"file": ("retest.log", b"pass\n", "text/plain")},
        follow_redirects=False,
    )
    assert uploaded.status_code == 303
    item = list_evidence_artifacts(main.DB_PATH, verification_id=verification_id)[0]
    assert item["scan_status"] == "BASELINE_ONLY"
    blocked = client.get(f"/evidence/{item['evidence_id']}/download")
    assert blocked.status_code == 423
    waived = client.post(
        f"/evidence/{item['evidence_id']}/scan-waiver",
        data={"csrf_token": token, "reason": "isolated baseline review"},
        follow_redirects=False,
    )
    assert waived.status_code == 303
    download = client.get(f"/evidence/{item['evidence_id']}/download")
    assert download.status_code == 200
    assert download.content == b"pass\n"
    assert client.get(f"/finding/F-0001").status_code == 200


def test_raw_sqlite_restore_rejects_database_with_external_evidence(client: TestClient):
    token = client.get("/").cookies.get(main.CSRF_COOKIE) or client.cookies.get(main.CSRF_COOKIE)
    finding = client.get("/api/v1/findings/F-0001").json()
    client.post(
        "/finding/F-0001",
        data={
            "csrf_token": token, "row_version": finding["row_version"], "status": "MITIGATED",
            "owner": "operator", "due_date": "", "exception_expiry": "",
            "risk_acceptance_reason": "", "risk_acceptance_approver": "", "notes": "patched",
        }, follow_redirects=False,
    )
    finding = client.get("/api/v1/findings/F-0001").json()
    client.post(
        "/finding/F-0001/verification-requests",
        data={"csrf_token": token, "row_version": finding["row_version"], "method": "RETEST", "evidence_note": "retest"},
        follow_redirects=False,
    )
    verification_id = client.get("/api/v1/verifications?finding_id=F-0001").json()["items"][0]["verification_id"]
    client.post(
        f"/verifications/{verification_id}/evidence",
        data={"csrf_token": token, "notes": "proof"},
        files={"file": ("proof.txt", b"proof", "text/plain")}, follow_redirects=False,
    )
    raw = client.get("/export/backup.sqlite3")
    restored = client.post(
        "/restore-backup", data={"csrf_token": token, "confirmation": "RESTORE"},
        files={"file": ("backup.sqlite3", raw.content, "application/vnd.sqlite3")},
        follow_redirects=False,
    )
    assert restored.status_code == 400
    assert "복구 번들 ZIP" in restored.text
