from __future__ import annotations

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
    list_evidence_custody_events,
    record_evidence_access,
    scan_evidence_artifact,
    store_verification_evidence,
    transfer_evidence_custody,
    verify_evidence_custody_chain,
    verify_evidence_store,
)
from app.services.recovery import create_recovery_bundle, validate_recovery_bundle


def _row(fid: str = "CUST-1") -> dict:
    return {
        "finding_id": fid,
        "product": "Custody Demo",
        "asset_name": "custody-host",
        "cve_id": "CVE-2026-17001",
        "status": "OPEN",
        "scanner_source": "custody-scanner",
        "record_state": "ACTIVE",
        "row_version": 1,
        "score": 60,
        "first_seen_at": "2026-07-01",
        "first_scored_at": "2026-07-01",
    }


def _pending(db: Path, fid: str = "CUST-1") -> dict:
    init_db(db)
    apply_import_batch(db, [_row(fid)], scanner_source="custody-scanner", filename="one.csv")
    current = get_finding(db, fid)
    update_workflow(
        db, fid, status="MITIGATED", owner="operator", due_date="", exception_expiry="",
        risk_acceptance_reason="", risk_acceptance_approver="", notes="patched",
        actor="operator", expected_version=current["row_version"],
    )
    current = get_finding(db, fid)
    return create_remediation_verification_request(
        db, fid, method="RETEST", evidence_note="proof follows", actor="operator",
        expected_version=current["row_version"],
    )


def test_schema_v17_has_provenance_and_custody_chain(tmp_path: Path):
    db = tmp_path / "schema.sqlite3"
    init_db(db)
    with sqlite3.connect(db) as conn:
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        columns = {row[1] for row in conn.execute("PRAGMA table_info(verification_evidence_artifacts)")}
        triggers = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='trigger'")}
    assert version == CURRENT_SCHEMA_VERSION == 40
    assert "evidence_custody_events" in tables
    assert {
        "source_type", "source_reference", "acquisition_method", "collected_by", "collected_at",
        "current_custodian", "custody_last_seq", "custody_last_hash",
    } <= columns
    assert {"evidence_custody_immutable_update", "evidence_custody_immutable_delete"} <= triggers


def test_provenance_custody_transfer_access_and_integrity(tmp_path: Path):
    db = tmp_path / "custody.sqlite3"
    evidence_dir = tmp_path / "evidence"
    request = _pending(db)
    item = store_verification_evidence(
        db, evidence_dir, verification_id=request["verification_id"], filename="retest.log",
        content=b"retest passed", notes="ticket evidence", actor="collector-a", max_bytes=1024,
        source_type="TICKET_ATTACHMENT", source_reference="CHG-1700",
        acquisition_method="EXPORT", collected_at="2026-07-21T01:02:03+00:00",
    )
    assert item["source_type"] == "TICKET_ATTACHMENT"
    assert item["source_reference"] == "CHG-1700"
    assert item["current_custodian"] == "collector-a"
    assert verify_evidence_custody_chain(db, item["evidence_id"])["valid"] is True

    item = scan_evidence_artifact(db, evidence_dir, item["evidence_id"], mode="builtin", actor="scanner")
    item = transfer_evidence_custody(
        db, item["evidence_id"], actor="collector-a", to_custodian="approver-b", purpose="approval review"
    )
    record_evidence_access(db, item["evidence_id"], actor="approver-b", purpose="review download")
    events = list(reversed(list_evidence_custody_events(db, item["evidence_id"])))
    assert [event["event_type"] for event in events] == ["ACQUIRED", "SCANNED", "TRANSFERRED", "DOWNLOADED"]
    assert events[2]["from_custodian"] == "collector-a"
    assert events[2]["to_custodian"] == "approver-b"
    integrity = verify_evidence_custody_chain(db, item["evidence_id"])
    assert integrity["valid"] is True
    assert integrity["current_custodian"] == "approver-b"
    assert integrity["event_count"] == 4


def test_provenance_validation_and_same_custodian_block(tmp_path: Path):
    db = tmp_path / "validation.sqlite3"
    evidence_dir = tmp_path / "evidence"
    request = _pending(db)
    with pytest.raises(ValueError, match="출처 유형"):
        store_verification_evidence(
            db, evidence_dir, verification_id=request["verification_id"], filename="proof.txt",
            content=b"proof", notes="", actor="collector", max_bytes=1024, source_type="UNKNOWN",
        )
    with pytest.raises(ValueError, match="ISO 8601"):
        store_verification_evidence(
            db, evidence_dir, verification_id=request["verification_id"], filename="proof.txt",
            content=b"proof", notes="", actor="collector", max_bytes=1024, collected_at="yesterday",
        )
    item = store_verification_evidence(
        db, evidence_dir, verification_id=request["verification_id"], filename="proof.txt",
        content=b"proof", notes="", actor="collector", max_bytes=1024,
    )
    with pytest.raises(ValueError, match="다른 담당자"):
        transfer_evidence_custody(db, item["evidence_id"], actor="collector", to_custodian="collector", purpose="same")


def test_custody_events_and_provenance_are_immutable_and_tampering_detected(tmp_path: Path):
    db = tmp_path / "immutable.sqlite3"
    evidence_dir = tmp_path / "evidence"
    request = _pending(db)
    item = store_verification_evidence(
        db, evidence_dir, verification_id=request["verification_id"], filename="proof.txt",
        content=b"proof", notes="", actor="collector", max_bytes=1024,
    )
    with sqlite3.connect(db) as conn:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("UPDATE evidence_custody_events SET purpose='changed' WHERE evidence_id=?", (item["evidence_id"],))
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("UPDATE verification_evidence_artifacts SET source_reference='changed' WHERE evidence_id=?", (item["evidence_id"],))
        conn.execute(
            "UPDATE verification_evidence_artifacts SET current_custodian='tampered' WHERE evidence_id=?",
            (item["evidence_id"],),
        )
        conn.commit()
    result = verify_evidence_custody_chain(db, item["evidence_id"])
    assert result["valid"] is False
    assert "current_custodian_mismatch" in result["issues"]
    assert verify_evidence_store(db, evidence_dir)["valid"] is False


def test_v16_evidence_migration_backfills_genesis_custody_event(tmp_path: Path):
    db = tmp_path / "migrate.sqlite3"
    evidence_dir = tmp_path / "evidence"
    request = _pending(db)
    item = store_verification_evidence(
        db, evidence_dir, verification_id=request["verification_id"], filename="proof.txt",
        content=b"proof", notes="", actor="legacy-user", max_bytes=1024,
    )
    with sqlite3.connect(db) as conn:
        conn.execute("DROP TRIGGER evidence_custody_immutable_delete")
        conn.execute("DROP TRIGGER verification_evidence_core_immutable")
        conn.execute("DELETE FROM evidence_custody_events WHERE evidence_id=?", (item["evidence_id"],))
        conn.execute(
            "UPDATE verification_evidence_artifacts SET custody_last_seq=0,custody_last_hash='',current_custodian='',collected_by='',collected_at='' WHERE evidence_id=?",
            (item["evidence_id"],),
        )
        conn.execute("PRAGMA user_version=16")
        conn.commit()
    init_db(db)
    events = list_evidence_custody_events(db, item["evidence_id"])
    migrated = get_evidence_artifact(db, item["evidence_id"])
    assert len(events) == 1
    assert events[0]["event_type"] == "LEGACY_IMPORTED"
    assert migrated["current_custodian"] == "legacy-user"
    assert verify_evidence_custody_chain(db, item["evidence_id"])["valid"] is True


def test_recovery_manifest_carries_and_validates_custody(tmp_path: Path):
    db = tmp_path / "live.sqlite3"
    evidence_dir = tmp_path / "evidence"
    bundle = tmp_path / "bundle.zip"
    request = _pending(db)
    item = store_verification_evidence(
        db, evidence_dir, verification_id=request["verification_id"], filename="proof.txt",
        content=b"proof", notes="", actor="collector", max_bytes=1024,
        source_type="SCANNER_EXPORT", source_reference="scan-17", acquisition_method="EXPORT",
    )
    scan_evidence_artifact(db, evidence_dir, item["evidence_id"], mode="builtin", actor="scanner")
    create_recovery_bundle(db, bundle, evidence_dir=evidence_dir, created_by="admin")
    checked = validate_recovery_bundle(bundle, current_schema_version=CURRENT_SCHEMA_VERSION)
    assert checked["evidence"]["artifact_count"] == 1
    with zipfile.ZipFile(bundle) as archive:
        manifest = json.loads(archive.read("evidence-manifest.json"))
    artifact = manifest["artifacts"][0]
    assert artifact["source_reference"] == "scan-17"
    assert artifact["custody_integrity"]["valid"] is True
    assert artifact["custody_integrity"]["event_count"] == 2

    with sqlite3.connect(db) as conn:
        conn.execute(
            "UPDATE verification_evidence_artifacts SET custody_last_hash='bad' WHERE evidence_id=?",
            (item["evidence_id"],),
        )
        conn.commit()
    with pytest.raises(ValueError, match="보관 사슬"):
        create_recovery_bundle(db, tmp_path / "bad.zip", evidence_dir=evidence_dir, created_by="admin")


def test_web_upload_download_transfer_and_custody_api(client: TestClient):
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
    uploaded = client.post(
        f"/verifications/{verification_id}/evidence",
        data={
            "csrf_token": token, "notes": "ticket proof", "source_type": "TICKET_ATTACHMENT",
            "source_reference": "CHG-17", "acquisition_method": "EXPORT",
            "collected_at": "2026-07-21T01:00:00+00:00",
        },
        files={"file": ("proof.txt", b"proof", "text/plain")}, follow_redirects=False,
    )
    assert uploaded.status_code == 303
    from app.services.evidence import list_evidence_artifacts
    item = list_evidence_artifacts(main.DB_PATH, verification_id=verification_id)[0]
    assert item["source_reference"] == "CHG-17"
    assert item["scan_status"] == "BASELINE_ONLY"
    waived = client.post(
        f"/evidence/{item['evidence_id']}/scan-waiver",
        data={"csrf_token": token, "reason": "isolated baseline review"},
        follow_redirects=False,
    )
    assert waived.status_code == 303
    downloaded = client.get(f"/evidence/{item['evidence_id']}/download")
    assert downloaded.status_code == 200
    transferred = client.post(
        f"/evidence/{item['evidence_id']}/custody-transfer",
        data={"csrf_token": token, "to_custodian": "approver-b", "purpose": "approval"},
        follow_redirects=False,
    )
    assert transferred.status_code == 303
    custody = client.get(f"/api/v1/evidence/{item['evidence_id']}/custody").json()
    types = [row["event_type"] for row in reversed(custody["items"])]
    assert types == ["ACQUIRED", "SCANNED", "SCAN_WAIVED", "DOWNLOADED", "TRANSFERRED"]
    assert custody["integrity"]["valid"] is True
    assert custody["integrity"]["current_custodian"] == "approver-b"
