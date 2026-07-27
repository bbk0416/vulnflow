from __future__ import annotations

import os
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import app.main as main
from app.core.storage import (
    CURRENT_SCHEMA_VERSION,
    apply_import_batch,
    create_background_job,
    create_remediation_verification_request,
    decide_remediation_verification_request,
    get_finding,
    init_db,
    update_workflow,
)
from app.services.evidence import (
    EICAR_MARKER,
    evidence_download_allowed,
    get_evidence_artifact,
    list_evidence_artifacts,
    scan_evidence_artifact,
    scan_evidence_path,
    store_verification_evidence,
    waive_evidence_scan,
)


def _row(fid: str = "Q-1") -> dict:
    return {
        "finding_id": fid,
        "product": "Quarantine Demo",
        "asset_name": "quarantine-host",
        "cve_id": "CVE-2026-16001",
        "status": "OPEN",
        "scanner_source": "quarantine-scanner",
        "record_state": "ACTIVE",
        "row_version": 1,
        "score": 60,
        "first_seen_at": "2026-07-01",
        "first_scored_at": "2026-07-01",
    }


def _pending(db: Path, fid: str = "Q-1") -> dict:
    init_db(db)
    apply_import_batch(db, [_row(fid)], scanner_source="quarantine-scanner", filename="one.csv")
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


def test_schema_v16_has_scan_columns_and_job_type(tmp_path: Path):
    db = tmp_path / "schema.sqlite3"
    init_db(db)
    with sqlite3.connect(db) as conn:
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        columns = {row[1] for row in conn.execute("PRAGMA table_info(verification_evidence_artifacts)")}
    assert version == CURRENT_SCHEMA_VERSION == 40
    assert {
        "scan_status", "scan_engine", "scan_signature", "scan_details", "scanned_at",
        "scan_error", "scan_waived_by", "scan_waived_at", "scan_waiver_reason",
    } <= columns
    job = create_background_job(
        db, job_type="EVIDENCE_SCAN", payload={"evidence_id": "EVD-X"}, requested_by="admin"
    )
    assert job["job_type"] == "EVIDENCE_SCAN"


def test_builtin_scan_clean_and_eicar_detection(tmp_path: Path):
    clean = tmp_path / "clean.txt"
    clean.write_bytes(b"retest passed\n")
    infected = tmp_path / "eicar.txt"
    infected.write_bytes(b"prefix " + EICAR_MARKER + b" suffix")
    clean_result = scan_evidence_path(clean, mode="builtin")
    infected_result = scan_evidence_path(infected, mode="builtin")
    assert clean_result["scan_status"] == "BASELINE_ONLY"
    assert clean_result["scan_engine"] == "builtin-baseline"
    assert infected_result["scan_status"] == "INFECTED"
    assert infected_result["scan_signature"] == "EICAR-Test-Signature"


def test_init_db_reclassifies_legacy_builtin_clean_verdict(tmp_path: Path):
    db = tmp_path / "legacy.sqlite3"
    evidence_dir = tmp_path / "evidence"
    request = _pending(db)
    item = store_verification_evidence(
        db, evidence_dir, verification_id=request["verification_id"], filename="legacy.log",
        content=b"legacy", notes="", actor="operator", max_bytes=1024,
    )
    from app.services.evidence import record_evidence_scan_result
    record_evidence_scan_result(
        db, item["evidence_id"],
        result={
            "scan_status": "CLEAN", "scan_engine": "builtin-baseline",
            "scan_signature": "baseline-no-eicar", "scan_details": "legacy verdict",
            "scan_error": "",
        },
        actor="legacy-scanner",
    )
    init_db(db)
    assert get_evidence_artifact(db, item["evidence_id"])["scan_status"] == "BASELINE_ONLY"


def test_disabled_scan_requires_admin_waiver(tmp_path: Path):
    db = tmp_path / "disabled.sqlite3"
    evidence_dir = tmp_path / "evidence"
    request = _pending(db)
    item = store_verification_evidence(
        db, evidence_dir, verification_id=request["verification_id"], filename="proof.txt",
        content=b"proof", notes="", actor="operator", max_bytes=1024,
    )
    item = scan_evidence_artifact(db, evidence_dir, item["evidence_id"], mode="disabled", actor="scanner")
    assert item["scan_status"] == "NOT_SCANNED"
    assert evidence_download_allowed(item, require_clean=True) is False
    item = waive_evidence_scan(db, item["evidence_id"], actor="admin", reason="isolated offline review")
    assert item["scan_status"] == "WAIVED"
    assert item["scan_waived_by"] == "admin"
    assert evidence_download_allowed(item, require_clean=True) is True


def test_infected_evidence_cannot_be_waived_or_approved(tmp_path: Path):
    db = tmp_path / "infected.sqlite3"
    evidence_dir = tmp_path / "evidence"
    request = _pending(db)
    item = store_verification_evidence(
        db, evidence_dir, verification_id=request["verification_id"], filename="eicar.txt",
        content=EICAR_MARKER, notes="", actor="operator", max_bytes=1024,
    )
    item = scan_evidence_artifact(db, evidence_dir, item["evidence_id"], mode="builtin", actor="scanner")
    assert item["scan_status"] == "INFECTED"
    with pytest.raises(ValueError, match="면제할 수 없습니다"):
        waive_evidence_scan(db, item["evidence_id"], actor="admin", reason="force")
    with pytest.raises(ValueError, match="검사 또는 관리자 면제"):
        decide_remediation_verification_request(
            db, request["verification_id"], decision="APPROVE", decision_note="verified", actor="approver"
        )


def test_builtin_baseline_requires_explicit_waiver_for_approval(tmp_path: Path):
    db = tmp_path / "clean.sqlite3"
    evidence_dir = tmp_path / "evidence"
    request = _pending(db)
    item = store_verification_evidence(
        db, evidence_dir, verification_id=request["verification_id"], filename="proof.log",
        content=b"retest passed", notes="", actor="operator", max_bytes=1024,
    )
    item = scan_evidence_artifact(db, evidence_dir, item["evidence_id"], mode="builtin", actor="scanner")
    assert item["scan_status"] == "BASELINE_ONLY"
    assert evidence_download_allowed(item, require_clean=True) is False
    with pytest.raises(ValueError, match="검사 또는 관리자 면제"):
        decide_remediation_verification_request(
            db, request["verification_id"], decision="APPROVE", decision_note="verified", actor="approver"
        )
    item = waive_evidence_scan(db, item["evidence_id"], actor="admin", reason="isolated baseline review")
    assert item["scan_status"] == "WAIVED"
    decided = decide_remediation_verification_request(
        db, request["verification_id"], decision="APPROVE", decision_note="verified", actor="approver"
    )
    assert decided["status"] == "APPROVED"


def test_clamscan_adapter_clean_infected_error_and_missing(tmp_path: Path):
    scanner = tmp_path / "fake-clamscan"
    scanner.write_text(
        "#!/bin/sh\ncase \"$3\" in *infected*) echo \"$3: Unit.Test FOUND\"; exit 1;; *error*) echo fail >&2; exit 2;; *) echo \"$3: OK\"; exit 0;; esac\n",
        encoding="utf-8",
    )
    scanner.chmod(0o755)
    clean = tmp_path / "clean.txt"; clean.write_text("ok")
    infected = tmp_path / "infected.txt"; infected.write_text("bad")
    error = tmp_path / "error.txt"; error.write_text("error")
    assert scan_evidence_path(clean, mode="clamscan", clamscan_path=str(scanner))["scan_status"] == "CLEAN"
    infected_result = scan_evidence_path(infected, mode="clamscan", clamscan_path=str(scanner))
    assert infected_result["scan_status"] == "INFECTED"
    assert infected_result["scan_signature"] == "Unit.Test"
    assert scan_evidence_path(error, mode="clamscan", clamscan_path=str(scanner))["scan_status"] == "ERROR"
    assert scan_evidence_path(clean, mode="clamscan", clamscan_path=str(tmp_path / "missing"))["scan_status"] == "ERROR"


def test_web_eicar_is_quarantined_and_download_blocked(client: TestClient):
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
        f"/verifications/{verification_id}/evidence", data={"csrf_token": token, "notes": "eicar"},
        files={"file": ("eicar.txt", EICAR_MARKER, "text/plain")}, follow_redirects=False,
    )
    assert uploaded.status_code == 303
    item = list_evidence_artifacts(main.DB_PATH, verification_id=verification_id)[0]
    assert item["scan_status"] == "INFECTED"
    download = client.get(f"/evidence/{item['evidence_id']}/download")
    assert download.status_code == 423
    approval = client.post(
        f"/verifications/{verification_id}/decision",
        data={"csrf_token": token, "decision": "APPROVE", "decision_note": "verified"},
        follow_redirects=False,
    )
    assert approval.status_code == 400
