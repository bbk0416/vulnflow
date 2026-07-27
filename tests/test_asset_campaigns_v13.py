from __future__ import annotations

from pathlib import Path
import sqlite3

import pytest
from fastapi.testclient import TestClient

import app.main as main
from app.core.storage import (
    CURRENT_SCHEMA_VERSION,
    ConcurrencyError,
    apply_asset_inventory,
    add_campaign_findings,
    apply_import_batch,
    bulk_update_workflow,
    create_campaign,
    get_asset,
    get_campaign,
    get_finding,
    init_db,
    list_assets,
    list_campaigns,
    list_exposure_groups,
    remove_campaign_finding,
    update_campaign_status,
)


def _finding(fid: str, cve: str, asset_id: str, asset_name: str, *, score: int = 70, kev: int = 0):
    return {
        "finding_id": fid,
        "product": "Billing API",
        "product_version": "1.0",
        "asset_id": asset_id,
        "asset_name": asset_name,
        "environment": "prod",
        "cve_id": cve,
        "component": "openssl",
        "component_version": "3.0",
        "status": "OPEN",
        "scanner_source": "scanner-v13",
        "record_state": "ACTIVE",
        "row_version": 1,
        "score": score,
        "kev": kev,
        "epss": 0.8,
        "asset_criticality": 3,
        "data_sensitivity": 3,
        "internet_exposed": 0,
        "first_seen_at": "2026-07-01",
        "first_scored_at": "2026-07-01",
    }


def _csrf(client: TestClient) -> str:
    assert client.get("/").status_code == 200
    return client.cookies.get(main.CSRF_COOKIE)


def test_v12_database_migrates_and_backfills_assets(tmp_path: Path):
    db = tmp_path / "legacy-v12.sqlite3"
    fixture = (Path(__file__).parent / "fixtures" / "v3_schema.sql").read_text(encoding="utf-8")
    with sqlite3.connect(db) as conn:
        conn.executescript(fixture)
        conn.execute(
            "INSERT INTO findings(finding_id,product,cve_id,status,asset_id,asset_name,environment,asset_criticality,data_sensitivity,internet_exposed) VALUES(?,?,?,?,?,?,?,?,?,?)",
            ("LEG-1", "Legacy", "CVE-2026-10001", "OPEN", "srv-1", "legacy-api", "prod", 4, 5, 1),
        )
        conn.execute("PRAGMA user_version=12")
        conn.commit()
    init_db(db)
    with sqlite3.connect(db) as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == CURRENT_SCHEMA_VERSION
        ref = conn.execute("SELECT asset_ref_id FROM findings WHERE finding_id='LEG-1'").fetchone()[0]
        asset = conn.execute("SELECT asset_name,criticality,data_sensitivity,internet_exposed FROM assets WHERE asset_ref_id=?", (ref,)).fetchone()
    assert asset == ("legacy-api", 4, 5, 1)


def test_asset_inventory_links_findings_and_exposure_groups(tmp_path: Path):
    db = tmp_path / "assets.sqlite3"
    init_db(db)
    apply_import_batch(
        db,
        [
            _finding("F-1", "CVE-2026-20001", "api-1", "billing-api-a", kev=1),
            _finding("F-2", "CVE-2026-20001", "api-2", "billing-api-b", score=65),
        ],
        scanner_source="scanner-v13",
        filename="scan.csv",
    )
    assets = list_assets(db)
    assert len(assets) == 2
    assert sum(a["finding_count"] for a in assets) == 2
    result = apply_asset_inventory(
        db,
        [{
            "asset_id": "api-1", "asset_name": "billing-api-a", "service_name": "Billing",
            "business_unit": "Payments", "owner": "platform-team", "environment": "prod",
            "criticality": 5, "data_sensitivity": 5, "internet_exposed": True, "tags": "pci,external",
        }],
        actor="asset-owner",
    )
    assert result["linked_findings"] == 1
    finding = get_finding(db, "F-1")
    assert finding["asset_criticality"] == 5
    assert finding["internet_exposed"] == 1
    asset = get_asset(db, finding["asset_ref_id"])
    assert asset["service_name"] == "Billing"
    assert asset["business_unit"] == "Payments"
    groups = list_exposure_groups(db)
    group = next(g for g in groups if g["cve_id"] == "CVE-2026-20001")
    assert group["asset_count"] == 2
    assert group["active_count"] == 2
    assert group["kev_count"] == 1


def test_campaign_lifecycle_and_optimistic_lock(tmp_path: Path):
    db = tmp_path / "campaign.sqlite3"
    init_db(db)
    apply_import_batch(
        db,
        [_finding("F-1", "CVE-2026-30001", "a-1", "a1"), _finding("F-2", "CVE-2026-30001", "a-2", "a2")],
        scanner_source="scanner-v13",
        filename="scan.csv",
    )
    campaign = create_campaign(
        db, title="OpenSSL emergency rollout", description="Patch affected API nodes",
        owner="platform", due_date="2026-08-01", finding_ids=["F-1", "F-2"], actor="operator",
    )
    assert campaign["finding_count"] == 2
    assert campaign["status"] == "PLANNED"
    active = update_campaign_status(
        db, campaign["campaign_id"], status="ACTIVE", actor="operator", expected_version=campaign["row_version"]
    )
    assert active["status"] == "ACTIVE"
    with pytest.raises(ValueError, match="활성 취약점"):
        update_campaign_status(
            db, campaign["campaign_id"], status="COMPLETED", actor="operator",
            expected_version=active["row_version"],
        )
    with pytest.raises(ConcurrencyError):
        update_campaign_status(
            db, campaign["campaign_id"], status="CANCELLED", actor="stale",
            expected_version=campaign["row_version"],
        )
    assert list_campaigns(db, status="ACTIVE")[0]["campaign_id"] == campaign["campaign_id"]


def test_asset_and_campaign_ui_routes(client: TestClient):
    assert client.get("/assets").status_code == 200
    assert client.get("/exposure-groups").status_code == 200
    assert client.get("/campaigns").status_code == 200
    token = _csrf(client)
    asset_csv = (
        b"asset_id,asset_name,service_name,business_unit,owner,environment,criticality,data_sensitivity,internet_exposed,tags\n"
        b"edge-prod-01,Edge Gateway,Remote Access,Infrastructure,edge-team,prod,5,4,1,external\n"
    )
    uploaded = client.post(
        "/assets/upload", data={"csrf_token": token},
        files={"file": ("assets.csv", asset_csv, "text/csv")}, follow_redirects=False,
    )
    assert uploaded.status_code == 303
    assets = client.get("/api/v1/assets?query=Edge").json()["items"]
    assert any(a["external_asset_id"] == "edge-prod-01" for a in assets)
    created = client.post(
        "/campaigns",
        data={
            "csrf_token": token, "title": "PAN-OS response", "cve_id": "CVE-2024-3400",
            "owner": "network-team", "due_date": "2026-08-01", "description": "KEV response",
            "finding_ids": "", "apply_workflow": "true",
        },
        follow_redirects=False,
    )
    assert created.status_code == 303
    location = created.headers["location"]
    detail = client.get(location)
    assert detail.status_code == 200 and "PAN-OS response" in detail.text
    groups = client.get("/api/v1/exposure-groups").json()
    assert groups["count"] >= 1


def test_authoritative_asset_context_survives_scanner_refresh(client: TestClient):
    token = _csrf(client)
    assets_csv = (
        b"asset_id,asset_name,service_name,criticality,data_sensitivity,internet_exposed\n"
        b"ctx-asset-1,Critical API,Payment Service,5,5,1\n"
    )
    assert client.post(
        "/assets/upload", data={"csrf_token": token},
        files={"file": ("assets.csv", assets_csv, "text/csv")}, follow_redirects=False,
    ).status_code == 303
    findings_csv = (
        b"finding_id,product,asset_id,asset_name,cve_id,cvss,asset_criticality,data_sensitivity,internet_exposed\n"
        b"CTX-F-1,Payment API,ctx-asset-1,scanner-name,CVE-2026-41001,7.5,1,1,0\n"
    )
    assert client.post(
        "/upload/findings", data={"csrf_token": token, "scanner_source": "scanner-context"},
        files={"file": ("findings.csv", findings_csv, "text/csv")}, follow_redirects=False,
    ).status_code == 303
    item = client.get("/api/v1/findings/CTX-F-1").json()
    assert item["asset_name"] == "Critical API"
    assert item["asset_criticality"] == 5
    assert item["data_sensitivity"] == 5
    assert item["internet_exposed"] == 1


def test_campaign_member_management_and_completion_guard(tmp_path: Path):
    db = tmp_path / "campaign-members.sqlite3"
    init_db(db)
    apply_import_batch(
        db,
        [_finding("F-1", "CVE-2026-50001", "m-1", "m1"), _finding("F-2", "CVE-2026-50002", "m-2", "m2")],
        scanner_source="scanner-v13", filename="scan.csv",
    )
    campaign = create_campaign(db, title="Quarterly rollout", finding_ids=["F-1"], actor="operator")
    assert add_campaign_findings(db, campaign["campaign_id"], ["F-2"], actor="operator") == 1
    assert get_campaign(db, campaign["campaign_id"])["finding_count"] == 2
    assert remove_campaign_finding(db, campaign["campaign_id"], "F-1", actor="operator") is True
    current = get_campaign(db, campaign["campaign_id"])
    with pytest.raises(ValueError, match="활성 취약점"):
        update_campaign_status(db, campaign["campaign_id"], status="COMPLETED", actor="operator", expected_version=current["row_version"])
    bulk_update_workflow(db, ["F-2"], status="CLOSED", notes_append="campaign completed", actor="operator")
    current = get_campaign(db, campaign["campaign_id"])
    completed = update_campaign_status(db, campaign["campaign_id"], status="COMPLETED", actor="operator", expected_version=current["row_version"])
    assert completed["status"] == "COMPLETED"
    with pytest.raises(ValueError):
        add_campaign_findings(db, campaign["campaign_id"], ["F-1"], actor="operator")


def test_storage_layer_preserves_inventory_authority(tmp_path: Path):
    db = tmp_path / "authority.sqlite3"
    init_db(db)
    apply_asset_inventory(
        db,
        [{
            "asset_id": "auth-1", "asset_name": "Authoritative API", "environment": "prod",
            "criticality": 5, "data_sensitivity": 4, "internet_exposed": True,
        }],
        actor="asset-owner",
    )
    apply_import_batch(
        db,
        [_finding("AUTH-F-1", "CVE-2026-60001", "auth-1", "scanner-name") | {
            "environment": "dev", "asset_criticality": 1, "data_sensitivity": 1,
            "internet_exposed": 0,
        }],
        scanner_source="direct-storage", filename="scan.csv",
    )
    item = get_finding(db, "AUTH-F-1")
    assert item["asset_name"] == "Authoritative API"
    assert item["environment"] == "prod"
    assert item["asset_criticality"] == 5
    assert item["data_sensitivity"] == 4
    assert item["internet_exposed"] == 1


def test_campaign_creation_and_workflow_are_atomic(tmp_path: Path):
    db = tmp_path / "campaign-atomic.sqlite3"
    init_db(db)
    apply_import_batch(
        db, [_finding("F-ATOMIC", "CVE-2026-60002", "atomic-1", "atomic")],
        scanner_source="scanner-v13", filename="scan.csv",
    )
    campaign = create_campaign(
        db, title="Atomic rollout", finding_ids=["F-ATOMIC"], owner="platform",
        due_date="2026-08-10", actor="operator", apply_workflow=True,
    )
    finding = get_finding(db, "F-ATOMIC")
    assert campaign["status"] == "ACTIVE"
    assert finding["status"] == "IN_PROGRESS"
    assert finding["owner"] == "platform"
    assert finding["due_date"] == "2026-08-10"

    with sqlite3.connect(db) as conn:
        conn.execute(
            "CREATE TRIGGER fail_campaign_workflow BEFORE UPDATE ON findings "
            "BEGIN SELECT RAISE(ABORT, 'forced workflow failure'); END"
        )
        conn.commit()
    with pytest.raises(sqlite3.IntegrityError, match="forced workflow failure"):
        create_campaign(
            db, title="Must rollback", finding_ids=["F-ATOMIC"], actor="operator",
            apply_workflow=True,
        )
    assert all(item["title"] != "Must rollback" for item in list_campaigns(db))


def test_asset_upload_rejects_non_csv(client: TestClient):
    token = _csrf(client)
    response = client.post(
        "/assets/upload", data={"csrf_token": token},
        files={"file": ("assets.txt", b"asset_id,asset_name\na-1,A", "text/plain")},
    )
    assert response.status_code == 400
    assert "CSV" in response.text
