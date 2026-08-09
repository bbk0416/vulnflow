from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import app.main as main
from app.core.storage import (
    ConcurrencyError,
    acquire_cluster_lease,
    active_cluster_lease,
    begin_cluster_write_activity,
    connect,
    count_cluster_write_activities,
    deregister_cluster_instance,
    end_cluster_write_activity,
    get_cluster_instance,
    init_coordination_db,
    init_db,
    list_cluster_instances,
    prune_stale_cluster_instances,
    register_cluster_instance,
    release_cluster_lease,
    renew_cluster_lease,
    restore_database,
    upsert_findings,
)


def test_instance_registration_heartbeat_and_stop(tmp_path: Path):
    coord = tmp_path / "coord.sqlite3"
    init_coordination_db(coord)
    created = register_cluster_instance(
        coord, instance_id="node-a", hostname="host-a", process_id=101,
        capabilities=["api", "worker"], metadata={"zone": "local"},
    )
    assert created["status"] == "ACTIVE"
    assert created["capabilities"] == ["api", "worker"]
    assert get_cluster_instance(coord, "node-a")["metadata"] == {"zone": "local"}
    assert deregister_cluster_instance(coord, instance_id="node-a") is True
    assert get_cluster_instance(coord, "node-a")["status"] == "STOPPED"


def test_stale_instance_pruning(tmp_path: Path):
    coord = tmp_path / "coord.sqlite3"
    init_coordination_db(coord)
    register_cluster_instance(coord, instance_id="node-a", hostname="host", process_id=1)
    old = (datetime.now(timezone.utc) - timedelta(minutes=5)).replace(microsecond=0).isoformat()
    with connect(coord) as conn:
        conn.execute("UPDATE cluster_instances SET last_heartbeat_at=? WHERE instance_id='node-a'", (old,))
        conn.commit()
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=30)).replace(microsecond=0).isoformat()
    assert prune_stale_cluster_instances(coord, stale_before=cutoff) == 1
    assert list_cluster_instances(coord)[0]["status"] == "STALE"


def test_fenced_lease_exclusion_and_failover(tmp_path: Path):
    coord = tmp_path / "coord.sqlite3"
    init_coordination_db(coord)
    first = acquire_cluster_lease(
        coord, lease_name="scheduler", holder_id="node-a", ttl_seconds=30, purpose="test"
    )
    assert first and first["fencing_token"] == 1
    assert acquire_cluster_lease(
        coord, lease_name="scheduler", holder_id="node-b", ttl_seconds=30
    ) is None
    renewed = renew_cluster_lease(
        coord, lease_name="scheduler", holder_id="node-a",
        fencing_token=first["fencing_token"], ttl_seconds=30,
    )
    assert renewed["fencing_token"] == 1
    expired = (datetime.now(timezone.utc) - timedelta(seconds=1)).replace(microsecond=0).isoformat()
    with connect(coord) as conn:
        conn.execute("UPDATE cluster_leases SET lease_expires_at=? WHERE lease_name='scheduler'", (expired,))
        conn.commit()
    second = acquire_cluster_lease(
        coord, lease_name="scheduler", holder_id="node-b", ttl_seconds=30
    )
    assert second and second["fencing_token"] == 2
    with pytest.raises(ConcurrencyError):
        renew_cluster_lease(
            coord, lease_name="scheduler", holder_id="node-a",
            fencing_token=first["fencing_token"], ttl_seconds=30,
        )
    assert release_cluster_lease(
        coord, lease_name="scheduler", holder_id="node-a", fencing_token=1
    ) is False
    assert release_cluster_lease(
        coord, lease_name="scheduler", holder_id="node-b", fencing_token=2
    ) is True
    third = acquire_cluster_lease(
        coord, lease_name="scheduler", holder_id="node-c", ttl_seconds=30
    )
    assert third and third["fencing_token"] == 3


def test_coordination_lease_survives_operational_database_restore(tmp_path: Path):
    live = tmp_path / "live.sqlite3"
    backup = tmp_path / "backup.sqlite3"
    coord = tmp_path / "coord.sqlite3"
    init_db(live)
    init_db(backup)
    init_coordination_db(coord)
    upsert_findings(live, [{"finding_id": "F-LIVE", "product": "A", "cve_id": "CVE-2026-10000"}], audit=False)
    upsert_findings(backup, [{"finding_id": "F-BACKUP", "product": "B", "cve_id": "CVE-2026-10001"}], audit=False)
    lease = acquire_cluster_lease(
        coord, lease_name="exclusive:restore", holder_id="node-a", ttl_seconds=120
    )
    assert lease is not None
    restore_database(live, backup, actor="tester")
    assert active_cluster_lease(coord, "exclusive:restore")["holder_id"] == "node-a"


def test_restore_lease_blocks_other_write_requests(tmp_path: Path, monkeypatch):
    token = "z" * 32
    db = tmp_path / "app.sqlite3"
    coord = tmp_path / "coord.sqlite3"
    monkeypatch.setattr(main, "DB_PATH", db)
    monkeypatch.setattr(main, "COORDINATION_DB_ENV", str(coord))
    monkeypatch.setattr(main, "AUTH_API_TOKENS_JSON", json.dumps({"admin": {"token": token, "role": "admin", "projects": "*"}}))
    monkeypatch.setattr(main, "JOB_WORKER_ENABLED", False)
    headers = {"Authorization": f"Bearer {token}"}
    with TestClient(main.app) as client:
        lease = acquire_cluster_lease(
            coord, lease_name=main.RESTORE_LEASE_NAME, holder_id="other-node", ttl_seconds=60
        )
        assert lease is not None
        response = client.post("/api/v1/jobs/queue/RESCORE_ALL", headers=headers)
        assert response.status_code == 503
        assert response.headers["Retry-After"] == "5"


def test_cluster_api_reports_instance_and_scheduler_lease(tmp_path: Path, monkeypatch):
    token = "c" * 32
    db = tmp_path / "app.sqlite3"
    coord = tmp_path / "coord.sqlite3"
    monkeypatch.setattr(main, "DB_PATH", db)
    monkeypatch.setattr(main, "COORDINATION_DB_ENV", str(coord))
    monkeypatch.setattr(main, "AUTH_API_TOKENS_JSON", json.dumps({"admin": {"token": token, "role": "admin", "projects": "*"}}))
    monkeypatch.setattr(main, "JOB_WORKER_ENABLED", False)
    headers = {"Authorization": f"Bearer {token}"}
    with TestClient(main.app) as client:
        response = client.get("/api/v1/system/cluster", headers=headers)
        assert response.status_code == 200
        body = response.json()
        assert body["coordination_enabled"] is True
        assert body["instance_id"] == main.INSTANCE_ID
        assert any(item["instance_id"] == main.INSTANCE_ID for item in body["instances"])
        assert any(item["lease_name"] == main.SCHEDULER_LEASE_NAME for item in body["leases"])


def test_cluster_ui_is_admin_only(tmp_path: Path, monkeypatch):
    db = tmp_path / "app.sqlite3"
    coord = tmp_path / "coord.sqlite3"
    monkeypatch.setattr(main, "DB_PATH", db)
    monkeypatch.setattr(main, "COORDINATION_DB_ENV", str(coord))
    viewer_token = "viewer-cluster-token-12345678"
    admin_token = "admin-cluster-token-123456789"
    monkeypatch.setattr(main, "AUTH_USERS_JSON", "")
    monkeypatch.setattr(main, "AUTH_API_TOKENS_JSON", json.dumps({
        "viewer": {"token": viewer_token, "role": "viewer", "projects": "*"},
        "admin": {"token": admin_token, "role": "admin", "projects": "*"},
    }))
    monkeypatch.setattr(main, "JOB_WORKER_ENABLED", False)
    with TestClient(main.app) as client:
        viewer = client.get("/cluster", headers={"Authorization": f"Bearer {viewer_token}"})
        assert viewer.status_code == 403
        admin = client.get("/cluster", headers={"Authorization": f"Bearer {admin_token}"})
        assert admin.status_code == 200
        assert "인스턴스 조정" in admin.text


def test_write_activity_registration_and_cleanup(tmp_path: Path):
    coord = tmp_path / "coord.sqlite3"
    init_coordination_db(coord)
    item = begin_cluster_write_activity(
        coord, activity_id="req-1", instance_id="node-a", actor="operator",
        method="POST", path="/api/v1/findings/F-1/workflow", ttl_seconds=60,
    )
    assert item["method"] == "POST"
    assert count_cluster_write_activities(coord) == 1
    assert end_cluster_write_activity(coord, activity_id="req-1") is True
    assert count_cluster_write_activities(coord) == 0


def test_successful_write_request_cleans_cluster_activity(tmp_path: Path, monkeypatch):
    token = "w" * 32
    db = tmp_path / "app.sqlite3"
    coord = tmp_path / "coord.sqlite3"
    monkeypatch.setattr(main, "DB_PATH", db)
    monkeypatch.setattr(main, "COORDINATION_DB_ENV", str(coord))
    monkeypatch.setattr(main, "AUTH_API_TOKENS_JSON", json.dumps({"operator": {"token": token, "role": "operator", "projects": "*"}}))
    monkeypatch.setattr(main, "JOB_WORKER_ENABLED", False)
    with TestClient(main.app) as client:
        response = client.post(
            "/api/v1/jobs/queue/RESCORE_ALL",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200
        assert count_cluster_write_activities(coord) == 0


def test_duplicate_active_instance_id_is_rejected(tmp_path: Path):
    coord = tmp_path / "coord.sqlite3"
    init_coordination_db(coord)
    register_cluster_instance(coord, instance_id="same-id", hostname="host", process_id=100)
    with pytest.raises(ConcurrencyError, match="이미 사용 중"):
        register_cluster_instance(coord, instance_id="same-id", hostname="host", process_id=200)
    with connect(coord) as conn:
        conn.execute("UPDATE cluster_instances SET status='STALE' WHERE instance_id='same-id'")
        conn.commit()
    takeover = register_cluster_instance(coord, instance_id="same-id", hostname="host", process_id=200)
    assert takeover["status"] == "ACTIVE"
    assert takeover["process_id"] == 200


def test_concurrent_empty_database_initialization(tmp_path):
    """Concurrent first start must not fail while WAL/schema are being created."""
    from concurrent.futures import ThreadPoolExecutor
    import sqlite3
    from app.core.storage import init_db, init_coordination_db, count_findings

    operational = tmp_path / "simultaneous-operational.sqlite3"
    coordination = tmp_path / "simultaneous-coordination.sqlite3"

    def initialize_pair(_: int) -> None:
        init_db(operational)
        init_coordination_db(coordination)

    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(initialize_pair, range(24)))

    assert count_findings(operational) == 0
    with sqlite3.connect(coordination) as conn:
        assert conn.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='cluster_instances'"
        ).fetchone()[0] == 1
