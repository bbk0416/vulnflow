from __future__ import annotations

import json
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import app.main as main
from app.core.observability import Metrics
from app.core.storage import CURRENT_SCHEMA_VERSION, connect, init_db, validate_database_file
from app.services.config_changes import (
    change_control_counts,
    create_change_request,
    decide_change_request,
    evaluate_change_control,
    get_change_request,
    list_change_requests,
    promote_change_request,
)
from app.services.config_drift import create_baseline, evaluate_drift
from app.services.recovery import build_config_audit


def _audit(db: Path, **env: str):
    return build_config_audit(env=env, db_path=db, base_dir=Path(__file__).resolve().parents[1])


def _window(hours: int = 2) -> tuple[str, str]:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    return (now - timedelta(minutes=5)).isoformat(), (now + timedelta(hours=hours)).isoformat()


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _csrf(client, path: str = "/config-changes", headers: dict[str, str] | None = None) -> str:
    response = client.get(path, headers=headers or {})
    assert response.status_code == 200
    match = re.search(r'name="csrf_token" value="([^"]+)"', response.text)
    assert match
    return match.group(1)


def test_schema_30_and_change_request_tables(tmp_path: Path):
    db = tmp_path / "vf.db"
    init_db(db)
    assert CURRENT_SCHEMA_VERSION == 46
    with connect(db) as conn:
        assert int(conn.execute("PRAGMA user_version").fetchone()[0]) == CURRENT_SCHEMA_VERSION == 46
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert "config_change_requests" in tables
        migration = conn.execute("SELECT name FROM schema_migrations WHERE version=30").fetchone()
        assert migration and migration[0] == "configuration_change_control"
        triggers = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='trigger'")}
        assert {"config_change_requests_core_immutable", "config_change_requests_no_delete"} <= triggers


def test_request_approval_and_approved_window_classification(tmp_path: Path):
    db = tmp_path / "vf.db"
    init_db(db)
    base = _audit(db)
    create_baseline(db, base, actor="admin")
    target = _audit(db, VULNFLOW_WEBHOOK_ALLOW_INSECURE_HTTP="1")
    start, end = _window()
    request = create_change_request(
        db, target, actor="operator", title="Webhook transport change", reason="staged migration",
        rollback_plan="restore HTTPS-only setting and restart", window_start=start, window_end=end,
    )
    assert request["status"] == "PENDING"
    assert request["impact"]["severity"] == "HIGH"
    pending = evaluate_change_control(db, target, evaluate_drift(db, target))
    assert pending["status"] == "DRIFT"
    assert pending["control_status"] == "PENDING"
    with pytest.raises(ValueError, match="자신의 요청"):
        decide_change_request(db, request["request_id"], actor="operator", decision="APPROVE")
    approved = decide_change_request(db, request["request_id"], actor="approver", decision="APPROVE")
    assert approved["status"] == "APPROVED"
    controlled = evaluate_change_control(db, target, evaluate_drift(db, target))
    assert controlled["control_status"] == "APPROVED_WINDOW"
    unexpected = _audit(
        db, VULNFLOW_WEBHOOK_ALLOW_INSECURE_HTTP="1", VULNFLOW_EVIDENCE_REQUIRE_CLEAN="0"
    )
    extra = evaluate_change_control(db, unexpected, evaluate_drift(db, unexpected))
    assert extra["control_status"] == "UNAPPROVED"


def test_apply_promotes_exact_target_and_preserves_history(tmp_path: Path):
    db = tmp_path / "vf.db"
    init_db(db)
    create_baseline(db, _audit(db), actor="admin", note="initial")
    target = _audit(db, VULNFLOW_EXPORT_QUOTA_MB="2048")
    start, end = _window()
    request = create_change_request(
        db, target, actor="operator", title="Quota adjustment", reason="capacity plan",
        rollback_plan="restore quota to 1024 and rerun storage status", window_start=start, window_end=end,
    )
    decide_change_request(db, request["request_id"], actor="approver", decision="APPROVE")
    applied = promote_change_request(db, request["request_id"], target, actor="approver", note="validated")
    assert applied["status"] == "APPLIED"
    assert applied["applied_baseline_id"]
    assert evaluate_drift(db, target)["status"] == "IN_SYNC"
    with connect(db) as conn:
        statuses = [row[0] for row in conn.execute(
            "SELECT status FROM config_baselines ORDER BY created_at DESC,baseline_id DESC"
        ).fetchall()]
        assert sorted(statuses) == ["ACTIVE", "RETIRED"]
        with pytest.raises(sqlite3.DatabaseError):
            conn.execute(
                "UPDATE config_change_requests SET target_hash='tampered' WHERE request_id=?",
                (request["request_id"],),
            )
        with pytest.raises(sqlite3.DatabaseError):
            conn.execute("DELETE FROM config_change_requests WHERE request_id=?", (request["request_id"],))


def test_apply_blocks_target_or_baseline_change(tmp_path: Path):
    db = tmp_path / "vf.db"
    init_db(db)
    create_baseline(db, _audit(db), actor="admin")
    target = _audit(db, VULNFLOW_COOKIE_SECURE="1")
    start, end = _window()
    request = create_change_request(
        db, target, actor="operator", title="Secure cookie", reason="TLS rollout",
        rollback_plan="restore cookie mode", window_start=start, window_end=end,
    )
    decide_change_request(db, request["request_id"], actor="approver", decision="APPROVE")
    with pytest.raises(ValueError, match="목표 스냅샷"):
        promote_change_request(db, request["request_id"], _audit(db), actor="approver")
    create_baseline(db, _audit(db, VULNFLOW_EXPORT_QUOTA_MB="2048"), actor="admin")
    with pytest.raises(ValueError, match="활성 기준선"):
        promote_change_request(db, request["request_id"], target, actor="approver")


def test_secret_target_rejected_and_metrics_counts(tmp_path: Path):
    db = tmp_path / "vf.db"
    init_db(db)
    create_baseline(db, _audit(db), actor="admin")
    start, end = _window()
    target = _audit(db, VULNFLOW_COOKIE_SECURE="1")
    target["settings"]["authentication"]["password"] = "raw-secret"
    with pytest.raises(ValueError, match="비밀번호"):
        create_change_request(
            db, target, actor="operator", title="bad", reason="bad", rollback_plan="rollback",
            window_start=start, window_end=end,
        )
    clean = _audit(db, VULNFLOW_COOKIE_SECURE="1")
    req = create_change_request(
        db, clean, actor="operator", title="good", reason="good", rollback_plan="rollback",
        window_start=start, window_end=end,
    )
    decide_change_request(db, req["request_id"], actor="approver", decision="APPROVE")
    counts = change_control_counts(db)
    assert counts["approved"] == 1
    text = Metrics().render_prometheus(config_change_pending=2, config_change_approved=1)
    assert "vulnflow_config_change_pending 2" in text
    assert "vulnflow_config_change_approved 1" in text
    assert validate_database_file(db)["schema_version"] == 46


def test_ui_request_approve_and_apply(client, monkeypatch):
    admin_token = "admin-token-1234567890123456"
    operator_token = "operator-token-123456789012"
    approver_token = "approver-token-123456789012"
    monkeypatch.setattr(main, "AUTH_API_TOKENS_JSON", json.dumps({
        "admin": {"token": admin_token, "role": "admin", "projects": "*"},
        "operator": {"token": operator_token, "role": "operator", "projects": "*"},
        "approver": {"token": approver_token, "role": "approver", "projects": "*"},
    }))
    admin = _auth(admin_token)
    operator = _auth(operator_token)
    approver = _auth(approver_token)
    token = _csrf(client, "/system", admin)
    response = client.post(
        "/system/config-baseline", data={"csrf_token": token, "note": "initial"},
        headers=admin, follow_redirects=False,
    )
    assert response.status_code == 303
    monkeypatch.setenv("VULNFLOW_COOKIE_SECURE", "1")
    start, end = _window()
    token = _csrf(client, headers=operator)
    response = client.post(
        "/config-changes/request",
        data={
            "csrf_token": token, "title": "secure cookie", "reason": "TLS rollout",
            "rollback_plan": "restore previous cookie setting", "window_start": start,
            "window_end": end,
        },
        headers=operator, follow_redirects=False,
    )
    assert response.status_code == 303
    page = client.get("/config-changes", headers=operator)
    assert "secure cookie" in page.text
    with connect(main.DB_PATH) as conn:
        request_id = conn.execute("SELECT request_id FROM config_change_requests LIMIT 1").fetchone()[0]
    token = _csrf(client, headers=approver)
    response = client.post(
        f"/config-changes/{request_id}/decision",
        data={"csrf_token": token, "decision": "APPROVE", "decision_note": "approved"},
        headers=approver, follow_redirects=False,
    )
    assert response.status_code == 303
    token = _csrf(client, headers=approver)
    response = client.post(
        f"/config-changes/{request_id}/apply",
        data={"csrf_token": token, "note": "validated"},
        headers=approver, follow_redirects=False,
    )
    assert response.status_code == 303
    assert get_change_request(main.DB_PATH, request_id)["status"] == "APPLIED"


def test_bearer_api_change_control_flow(client, monkeypatch):
    create_baseline(
        main.DB_PATH, build_config_audit(db_path=main.DB_PATH, base_dir=Path(__file__).resolve().parents[1]),
        actor="bootstrap-admin",
    )
    operator_token = "operator-token-1234567890"
    approver_token = "approver-token-1234567890"
    monkeypatch.setattr(main, "AUTH_API_TOKENS_JSON", json.dumps({
        "change-bot": {"token": operator_token, "role": "operator", "projects": "*"},
        "change-approver": {"token": approver_token, "role": "approver", "projects": "*"},
    }))
    monkeypatch.setenv("VULNFLOW_COOKIE_SECURE", "1")
    start, end = _window()
    response = client.post(
        "/api/v1/system/config-changes",
        headers={"Authorization": f"Bearer {operator_token}"},
        json={
            "title": "API planned change", "reason": "TLS rollout",
            "rollback_plan": "restore previous cookie setting", "window_start": start,
            "window_end": end,
        },
    )
    assert response.status_code == 200, response.text
    request_id = response.json()["request_id"]
    response = client.post(
        f"/api/v1/system/config-changes/{request_id}/decision",
        headers={"Authorization": f"Bearer {approver_token}"},
        json={"decision": "APPROVE", "decision_note": "approved"},
    )
    assert response.status_code == 200, response.text
    response = client.post(
        f"/api/v1/system/config-changes/{request_id}/apply",
        headers={"Authorization": f"Bearer {approver_token}"},
        json={"note": "validated"},
    )
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "APPLIED"


def test_direct_rebaseline_ui_is_blocked_after_drift(client, monkeypatch):
    token = _csrf(client, "/system")
    response = client.post(
        "/system/config-baseline", data={"csrf_token": token, "note": "initial"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    monkeypatch.setenv("VULNFLOW_COOKIE_SECURE", "1")
    token = _csrf(client, "/system")
    response = client.post(
        "/system/config-baseline", data={"csrf_token": token, "note": "bypass"},
        follow_redirects=False,
    )
    assert response.status_code == 400
    assert "구성 변경 승인 요청" in response.text
