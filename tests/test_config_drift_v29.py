from __future__ import annotations

import re
import sqlite3
from pathlib import Path

import pytest

from app.core.observability import Metrics
from app.core.storage import CURRENT_SCHEMA_VERSION, connect, init_db, validate_database_file
from app.services.config_drift import (
    create_baseline,
    evaluate_drift,
    list_baselines,
    list_drift_checks,
    record_drift_check,
)
from app.services.recovery import build_config_audit


def _audit(db: Path, **env: str):
    return build_config_audit(env=env, db_path=db, base_dir=Path(__file__).resolve().parents[1])


def _csrf(client) -> str:
    response = client.get("/system")
    assert response.status_code == 200
    match = re.search(r'name="csrf_token" value="([^"]+)"', response.text)
    assert match
    return match.group(1)


def test_schema_29_and_config_tables(tmp_path: Path):
    db = tmp_path / "vf.db"
    init_db(db)
    assert CURRENT_SCHEMA_VERSION == 46
    with connect(db) as conn:
        assert int(conn.execute("PRAGMA user_version").fetchone()[0]) == CURRENT_SCHEMA_VERSION == 46
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert {"config_baselines", "config_drift_checks"} <= tables
        migration = conn.execute("SELECT name FROM schema_migrations WHERE version=29").fetchone()
        assert migration and migration[0] == "configuration_baseline_drift"


def test_baseline_is_stable_and_does_not_store_secrets(tmp_path: Path):
    db = tmp_path / "vf.db"
    init_db(db)
    env = {
        "VULNFLOW_USERS_JSON": '{"admin":{"password":"super-secret","role":"admin","projects":"*"}}',
        "VULNFLOW_API_TOKENS_JSON": '{"automation":{"token":"api-secret","role":"operator","projects":"*"}}',
        "VULNFLOW_WEBHOOKS_JSON": '{"ops":{"url":"https://user:pass@example.test/private/path","secret":"hook-secret","events":["workflow.changed"]}}',
    }
    audit = _audit(db, **env)
    baseline = create_baseline(db, audit, actor="admin", note="approved")
    stored = str(baseline["snapshot"])
    for secret in ("super-secret", "api-secret", "hook-secret", "/private/path", "user:pass"):
        assert secret not in stored
    assert evaluate_drift(db, _audit(db, **env))["status"] == "IN_SYNC"


def test_drift_detects_security_change_and_ignores_generated_time(tmp_path: Path):
    db = tmp_path / "vf.db"
    init_db(db)
    create_baseline(db, _audit(db), actor="admin")
    assert evaluate_drift(db, _audit(db))["status"] == "IN_SYNC"
    drift = evaluate_drift(db, _audit(db, VULNFLOW_WEBHOOK_ALLOW_INSECURE_HTTP="1"))
    assert drift["status"] == "DRIFT"
    assert drift["severity"] == "HIGH"
    assert any(item["path"] == "settings.webhooks.allow_insecure_http" for item in drift["changes"])
    assert all("generated_at" not in item["path"] for item in drift["changes"])


def test_rebaseline_retires_previous_and_checks_are_immutable(tmp_path: Path):
    db = tmp_path / "vf.db"
    init_db(db)
    create_baseline(db, _audit(db), actor="admin", note="initial")
    changed = _audit(db, VULNFLOW_EXPORT_QUOTA_MB="2048")
    check = record_drift_check(db, changed, actor="auditor")
    assert check["status"] == "DRIFT"
    assert list_drift_checks(db)[0]["change_count"] >= 1
    create_baseline(db, changed, actor="admin", note="approved quota change")
    baselines = list_baselines(db)
    assert [item["status"] for item in baselines[:2]] == ["ACTIVE", "RETIRED"]
    assert evaluate_drift(db, changed)["status"] == "IN_SYNC"
    with connect(db) as conn:
        check_id = conn.execute("SELECT check_id FROM config_drift_checks LIMIT 1").fetchone()[0]
        with pytest.raises(sqlite3.DatabaseError):
            conn.execute("UPDATE config_drift_checks SET severity='LOW' WHERE check_id=?", (check_id,))


def test_system_ui_creates_baseline_and_records_check(client):
    token = _csrf(client)
    response = client.post(
        "/system/config-baseline",
        data={"csrf_token": token, "note": "UI approved"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    token = _csrf(client)
    response = client.post(
        "/system/config-drift/check",
        data={"csrf_token": token},
        follow_redirects=False,
    )
    assert response.status_code == 303
    page = client.get("/system")
    assert "구성 기준선·드리프트" in page.text
    assert "IN_SYNC" in page.text


def test_metrics_and_restore_validation_include_v29(tmp_path: Path):
    db = tmp_path / "vf.db"
    init_db(db)
    create_baseline(db, _audit(db), actor="admin")
    summary = validate_database_file(db)
    assert summary["schema_version"] == 46
    text = Metrics().render_prometheus(config_baseline_present=1, config_drift_changes=2)
    assert "vulnflow_config_baseline_present 1" in text
    assert "vulnflow_config_drift_changes 2" in text
