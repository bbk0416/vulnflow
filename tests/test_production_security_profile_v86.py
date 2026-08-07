from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from app.core.auth import Principal, parse_api_tokens
from app.core.database_schema import CURRENT_SCHEMA_VERSION, init_db
from app.services.accounts import authenticate_session, create_session, create_user
from app.services.projects import accessible_projects
from app.services.security_profile import enforce_security_profile, evaluate_security_profile


def _production_values(tmp_path: Path) -> dict[str, object]:
    return {
        "SECURITY_PROFILE": "production",
        "PUBLIC_BASE_URL": "https://vulnflow.example.test",
        "COOKIE_SECURE": True,
        "DEMO_MODE": False,
        "ALLOW_LOCAL_ADMIN_FALLBACK": False,
        "AUTH_SESSION_BINDING": "user-agent",
        "AUTH_SESSION_IDLE_MINUTES": 30,
        "RUNTIME_DEPENDENCY_POLICY": "enforce",
        "OUTBOUND_ALLOW_PRIVATE_NETWORKS": False,
        "OUTBOUND_HOST_ALLOWLIST": "*.atlassian.net",
        "EVIDENCE_REQUIRE_CLEAN": True,
        "EVIDENCE_SCANNER_MODE": "builtin",
        "AUDIT_REQUIRE_SIGNATURE": True,
        "AUDIT_SIGNING_KEY": "audit-signing-key-value",
        "SIGNING_KEYS_JSON": "",
        "AUDIT_ACTIVE_KEY_ID": "",
        "BACKUP_REQUIRE_SIGNATURE": True,
        "BACKUP_SIGNING_KEY": "backup-signing-key-value",
        "BACKUP_ACTIVE_KEY_ID": "",
        "CURSOR_SIGNING_KEY_CONFIGURED": True,
        "BACKUP_INTERVAL_HOURS": 12,
        "EXTERNAL_BACKUP_DIR": tmp_path / "external-backups",
    }


def test_api_tokens_without_project_scope_have_no_access(tmp_path: Path) -> None:
    db = tmp_path / "control.db"
    init_db(db)
    principal = Principal("api:unscoped", "admin", "bearer", ())
    assert accessible_projects(db, principal) == []
    parsed = parse_api_tokens(
        '{"unscoped":{"token":"0123456789abcdef","role":"admin"}}'
    )
    assert parsed["unscoped"]["projects"] == ()


def test_session_user_agent_binding_revokes_mismatch(tmp_path: Path) -> None:
    db = tmp_path / "control.db"
    init_db(db)
    create_user(
        db,
        username="operator",
        password="Secure-Test-Password!7",
        role="operator",
        actor="test",
    )
    raw, _ = create_session(
        db,
        username="operator",
        user_agent="Browser A",
        client_key="127.0.0.1",
    )
    assert authenticate_session(
        db,
        raw,
        user_agent="Browser A",
        client_key="127.0.0.1",
        binding_mode="user-agent",
        idle_minutes=30,
    ) is not None
    assert authenticate_session(
        db,
        raw,
        user_agent="Browser B",
        client_key="127.0.0.1",
        binding_mode="user-agent",
        idle_minutes=30,
    ) is None
    assert authenticate_session(db, raw) is None


def test_session_idle_timeout_revokes_stale_session(tmp_path: Path) -> None:
    db = tmp_path / "control.db"
    init_db(db)
    create_user(
        db,
        username="viewer",
        password="Secure-Test-Password!7",
        role="viewer",
        actor="test",
    )
    raw, _ = create_session(db, username="viewer", user_agent="Browser A")
    stale = (datetime.now(timezone.utc) - timedelta(minutes=31)).replace(microsecond=0).isoformat()
    import sqlite3

    with sqlite3.connect(db) as conn:
        conn.execute("UPDATE auth_sessions SET last_seen_at=?", (stale,))
    assert authenticate_session(
        db,
        raw,
        user_agent="Browser A",
        binding_mode="user-agent",
        idle_minutes=30,
    ) is None


def test_production_profile_is_fail_closed(tmp_path: Path) -> None:
    values = _production_values(tmp_path)
    tokens = parse_api_tokens(
        '{"automation":{"token":"0123456789abcdef","role":"operator","projects":"*"}}'
    )
    report = enforce_security_profile(values, tokens=tokens)
    assert report.passed

    unsafe = dict(values)
    unsafe["COOKIE_SECURE"] = False
    unsafe["PUBLIC_BASE_URL"] = "http://127.0.0.1:8000"
    unsafe_tokens = parse_api_tokens(
        '{"automation":{"token":"0123456789abcdef","role":"operator"}}'
    )
    report = evaluate_security_profile(unsafe, tokens=unsafe_tokens)
    codes = {item.code for item in report.findings}
    assert {"https.public_url", "cookie.secure", "api.scope"} <= codes
    with pytest.raises(RuntimeError, match="운영 보안 프로필 검증 실패"):
        enforce_security_profile(unsafe, tokens=unsafe_tokens)


def test_schema_46_installs_session_last_seen(tmp_path: Path) -> None:
    db = tmp_path / "control.db"
    init_db(db)
    import sqlite3

    with sqlite3.connect(db) as conn:
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        columns = {row[1] for row in conn.execute("PRAGMA table_info(auth_sessions)")}
    assert version == CURRENT_SCHEMA_VERSION == 46
    assert "last_seen_at" in columns


def test_production_deployment_contract_rehearsal_passes() -> None:
    from scripts.production_security_rehearsal import run_rehearsal

    report = run_rehearsal()
    assert report["passed"] is True
    assert all(report["checks"].values())
