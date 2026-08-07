from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import app.main as main
from app.core.database_schema import CURRENT_SCHEMA_VERSION, init_db
from app.services.accounts import (
    authenticate_session,
    authenticate_user_password,
    create_session,
    create_user,
    get_user,
    hash_password,
    list_users,
    unlock_user,
    verify_password,
)


def _settings(tmp_path: Path, db: Path) -> dict:
    default_root = tmp_path / "runtime-projects" / "default"
    return {
        "DATA_DIR": tmp_path / "runtime-data",
        "LEGACY_DB_PATH": db,
        "CONTROL_DB_PATH": tmp_path / "runtime-control.db",
        "DEFAULT_PROJECT_ROOT": default_root,
        "DEFAULT_PROJECT_DB_PATH": default_root / "vulnflow.db",
        "DB_PATH": default_root / "vulnflow.db",
        "EVIDENCE_DIR": default_root / "evidence",
        "EXPORT_DIR": default_root / "exports",
        "RECOVERY_DIR": default_root / "backups" / "recovery",
        "LEGACY_EVIDENCE_DIR": tmp_path / "evidence",
        "LEGACY_EXPORT_DIR": tmp_path / "exports",
        "LEGACY_IMPORT_PREVIEW_DIR": tmp_path / "previews",
        "LEGACY_RECOVERY_DIR": tmp_path / "recovery",
        "AUTH_USERS_JSON": "",
        "AUTH_API_TOKENS_JSON": "",
        "AUTH_USER": "",
        "AUTH_PASSWORD": "",
        "AUTH_SESSION_COOKIE": "vulnflow_session",
        "AUTH_SESSION_MINUTES": 60,
        "AUTH_MAX_ACTIVE_SESSIONS": 10,
        "AUTH_RATE_WINDOW_SECONDS": 300,
        "AUTH_RATE_USERNAME_CLIENT_ATTEMPTS": 5,
        "AUTH_RATE_CLIENT_ATTEMPTS": 25,
        "AUTH_LOCK_THRESHOLD": 5,
        "AUTH_LOCK_MINUTES": 5,
        "COOKIE_SECURE": False,
        "DEMO_MODE": False,
        "ALLOW_LOCAL_ADMIN_FALLBACK": False,
        "JOB_WORKER_ENABLED": False,
        "CLUSTER_COORDINATION_ENABLED": False,
    }


def _create_admin(db: Path, password: str = "Correct-Horse-42!") -> None:
    init_db(db)
    create_user(db, username="admin", password=password, role="admin", actor="test")


def test_schema_42_contains_database_auth_tables(tmp_path: Path):
    db = tmp_path / "auth.sqlite3"
    init_db(db)
    with sqlite3.connect(db) as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == CURRENT_SCHEMA_VERSION == 46
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"app_users", "auth_sessions", "auth_login_attempts"} <= tables


def test_password_hash_is_scrypt_and_never_plaintext():
    password = "Correct-Horse-42!"
    encoded = hash_password(password)
    assert password not in encoded
    assert encoded.startswith("vulnflow-scrypt-v1$")
    assert verify_password(password, encoded)
    assert not verify_password("wrong-password", encoded)


def test_session_database_contains_only_token_hash(tmp_path: Path):
    db = tmp_path / "session.sqlite3"
    _create_admin(db)
    raw, _expires = create_session(db, username="admin", lifetime_minutes=60)
    principal = authenticate_session(db, raw)
    assert principal is not None
    assert principal.username == "admin"
    with sqlite3.connect(db) as conn:
        row = conn.execute("SELECT session_hash FROM auth_sessions").fetchone()
    assert row is not None
    assert raw not in row[0]
    assert len(row[0]) == 64


def test_browser_login_session_and_logout(tmp_path: Path):
    db = tmp_path / "web.sqlite3"
    _create_admin(db)
    application = main.create_app(setting_overrides=_settings(tmp_path, db))
    with TestClient(application) as client:
        anonymous = client.get("/", headers={"Accept": "text/html"}, follow_redirects=False)
        assert anonymous.status_code == 303
        assert anonymous.headers["location"].startswith("/login?next=")

        login_page = client.get("/login")
        assert login_page.status_code == 200
        assert "계정으로 로그인" in login_page.text
        csrf = client.cookies.get("vulnflow_csrf")
        assert csrf

        logged_in = client.post(
            "/login",
            data={
                "username": "admin",
                "password": "Correct-Horse-42!",
                "csrf_token": csrf,
                "next": "/",
            },
            follow_redirects=False,
        )
        assert logged_in.status_code == 303
        assert logged_in.headers["location"] == "/"
        assert client.cookies.get("vulnflow_session")

        home = client.get("/")
        assert home.status_code == 200
        assert "admin" in home.text
        assert "로그아웃" in home.text

        csrf = client.cookies.get("vulnflow_csrf")
        logged_out = client.post(
            "/logout", data={"csrf_token": csrf}, follow_redirects=False
        )
        assert logged_out.status_code == 303
        assert logged_out.headers["location"] == "/login?notice=logged_out"
        assert not client.cookies.get("vulnflow_session")


def test_failed_logins_are_limited_per_client_without_locking_account(tmp_path: Path):
    db = tmp_path / "rate-limit.sqlite3"
    _create_admin(db)
    for index in range(4):
        result = authenticate_user_password(
            db,
            username="admin",
            password=f"Wrong-Password-{index}!",
            client_key="198.51.100.10",
            rate_window_seconds=300,
            username_client_attempts=5,
            client_attempts=25,
        )
        assert result.status == "invalid"
    limited = authenticate_user_password(
        db,
        username="admin",
        password="Wrong-Password-5!",
        client_key="198.51.100.10",
        rate_window_seconds=300,
        username_client_attempts=5,
        client_attempts=25,
    )
    assert limited.status == "rate_limited"
    assert limited.retry_after_seconds == 300
    user = get_user(db, "admin")
    assert user["failed_attempts"] == 0
    assert user["locked_until"] == ""

    # A correct password from the same or a different client is never blocked by
    # attacker-created failure history.
    success = authenticate_user_password(
        db,
        username="admin",
        password="Correct-Horse-42!",
        client_key="203.0.113.7",
        rate_window_seconds=300,
        username_client_attempts=5,
        client_attempts=25,
    )
    assert success.status == "ok"


def test_client_wide_limit_stops_username_rotation(tmp_path: Path):
    db = tmp_path / "client-limit.sqlite3"
    _create_admin(db)
    statuses = []
    for index in range(6):
        result = authenticate_user_password(
            db,
            username=f"unknown{index}",
            password="Wrong-Password-42!",
            client_key="198.51.100.20",
            rate_window_seconds=300,
            username_client_attempts=10,
            client_attempts=5,
        )
        statuses.append(result.status)
    assert statuses[:4] == ["invalid"] * 4
    assert statuses[4:] == ["rate_limited", "rate_limited"]


def test_schema_migration_clears_legacy_global_lock_state(tmp_path: Path):
    db = tmp_path / "legacy-lock.sqlite3"
    _create_admin(db)
    with sqlite3.connect(db) as conn:
        conn.execute("PRAGMA user_version=44")
        conn.execute(
            "UPDATE app_users SET failed_attempts=5,locked_until='2099-01-01T00:00:00+00:00' WHERE username='admin'"
        )
        conn.commit()
    init_db(db)
    user = get_user(db, "admin")
    assert user["failed_attempts"] == 0
    assert user["locked_until"] == ""
    assert authenticate_user_password(
        db,
        username="admin",
        password="Correct-Horse-42!",
        client_key="203.0.113.8",
    ).status == "ok"


def test_login_endpoint_does_not_enumerate_account_state(tmp_path: Path):
    db = tmp_path / "enumeration.sqlite3"
    _create_admin(db)
    create_user(db, username="disabled", password="Disabled-Account-42!", role="viewer", actor="test")
    from app.services.accounts import set_user_active
    set_user_active(db, username="disabled", active=False, actor="test")
    settings = _settings(tmp_path, db) | {
        "AUTH_RATE_USERNAME_CLIENT_ATTEMPTS": 3,
        "AUTH_RATE_CLIENT_ATTEMPTS": 20,
        "AUTH_RATE_WINDOW_SECONDS": 120,
    }
    application = main.create_app(setting_overrides=settings)
    with TestClient(application) as client:
        page = client.get("/login")
        csrf = client.cookies.get("vulnflow_csrf")
        responses = []
        for username, password in (
            ("missing", "Missing-Account-42!"),
            ("disabled", "Disabled-Account-42!"),
            ("admin", "Wrong-Password-42!"),
        ):
            response = client.post(
                "/login",
                data={"username": username, "password": password, "csrf_token": csrf, "next": "/"},
            )
            responses.append(response)
        assert {response.status_code for response in responses} == {401}
        assert {"로그인 정보를 확인할 수 없습니다. 잠시 후 다시 시도하세요." in response.text for response in responses} == {True}



def test_plaintext_environment_accounts_are_rejected(tmp_path: Path):
    db = tmp_path / "legacy.sqlite3"
    application = main.create_app(
        setting_overrides=_settings(tmp_path, db)
        | {"AUTH_USERS_JSON": '{"admin":{"password":"plain","role":"admin"}}'}
    )
    with pytest.raises(RuntimeError, match="평문 환경변수 사용자 인증은 제거"):
        with TestClient(application):
            pass


def test_basic_auth_is_not_accepted_for_browser_users(tmp_path: Path):
    db = tmp_path / "basic.sqlite3"
    _create_admin(db)
    application = main.create_app(setting_overrides=_settings(tmp_path, db))
    with TestClient(application) as client:
        response = client.get(
            "/api/v1/findings", auth=("admin", "Correct-Horse-42!")
        )
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == 'Bearer realm="VulnFlow API"'




def test_admin_user_management_routes_apply_security_changes(tmp_path: Path):
    db = tmp_path / "admin-users.sqlite3"
    _create_admin(db)
    application = main.create_app(setting_overrides=_settings(tmp_path, db))
    with TestClient(application) as client:
        client.get("/login")
        csrf = client.cookies.get("vulnflow_csrf")
        login = client.post(
            "/login",
            data={
                "username": "admin",
                "password": "Correct-Horse-42!",
                "csrf_token": csrf,
                "next": "/admin/users",
            },
            follow_redirects=False,
        )
        assert login.status_code == 303
        csrf = client.cookies.get("vulnflow_csrf")

        created = client.post(
            "/admin/users",
            data={
                "username": "operator01",
                "password": "Operator-Initial-42!",
                "role": "operator",
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )
        assert created.status_code == 303
        runtime_control = Path(application.state.vulnflow_context.get("CONTROL_DB_PATH"))
        assert get_user(runtime_control, "operator01")["role"] == "operator"

        raw_session, _ = create_session(runtime_control, username="operator01")
        disabled = client.post(
            "/admin/users/operator01/status",
            data={"active": "0", "csrf_token": csrf},
            follow_redirects=False,
        )
        assert disabled.status_code == 303
        assert get_user(runtime_control, "operator01")["is_active"] == 0
        assert authenticate_session(runtime_control, raw_session) is None

        enabled = client.post(
            "/admin/users/operator01/status",
            data={"active": "1", "csrf_token": csrf},
            follow_redirects=False,
        )
        assert enabled.status_code == 303
        reset = client.post(
            "/admin/users/operator01/password",
            data={"password": "Operator-Reset-84!", "csrf_token": csrf},
            follow_redirects=False,
        )
        assert reset.status_code == 303
        assert authenticate_user_password(
            runtime_control, username="operator01", password="Operator-Reset-84!"
        ).status == "ok"

        page = client.get("/admin/users")
        assert page.status_code == 200
        assert "operator01" in page.text
        assert "Operator-Reset-84!" not in page.text


def test_user_list_never_returns_password_hash(tmp_path: Path):
    db = tmp_path / "list.sqlite3"
    _create_admin(db)
    users = list_users(db)
    assert users and users[0]["username"] == "admin"
    assert all("password_hash" not in item for item in users)
