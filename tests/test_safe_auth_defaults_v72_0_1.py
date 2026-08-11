from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import app.main as main
from app.core.auth import authenticate_request, is_trusted_local_host


def _app(tmp_path: Path, *, fallback: bool):
    return main.create_app(
        setting_overrides={
            "DB_PATH": tmp_path / "vulnflow.db",
            "EVIDENCE_DIR": tmp_path / "evidence",
            "EXPORT_DIR": tmp_path / "exports",
            "RECOVERY_DIR": tmp_path / "recovery",
            "AUTH_USERS_JSON": "",
            "AUTH_API_TOKENS_JSON": "",
            "AUTH_USER": "",
            "AUTH_PASSWORD": "",
            "DEMO_MODE": fallback,
            "ALLOW_LOCAL_ADMIN_FALLBACK": fallback,
            "JOB_WORKER_ENABLED": False,
            "CLUSTER_COORDINATION_ENABLED": False,
        }
    )


def test_authentication_is_closed_by_default():
    assert authenticate_request("", client_host="127.0.0.1") is None


def test_explicit_fallback_is_loopback_only():
    local = authenticate_request(
        "", allow_local_fallback=True, client_host="127.0.0.1"
    )
    assert local is not None
    assert (local.username, local.role, local.auth_method) == (
        "local-user",
        "admin",
        "local",
    )
    assert authenticate_request(
        "", allow_local_fallback=True, client_host="192.0.2.10"
    ) is None


def test_loopback_detection_supports_ipv4_ipv6_and_testclient():
    assert is_trusted_local_host("127.0.0.1")
    assert is_trusted_local_host("::1")
    assert is_trusted_local_host("testclient")
    assert not is_trusted_local_host("0.0.0.0")
    assert not is_trusted_local_host("example.test")


def test_startup_refuses_missing_auth_without_explicit_fallback(tmp_path: Path):
    application = _app(tmp_path, fallback=False)
    with pytest.raises(RuntimeError, match="활성 사용자 계정 또는 API token이 없습니다"):
        with TestClient(application):
            pass


def test_explicit_local_fallback_starts_only_for_local_testclient(tmp_path: Path):
    application = _app(tmp_path, fallback=True)
    with TestClient(application) as client:
        response = client.get("/")
        assert response.status_code == 200
        assert response.headers["x-request-id"]


def test_partial_legacy_credentials_fail_startup(tmp_path: Path):
    application = main.create_app(
        setting_overrides={
            "DB_PATH": tmp_path / "partial.db",
            "EVIDENCE_DIR": tmp_path / "evidence",
            "EXPORT_DIR": tmp_path / "exports",
            "RECOVERY_DIR": tmp_path / "recovery",
            "AUTH_USERS_JSON": "",
            "AUTH_API_TOKENS_JSON": "",
            "AUTH_USER": "admin",
            "AUTH_PASSWORD": "",
            "DEMO_MODE": False,
            "ALLOW_LOCAL_ADMIN_FALLBACK": False,
            "JOB_WORKER_ENABLED": False,
            "CLUSTER_COORDINATION_ENABLED": False,
        }
    )
    with pytest.raises(RuntimeError, match="평문 환경변수 사용자 인증은 제거되었습니다"):
        with TestClient(application):
            pass


def test_container_and_local_launch_defaults_are_explicit():
    root = Path(__file__).resolve().parents[1]
    compose = (root / "docker-compose.yml").read_text(encoding="utf-8")
    dockerfile = (root / "Dockerfile").read_text(encoding="utf-8")
    assert "/app/external-backups" in dockerfile
    linux = (root / "run_linux.sh").read_text(encoding="utf-8")
    windows = (root / "run_windows.ps1").read_text(encoding="utf-8")
    assert 'vulnflow:72.0.73' in compose
    assert 'VULNFLOW_DEMO_MODE:-0' in compose
    assert 'VULNFLOW_ALLOW_LOCAL_ADMIN_FALLBACK:-0' in compose
    assert 'VULNFLOW_COOKIE_SECURE:-1' in compose
    assert 'VULNFLOW_DEMO_MODE=0' in dockerfile
    assert 'VULNFLOW_ALLOW_LOCAL_ADMIN_FALLBACK=0' in dockerfile
    assert 'VULNFLOW_DEMO_MODE:=0' in linux
    assert 'VULNFLOW_ALLOW_LOCAL_ADMIN_FALLBACK:=0' in linux
    assert 'VULNFLOW_DEMO_MODE = "0"' in windows
    assert 'VULNFLOW_ALLOW_LOCAL_ADMIN_FALLBACK = "0"' in windows
