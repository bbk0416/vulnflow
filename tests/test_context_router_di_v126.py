from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import threading

import pytest
import types

from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

import app.main as main
from app.core.context import get_application_context
from app.core.database_schema import init_db
from app.effective_routes import effective_api_route, effective_api_routes
from app.routers import CONTEXT_ROUTER_MODULES, pilot
from app.services.accounts import create_user

PASSWORD = "Correct-Horse-42!"


def _settings(root: Path, legacy_db: Path) -> dict[str, object]:
    default_root = root / "runtime-projects" / "default"
    return {
        "DATA_DIR": root / "runtime-data",
        "LEGACY_DB_PATH": legacy_db,
        "CONTROL_DB_PATH": root / "runtime-control.db",
        "DEFAULT_PROJECT_ROOT": default_root,
        "DEFAULT_PROJECT_DB_PATH": default_root / "vulnflow.db",
        "DB_PATH": default_root / "vulnflow.db",
        "EVIDENCE_DIR": default_root / "evidence",
        "EXPORT_DIR": default_root / "exports",
        "RECOVERY_DIR": default_root / "backups" / "recovery",
        "LEGACY_EVIDENCE_DIR": root / "evidence",
        "LEGACY_EXPORT_DIR": root / "exports",
        "LEGACY_IMPORT_PREVIEW_DIR": root / "previews",
        "LEGACY_RECOVERY_DIR": root / "recovery",
        "IMPORT_PREVIEW_DIR": default_root / "import-previews",
        "PROJECTS_DIR": root / "projects",
        "AUTH_USERS_JSON": "",
        "AUTH_API_TOKENS_JSON": "",
        "AUTH_USER": "",
        "AUTH_PASSWORD": "",
        "AUTH_SESSION_COOKIE": "vulnflow_session",
        "AUTH_SESSION_MINUTES": 60,
        "AUTH_MAX_ACTIVE_SESSIONS": 10,
        "AUTH_LOCK_THRESHOLD": 5,
        "AUTH_LOCK_MINUTES": 15,
        "COOKIE_SECURE": False,
        "DEMO_MODE": False,
        "ALLOW_LOCAL_ADMIN_FALLBACK": False,
        "JOB_WORKER_ENABLED": False,
        "CLUSTER_COORDINATION_ENABLED": False,
        "PUBLIC_BASE_URL": "",
    }


def _application(root: Path):
    root.mkdir(parents=True, exist_ok=True)
    legacy_db = root / "legacy.db"
    init_db(legacy_db)
    create_user(legacy_db, username="admin", password=PASSWORD, role="admin", actor="test")
    return main.create_app(setting_overrides=_settings(root, legacy_db))


def _login(client: TestClient) -> str:
    assert client.get("/login").status_code == 200
    csrf = str(client.cookies.get("vulnflow_csrf"))
    response = client.post(
        "/login",
        data={"username": "admin", "password": PASSWORD, "csrf_token": csrf, "next": "/"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    return str(client.cookies.get("vulnflow_csrf"))


def _route(application, name: str):
    return effective_api_route(application, name)


def test_pilot_dependency_install_is_a_noop() -> None:
    before = dict(pilot.__dict__)
    pilot.install_dependencies({"DB_PATH": object(), "app": object()})
    assert pilot.__dict__ == before
    assert "DB_PATH" not in pilot.__dict__
    assert "app" not in pilot.__dict__


def test_secondary_apps_share_context_router_endpoints_without_cloning(tmp_path: Path) -> None:
    first = _application(tmp_path / "first")
    second = _application(tmp_path / "second")
    first_context = get_application_context(first)
    second_context = get_application_context(second)

    assert CONTEXT_ROUTER_MODULES == (pilot,)
    assert pilot in first_context.router_modules
    assert pilot in second_context.router_modules
    assert _route(first, "pilot_center").endpoint is pilot.pilot_center
    assert _route(second, "pilot_center").endpoint is pilot.pilot_center
    assert first_context is not second_context


def test_context_router_remains_registered_while_only_legacy_routers_are_cloned(
    tmp_path: Path,
) -> None:
    application = _application(tmp_path / "mixed-runtime")
    context = get_application_context(application)
    shared = [module for module in context.router_modules if module in CONTEXT_ROUTER_MODULES]
    isolated = [module for module in context.router_modules if module not in CONTEXT_ROUTER_MODULES]

    assert shared == [pilot]
    assert isinstance(pilot, types.ModuleType)
    assert len(pilot.router.routes) == 4
    assert len(isolated) == 15
    assert all(isinstance(module, types.SimpleNamespace) for module in isolated)
    assert all(not module.router.routes for module in isolated)




def test_context_router_registration_uses_fastapi_public_include_api(tmp_path: Path, monkeypatch) -> None:
    from fastapi import FastAPI

    original_include = FastAPI.include_router
    seen: list[object] = []

    def tracking_include(application, router, *args, **kwargs):
        seen.append(router)
        return original_include(application, router, *args, **kwargs)

    monkeypatch.setattr(FastAPI, "include_router", tracking_include)
    application = _application(tmp_path / "public-include")

    assert seen == [pilot.router]
    assert _route(application, "pilot_center").endpoint is pilot.pilot_center

def test_effective_route_inventory_counts_lazy_and_flattened_includes(tmp_path: Path) -> None:
    application = _application(tmp_path / "effective-inventory")
    routes = effective_api_routes(application)

    assert len(routes) == 276
    assert len([route for route in routes if route.endpoint in {
        item.endpoint for item in pilot.router.routes if isinstance(item, APIRoute)
    }]) == 4
    assert str(application.url_path_for("pilot_center")) == "/pilot"


@pytest.mark.filterwarnings("error::pydantic.warnings.UnsupportedFieldAttributeWarning")
def test_concurrent_pilot_requests_keep_application_contexts_isolated(tmp_path: Path) -> None:
    barrier = threading.Barrier(2)

    def exercise(label: str) -> list[str]:
        application = _application(tmp_path / label.lower())
        with TestClient(application) as client:
            csrf = _login(client)
            saved = client.post(
                "/pilot/profile",
                data={
                    "customer_name": label,
                    "engagement_name": f"{label} engagement",
                    "csrf_token": csrf,
                },
                follow_redirects=False,
            )
            assert saved.status_code == 303
            barrier.wait(timeout=10)
            observed: list[str] = []
            for _ in range(10):
                response = client.get("/api/v1/pilot-readiness")
                assert response.status_code == 200
                observed.append(str(response.json()["profile"]["customer_name"]))
            return observed

    with ThreadPoolExecutor(max_workers=2) as executor:
        alpha, beta = executor.map(exercise, ("Alpha", "Beta"))

    assert alpha == ["Alpha"] * 10
    assert beta == ["Beta"] * 10
