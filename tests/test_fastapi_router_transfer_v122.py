from __future__ import annotations

import gc
from pathlib import Path
import shutil
import types
import weakref

from fastapi import FastAPI
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

import app.main as main
from app.core.context import get_application_context
from app.effective_routes import effective_api_routes
from app.routers import CONTEXT_ROUTER_MODULES, pilot

ROOT = Path(__file__).resolve().parents[1]


def _settings(root: Path) -> dict[str, object]:
    default_root = root / "projects" / "default"
    for sample in (
        "sample_findings.csv",
        "sample_product_release.cdx.json",
        "sample_sbom.cdx.json",
        "sample_sbom_v2.cdx.json",
    ):
        root.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / "data" / sample, root / sample)
    return {
        "DATA_DIR": root,
        "LEGACY_DB_PATH": root / "legacy-vulnflow.db",
        "CONTROL_DB_PATH": root / "control.db",
        "DEFAULT_PROJECT_ROOT": default_root,
        "DEFAULT_PROJECT_DB_PATH": default_root / "vulnflow.db",
        "DB_PATH": default_root / "vulnflow.db",
        "PROJECTS_DIR": root / "projects",
        "EVIDENCE_DIR": default_root / "evidence",
        "EXPORT_DIR": default_root / "exports",
        "IMPORT_PREVIEW_DIR": default_root / "import-previews",
        "RECOVERY_DIR": default_root / "backups" / "recovery",
        "LEGACY_EVIDENCE_DIR": root / "legacy-evidence",
        "LEGACY_EXPORT_DIR": root / "legacy-exports",
        "LEGACY_IMPORT_PREVIEW_DIR": root / "legacy-previews",
        "LEGACY_RECOVERY_DIR": root / "legacy-recovery",
        "EXTERNAL_BACKUP_DIR": root / "external-backups",
        "COORDINATION_DB_ENV": str(root / "coordination.db"),
        "CLUSTER_COORDINATION_ENABLED": False,
        "DEMO_MODE": True,
        "ALLOW_LOCAL_ADMIN_FALLBACK": True,
        "JOB_WORKER_ENABLED": False,
        "WEBHOOKS_JSON": "{}",
        "LIFECYCLE_SHUTDOWN_TIMEOUT_SECONDS": 1.0,
    }


def _runtime_namespace_count() -> int:
    return sum(
        1
        for item in gc.get_objects()
        if isinstance(item, types.SimpleNamespace)
        and ".__runtime_" in str(getattr(item, "__name__", ""))
    )


def _api_route_count() -> int:
    return sum(1 for item in gc.get_objects() if isinstance(item, APIRoute))


def test_isolated_assembly_uses_public_include_only_for_context_router(
    tmp_path: Path, monkeypatch,
) -> None:
    original_include = FastAPI.include_router
    included: list[object] = []

    def guarded_include(application, router, *args, **kwargs):
        if router is not pilot.router:
            raise AssertionError("legacy isolated routers must be transferred directly")
        included.append(router)
        return original_include(application, router, *args, **kwargs)

    monkeypatch.setattr(FastAPI, "include_router", guarded_include)
    application = main.create_app(setting_overrides=_settings(tmp_path / "bypass"))
    assert included == [pilot.router]
    assert len(effective_api_routes(application)) == 276
    with TestClient(application) as client:
        assert client.get("/health/live").status_code == 200


def test_transferred_routes_are_direct_and_bound_to_the_application(tmp_path: Path) -> None:
    application = main.create_app(setting_overrides=_settings(tmp_path / "direct"))
    context = get_application_context(application)
    routes = [route for route in application.router.routes if isinstance(route, APIRoute)]

    assert len(effective_api_routes(application)) == 276
    assert len(routes) in {272, 276}
    assert all(route.dependency_overrides_provider is application for route in routes)
    assert all(module.router.routes for module in CONTEXT_ROUTER_MODULES)
    assert all(
        not module.router.routes
        for module in context.router_modules
        if module not in CONTEXT_ROUTER_MODULES
    )


def test_direct_route_transfer_preserves_restart(tmp_path: Path) -> None:
    application = main.create_app(setting_overrides=_settings(tmp_path / "restart"))
    for _ in range(2):
        with TestClient(application) as client:
            assert client.get("/health/live").status_code == 200
            assert client.get("/health/ready").status_code == 200


def test_repeated_direct_transfers_release_created_route_graphs(tmp_path: Path) -> None:
    gc.collect()
    baseline_routes = _api_route_count()
    baseline_namespaces = _runtime_namespace_count()
    application_references: list[weakref.ReferenceType[object]] = []
    route_references: list[weakref.ReferenceType[object]] = []
    endpoint_references: list[weakref.ReferenceType[object]] = []

    for index in range(3):
        application = main.create_app(setting_overrides=_settings(tmp_path / f"cycle-{index}"))
        routes = [route for route in application.router.routes if isinstance(route, APIRoute)]
        assert len(effective_api_routes(application)) == 276
        assert len(routes) in {272, 276}
        route_references.extend(weakref.ref(route) for route in routes)
        shared_endpoints = {
            route.endpoint
            for module in CONTEXT_ROUTER_MODULES
            for route in module.router.routes
            if isinstance(route, APIRoute)
        }
        endpoint_references.extend(
            weakref.ref(route.endpoint)
            for route in routes
            if route.endpoint not in shared_endpoints
        )
        with TestClient(application) as client:
            assert client.get("/health/live").status_code == 200
        application_references.append(weakref.ref(application))
        del client, routes, application
        gc.collect()

    gc.collect()
    assert all(reference() is None for reference in application_references)
    assert all(reference() is None for reference in route_references)
    assert all(reference() is None for reference in endpoint_references)
    assert _api_route_count() <= baseline_routes
    assert _runtime_namespace_count() <= baseline_namespaces
