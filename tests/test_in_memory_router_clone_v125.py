from __future__ import annotations

import builtins
from pathlib import Path
import shutil
from types import FunctionType, SimpleNamespace

from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

import app.main as main
import app.router_cloning as router_cloning
import app.routers as routers
from app.core.context import get_application_context
from app.routers import accounts, operations

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


def _route(application, name: str) -> APIRoute:
    return next(
        route
        for route in application.router.routes
        if isinstance(route, APIRoute) and route.name == name
    )


def test_router_runtime_contains_no_source_compilation_or_execution() -> None:
    sources = [
        (ROOT / "app" / "routers" / "__init__.py").read_text(encoding="utf-8"),
        (ROOT / "app" / "router_cloning.py").read_text(encoding="utf-8"),
    ]
    assert all("compile(" not in source for source in sources)
    assert all("exec(" not in source for source in sources)
    assert all(".read_text(" not in source for source in sources)


def test_router_clone_does_not_open_the_router_source(monkeypatch) -> None:
    original_open = builtins.open

    def guarded_open(file, *args, **kwargs):
        if str(file).replace("\\", "/").endswith("/app/routers/accounts.py"):
            raise AssertionError("router source must not be opened during runtime cloning")
        return original_open(file, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", guarded_open)
    clone = routers._clone_router_module(accounts, "sourcefree")

    assert isinstance(clone, SimpleNamespace)
    assert len(clone.router.routes) == len(accounts.router.routes) == 9


def test_cloned_route_functions_share_one_private_namespace() -> None:
    clone = routers._clone_router_module(accounts, "private")
    functions = [
        value
        for value in clone.__dict__.values()
        if isinstance(value, FunctionType) and value.__module__ == clone.__name__
    ]
    routes = [route for route in clone.router.routes if isinstance(route, APIRoute)]

    assert functions
    assert len(routes) == 9
    assert all(function.__globals__ is clone.__dict__ for function in functions)
    assert all(route.endpoint.__globals__ is clone.__dict__ for route in routes)
    assert all(route.endpoint.__module__ == clone.__name__ for route in routes)



def test_cloned_route_parameter_defaults_restore_constructor_state() -> None:
    implicit = accounts.login_submit.__defaults__[0]
    explicit = next(
        default
        for name in ("api_queue_import_job", "api_queue_job")
        for default in (getattr(operations, name).__defaults__ or ())
        if getattr(default, "alias", None) == "Idempotency-Key"
    )

    implicit_clone = router_cloning._clone_parameter_value(implicit)
    explicit_clone = router_cloning._clone_parameter_value(explicit)

    assert implicit_clone is not implicit
    assert implicit_clone.alias is None
    assert implicit_clone.annotation is None
    assert explicit_clone is not explicit
    assert explicit_clone.alias == "Idempotency-Key"
    assert explicit_clone.validation_alias == "Idempotency-Key"
    assert explicit_clone.serialization_alias == "Idempotency-Key"
    assert explicit_clone.annotation is None


def test_complete_router_assembly_uses_one_serialization_boundary(
    tmp_path: Path,
    monkeypatch,
) -> None:
    class RecordingLock:
        def __init__(self) -> None:
            self.entered = 0
            self.exited = 0

        def __enter__(self):
            self.entered += 1
            return self

        def __exit__(self, exc_type, exc, traceback) -> None:
            self.exited += 1

    recording_lock = RecordingLock()
    monkeypatch.setattr(routers, "_ROUTER_ASSEMBLY_LOCK", recording_lock)

    application = main.create_app(setting_overrides=_settings(tmp_path / "serialized"))

    assert recording_lock.entered == 1
    assert recording_lock.exited == 1
    assert len(application.router.routes) >= 276


def test_multiple_apps_receive_distinct_in_memory_route_namespaces(tmp_path: Path) -> None:
    first = main.create_app(setting_overrides=_settings(tmp_path / "first"))
    second = main.create_app(setting_overrides=_settings(tmp_path / "second"))
    first_context = get_application_context(first)
    second_context = get_application_context(second)
    first_login = _route(first, "login_page").endpoint
    second_login = _route(second, "login_page").endpoint

    assert first_login is not second_login
    assert first_login.__globals__ is not second_login.__globals__
    assert first_login.__globals__["CONTROL_DB_PATH"] == first_context.settings.require("CONTROL_DB_PATH")
    assert second_login.__globals__["CONTROL_DB_PATH"] == second_context.settings.require("CONTROL_DB_PATH")

    with TestClient(first) as client:
        assert client.get("/health/live").status_code == 200
    with TestClient(second) as client:
        assert client.get("/health/live").status_code == 200
