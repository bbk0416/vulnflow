from __future__ import annotations

import gc
from pathlib import Path
import shutil
import sys
import types
import weakref

from fastapi.testclient import TestClient

import app.main as main
from app.core.context import get_application_context
from app.routers import CONTEXT_ROUTER_MODULES

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


def _runtime_module_count() -> int:
    return sum(
        1
        for item in gc.get_objects()
        if isinstance(item, types.ModuleType)
        and ".__runtime_" in str(getattr(item, "__name__", ""))
    )


def test_isolated_router_runtime_uses_plain_namespaces(tmp_path: Path) -> None:
    application = main.create_app(setting_overrides=_settings(tmp_path / "namespace"))
    context = get_application_context(application)
    assert len(context.router_modules) == 16
    shared = [item for item in context.router_modules if item in CONTEXT_ROUTER_MODULES]
    isolated = [item for item in context.router_modules if item not in CONTEXT_ROUTER_MODULES]
    assert shared == list(CONTEXT_ROUTER_MODULES)
    assert all(isinstance(item, types.ModuleType) for item in shared)
    assert all(isinstance(item, types.SimpleNamespace) for item in isolated)
    assert all(not isinstance(item, types.ModuleType) for item in isolated)
    assert all(".__runtime_" in item.__name__ for item in isolated)


def test_isolated_router_namespaces_are_not_registered_modules(tmp_path: Path) -> None:
    application = main.create_app(setting_overrides=_settings(tmp_path / "registry"))
    context = get_application_context(application)
    shared = [item for item in context.router_modules if item in CONTEXT_ROUTER_MODULES]
    isolated = [item for item in context.router_modules if item not in CONTEXT_ROUTER_MODULES]
    assert all(item.__name__ in sys.modules for item in shared)
    assert all(item.__name__ not in sys.modules for item in isolated)


def test_plain_namespace_runtime_restarts_and_releases_app(tmp_path: Path) -> None:
    application = main.create_app(setting_overrides=_settings(tmp_path / "restart"))
    context = get_application_context(application)
    with TestClient(application) as client:
        assert client.get("/health/ready").status_code == 200
    isolated = [item for item in context.router_modules if item not in CONTEXT_ROUTER_MODULES]
    shared = [item for item in context.router_modules if item in CONTEXT_ROUTER_MODULES]
    assert all("app" not in item.__dict__ for item in isolated)
    assert all("app" not in item.__dict__ for item in shared)
    with TestClient(application) as client:
        assert client.get("/health/ready").status_code == 200
        assert all(item.__dict__.get("app") is application for item in isolated)
        assert all("app" not in item.__dict__ for item in shared)
    assert all("app" not in item.__dict__ for item in isolated)
    assert all("app" not in item.__dict__ for item in shared)


def test_repeated_plain_namespace_apps_add_no_runtime_modules(tmp_path: Path) -> None:
    gc.collect()
    baseline = _runtime_module_count()
    references: list[weakref.ReferenceType[object]] = []
    for index in range(3):
        application = main.create_app(setting_overrides=_settings(tmp_path / f"cycle-{index}"))
        with TestClient(application) as client:
            assert client.get("/health/live").status_code == 200
        references.append(weakref.ref(application))
        del client, application
        gc.collect()
    assert all(reference() is None for reference in references)
    assert _runtime_module_count() == baseline
