from __future__ import annotations

import gc
from pathlib import Path
import shutil
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


def test_isolated_lifespan_releases_application_back_reference(tmp_path: Path) -> None:
    application = main.create_app(setting_overrides=_settings(tmp_path / "release"))
    context = get_application_context(application)
    modules = tuple(context.router_modules)
    assert modules
    isolated = [module for module in modules if module not in CONTEXT_ROUTER_MODULES]
    shared = [module for module in modules if module in CONTEXT_ROUTER_MODULES]
    assert all(module.__dict__.get("app") is application for module in isolated)
    assert all("app" not in module.__dict__ for module in shared)

    with TestClient(application) as client:
        assert client.get("/health/live").status_code == 200
        assert context.app is application

    assert context.app is None
    assert "app" not in context.namespace
    assert all("app" not in module.__dict__ for module in modules)


def test_isolated_application_can_restart_after_release(tmp_path: Path) -> None:
    application = main.create_app(setting_overrides=_settings(tmp_path / "restart"))
    context = get_application_context(application)

    with TestClient(application) as client:
        assert client.get("/health/ready").status_code == 200
    assert context.app is None

    with TestClient(application) as client:
        assert client.get("/health/ready").status_code == 200
        assert context.app is application
    assert context.app is None


def test_repeated_isolated_lifespans_do_not_retain_apps_or_runtime_modules(tmp_path: Path) -> None:
    gc.collect()
    baseline_modules = _runtime_module_count()
    references: list[weakref.ReferenceType[object]] = []

    for index in range(3):
        application = main.create_app(
            setting_overrides=_settings(tmp_path / f"cycle-{index}")
        )
        with TestClient(application) as client:
            assert client.get("/health/live").status_code == 200
        references.append(weakref.ref(application))
        del client, application
        gc.collect()

    assert all(reference() is None for reference in references)
    assert _runtime_module_count() == baseline_modules


def test_router_release_contract_remains_scoped_to_isolated_instances() -> None:
    from app.routers import ROUTER_MODULES, release_runtime_application

    assert main.APPLICATION_CONTEXT.router_modules == tuple(ROUTER_MODULES)
    assert release_runtime_application(main.APPLICATION_CONTEXT) is False
    assert main.APPLICATION_CONTEXT.app is main.app
