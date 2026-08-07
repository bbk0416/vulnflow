from __future__ import annotations

from functools import lru_cache
from pathlib import Path
import shutil
from types import SimpleNamespace

from fastapi.testclient import TestClient

import app.fastapi_runtime_cache as cache_runtime
import app.main as main
import app.routers as routers

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


def _cached_classifier():
    @lru_cache(maxsize=16)
    def classify(value: object) -> bool:
        return callable(value)

    classify(object())
    return classify


def test_callable_cache_cleanup_discovers_and_deduplicates_lru_wrappers(monkeypatch) -> None:
    first = _cached_classifier()
    second = _cached_classifier()
    models = SimpleNamespace(
        _is_gen_callable_cached=first,
        _is_async_gen_callable_cached=second,
        _is_coroutine_callable_cached=first,
    )
    utils = SimpleNamespace(_is_gen_callable_cached=first)
    modules = {
        "fastapi.dependencies.models": models,
        "fastapi.dependencies.utils": utils,
    }
    monkeypatch.setattr(cache_runtime, "import_module", modules.__getitem__)

    cleared = cache_runtime.clear_callable_classification_caches()

    assert len(cleared) == 2
    assert first.cache_info().currsize == 0
    assert second.cache_info().currsize == 0


def test_callable_cache_cleanup_is_compatible_with_missing_private_apis(monkeypatch) -> None:
    def import_fake(name: str):
        if name.endswith("models"):
            return SimpleNamespace(_is_gen_callable_cached=lambda _value: False)
        raise ImportError(name)

    monkeypatch.setattr(cache_runtime, "import_module", import_fake)
    assert cache_runtime.clear_callable_classification_caches() == ()


def test_isolated_lifespan_clears_callable_classification_caches(
    tmp_path: Path, monkeypatch,
) -> None:
    calls: list[str] = []
    monkeypatch.setattr(
        routers,
        "clear_callable_classification_caches",
        lambda: calls.append("cleared") or ("fake.cache",),
    )
    application = main.create_app(setting_overrides=_settings(tmp_path / "isolated"))

    with TestClient(application) as client:
        assert client.get("/health/live").status_code == 200

    assert calls == ["cleared"]


def test_primary_runtime_release_does_not_clear_global_callable_caches(monkeypatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr(
        routers,
        "clear_callable_classification_caches",
        lambda: calls.append("cleared") or (),
    )

    assert routers.release_runtime_application(main.APPLICATION_CONTEXT) is False
    assert calls == []
