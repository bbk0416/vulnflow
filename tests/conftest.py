from pathlib import Path
import shutil
import sys

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import app.main as main


@pytest.fixture(autouse=True)
def enable_explicit_test_local_fallback(monkeypatch):
    # Production defaults deny unauthenticated startup. Starlette's synthetic
    # testclient host is treated as local only when the fallback is explicit.
    monkeypatch.setattr(main, "DEMO_MODE", True)
    monkeypatch.setattr(main, "ALLOW_LOCAL_ADMIN_FALLBACK", True)
    monkeypatch.setattr(
        main.APPLICATION_CONTEXT,
        "settings",
        main.APPLICATION_CONTEXT.settings.with_overrides(
            {"DEMO_MODE": True, "ALLOW_LOCAL_ADMIN_FALLBACK": True}
        ),
    )


@pytest.fixture()
def client(tmp_path: Path, monkeypatch):
    control_db = tmp_path / "control.db"
    default_root = tmp_path / "projects" / "default"
    default_db = default_root / "vulnflow.db"
    overrides = {
        "DATA_DIR": tmp_path,
        "LEGACY_DB_PATH": tmp_path / "legacy-vulnflow.db",
        "CONTROL_DB_PATH": control_db,
        "DEFAULT_PROJECT_ROOT": default_root,
        "DEFAULT_PROJECT_DB_PATH": default_db,
        "DB_PATH": default_db,
        "PROJECTS_DIR": tmp_path / "projects",
        "EVIDENCE_DIR": default_root / "evidence",
        "EXPORT_DIR": default_root / "exports",
        "IMPORT_PREVIEW_DIR": default_root / "import-previews",
        "RECOVERY_DIR": default_root / "backups" / "recovery",
        "LEGACY_EVIDENCE_DIR": tmp_path / "legacy-evidence",
        "LEGACY_EXPORT_DIR": tmp_path / "legacy-exports",
        "LEGACY_IMPORT_PREVIEW_DIR": tmp_path / "legacy-previews",
        "LEGACY_RECOVERY_DIR": tmp_path / "legacy-recovery",
    }
    for sample in (
        "sample_findings.csv",
        "sample_product_release.cdx.json",
        "sample_sbom.cdx.json",
        "sample_sbom_v2.cdx.json",
    ):
        shutil.copy2(ROOT / "data" / sample, tmp_path / sample)
    for name, value in overrides.items():
        monkeypatch.setattr(main, name, value, raising=False)
    monkeypatch.setattr(
        main.APPLICATION_CONTEXT,
        "settings",
        main.APPLICATION_CONTEXT.settings.with_overrides(overrides),
    )
    with TestClient(main.app) as test_client:
        yield test_client
