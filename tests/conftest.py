from pathlib import Path
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
    monkeypatch.setattr(main, "ALLOW_LOCAL_ADMIN_FALLBACK", True)
    monkeypatch.setattr(
        main.APPLICATION_CONTEXT,
        "settings",
        main.APPLICATION_CONTEXT.settings.with_overrides(
            {"ALLOW_LOCAL_ADMIN_FALLBACK": True}
        ),
    )


@pytest.fixture()
def client(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "vulnflow.db")
    monkeypatch.setattr(main, "EVIDENCE_DIR", tmp_path / "evidence")
    monkeypatch.setattr(main, "RECOVERY_DIR", tmp_path / "recovery")
    with TestClient(main.app) as test_client:
        yield test_client
