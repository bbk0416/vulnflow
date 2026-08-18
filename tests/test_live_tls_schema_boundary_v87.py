from __future__ import annotations

import json
from pathlib import Path

import yaml

from app.core import database_schema
from app.core.schema_versions import CURRENT_APP_VERSION, CURRENT_SCHEMA_VERSION
from scripts.container_deployment_rehearsal import _deployment_environment
from scripts.live_tls_proxy_rehearsal import (
    _render_nginx_configuration,
    _runtime_environment,
)
from scripts.production_security_rehearsal import run_rehearsal


ROOT = Path(__file__).resolve().parents[1]

def _path_endswith_components(value: str, *components: str) -> bool:
    normalized = value.replace("\\", "/").rstrip("/")
    parts = tuple(part for part in normalized.split("/") if part)
    return parts[-len(components):] == components if len(parts) >= len(components) else False



def test_database_schema_facade_reexports_central_versions() -> None:
    assert CURRENT_APP_VERSION == "72.0.91"
    assert CURRENT_SCHEMA_VERSION == 46
    assert database_schema.CURRENT_APP_VERSION == CURRENT_APP_VERSION
    assert database_schema.CURRENT_SCHEMA_VERSION == CURRENT_SCHEMA_VERSION


def test_schema_implementation_is_split_below_hard_budgets() -> None:
    limits = {
        "app/core/database_schema.py": 220,
        "app/core/database_backfills.py": 120,
        "app/core/database_migrations.py": 360,
        "app/core/database_search.py": 80,
        "app/core/database_triggers.py": 260,
        "app/core/schema_versions.py": 30,
    }
    for relative, maximum in limits.items():
        path = ROOT / relative
        assert path.is_file()
        assert len(path.read_text(encoding="utf-8").splitlines()) <= maximum
    facade = (ROOT / "app/core/database_schema.py").read_text(encoding="utf-8")
    assert "CREATE TRIGGER" not in facade
    assert "ALTER TABLE" not in facade
    version_check = (ROOT / "scripts/version_consistency_smoke.py").read_text(encoding="utf-8")
    assert "app/core/schema_versions.py" in version_check


def test_production_proxy_overwrites_untrusted_forwarded_for() -> None:
    nginx = (ROOT / "deploy/nginx/vulnflow.conf").read_text(encoding="utf-8")
    compose = yaml.safe_load((ROOT / "docker-compose.production.yml").read_text(encoding="utf-8"))
    app = compose["services"]["vulnflow"]
    assert app["environment"]["FORWARDED_ALLOW_IPS"] == "*"
    assert compose["networks"]["backend"]["internal"] is True
    assert "proxy_set_header X-Forwarded-For $remote_addr;" in nginx
    assert "$proxy_add_x_forwarded_for" not in nginx
    assert "proxy_set_header X-Forwarded-Proto https;" in nginx
    assert "proxy_set_header X-Forwarded-Port 443;" in nginx


def test_live_rehearsal_renders_the_deployed_nginx_template(tmp_path: Path) -> None:
    config = _render_nginx_configuration(
        tmp_path,
        app_port=18000,
        http_port=18080,
        https_port=18443,
        certificate=tmp_path / "fullchain.pem",
        private_key=tmp_path / "privkey.pem",
    ).read_text(encoding="utf-8")
    assert "listen 127.0.0.1:18080;" in config
    assert "listen 127.0.0.1:18443 ssl;" in config
    assert "proxy_pass http://127.0.0.1:18000;" in config
    assert "proxy_set_header X-Forwarded-For $remote_addr;" in config
    assert "https://localhost:18443$request_uri" in config


def test_rehearsal_environments_use_split_storage_and_scoped_tokens(tmp_path: Path) -> None:
    live = _runtime_environment(tmp_path / "live", 18443)
    assert _path_endswith_components(live["VULNFLOW_CONTROL_DB"], "control.db")
    assert _path_endswith_components(live["VULNFLOW_DEFAULT_PROJECT_DB"], "projects", "default", "vulnflow.db")
    assert live["VULNFLOW_SECURITY_PROFILE"] == "pilot"
    assert live["VULNFLOW_RUNTIME_DEPENDENCY_POLICY"] == "warn"

    container = _deployment_environment(tmp_path / "container", 1)
    tokens = json.loads(container["VULNFLOW_API_TOKENS_JSON"])
    assert _path_endswith_components(container["VULNFLOW_CONTROL_DB"], "control.db")
    assert _path_endswith_components(container["VULNFLOW_DEFAULT_PROJECT_DB"], "projects", "default", "vulnflow.db")
    assert all(item["projects"] == ["default"] for item in tokens.values())


def test_rehearsal_path_contract_accepts_windows_and_posix_separators() -> None:
    assert _path_endswith_components(
        r"C:\validation\data\projects\default\vulnflow.db",
        "projects",
        "default",
        "vulnflow.db",
    )
    assert _path_endswith_components(
        "/validation/data/projects/default/vulnflow.db",
        "projects",
        "default",
        "vulnflow.db",
    )
    assert not _path_endswith_components(
        r"C:\validation\data\projects\other\vulnflow.db",
        "projects",
        "default",
        "vulnflow.db",
    )


def test_static_production_rehearsal_covers_proxy_trust_boundary() -> None:
    report = run_rehearsal(ROOT)
    assert report["passed"] is True
    assert report["checks"]["proxy_headers_trusted_only_on_internal_network"] is True
    assert report["checks"]["forwarded_for_overwritten_at_edge"] is True
    assert report["checks"]["duplicate_edge_headers_hidden"] is True
