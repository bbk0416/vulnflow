from __future__ import annotations

from pathlib import Path

from scripts.production_compose_rehearsal import (
    build_rehearsal_compose,
    rehearsal_environment,
    run_rehearsal,
)

ROOT = Path(__file__).resolve().parents[1]


def test_generated_production_compose_uses_loopback_tls_and_no_app_port(tmp_path: Path) -> None:
    certs = tmp_path / "certs"
    certs.mkdir()
    compose = build_rehearsal_compose(
        ROOT,
        certificate_directory=certs,
        http_port=18080,
        https_port=18443,
        image="vulnflow:test-compose",
    )
    app = compose["services"]["vulnflow"]
    proxy = compose["services"]["proxy"]
    assert not app.get("ports")
    assert app["build"]["context"] == str(ROOT.resolve())
    assert proxy["ports"] == ["127.0.0.1:18080:80", "127.0.0.1:18443:443"]
    cert_mounts = [
        item
        for item in proxy["volumes"]
        if isinstance(item, dict) and item.get("target") == "/etc/nginx/certs"
    ]
    assert len(cert_mounts) == 1
    assert cert_mounts[0]["type"] == "bind"
    assert cert_mounts[0]["read_only"] is True


def test_compose_rehearsal_environment_is_fail_closed() -> None:
    env = rehearsal_environment(https_port=18443)
    assert env["VULNFLOW_PUBLIC_BASE_URL"] == "https://localhost:18443"
    assert env["VULNFLOW_OUTBOUND_ALLOW_PRIVATE_NETWORKS"] == "0"
    assert env["VULNFLOW_SMTP_ALLOW_PRIVATE_NETWORKS"] == "0"
    assert env["VULNFLOW_SMTP_ALLOW_PLAIN"] == "0"
    assert '"projects": ["default"]' in env["VULNFLOW_API_TOKENS_JSON"]


def test_compose_rehearsal_reports_unavailable_without_docker(monkeypatch) -> None:
    monkeypatch.setattr("scripts.production_compose_rehearsal.shutil.which", lambda name: None)
    report = run_rehearsal(require_docker=False)
    assert report["available"] is False
    assert report["passed"] is None
    assert "docker" in report["reason"]


def test_public_ci_requires_actual_production_compose_rehearsal() -> None:
    workflow = (ROOT / ".github/workflows/public-ci.yml").read_text(encoding="utf-8")
    assert "production_compose_rehearsal.py --require-docker" in workflow
    assert "production-validation / Docker upgrade and production Compose" in workflow
