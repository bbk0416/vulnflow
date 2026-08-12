from __future__ import annotations

import json
import tempfile
from pathlib import Path
import sys

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import app.main as main
from app.core.auth import authenticate_request, is_trusted_local_host


def main_smoke() -> dict[str, object]:
    checks: list[dict[str, object]] = []

    def check(name: str, passed: bool) -> None:
        checks.append({"name": name, "passed": bool(passed)})

    check("default_closed", authenticate_request("", client_host="127.0.0.1") is None)
    local = authenticate_request("", allow_local_fallback=True, client_host="127.0.0.1")
    check("explicit_loopback_admin", local is not None and local.auth_method == "local" and local.role == "admin")
    check("remote_fallback_blocked", authenticate_request("", allow_local_fallback=True, client_host="192.0.2.2") is None)
    check("ipv6_loopback", is_trusted_local_host("::1"))

    with tempfile.TemporaryDirectory(prefix="vulnflow-safe-auth-") as temporary:
        root = Path(temporary)
        common = {
            "DB_PATH": root / "vulnflow.db",
            "EVIDENCE_DIR": root / "evidence",
            "EXPORT_DIR": root / "exports",
            "RECOVERY_DIR": root / "recovery",
            "AUTH_USERS_JSON": "",
            "AUTH_API_TOKENS_JSON": "",
            "AUTH_USER": "",
            "AUTH_PASSWORD": "",
            "JOB_WORKER_ENABLED": False,
            "CLUSTER_COORDINATION_ENABLED": False,
        }
        denied = main.create_app(setting_overrides={**common, "ALLOW_LOCAL_ADMIN_FALLBACK": False})
        denied_start = False
        try:
            with TestClient(denied):
                pass
        except RuntimeError as exc:
            denied_start = "활성 사용자 계정 또는 API token" in str(exc)
        check("missing_auth_startup_denied", denied_start)

        allowed = main.create_app(
            setting_overrides={**common, "DEMO_MODE": True, "ALLOW_LOCAL_ADMIN_FALLBACK": True}
        )
        with TestClient(allowed) as client:
            check("explicit_testclient_local", client.get("/").status_code == 200)

    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    linux = (ROOT / "run_linux.sh").read_text(encoding="utf-8")
    windows = (ROOT / "run_windows.ps1").read_text(encoding="utf-8")
    check("compose_version_tag", "vulnflow:72.0.79" in compose)
    check("compose_fallback_disabled", "VULNFLOW_ALLOW_LOCAL_ADMIN_FALLBACK:-0" in compose)
    check("container_fallback_disabled", "VULNFLOW_ALLOW_LOCAL_ADMIN_FALLBACK=0" in dockerfile)
    check(
        "local_launchers_default_closed",
        "VULNFLOW_ALLOW_LOCAL_ADMIN_FALLBACK:=0" in linux
        and 'VULNFLOW_ALLOW_LOCAL_ADMIN_FALLBACK = "0"' in windows,
    )

    passed = sum(bool(item["passed"]) for item in checks)
    payload = {
        "title": "VulnFlow 72.0.79 safe authentication defaults verification",
        "version": main.CURRENT_APP_VERSION,
        "passed": passed,
        "total": len(checks),
        "checks": checks,
    }
    reports = ROOT / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    (reports / "safe_auth_defaults_verification.json").write_text(
        json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    lines = [payload["title"], "", f"version: {payload['version']}"]
    lines.extend(f"[{ 'PASS' if item['passed'] else 'FAIL' }] {item['name']}" for item in checks)
    lines.append("")
    lines.append(f"result: {passed}/{len(checks)}")
    (reports / "safe_auth_defaults_verification.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    if passed != len(checks):
        raise SystemExit(1)
    return payload


if __name__ == "__main__":
    main_smoke()
