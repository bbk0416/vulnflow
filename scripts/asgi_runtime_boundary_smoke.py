from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import app.main as main
from app import application_runtime
from app.application_lifespan import application_lifespan, lifespan_scoped
from app.application_runtime_common import runtime_callback
from app.core.architecture import build_architecture_report
from app.core.context import get_application_context
from app.http_runtime import friendly_http_error, local_security, local_security_scoped


def main_smoke() -> None:
    architecture = build_architecture_report(ROOT)
    by_path = {item["path"]: item for item in architecture["modules"]}
    with tempfile.TemporaryDirectory(prefix="vulnflow-v72-asgi-runtime-") as temp:
        root = Path(temp)
        application = main.create_app(setting_overrides={
            "DB_PATH": root / "runtime.db",
            "EVIDENCE_DIR": root / "evidence",
            "EXPORT_DIR": root / "exports",
            "RECOVERY_DIR": root / "recovery",
            "COORDINATION_DB_ENV": str(root / "coordination.db"),
            "CLUSTER_COORDINATION_ENABLED": False,
        "DEMO_MODE": True,
            "ALLOW_LOCAL_ADMIN_FALLBACK": True,
            "JOB_WORKER_ENABLED": False,
            "MAINTENANCE_INTERVAL_MINUTES": 1,
            "WEBHOOK_INTERVAL_SECONDS": 1,
            "BACKUP_INTERVAL_HOURS": 1,
            "LIFECYCLE_SHUTDOWN_TIMEOUT_SECONDS": 0.5,
        })
        context = get_application_context(application)
        with TestClient(application) as client:
            response = client.get("/health/ready", headers={"X-Request-ID": "v72-smoke"})
            running = context.runtime_snapshot()
        stopped = context.runtime_snapshot()

    checks = {
        "version_72_0_7": main.CURRENT_APP_VERSION == "72.0.99",
        "schema_42": main.CURRENT_SCHEMA_VERSION == 46,
        "architecture_pass": architecture["status"] == "PASS",
        "facade_budget": by_path["app/application_runtime.py"]["lines"] <= 60,
        "lifespan_budget": by_path["app/application_lifespan.py"]["lines"] <= 180,
        "http_runtime_budget": by_path["app/http_runtime.py"]["lines"] <= 260,
        "facade_identity": (
            application_runtime.application_lifespan is application_lifespan
            and application_runtime.lifespan_scoped is lifespan_scoped
            and application_runtime.local_security is local_security
            and application_runtime.local_security_scoped is local_security_scoped
            and application_runtime.friendly_http_error is friendly_http_error
            and application_runtime.runtime_callback is runtime_callback
        ),
        "health_round_trip": response.status_code == 200 and response.headers.get("X-Request-ID") == "v72-smoke",
        "lifecycle_running": running.get("lifecycle_state") == "RUNNING",
        "lifecycle_stopped": stopped.get("lifecycle_state") == "STOPPED" and stopped.get("lifecycle_shutdown_timed_out") is False,
    }
    payload = {
        "title": "VulnFlow 72.0.99 split ASGI runtime boundary verification",
        "version": main.CURRENT_APP_VERSION,
        "checks": [{"name": name, "passed": passed} for name, passed in checks.items()],
        "result": f"{sum(checks.values())}/{len(checks)}",
    }
    reports = ROOT / "reports"
    reports.mkdir(exist_ok=True)
    (reports / "asgi_runtime_boundary_verification.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    lines = [payload["title"], f"version: {payload['version']}", ""]
    lines += [f"{name}: {'PASS' if passed else 'FAIL'}" for name, passed in checks.items()]
    lines += ["", f"result: {payload['result']}"]
    (reports / "asgi_runtime_boundary_verification.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    if not all(checks.values()):
        raise SystemExit(1)


if __name__ == "__main__":
    main_smoke()
