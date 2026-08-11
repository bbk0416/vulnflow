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
from app import endpoint_workflows
from app.core.architecture import build_architecture_report
from app.core.context import get_application_context


def main_smoke() -> None:
    architecture = build_architecture_report(ROOT)
    by_path = {item["path"]: item for item in architecture["modules"]}
    with tempfile.TemporaryDirectory(prefix="vulnflow-v69-endpoint-") as temp:
        root = Path(temp)
        application = main.create_app(setting_overrides={
            "DB_PATH": root / "workflow.db",
            "EVIDENCE_DIR": root / "evidence",
            "EXPORT_DIR": root / "exports",
            "RECOVERY_DIR": root / "recovery",
            "COORDINATION_DB_ENV": str(root / "coordination.db"),
            "CLUSTER_COORDINATION_ENABLED": False,
        "DEMO_MODE": True,
            "ALLOW_LOCAL_ADMIN_FALLBACK": True,
            "JOB_WORKER_ENABLED": False,
            "LIFECYCLE_SHUTDOWN_TIMEOUT_SECONDS": 0.5,
        })
        context = get_application_context(application)
        with TestClient(application) as client:
            response = client.get("/health/ready", headers={"X-Request-ID": "v69-workflow-smoke"})
        stopped = context.runtime_snapshot()

    checks = {
        "version_72_0_7": main.CURRENT_APP_VERSION == "72.0.76",
        "schema_42": main.CURRENT_SCHEMA_VERSION == 46,
        "architecture_pass": architecture["status"] == "PASS",
        "main_budget": by_path["app/main.py"]["lines"] <= 500,
        "workflow_budget": by_path["app/endpoint_workflows.py"]["lines"] <= 500,
        "workflow_does_not_import_main": "app.main" not in by_path["app/endpoint_workflows.py"]["internal_imports"],
        "compatibility_object": isinstance(main._ENDPOINT_WORKFLOWS, endpoint_workflows.EndpointWorkflows),
        "route_count_261": sum(int(item.get("routes") or 0) for item in architecture["modules"]) == 261,
        "health_round_trip": response.status_code == 200 and response.headers.get("X-Request-ID") == "v69-workflow-smoke",
        "lifecycle_stopped": stopped.get("lifecycle_state") == "STOPPED" and stopped.get("lifecycle_shutdown_timed_out") is False,
    }
    payload = {
        "title": "VulnFlow 72.0.76 endpoint workflow boundary verification",
        "version": main.CURRENT_APP_VERSION,
        "checks": [{"name": name, "passed": passed} for name, passed in checks.items()],
        "result": f"{sum(checks.values())}/{len(checks)}",
    }
    reports = ROOT / "reports"
    reports.mkdir(exist_ok=True)
    (reports / "endpoint_workflow_boundary_verification.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    lines = [payload["title"], f"version: {payload['version']}", ""]
    lines += [f"{name}: {'PASS' if passed else 'FAIL'}" for name, passed in checks.items()]
    lines += ["", f"result: {payload['result']}"]
    (reports / "endpoint_workflow_boundary_verification.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    if not all(checks.values()):
        raise SystemExit(1)


if __name__ == "__main__":
    main_smoke()
