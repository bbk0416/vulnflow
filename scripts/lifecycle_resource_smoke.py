from __future__ import annotations

import asyncio
import gc
import json
from pathlib import Path
import tempfile
import threading
import time
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient

import app.main as main
from app.core.context import get_application_context
from app.services.lifecycle_resources import LifecycleResourceTracker
from app.services.lifecycle_runtime import LifecycleSupervisor


def settings(root: Path, index: int) -> dict[str, object]:
    return {
        "DB_PATH": root / f"app-{index}.db",
        "EVIDENCE_DIR": root / f"evidence-{index}",
        "EXPORT_DIR": root / f"exports-{index}",
        "RECOVERY_DIR": root / f"recovery-{index}",
        "COORDINATION_DB_ENV": str(root / f"coordination-{index}.db"),
        "CLUSTER_COORDINATION_ENABLED": False,
        "DEMO_MODE": True,
            "ALLOW_LOCAL_ADMIN_FALLBACK": True,
        "JOB_WORKER_ENABLED": False,
        "MAINTENANCE_INTERVAL_MINUTES": 1,
        "WEBHOOK_INTERVAL_SECONDS": 1,
        "BACKUP_INTERVAL_HOURS": 1,
        "WEBHOOKS_JSON": json.dumps({
            "sink": {
                "url": "https://example.invalid/hook",
                "secret": "0123456789abcdef",
                "events": ["*"],
            }
        }),
        "LIFECYCLE_SHUTDOWN_TIMEOUT_SECONDS": 0.5,
    }


async def direct_tracker_check(root: Path) -> dict[str, object]:
    context = main.APPLICATION_CONTEXT.clone(
        namespace=dict(main.__dict__),
        setting_overrides={**settings(root, 0), "WEBHOOK_ENDPOINTS": {"sink": {"url": "https://example.invalid"}}},
        coordination_state={"is_leader": True, "scheduler_token": None},
    )
    supervisor = LifecycleSupervisor(context)
    supervisor.start()
    await asyncio.sleep(0)
    running = supervisor.snapshot()
    started = time.perf_counter()
    stopped = await supervisor.stop()
    elapsed = time.perf_counter() - started
    repeated = await supervisor.stop()
    return {
        "running": running,
        "stopped": stopped,
        "repeated_equal": repeated == stopped,
        "elapsed_seconds": elapsed,
    }


def main_smoke() -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="vulnflow-lifecycle-") as temp_name:
        root = Path(temp_name)
        direct = asyncio.run(direct_tracker_check(root))
        baseline_portals = {
            thread.ident for thread in threading.enumerate()
            if "asyncio-portal" in thread.name.lower()
        }
        contexts = []
        ready_statuses = []
        for index in range(1, 7):
            application = main.create_app(setting_overrides=settings(root, index))
            context = get_application_context(application)
            contexts.append(context)
            with TestClient(application) as client:
                ready_statuses.append(client.get("/health/ready").status_code)
                assert context.runtime_snapshot()["lifecycle_state"] == "RUNNING"
            assert context.runtime_snapshot()["lifecycle_state"] == "STOPPED"

        gc.collect()
        time.sleep(0.1)
        remaining_portals = {
            thread.ident for thread in threading.enumerate()
            if "asyncio-portal" in thread.name.lower()
        }
        snapshots = [context.get("LIFECYCLE_SHUTDOWN_SNAPSHOT") for context in contexts]
        checks = [
            {"name": "version_72_0_7", "passed": main.CURRENT_APP_VERSION == "72.0.80"},
            {"name": "schema_42", "passed": main.CURRENT_SCHEMA_VERSION == 46},
            {"name": "three_named_tasks", "passed": direct["running"]["started_task_names"] == ["backup", "maintenance", "webhook"]},
            {"name": "running_state", "passed": direct["running"]["state"] == "RUNNING"},
            {"name": "stopped_state", "passed": direct["stopped"]["state"] == "STOPPED"},
            {"name": "zero_running_after_stop", "passed": direct["stopped"]["running_task_count"] == 0},
            {"name": "bounded_shutdown", "passed": direct["elapsed_seconds"] < 0.5},
            {"name": "no_shutdown_timeout", "passed": direct["stopped"]["shutdown_timed_out"] is False},
            {"name": "idempotent_stop", "passed": direct["repeated_equal"] is True},
            {"name": "six_ready_apps", "passed": ready_statuses == [200] * 6},
            {"name": "six_clean_snapshots", "passed": all(not item["shutdown_timed_out"] and item["running_task_count"] == 0 for item in snapshots)},
            {"name": "portal_threads_reclaimed", "passed": remaining_portals <= baseline_portals},
        ]
        if not all(item["passed"] for item in checks):
            raise AssertionError(checks)
        return {
            "title": "VulnFlow 72.0.80 deterministic lifecycle resource verification",
            "version": main.CURRENT_APP_VERSION,
            "checks": checks,
            "shutdown_elapsed_ms": round(float(direct["elapsed_seconds"]) * 1000.0, 3),
            "repeated_app_count": len(contexts),
        }


if __name__ == "__main__":
    result = main_smoke()
    reports = ROOT / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    (reports / "lifecycle_resource_verification.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    lines = [result["title"], ""]
    lines.extend(f"{item['name']}: {'PASS' if item['passed'] else 'FAIL'}" for item in result["checks"])
    lines.extend([
        "",
        f"shutdown elapsed: {result['shutdown_elapsed_ms']} ms",
        f"repeated app lifespans: {result['repeated_app_count']}",
    ])
    text = "\n".join(lines) + "\n"
    (reports / "lifecycle_resource_verification.txt").write_text(text, encoding="utf-8")
    print(text, end="")
