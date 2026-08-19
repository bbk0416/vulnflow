from __future__ import annotations

import ast
import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import app.main as main
from app.core.architecture import build_architecture_report
from app.services import job_dispatch, job_runtime, job_worker_runtime


def main_smoke() -> int:
    architecture = build_architecture_report(ROOT)
    modules = {item["path"]: item for item in architecture["modules"]}
    importers: list[str] = []
    for path in sorted((ROOT / "app").rglob("*.py")):
        relative = path.relative_to(ROOT).as_posix()
        if relative == "app/services/job_runtime.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "app.services.job_runtime":
                importers.append(relative)
            elif isinstance(node, ast.Import) and any(alias.name == "app.services.job_runtime" for alias in node.names):
                importers.append(relative)

    context = main.APPLICATION_CONTEXT.clone(namespace=dict(main.__dict__), coordination_state={})
    stop_event = asyncio.Event()
    stop_event.set()
    asyncio.run(job_worker_runtime.job_worker_loop(context, stop_event=stop_event))

    checks = {
        "version_72_0_7": main.CURRENT_APP_VERSION == "72.0.92",
        "facade_dispatch_identity": job_runtime.execute_background_job is job_dispatch.execute_background_job,
        "facade_worker_identity": job_runtime.job_worker_loop is job_worker_runtime.job_worker_loop,
        "internal_facade_importers_zero": not importers,
        "dispatch_owner_present": "def execute_background_job(" in (ROOT / "app/services/job_dispatch.py").read_text(encoding="utf-8"),
        "worker_owner_present": "async def job_worker_loop(" in (ROOT / "app/services/job_worker_runtime.py").read_text(encoding="utf-8"),
        "facade_is_thin": modules["app/services/job_runtime.py"]["lines"] <= 60,
        "dispatch_budget": modules["app/services/job_dispatch.py"]["lines"] <= 320,
        "worker_budget": modules["app/services/job_worker_runtime.py"]["lines"] <= 160,
        "architecture_pass": architecture["status"] == "PASS" and architecture["route_count"] == 261,
    }
    payload = {
        "title": "VulnFlow 72.0.92 background job runtime boundary verification",
        "version": main.CURRENT_APP_VERSION,
        "checks": [{"name": name, "passed": passed} for name, passed in checks.items()],
        "internal_facade_importers": sorted(set(importers)),
        "result": f"{sum(checks.values())}/{len(checks)}",
    }
    reports = ROOT / "reports"
    reports.mkdir(exist_ok=True)
    (reports / "job_runtime_boundary_verification.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    lines = [payload["title"], f"version: {payload['version']}", ""]
    lines += [f"{name}: {'PASS' if passed else 'FAIL'}" for name, passed in checks.items()]
    lines += ["", f"result: {payload['result']}"]
    (reports / "job_runtime_boundary_verification.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    return 0 if all(checks.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main_smoke())
