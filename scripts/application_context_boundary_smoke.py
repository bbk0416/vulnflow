from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.core.architecture import build_architecture_report
from app.core.context import ApplicationContext, RequestRuntime, get_application_context
from app.core.context_composition import build_dependency_mapping, clone_application_context
from app.core.context_diagnostics import application_runtime_snapshot
from app.core.database_schema import CURRENT_APP_VERSION


def main_smoke() -> int:
    base_db = ROOT / "data" / "context-boundary-base.db"
    clone_db = ROOT / "data" / "context-boundary-clone.db"
    marker = object()
    context = ApplicationContext(
        namespace={
            "DB_PATH": base_db,
            "AUTH_API_TOKENS_JSON": '{"boundary":{"token":"boundary-secret","role":"admin","projects":"*"}}',
            "service_marker": marker,
        },
        templates=object(),
        metrics=object(),
        logger=object(),
        coordination_state={},
    )
    clone = clone_application_context(
        context,
        setting_overrides={"DB_PATH": clone_db},
        service_overrides={"clone_marker": object()},
    )
    snapshot = application_runtime_snapshot(context)
    runtime = RequestRuntime(context, "operator", "ADMIN", "smoke", "req-64")
    app = SimpleNamespace(state=SimpleNamespace(vulnflow_context=context))
    architecture = build_architecture_report(ROOT)
    modules = {item["path"]: item for item in architecture["modules"]}

    checks = {
        "version_72_0_7": CURRENT_APP_VERSION == "72.0.81",
        "context_lines_bounded": modules["app/core/context.py"]["lines"] <= 130,
        "composition_lines_bounded": modules["app/core/context_composition.py"]["lines"] <= 140,
        "diagnostics_lines_bounded": modules["app/core/context_diagnostics.py"]["lines"] <= 80,
        "dependency_mapping_owned": context.dependency_mapping() == build_dependency_mapping(context),
        "clone_isolated": clone.settings.require("DB_PATH") == clone_db and context.settings.require("DB_PATH") == base_db,
        "snapshot_non_secret": "boundary-secret" not in str(snapshot) and str(base_db) not in str(snapshot),
        "request_runtime_compatible": runtime.get("service_marker") is marker,
        "application_lookup_compatible": get_application_context(app) is context,
        "architecture_pass": architecture["status"] == "PASS",
    }
    report = {
        "title": "VulnFlow 72.0.81 application context boundary verification",
        "version": CURRENT_APP_VERSION,
        "checks": checks,
        "passed": sum(checks.values()),
        "total": len(checks),
    }
    reports = ROOT / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    (reports / "application_context_boundary_verification.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    lines = [report["title"], f"version: {CURRENT_APP_VERSION}", ""]
    lines.extend(f"{name}: {'PASS' if passed else 'FAIL'}" for name, passed in checks.items())
    lines.extend(["", f"result: {report['passed']}/{report['total']}"])
    (reports / "application_context_boundary_verification.txt").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if all(checks.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main_smoke())
