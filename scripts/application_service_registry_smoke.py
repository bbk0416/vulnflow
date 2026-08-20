from __future__ import annotations

import ast
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import app.main as main
from app.application_services import (
    APPLICATION_SERVICE_EXPORTS,
    application_service_snapshot,
    install_application_services,
)
from app.core.architecture import build_architecture_report


def main_smoke() -> int:
    tree = ast.parse((ROOT / "app/main.py").read_text(encoding="utf-8"))
    internal_imports = {
        node.module
        for node in tree.body
        if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("app.")
    }
    snapshot = application_service_snapshot()
    collision_blocked = False
    try:
        install_application_services({"count_findings": object()})
    except RuntimeError:
        collision_blocked = True
    checks = [
        ("version_72_0_7", main.CURRENT_APP_VERSION == "72.0.95"),
        ("schema_42", main.CURRENT_SCHEMA_VERSION == 46),
        ("registry_count", snapshot["service_export_count"] == len(APPLICATION_SERVICE_EXPORTS) >= 250),
        ("registry_fingerprint", len(snapshot["service_export_name_sha256"]) == 64),
        ("finding_identity", main.count_findings is APPLICATION_SERVICE_EXPORTS["count_findings"]),
        ("recovery_identity", main.backup_database is APPLICATION_SERVICE_EXPORTS["backup_database"]),
        ("worker_identity", main.execute_background_job_for_context is APPLICATION_SERVICE_EXPORTS["execute_background_job_for_context"]),
        ("collision_blocked", collision_blocked),
        ("no_repository_imports_in_main", not any(name.startswith("app.repositories.") for name in internal_imports)),
        ("architecture_pass", build_architecture_report(ROOT)["status"] == "PASS"),
    ]
    passed = sum(bool(value) for _, value in checks)
    payload = {
        "title": "VulnFlow 72.0.95 application service registry verification",
        "version": main.CURRENT_APP_VERSION,
        "schema_version": main.CURRENT_SCHEMA_VERSION,
        "service_export_count": snapshot["service_export_count"],
        "service_export_name_sha256": snapshot["service_export_name_sha256"],
        "passed": passed,
        "total": len(checks),
        "checks": [{"name": name, "passed": bool(value)} for name, value in checks],
    }
    reports = ROOT / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    (reports / "application_service_registry_verification.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    lines = [payload["title"], f"version: {payload['version']}", f"schema: {payload['schema_version']}", ""]
    lines.extend(f"{'PASS' if value else 'FAIL'} {name}" for name, value in checks)
    lines.extend(["", f"result: {passed}/{len(checks)}"])
    (reports / "application_service_registry_verification.txt").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )
    print("\n".join(lines))
    return 0 if passed == len(checks) else 1


if __name__ == "__main__":
    raise SystemExit(main_smoke())
