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
from app.core.architecture import build_architecture_report
from app.services import request_processing, view_models


def main_smoke() -> int:
    main_tree = ast.parse((ROOT / "app/main.py").read_text(encoding="utf-8"))
    main_functions = {
        node.name for node in main_tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    extracted = {
        "_bounded_text", "_date_text", "_number", "_active", "_csv_safe",
        "_filter_findings", "_public_job", "_job_role", "_export_filters_from_values",
    }
    architecture = build_architecture_report(ROOT)
    checks = [
        ("version_72_0_7", main.CURRENT_APP_VERSION == "72.0.96"),
        ("schema_42", main.CURRENT_SCHEMA_VERSION == 46),
        ("main_line_budget", len((ROOT / "app/main.py").read_text().splitlines()) < 1250),
        ("request_processing_module", hasattr(request_processing, "normalize_finding_row")),
        ("view_model_module", hasattr(view_models, "evidence_with_custody")),
        ("pure_alias_identity", main._csv_safe is request_processing.csv_safe),
        ("validation_alias_identity", main._bounded_text is request_processing.bounded_text),
        ("no_extracted_definitions_in_main", not (extracted & main_functions)),
        ("no_main_import_in_extracted_services", "app.main" not in (ROOT / "app/services/request_processing.py").read_text() and "app.main" not in (ROOT / "app/services/view_models.py").read_text()),
        ("architecture_pass", architecture["status"] == "PASS"),
    ]
    passed = sum(bool(value) for _, value in checks)
    payload = {
        "title": "VulnFlow 72.0.96 main helper modularization verification",
        "version": main.CURRENT_APP_VERSION,
        "schema_version": main.CURRENT_SCHEMA_VERSION,
        "passed": passed,
        "total": len(checks),
        "checks": [{"name": name, "passed": bool(value)} for name, value in checks],
    }
    reports = ROOT / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    (reports / "main_helper_modularization_verification.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    lines = [payload["title"], f"version: {payload['version']}", f"schema: {payload['schema_version']}", f"result: {passed}/{len(checks)}", ""]
    lines.extend(f"{'PASS' if value else 'FAIL'} {name}" for name, value in checks)
    (reports / "main_helper_modularization_verification.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    return 0 if passed == len(checks) else 1


if __name__ == "__main__":
    raise SystemExit(main_smoke())
