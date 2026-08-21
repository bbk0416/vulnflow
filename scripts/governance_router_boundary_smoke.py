from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import app.main as main
from app.core.architecture import build_architecture_report
from app.core.database_schema import CURRENT_APP_VERSION
from app.routers import governance, governance_controls, governance_policy, route_inventory


def main_smoke() -> int:
    inventory = route_inventory()
    domains = {
        "policy": governance_policy,
        "audit": governance,
        "controls": governance_controls,
    }
    route_sets = {name: set(module.ROUTE_NAMES) for name, module in domains.items()}
    architecture = build_architecture_report(ROOT)
    module_map = {item["path"]: item for item in architecture["modules"]}
    checks = {
        "version_72_0_7": CURRENT_APP_VERSION == "72.0.101",
        "policy_routes_9": len(route_sets["policy"]) == 9,
        "audit_routes_11": len(route_sets["audit"]) == 11,
        "controls_routes_21": len(route_sets["controls"]) == 21,
        "route_names_disjoint": not (
            route_sets["policy"] & route_sets["audit"]
            or route_sets["policy"] & route_sets["controls"]
            or route_sets["audit"] & route_sets["controls"]
        ),
        "inventory_matches": all(
            inventory.get(module.__name__.rsplit(".", 1)[-1]) == module.ROUTE_NAMES
            for module in domains.values()
        ),
        "main_identity": all(
            getattr(main, route_name) is getattr(module, route_name)
            for module in domains.values()
            for route_name in module.ROUTE_NAMES
        ),
        "governance_routes_41": sum(len(routes) for routes in route_sets.values()) == 41,
        "route_count_261": architecture["route_count"] == 261,
        "architecture_pass": architecture["status"] == "PASS"
            and module_map["app/routers/governance_policy.py"]["lines"] <= 320
            and module_map["app/routers/governance.py"]["lines"] <= 280
            and module_map["app/routers/governance_controls.py"]["lines"] <= 520,
    }
    report = {
        "title": "VulnFlow 72.0.101 governance router boundary verification",
        "version": CURRENT_APP_VERSION,
        "checks": checks,
        "passed": sum(checks.values()),
        "total": len(checks),
    }
    reports = ROOT / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    (reports / "governance_router_boundary_verification.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    lines = [report["title"], f"version: {CURRENT_APP_VERSION}", ""]
    lines.extend(f"{name}: {'PASS' if passed else 'FAIL'}" for name, passed in checks.items())
    lines.extend(["", f"result: {report['passed']}/{report['total']}"])
    (reports / "governance_router_boundary_verification.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if all(checks.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main_smoke())
