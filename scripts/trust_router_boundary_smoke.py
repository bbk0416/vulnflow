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
from app.routers import route_inventory, trust, trust_observability


def main_smoke() -> int:
    inventory = route_inventory()
    core = set(trust.ROUTE_NAMES)
    observers = set(trust_observability.ROUTE_NAMES)
    architecture = build_architecture_report(ROOT)
    module_map = {item["path"]: item for item in architecture["modules"]}
    checks = {
        "version_72_0_6": CURRENT_APP_VERSION == "72.0.12",
        "core_routes_9": len(core) == 9,
        "observability_routes_14": len(observers) == 14,
        "route_names_disjoint": core.isdisjoint(observers),
        "inventory_core": inventory.get("trust") == trust.ROUTE_NAMES,
        "inventory_observability": inventory.get("trust_observability") == trust_observability.ROUTE_NAMES,
        "main_core_identity": all(getattr(main, name) is getattr(trust, name) for name in core),
        "main_observability_identity": all(getattr(main, name) is getattr(trust_observability, name) for name in observers),
        "route_count_241": architecture["route_count"] == 241,
        "architecture_pass": architecture["status"] == "PASS"
            and module_map["app/routers/trust.py"]["lines"] <= 260
            and module_map["app/routers/trust_observability.py"]["lines"] <= 340,
    }
    report = {
        "title": "VulnFlow 72.0.12 trust router boundary verification",
        "version": CURRENT_APP_VERSION,
        "checks": checks,
        "passed": sum(checks.values()),
        "total": len(checks),
    }
    reports = ROOT / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    (reports / "trust_router_boundary_verification.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    lines = [report["title"], f"version: {CURRENT_APP_VERSION}", ""]
    lines.extend(f"{name}: {'PASS' if passed else 'FAIL'}" for name, passed in checks.items())
    lines.extend(["", f"result: {report['passed']}/{report['total']}"])
    (reports / "trust_router_boundary_verification.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if all(checks.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main_smoke())
