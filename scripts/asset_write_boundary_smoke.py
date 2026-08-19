from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.core import storage
from app.core.architecture import build_architecture_report
from app.repositories import (
    asset_identity_writes,
    asset_inventory,
    asset_merge,
    asset_merge_rollback,
    asset_writes,
)


def main() -> None:
    architecture = build_architecture_report(ROOT)
    by_path = {item["path"]: item for item in architecture["modules"]}
    importers = [
        item["path"] for item in architecture["modules"]
        if item["path"] != "app/repositories/asset_writes.py"
        and "app.repositories.asset_writes" in item["internal_imports"]
    ]
    with tempfile.TemporaryDirectory(prefix="vulnflow-v66-asset-write-") as temp:
        db = Path(temp) / "vulnflow.db"
        storage.init_db(db)
        result = asset_inventory.apply_asset_inventory(
            db,
            [{
                "asset_id": "INV-V66",
                "asset_name": "asset-write-boundary",
                "environment": "prod",
                "criticality": 4,
                "data_sensitivity": 3,
                "internet_exposed": True,
            }],
            actor="v66-smoke",
        )
        asset = storage.list_assets(db)[0]
        identifiers = asset_identity_writes.list_asset_identifiers(db, asset["asset_ref_id"])

    checks = {
        "version_72_0_7": storage.CURRENT_APP_VERSION == "72.0.92",
        "schema_42": storage.CURRENT_SCHEMA_VERSION == 46,
        "identity_export": asset_writes.add_asset_identifier is asset_identity_writes.add_asset_identifier,
        "inventory_export": asset_writes.apply_asset_inventory is asset_inventory.apply_asset_inventory,
        "merge_export": asset_writes.create_asset_merge_request is asset_merge.create_asset_merge_request,
        "rollback_export": (
            asset_writes.approve_asset_merge_rollback_request
            is asset_merge_rollback.approve_asset_merge_rollback_request
        ),
        "internal_facade_importers_zero": importers == [],
        "facade_budget": by_path["app/repositories/asset_writes.py"]["lines"] <= 120,
        "owner_budgets": all((
            by_path["app/repositories/asset_identity_writes.py"]["lines"] <= 220,
            by_path["app/repositories/asset_inventory.py"]["lines"] <= 180,
            by_path["app/repositories/asset_merge.py"]["lines"] <= 820,
            by_path["app/repositories/asset_merge_rollback.py"]["lines"] <= 380,
        )),
        "inventory_round_trip": result["inserted"] == 1 and any(
            item["identifier_type"] == "INVENTORY_ID" for item in identifiers
        ) and architecture["status"] == "PASS",
    }
    payload = {
        "title": "VulnFlow 72.0.92 asset write repository boundary verification",
        "version": storage.CURRENT_APP_VERSION,
        "checks": [{"name": name, "passed": passed} for name, passed in checks.items()],
        "result": f"{sum(checks.values())}/{len(checks)}",
        "internal_facade_importers": importers,
    }
    reports = ROOT / "reports"
    reports.mkdir(exist_ok=True)
    (reports / "asset_write_boundary_verification.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    lines = [payload["title"], f"version: {payload['version']}", ""]
    lines += [f"{name}: {'PASS' if passed else 'FAIL'}" for name, passed in checks.items()]
    lines += ["", f"result: {payload['result']}"]
    (reports / "asset_write_boundary_verification.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    if not all(checks.values()):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
