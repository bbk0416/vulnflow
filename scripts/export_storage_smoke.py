from __future__ import annotations

import json
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import main
from app.core.storage import init_db, upsert_findings
from app.services.exports import (
    create_findings_csv_export,
    enforce_export_storage_budget,
    export_storage_status,
    get_export_artifact,
    set_export_artifact_pinned,
)


def seed(db: Path) -> None:
    init_db(db)
    rows = [
        main.normalize_row(
            {
                "finding_id": f"STORE-{idx}",
                "product": f"Storage Product {idx}",
                "asset_name": f"storage-node-{idx}",
                "cve_id": f"CVE-2026-{28000 + idx}",
                "cvss": str(7.5 + idx / 10),
                "status": "OPEN",
            },
            idx,
        )
        for idx in range(5)
    ]
    upsert_findings(db, rows, actor="storage-smoke")


def main_smoke() -> None:
    checks: list[str] = []
    with tempfile.TemporaryDirectory(prefix="vulnflow_export_storage_") as temp:
        root = Path(temp)
        db = root / "vulnflow.db"
        export_dir = root / "exports"
        seed(db)

        first = create_findings_csv_export(db, export_dir, filters={"status": "OPEN"}, actor="operator", retention_days=7)
        time.sleep(1.05)
        second = create_findings_csv_export(db, export_dir, filters={"record_state": "ALL"}, actor="operator", retention_days=7)
        time.sleep(1.05)
        third = create_findings_csv_export(db, export_dir, filters={}, actor="operator", retention_days=7)
        checks.append("three verified artifacts created")

        set_export_artifact_pinned(db, second["artifact_id"], pinned=True, actor="admin")
        checks.append("middle artifact pinned")

        keep_bytes = int(second["size_bytes"]) + int(third["size_bytes"])
        first_cleanup = enforce_export_storage_budget(
            db, export_dir, quota_bytes=keep_bytes, reserve_bytes=0, actor="storage-smoke"
        )
        if get_export_artifact(db, first["artifact_id"])["status"] != "EVICTED":
            raise SystemExit("oldest unpinned artifact was not evicted")
        if get_export_artifact(db, second["artifact_id"])["status"] != "READY":
            raise SystemExit("pinned artifact was evicted")
        checks += ["oldest unpinned artifact evicted", "pinned artifact protected"]

        set_export_artifact_pinned(db, second["artifact_id"], pinned=False, actor="admin")
        second_cleanup = enforce_export_storage_budget(
            db, export_dir, quota_bytes=int(third["size_bytes"]), reserve_bytes=0, actor="storage-smoke"
        )
        if get_export_artifact(db, second["artifact_id"])["status"] != "EVICTED":
            raise SystemExit("unprotected LRU artifact was not evicted")
        checks.append("unprotected artifact becomes evictable")

        set_export_artifact_pinned(db, third["artifact_id"], pinned=True, actor="admin")
        rejected = False
        try:
            create_findings_csv_export(
                db, export_dir, filters={}, actor="operator", retention_days=7,
                quota_bytes=1, reserve_bytes=0,
            )
        except RuntimeError:
            rejected = True
        if not rejected:
            raise SystemExit("quota admission should reject when only pinned data remains")
        checks.append("quota admission rejects when no evictable artifact exists")

        status = export_storage_status(
            db, export_dir, quota_bytes=int(third["size_bytes"]), reserve_bytes=0
        )
        if status["pinned_count"] != 1 or status["evicted_count"] != 2:
            raise SystemExit(f"unexpected storage status: {status}")
        checks += ["storage status counts pinned artifacts", "storage status counts evictions"]

        result = {
            "checks": len(checks),
            "items": checks,
            "first_cleanup": first_cleanup,
            "second_cleanup": second_cleanup,
            "final_status": status,
        }

    reports = ROOT / "reports"
    reports.mkdir(exist_ok=True)
    (reports / "export_storage_governance_verification.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    lines = ["VulnFlow 72.0.100 export storage governance smoke", ""]
    lines += [f"PASS {item}" for item in checks]
    lines += ["", f"checks={len(checks)}", f"evicted={status['evicted_count']}", f"pinned={status['pinned_count']}"]
    (reports / "export_storage_governance_verification.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main_smoke()
