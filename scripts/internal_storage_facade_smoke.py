from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import app.main as main
from app.core import database_schema, db, storage
from app.core.architecture import build_architecture_report
from app.repositories import audit, finding_writes, reconciliation
from app.services import database_lifecycle, evidence, exports

REPORTS = ROOT / "reports"


def main_smoke() -> None:
    report = build_architecture_report(ROOT)
    offenders = [
        item["path"]
        for item in report["modules"]
        if item["path"] != "app/core/storage.py"
        and "app.core.storage" in set(item.get("internal_imports") or [])
    ]
    checks = [
        ("version_72_0_7", storage.CURRENT_APP_VERSION == "72.0.76"),
        ("schema_42", storage.CURRENT_SCHEMA_VERSION == 46),
        ("facade_schema_identity", storage.init_db is database_schema.init_db),
        ("facade_audit_identity", storage.add_audit_event is audit.add_audit_event),
        ("facade_recovery_identity", storage.backup_database is database_lifecycle.backup_database),
        ("facade_finding_identity", storage.upsert_findings is finding_writes.upsert_findings),
        ("main_direct_owner", main.init_db is database_schema.init_db),
        ("service_direct_db", evidence.connect is db.connect),
        ("export_direct_owners", exports.backup_database is database_lifecycle.backup_database and exports.FIELDS is reconciliation.FIELDS),
        ("no_internal_facade_imports", offenders == [] and report["status"] == "PASS"),
    ]
    payload = {
        "title": "VulnFlow 72.0.76 internal storage facade boundary verification",
        "version": storage.CURRENT_APP_VERSION,
        "checks": [{"name": name, "passed": passed} for name, passed in checks],
        "passed": sum(bool(passed) for _, passed in checks),
        "total": len(checks),
        "offenders": offenders,
    }
    REPORTS.mkdir(parents=True, exist_ok=True)
    (REPORTS / "internal_storage_facade_verification.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    lines = [payload["title"], f"version: {payload['version']}", ""]
    lines.extend(f"{'PASS' if item['passed'] else 'FAIL'} {item['name']}" for item in payload["checks"])
    lines.extend(["", f"result: {payload['passed']}/{payload['total']}"])
    (REPORTS / "internal_storage_facade_verification.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    if payload["passed"] != payload["total"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main_smoke()
