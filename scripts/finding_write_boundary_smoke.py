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
from app.repositories import finding_approvals, finding_ingestion, finding_workflow, finding_writes


def _row() -> dict[str, object]:
    return {
        "finding_id": "F-V65-SMOKE",
        "product": "VulnFlow",
        "cve_id": "CVE-2026-65002",
        "status": "OPEN",
        "score": 55,
        "policy_version": "2.0.0",
        "first_seen_at": "2026-07-24",
        "first_scored_at": "2026-07-24",
    }


def main() -> None:
    architecture = build_architecture_report(ROOT)
    by_path = {item["path"]: item for item in architecture["modules"]}
    importers = [
        item["path"] for item in architecture["modules"]
        if item["path"] != "app/repositories/finding_writes.py"
        and "app.repositories.finding_writes" in item["internal_imports"]
    ]
    with tempfile.TemporaryDirectory(prefix="vulnflow-v66-finding-write-") as temp:
        db = Path(temp) / "vulnflow.db"
        storage.init_db(db)
        inserted = finding_ingestion.upsert_findings(db, [_row()], audit=False)
        finding_workflow.update_workflow(
            db,
            "F-V65-SMOKE",
            status="IN_PROGRESS",
            owner="smoke-owner",
            due_date="2026-08-31",
            exception_expiry="",
            risk_acceptance_reason="",
            risk_acceptance_approver="",
            notes="smoke",
            actor="smoke",
        )
        request = finding_approvals.create_risk_approval_request(
            db,
            "F-V65-SMOKE",
            requested_by="smoke",
            reason="temporary",
            exception_expiry="2099-12-31",
        )
        finding = storage.get_finding(db, "F-V65-SMOKE") or {}

    checks = {
        "version_72_0_7": storage.CURRENT_APP_VERSION == "72.0.88",
        "schema_42": storage.CURRENT_SCHEMA_VERSION == 46,
        "ingestion_identity": finding_writes.upsert_findings is finding_ingestion.upsert_findings,
        "workflow_identity": finding_writes.update_workflow is finding_workflow.update_workflow,
        "approval_identity": finding_writes.create_risk_approval_request is finding_approvals.create_risk_approval_request,
        "internal_facade_importers_zero": importers == [],
        "facade_budget": by_path["app/repositories/finding_writes.py"]["lines"] <= 100,
        "owner_budgets": (
            by_path["app/repositories/finding_ingestion.py"]["lines"] <= 760
            and by_path["app/repositories/finding_workflow.py"]["lines"] <= 660
            and by_path["app/repositories/finding_approvals.py"]["lines"] <= 220
        ),
        "round_trip": inserted == (1, 0) and finding.get("status") == "IN_PROGRESS" and request.get("status") == "PENDING",
        "architecture_pass": architecture["status"] == "PASS" and not architecture["cycles"],
    }
    payload = {
        "title": "VulnFlow 72.0.88 finding write repository boundary verification",
        "version": storage.CURRENT_APP_VERSION,
        "checks": [{"name": name, "passed": passed} for name, passed in checks.items()],
        "result": f"{sum(checks.values())}/{len(checks)}",
    }
    reports = ROOT / "reports"
    reports.mkdir(exist_ok=True)
    (reports / "finding_write_boundary_verification.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    lines = [payload["title"], f"version: {payload['version']}", ""]
    lines += [f"{name}: {'PASS' if passed else 'FAIL'}" for name, passed in checks.items()]
    lines += ["", f"result: {payload['result']}"]
    (reports / "finding_write_boundary_verification.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    if not all(checks.values()):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
