from __future__ import annotations

import tempfile
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.core.storage import (
    CURRENT_SCHEMA_VERSION, apply_import_batch, create_remediation_verification_request, get_finding, init_db, update_workflow
)
from app.services.evidence import (
    record_evidence_access, scan_evidence_artifact, store_verification_evidence,
    transfer_evidence_custody, verify_evidence_custody_chain,
)
from app.services.recovery import create_recovery_bundle, validate_recovery_bundle


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="vulnflow_custody_") as temp:
        root = Path(temp)
        db = root / "vulnflow.sqlite3"
        evidence_dir = root / "evidence"
        init_db(db)
        apply_import_batch(db, [{
            "finding_id": "CUSTODY-SMOKE-1", "product": "Custody Smoke", "asset_name": "host-1",
            "cve_id": "CVE-2026-17001", "status": "OPEN", "scanner_source": "smoke",
            "record_state": "ACTIVE", "row_version": 1, "score": 60,
            "first_seen_at": "2026-07-21", "first_scored_at": "2026-07-21",
        }], scanner_source="smoke", filename="smoke.csv")
        finding = get_finding(db, "CUSTODY-SMOKE-1")
        update_workflow(
            db, "CUSTODY-SMOKE-1", status="MITIGATED", owner="operator", due_date="",
            exception_expiry="", risk_acceptance_reason="", risk_acceptance_approver="",
            notes="patched", actor="operator", expected_version=finding["row_version"],
        )
        finding = get_finding(db, "CUSTODY-SMOKE-1")
        verification = create_remediation_verification_request(
            db, "CUSTODY-SMOKE-1", method="RETEST", evidence_note="proof", actor="operator",
            expected_version=finding["row_version"],
        )
        item = store_verification_evidence(
            db, evidence_dir, verification_id=verification["verification_id"], filename="proof.log",
            content=b"retest passed\n", notes="smoke", actor="collector-a", max_bytes=1024,
            source_type="SCANNER_EXPORT", source_reference="smoke-job-17", acquisition_method="EXPORT",
            collected_at="2026-07-21T01:00:00+00:00",
        )
        scan_evidence_artifact(db, evidence_dir, item["evidence_id"], mode="builtin", actor="scanner")
        transfer_evidence_custody(
            db, item["evidence_id"], actor="collector-a", to_custodian="approver-b", purpose="review"
        )
        record_evidence_access(db, item["evidence_id"], actor="approver-b", purpose="download review")
        integrity = verify_evidence_custody_chain(db, item["evidence_id"])
        if not integrity["valid"] or integrity["event_count"] != 4 or integrity["current_custodian"] != "approver-b":
            raise SystemExit(f"custody verification failed: {integrity}")
        bundle = root / "recovery.zip"
        create_recovery_bundle(db, bundle, evidence_dir=evidence_dir, created_by="admin")
        validated = validate_recovery_bundle(bundle, current_schema_version=CURRENT_SCHEMA_VERSION)
        if validated["evidence"]["artifact_count"] != 1:
            raise SystemExit("recovery bundle custody evidence missing")
        print("custody events: 4")
        print("current custodian: approver-b")
        print("recovery bundle custody validation: passed")


if __name__ == "__main__":
    main()
