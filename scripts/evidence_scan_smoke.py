from __future__ import annotations

import os
import tempfile
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="vulnflow_evidence_scan_smoke_") as temp_name:
        temp = Path(temp_name)
        fake = temp / "clamscan"
        fake.write_text(
            "#!/bin/sh\nif grep -a -q EICAR-STANDARD-ANTIVIRUS-TEST-FILE \"$3\"; then echo \"$3: Eicar-Signature FOUND\"; exit 1; fi\necho \"$3: OK\"; exit 0\n",
            encoding="utf-8",
        )
        fake.chmod(0o755)
        os.environ.update({
            "VULNFLOW_DB": str(temp / "scan.sqlite3"),
            "VULNFLOW_EVIDENCE_DIR": str(temp / "evidence"),
            "VULNFLOW_RECOVERY_DIR": str(temp / "recovery"),
            "VULNFLOW_EVIDENCE_SCANNER_MODE": "clamscan",
            "VULNFLOW_CLAMSCAN_PATH": str(fake),
            "VULNFLOW_JOB_WORKER_ENABLED": "0",
            "VULNFLOW_CLUSTER_COORDINATION_ENABLED": "0",
        })
        from app import main as app_main
        from app.core.storage import (
            apply_import_batch, claim_background_job, complete_background_job,
            create_background_job, create_remediation_verification_request, get_finding,
            init_db, update_workflow,
        )
        from app.services.evidence import EICAR_MARKER, get_evidence_artifact, store_verification_evidence

        init_db(app_main.DB_PATH)
        apply_import_batch(app_main.DB_PATH, [{
            "finding_id": "SCAN-1", "product": "Scan Demo", "asset_name": "host",
            "cve_id": "CVE-2026-16001", "status": "OPEN", "scanner_source": "smoke",
            "record_state": "ACTIVE", "row_version": 1, "score": 50,
            "first_seen_at": "2026-07-01", "first_scored_at": "2026-07-01",
        }], scanner_source="smoke", filename="scan.csv")
        finding = get_finding(app_main.DB_PATH, "SCAN-1")
        update_workflow(
            app_main.DB_PATH, "SCAN-1", status="MITIGATED", owner="ops", due_date="",
            exception_expiry="", risk_acceptance_reason="", risk_acceptance_approver="",
            notes="patched", actor="ops", expected_version=finding["row_version"],
        )
        finding = get_finding(app_main.DB_PATH, "SCAN-1")
        request = create_remediation_verification_request(
            app_main.DB_PATH, "SCAN-1", method="RETEST", evidence_note="scan smoke",
            actor="ops", expected_version=finding["row_version"],
        )
        statuses = []
        for name, content in (("clean.txt", b"clean"), ("eicar.txt", EICAR_MARKER)):
            artifact = store_verification_evidence(
                app_main.DB_PATH, app_main.EVIDENCE_DIR, verification_id=request["verification_id"],
                filename=name, content=content, notes="", actor="ops", max_bytes=1024,
            )
            create_background_job(
                app_main.DB_PATH, job_type="EVIDENCE_SCAN", payload={"evidence_id": artifact["evidence_id"]},
                requested_by="admin", max_attempts=1,
            )
            job = claim_background_job(app_main.DB_PATH, worker_id="scan-worker", allowed_types=["EVIDENCE_SCAN"])
            result = app_main._execute_background_job(job, worker_id="scan-worker")
            complete_background_job(
                app_main.DB_PATH, job_id=job["job_id"], worker_id="scan-worker", result=result,
            )
            statuses.append(get_evidence_artifact(app_main.DB_PATH, artifact["evidence_id"])["scan_status"])
        assert statuses == ["CLEAN", "INFECTED"], statuses
        print("evidence scan worker statuses:", ",".join(statuses))
        print("evidence scan smoke passed: 2 artifacts")


if __name__ == "__main__":
    main()
