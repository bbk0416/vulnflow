from __future__ import annotations

import json
import sqlite3
import tempfile
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.core.storage import CURRENT_APP_VERSION, CURRENT_SCHEMA_VERSION, init_db, validate_database_file
from app.repositories.execution_receipt_retention import archive_execution_receipts, list_execution_receipt_archives
from app.repositories.execution_receipts import count_execution_receipts, list_execution_receipts, replay_execution_receipt
from app.repositories.jobs import claim_background_job, complete_background_job, create_background_job, fail_background_job, purge_background_jobs
from app.repositories.webhooks import enqueue_webhook_events, record_webhook_delivery
from app.services.maintenance import run_maintenance

REPORT_JSON = ROOT / "reports" / "execution_receipt_retention_verification.json"
REPORT_TEXT = ROOT / "reports" / "execution_receipt_retention_verification.txt"
FUTURE = "2999-01-01T00:00:00+00:00"
OLD = "2020-01-01T00:00:00+00:00"


def main() -> None:
    checks: dict[str, bool] = {}
    with tempfile.TemporaryDirectory(prefix="vulnflow-receipt-retention-") as directory:
        db = Path(directory) / "vulnflow.sqlite3"
        init_db(db)
        with sqlite3.connect(db) as conn:
            version = int(conn.execute("PRAGMA user_version").fetchone()[0])
            archive_columns = {row[1] for row in conn.execute("PRAGMA table_info(execution_receipt_archives)")}
        checks["schema_33"] = version == CURRENT_SCHEMA_VERSION == 40
        checks["archive_redacted_columns"] = {
            "receipt_digest_sha256", "operation_summary_json", "outcome_summary_json", "actor_sha256"
        } <= archive_columns and not ({"payload_json", "result_json", "error", "actor"} & archive_columns)

        success = create_background_job(db, job_type="RESCORE_ALL", payload={"secret": "SUCCESS-SECRET"}, requested_by="operator")
        claim_background_job(db, worker_id="worker-secret")
        complete_background_job(db, job_id=success["job_id"], worker_id="worker-secret", result={"secret": "RESULT"})
        delivered = enqueue_webhook_events(db, endpoint_names=["ops"], event_type="done", payload={"secret": "WEBHOOK"})[0]
        record_webhook_delivery(db, event_id=delivered, delivered=True, response_status=204, error="", max_attempts=1)

        failed_job = create_background_job(db, job_type="INTEL_REFRESH", requested_by="operator", max_attempts=1)
        claim_background_job(db, worker_id="worker-final")
        fail_background_job(db, job_id=failed_job["job_id"], worker_id="worker-final", error="PRIVATE", retryable=False)
        failed_event = enqueue_webhook_events(db, endpoint_names=["ops"], event_type="failed", payload={})[0]
        record_webhook_delivery(db, event_id=failed_event, delivered=False, response_status=400, error="PRIVATE", max_attempts=1, retryable=False)

        archived = archive_execution_receipts(db, cutoff_at=FUTURE, actor="admin")
        checks["success_detail_archived"] = archived["receipt_count"] == 2
        checks["archive_digest"] = len(archived["receipt_digest_sha256"]) == 64
        remaining = list_execution_receipts(db)
        checks["dead_letters_preserved"] = {item["resource_id"] for item in remaining} == {failed_job["job_id"], failed_event}
        checks["dead_letter_count"] = count_execution_receipts(db)["dead_letters"] == 2
        with sqlite3.connect(db) as conn:
            conn.execute("UPDATE background_jobs SET completed_at=? WHERE job_id=?", (OLD, failed_job["job_id"]))
        purge_background_jobs(db, completed_before=FUTURE)
        with sqlite3.connect(db) as conn:
            checks["job_retention_preserves_dead_letter"] = conn.execute("SELECT COUNT(*) FROM background_jobs WHERE job_id=?", (failed_job["job_id"],)).fetchone()[0] == 1

        failed_receipt = next(item for item in remaining if item["resource_id"] == failed_job["job_id"])
        replay = replay_execution_receipt(db, failed_receipt["receipt_id"], actor="admin", reason="원인 수정 후 재처리")
        archived_again = archive_execution_receipts(db, cutoff_at=FUTURE, actor="admin")
        checks["replay_history_preserved"] = archived_again["receipt_count"] == 0 and replay["new_resource_id"].startswith("JOB-")

        with sqlite3.connect(db) as conn:
            archive_id = conn.execute("SELECT archive_id FROM execution_receipt_archives LIMIT 1").fetchone()[0]
            try:
                conn.execute("UPDATE execution_receipt_archives SET receipt_count=0 WHERE archive_id=?", (archive_id,))
            except sqlite3.IntegrityError:
                checks["archive_immutable"] = True
            else:
                checks["archive_immutable"] = False
            receipt_id = conn.execute("SELECT receipt_id FROM execution_receipts LIMIT 1").fetchone()[0]
            try:
                conn.execute("DELETE FROM execution_receipts WHERE receipt_id=?", (receipt_id,))
            except sqlite3.IntegrityError:
                checks["receipt_delete_guard_restored"] = True
            else:
                checks["receipt_delete_guard_restored"] = False
            conn.execute("UPDATE webhook_events SET last_attempt_at=? WHERE event_id=?", (OLD, failed_event))

        maintenance = run_maintenance(db, actor="admin", webhook_retention_days=1)
        checks["webhook_retention_preserves_dead_letter"] = maintenance["webhooks_deleted"] == 0
        checks["archive_listing"] = list_execution_receipt_archives(db)[0]["receipt_count"] == 2
        checks["recovery_validation"] = validate_database_file(db)["schema_version"] == 40

        result = {
            "version": CURRENT_APP_VERSION,
            "schema_version": CURRENT_SCHEMA_VERSION,
            "checks": checks,
            "passed": sum(bool(value) for value in checks.values()),
            "total": len(checks),
            "detailed_receipts": count_execution_receipts(db)["total"],
            "archived_receipts": count_execution_receipts(db)["archived"],
        }

    REPORT_JSON.parent.mkdir(parents=True, exist_ok=True)
    REPORT_JSON.write_text(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    lines = [
        "VulnFlow 72.0.11 execution receipt retention archive verification", "",
        f"version: {result['version']}", f"schema version: {result['schema_version']}",
        f"checks: {result['passed']}/{result['total']}", "",
    ]
    lines.extend(f"- {name}: {'PASS' if passed else 'FAIL'}" for name, passed in checks.items())
    REPORT_TEXT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    if result["passed"] != result["total"]:
        raise SystemExit("execution receipt retention verification failed")
    print(f"execution receipt retention verification passed: {result['passed']}/{result['total']}")


if __name__ == "__main__":
    main()
