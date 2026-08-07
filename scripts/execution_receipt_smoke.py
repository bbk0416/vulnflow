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
from app.repositories.execution_receipts import count_execution_receipts, list_execution_receipts, replay_execution_receipt
from app.repositories.jobs import claim_background_job, complete_background_job, create_background_job, fail_background_job
from app.repositories.webhooks import enqueue_webhook_events, record_webhook_delivery

REPORT_JSON = ROOT / "reports" / "execution_receipt_verification.json"
REPORT_TEXT = ROOT / "reports" / "execution_receipt_verification.txt"


def main() -> None:
    checks: dict[str, bool] = {}
    with tempfile.TemporaryDirectory(prefix="vulnflow-receipts-") as directory:
        db = Path(directory) / "vulnflow.sqlite3"
        init_db(db)
        with sqlite3.connect(db) as conn:
            columns = {row[1] for row in conn.execute("PRAGMA table_info(execution_receipts)")}
            version = int(conn.execute("PRAGMA user_version").fetchone()[0])
        checks["schema_32_receipts_on_schema_33"] = version == CURRENT_SCHEMA_VERSION == 46
        checks["redacted_columns"] = not ({"payload_json", "result_json", "error", "worker_id", "actor"} & columns)

        job = create_background_job(
            db, job_type="RESCORE_ALL", payload={"credential": "JOB-SECRET-44"},
            requested_by="operator", max_attempts=2,
        )
        claim_background_job(db, worker_id="worker-secret-44")
        fail_background_job(
            db, job_id=job["job_id"], worker_id="worker-secret-44",
            error="JOB-ERROR-SECRET-44", retryable=True,
        )
        with sqlite3.connect(db) as conn:
            conn.execute(
                "UPDATE background_jobs SET next_attempt_at='2000-01-01T00:00:00+00:00' WHERE job_id=?",
                (job["job_id"],),
            )
        claim_background_job(db, worker_id="worker-secret-44")
        complete_background_job(
            db, job_id=job["job_id"], worker_id="worker-secret-44",
            result={"result_secret": "RESULT-SECRET-44"},
        )
        job_receipts = list_execution_receipts(db, operation_type="BACKGROUND_JOB")
        checks["job_attempt_chain"] = [item["outcome"] for item in job_receipts] == ["SUCCEEDED", "RETRY"]

        failed_job = create_background_job(db, job_type="INTEL_REFRESH", requested_by="operator", max_attempts=1)
        claim_background_job(db, worker_id="worker-final")
        fail_background_job(
            db, job_id=failed_job["job_id"], worker_id="worker-final",
            error="FINAL-ERROR-SECRET-44", retryable=False,
        )
        dead_receipt = list_execution_receipts(db, operation_type="BACKGROUND_JOB", outcome="FAILED")[0]
        replay = replay_execution_receipt(
            db, dead_receipt["receipt_id"], actor="admin", reason="원인 제거 후 새 작업으로 재처리",
        )
        checks["job_dead_letter_replay"] = replay["new_resource_id"] != failed_job["job_id"]
        try:
            replay_execution_receipt(db, dead_receipt["receipt_id"], actor="admin", reason="duplicate")
        except ValueError:
            checks["one_time_replay"] = True
        else:
            checks["one_time_replay"] = False

        event_id = enqueue_webhook_events(
            db, endpoint_names=["ops"], event_type="finding.changed",
            payload={"token": "WEBHOOK-SECRET-44"}, actor="operator",
        )[0]
        record_webhook_delivery(
            db, event_id=event_id, delivered=False, response_status=503,
            error="WEBHOOK-ERROR-SECRET-44", max_attempts=2, retryable=True,
        )
        record_webhook_delivery(
            db, event_id=event_id, delivered=False, response_status=400,
            error="WEBHOOK-FINAL-SECRET-44", max_attempts=2, retryable=False,
        )
        webhook_receipts = list_execution_receipts(db, operation_type="WEBHOOK_DELIVERY")
        checks["webhook_attempt_chain"] = [item["outcome"] for item in webhook_receipts] == ["FAILED", "RETRY"]
        webhook_replay = replay_execution_receipt(
            db, webhook_receipts[0]["receipt_id"], actor="admin", reason="수신 시스템 설정 수정",
        )
        checks["webhook_dead_letter_replay"] = webhook_replay["new_resource_type"] == "webhook_event"

        with sqlite3.connect(db) as conn:
            receipt_blob = "\n".join(str(tuple(row)) for row in conn.execute("SELECT * FROM execution_receipts")).encode()
            receipt_id = conn.execute("SELECT receipt_id FROM execution_receipts LIMIT 1").fetchone()[0]
            try:
                conn.execute("UPDATE execution_receipts SET outcome='FAILED' WHERE receipt_id=?", (receipt_id,))
            except sqlite3.IntegrityError:
                checks["immutable_receipts"] = True
            else:
                checks["immutable_receipts"] = False
        checks["raw_values_absent"] = all(
            marker not in receipt_blob
            for marker in (
                b"JOB-SECRET-44", b"JOB-ERROR-SECRET-44", b"RESULT-SECRET-44",
                b"WEBHOOK-SECRET-44", b"WEBHOOK-ERROR-SECRET-44", b"worker-secret-44",
            )
        )
        summary = count_execution_receipts(db)
        checks["dead_letter_metric_cleared"] = summary["dead_letters"] == 0
        checks["recovery_validation"] = validate_database_file(db)["schema_version"] == 46

        result = {
            "version": CURRENT_APP_VERSION,
            "schema_version": CURRENT_SCHEMA_VERSION,
            "checks": checks,
            "passed": sum(bool(value) for value in checks.values()),
            "total": len(checks),
            "receipt_count": summary["total"],
        }

    REPORT_JSON.parent.mkdir(parents=True, exist_ok=True)
    REPORT_JSON.write_text(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    lines = [
        "VulnFlow redacted execution receipt verification", "",
        f"version: {result['version']}", f"schema version: {result['schema_version']}",
        f"checks: {result['passed']}/{result['total']}", "",
    ]
    lines.extend(f"- {name}: {'PASS' if passed else 'FAIL'}" for name, passed in checks.items())
    REPORT_TEXT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    if result["passed"] != result["total"]:
        raise SystemExit("execution receipt verification failed")
    print(f"execution receipt verification passed: {result['passed']}/{result['total']}")


if __name__ == "__main__":
    main()
