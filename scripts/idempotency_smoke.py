from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import tempfile
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.core.storage import (
    CURRENT_APP_VERSION,
    CURRENT_SCHEMA_VERSION,
    IdempotencyConflict,
    claim_background_job,
    complete_background_job,
    connect,
    create_background_job,
    enqueue_webhook_events,
    init_db,
    list_background_jobs,
    list_webhook_events,
)
from app.services.maintenance import run_maintenance

REPORT_JSON = ROOT / "reports" / "idempotency_verification.json"
REPORT_TEXT = ROOT / "reports" / "idempotency_verification.txt"


def main() -> None:
    checks: dict[str, bool] = {}
    with tempfile.TemporaryDirectory(prefix="vulnflow-idempotency-") as directory:
        db = Path(directory) / "vulnflow.sqlite3"
        init_db(db)
        with connect(db) as conn:
            version = int(conn.execute("PRAGMA user_version").fetchone()[0])
            columns = {row[1] for row in conn.execute("PRAGMA table_info(idempotency_records)")}
        checks["schema_31_ledger_on_schema_32"] = version == CURRENT_SCHEMA_VERSION == 46
        checks["raw_key_column_absent"] = "idempotency_key" not in columns

        key = "smoke-job-key-0001"
        first = create_background_job(
            db, job_type="RESCORE_ALL", requested_by="automation",
            idempotency_key=key, idempotency_request={"job_type": "RESCORE_ALL"},
        )
        claimed = claim_background_job(db, worker_id="worker-a")
        complete_background_job(
            db, job_id=first["job_id"], worker_id="worker-a", result={"rescored": 4}
        )
        replay = create_background_job(
            db, job_type="RESCORE_ALL", requested_by="automation",
            idempotency_key=key, idempotency_request={"job_type": "RESCORE_ALL"},
        )
        checks["completed_job_replay"] = (
            replay["job_id"] == first["job_id"]
            and replay["status"] == "SUCCEEDED"
            and replay.get("idempotent_replay") is True
        )
        checks["raw_key_not_persisted"] = key.encode() not in db.read_bytes()
        try:
            create_background_job(
                db, job_type="INTEL_REFRESH", requested_by="automation",
                idempotency_key=key, idempotency_request={"job_type": "INTEL_REFRESH"},
            )
        except IdempotencyConflict:
            checks["changed_request_conflict"] = True
        else:
            checks["changed_request_conflict"] = False

        concurrent_key = "smoke-concurrent-key-01"
        def enqueue(_: int) -> str:
            return create_background_job(
                db, job_type="DATABASE_MAINTENANCE", payload={"mode": "PASSIVE"},
                requested_by="admin", idempotency_key=concurrent_key,
            )["job_id"]
        with ThreadPoolExecutor(max_workers=8) as executor:
            identifiers = list(executor.map(enqueue, range(16)))
        checks["concurrent_single_resource"] = len(set(identifiers)) == 1

        webhook_key = "smoke-webhook-key-01"
        webhook_first = enqueue_webhook_events(
            db, endpoint_names=["ops", "audit"], event_type="finding.changed",
            payload={"finding_id": "F-1"}, actor="operator-a", idempotency_key=webhook_key,
        )
        webhook_replay = enqueue_webhook_events(
            db, endpoint_names=["ops", "audit"], event_type="finding.changed",
            payload={"finding_id": "F-1"}, actor="operator-a", idempotency_key=webhook_key,
        )
        checks["webhook_batch_replay"] = webhook_replay == webhook_first
        webhook_other = enqueue_webhook_events(
            db, endpoint_names=["ops", "audit"], event_type="finding.changed",
            payload={"finding_id": "F-1"}, actor="operator-b", idempotency_key=webhook_key,
        )
        checks["principal_bound_key"] = set(webhook_other).isdisjoint(webhook_first)

        with connect(db) as conn:
            conn.execute("UPDATE idempotency_records SET expires_at='2020-01-01T00:00:00+00:00'")
            conn.commit()
        reused = create_background_job(
            db, job_type="INTEL_REFRESH", requested_by="automation",
            idempotency_key=key, idempotency_request={"job_type": "INTEL_REFRESH"},
        )
        checks["expired_key_reusable"] = reused["job_id"] != first["job_id"]
        with connect(db) as conn:
            conn.execute("UPDATE idempotency_records SET expires_at='2020-01-01T00:00:00+00:00'")
            conn.commit()
        maintenance = run_maintenance(db, actor="admin")
        checks["maintenance_purges_expired"] = maintenance.get("idempotency_deleted", 0) > 0

        result = {
            "version": CURRENT_APP_VERSION,
            "schema_version": CURRENT_SCHEMA_VERSION,
            "checks": checks,
            "passed": sum(bool(value) for value in checks.values()),
            "total": len(checks),
            "background_jobs": len(list_background_jobs(db)),
            "webhook_events": len(list_webhook_events(db)),
        }

    REPORT_JSON.parent.mkdir(parents=True, exist_ok=True)
    REPORT_JSON.write_text(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    lines = [
        "VulnFlow durable idempotency verification",
        "",
        f"version: {result['version']}",
        f"schema version: {result['schema_version']}",
        f"checks: {result['passed']}/{result['total']}",
        "",
    ]
    lines.extend(f"- {name}: {'PASS' if passed else 'FAIL'}" for name, passed in checks.items())
    REPORT_TEXT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    if result["passed"] != result["total"]:
        raise SystemExit("idempotency verification failed")
    print(f"idempotency verification passed: {result['passed']}/{result['total']}")


if __name__ == "__main__":
    main()
