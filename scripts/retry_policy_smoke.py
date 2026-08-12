from __future__ import annotations

import json
import tempfile
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.core.retry import RetryPolicy, parse_retry_after, retryable_http_status
from app.core.storage import (
    claim_background_job,
    create_background_job,
    enqueue_webhook_events,
    fail_background_job,
    init_db,
    list_due_webhook_events,
    record_webhook_delivery,
)


def main() -> None:
    checks: list[tuple[str, bool]] = []
    policy = RetryPolicy(max_attempts=5, base_delay_seconds=15, max_delay_seconds=300, jitter_ratio=0.10)
    delay = policy.delay_for(2, operation_key="smoke-job")
    checks.append(("deterministic_backoff", delay == policy.delay_for(2, operation_key="smoke-job")))
    checks.append(("bounded_backoff", 0 <= delay <= 300))
    checks.append(("retry_after_seconds", parse_retry_after("180") == 180))
    checks.append(("retryable_429", retryable_http_status(429)))
    checks.append(("permanent_400", not retryable_http_status(400)))

    with tempfile.TemporaryDirectory(prefix="vulnflow-retry-") as td:
        db = Path(td) / "retry.db"
        init_db(db)
        job = create_background_job(db, job_type="CSV_IMPORT", requested_by="smoke", max_attempts=5)
        claim_background_job(db, worker_id="worker-smoke")
        failed_job = fail_background_job(
            db, job_id=job["job_id"], worker_id="worker-smoke",
            error="invalid payload", retryable=False, failure_kind="invalid_input",
        )
        checks.append(("permanent_job_terminal", failed_job["status"] == "FAILED" and failed_job["attempts"] == 1))

        event_id = enqueue_webhook_events(
            db, endpoint_names=["ops"], event_type="retry.smoke", payload={"value": 1}, actor="smoke"
        )[0]
        list_due_webhook_events(db)
        before = datetime.now(timezone.utc).replace(microsecond=0)
        retry_event = record_webhook_delivery(
            db, event_id=event_id, delivered=False, response_status=429,
            error="rate limited", max_attempts=5, retryable=True,
            retry_after_seconds=180, failure_kind="http_status",
        )
        next_at = datetime.fromisoformat(retry_event["next_attempt_at"])
        checks.append(("webhook_retry", retry_event["status"] == "RETRY"))
        checks.append(("webhook_retry_after", (next_at - before).total_seconds() >= 160))

    passed = sum(ok for _, ok in checks)
    payload = {
        "title": "VulnFlow 72.0.78 durable retry policy verification",
        "version": "72.0.78",
        "checks": [{"name": name, "passed": ok} for name, ok in checks],
        "passed": passed,
        "total": len(checks),
        "policy": policy.structural_snapshot(),
    }
    reports = ROOT / "reports"
    reports.mkdir(exist_ok=True)
    (reports / "retry_policy_verification.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
    lines = [payload["title"], "", *(f"[{'PASS' if ok else 'FAIL'}] {name}" for name, ok in checks), "", f"Result: {passed}/{len(checks)}"]
    (reports / "retry_policy_verification.txt").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))
    if passed != len(checks):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
