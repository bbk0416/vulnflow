from __future__ import annotations

import json
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.core.storage import init_coordination_db, init_db
from app.core.transactions import (
    SQLiteTransactionRegistry,
    SQLiteTransactionRuntime,
    transaction_scope,
    write_transaction,
)
from app.repositories.audit import add_audit_event, list_audit_events
from app.repositories.jobs import create_background_job, get_background_job


def main() -> int:
    checks: list[tuple[str, bool, str]] = []
    with tempfile.TemporaryDirectory(prefix="vulnflow-tx-") as temporary:
        base = Path(temporary)
        db_path = base / "runtime.sqlite3"
        runtime = SQLiteTransactionRuntime(db_path)
        with runtime.write(operation="create") as conn:
            conn.execute("CREATE TABLE values_table(id INTEGER PRIMARY KEY, value TEXT)")
            conn.execute("INSERT INTO values_table(value) VALUES('commit')")
        try:
            with runtime.write(operation="rollback") as conn:
                conn.execute("INSERT INTO values_table(value) VALUES('rollback')")
                raise RuntimeError("forced")
        except RuntimeError:
            pass
        with runtime.read(operation="verify") as conn:
            values = [row[0] for row in conn.execute("SELECT value FROM values_table ORDER BY id")]
        snapshot = runtime.structural_snapshot()
        checks.extend(
            [
                ("commit persisted", values == ["commit"], str(values)),
                ("rollback removed row", "rollback" not in values, str(values)),
                ("runtime counters", snapshot["commit_count"] == 1 and snapshot["rollback_count"] == 1, json.dumps(snapshot)),
            ]
        )

        audit_db = base / "audit.sqlite3"
        init_db(audit_db)
        before = len(list_audit_events(audit_db, limit=1000))
        try:
            with write_transaction(audit_db, operation="outer-audit") as conn:
                add_audit_event(
                    audit_db,
                    finding_id=None,
                    event_type="smoke_transaction",
                    summary="outer transaction rollback",
                    actor="transaction-smoke",
                    conn=conn,
                )
                raise ValueError("abort")
        except ValueError:
            pass
        after = list_audit_events(audit_db, limit=1000)
        checks.append(("borrowed audit rollback", len(after) == before, f"before={before} after={len(after)}"))

        registry_a = SQLiteTransactionRegistry()
        registry_b = SQLiteTransactionRegistry()
        job_db_a = base / "jobs-a.sqlite3"
        job_db_b = base / "jobs-b.sqlite3"
        init_db(job_db_a)
        init_db(job_db_b)
        with transaction_scope(registry_a):
            job = create_background_job(
                job_db_a,
                job_type="RESCORE_ALL",
                requested_by="transaction-smoke",
                dedupe_key="tx-smoke-a",
            )
            assert get_background_job(job_db_a, job["job_id"])
        with transaction_scope(registry_b):
            create_background_job(
                job_db_b,
                job_type="RESCORE_ALL",
                requested_by="transaction-smoke",
                dedupe_key="tx-smoke-b",
            )
        snap_a = registry_a.structural_snapshot()
        snap_b = registry_b.structural_snapshot()
        checks.extend(
            [
                ("registry A owns one DB", snap_a["database_count"] == 1, json.dumps(snap_a)),
                ("registry B owns one DB", snap_b["database_count"] == 1, json.dumps(snap_b)),
                ("registry objects isolated", registry_a is not registry_b, "separate objects"),
            ]
        )

        operational = base / "concurrent.sqlite3"
        coordination = base / "concurrent-coordination.sqlite3"

        def initialize(_: int) -> None:
            init_db(operational)
            init_coordination_db(coordination)

        with ThreadPoolExecutor(max_workers=8) as executor:
            list(executor.map(initialize, range(24)))
        checks.append(("concurrent initialization", operational.exists() and coordination.exists(), "24 initializers"))

    for relative in (
        "app/repositories/job_records.py",
        "app/repositories/job_execution.py",
        "app/repositories/cluster.py",
        "app/repositories/webhook_queue.py",
        "app/repositories/webhook_delivery.py",
        "app/repositories/audit.py",
    ):
        text = (ROOT / relative).read_text(encoding="utf-8")
        clean = "with connect(" not in text and 'execute("BEGIN IMMEDIATE")' not in text and ".commit()" not in text
        checks.append((f"managed boundary {relative}", clean, "manual transaction patterns absent" if clean else "manual pattern found"))

    passed = sum(ok for _, ok, _ in checks)
    payload = {
        "title": "VulnFlow 72.0.11 context-bound SQLite transaction verification",
        "version": "72.0.11",
        "passed": passed,
        "total": len(checks),
        "checks": [
            {"name": name, "status": "PASS" if ok else "FAIL", "detail": detail}
            for name, ok, detail in checks
        ],
    }
    reports = ROOT / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    (reports / "transaction_runtime_verification.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    lines = [payload["title"], "", f"result: {passed}/{len(checks)}"]
    lines.extend(f"- {'PASS' if ok else 'FAIL'}: {name} ({detail})" for name, ok, detail in checks)
    (reports / "transaction_runtime_verification.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    return 0 if passed == len(checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
