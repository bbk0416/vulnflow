from __future__ import annotations

"""Bounded SQLite contention, backup, and crash-recovery rehearsal.

This verification uses disposable project databases only. It exercises real
repository writes, audit chaining, a held SQLite writer lock, a backup while
writes continue, atomic backup failure handling, and process death inside an
uncommitted transaction.
"""

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.core.database_schema import CURRENT_APP_VERSION, CURRENT_SCHEMA_VERSION, init_db
from app.repositories.audit import verify_audit_integrity
from app.repositories.finding_ingestion import upsert_findings
from app.services.database_lifecycle import (
    backup_database,
    restore_database,
    validate_database_file,
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _finding(index: int, *, suffix: str = "") -> dict[str, Any]:
    token = f"{index:05d}{suffix}"
    return {
        "finding_id": f"FAULT-{token}",
        "product": "Runtime Fault Rehearsal",
        "cve_id": f"CVE-2026-{10000 + index:05d}",
        "cvss": 7.5,
        "status": "OPEN",
        "record_state": "ACTIVE",
        "scanner_source": "runtime-fault",
        "asset": f"host-{index % 8}",
    }


def _integrity(db_path: Path) -> str:
    with sqlite3.connect(db_path) as conn:
        return str(conn.execute("PRAGMA integrity_check").fetchone()[0])


def _finding_count(db_path: Path) -> int:
    with sqlite3.connect(db_path) as conn:
        return int(conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0])


def _concurrent_writes(db_path: Path, *, workers: int, writes_per_worker: int) -> dict[str, Any]:
    barrier = threading.Barrier(workers)

    def writer(worker: int) -> int:
        barrier.wait(timeout=10)
        completed = 0
        for offset in range(writes_per_worker):
            index = worker * writes_per_worker + offset
            inserted, updated = upsert_findings(
                db_path,
                [_finding(index)],
                actor=f"fault-writer-{worker}",
            )
            if inserted + updated != 1:
                raise RuntimeError("unexpected finding write result")
            completed += 1
        return completed

    started = time.perf_counter()
    completed = 0
    failures: list[str] = []
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="vulnflow-fault-writer") as pool:
        futures = [pool.submit(writer, worker) for worker in range(workers)]
        for future in as_completed(futures):
            try:
                completed += int(future.result())
            except Exception as exc:  # report structural error type only
                failures.append(type(exc).__name__)
    return {
        "requested": workers * writes_per_worker,
        "completed": completed,
        "failure_types": failures,
        "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
    }


def _lock_contention(db_path: Path) -> dict[str, Any]:
    acquired = threading.Event()

    def holder() -> None:
        with sqlite3.connect(db_path, timeout=5.0) as conn:
            conn.execute("PRAGMA busy_timeout=5000")
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "UPDATE system_metadata SET updated_at=updated_at WHERE key='schema_version'"
            )
            acquired.set()
            time.sleep(0.45)
            conn.commit()

    thread = threading.Thread(target=holder, name="vulnflow-fault-lock-holder")
    thread.start()
    if not acquired.wait(timeout=5):
        raise TimeoutError("lock holder did not acquire the write transaction")
    started = time.perf_counter()
    inserted, updated = upsert_findings(
        db_path,
        [_finding(90000)],
        actor="fault-lock-waiter",
    )
    elapsed_ms = (time.perf_counter() - started) * 1000
    thread.join(timeout=5)
    if thread.is_alive():
        raise RuntimeError("lock holder did not finish")
    return {
        "write_count": inserted + updated,
        "waited_ms": round(elapsed_ms, 3),
        "holder_finished": not thread.is_alive(),
    }


def _backup_during_writes(db_path: Path, backup_path: Path) -> dict[str, Any]:
    start = threading.Event()
    stop = threading.Event()
    completed = 0
    failure_types: list[str] = []

    def writer() -> None:
        nonlocal completed
        start.wait(timeout=5)
        for cycle in range(24):
            if stop.is_set():
                break
            try:
                upsert_findings(
                    db_path,
                    [_finding(91000 + cycle)],
                    actor="fault-backup-writer",
                )
                completed += 1
            except Exception as exc:
                failure_types.append(type(exc).__name__)
                break
            time.sleep(0.01)

    thread = threading.Thread(target=writer, name="vulnflow-fault-backup-writer")
    thread.start()
    start.set()
    time.sleep(0.04)
    started = time.perf_counter()
    backup_database(db_path, backup_path)
    backup_elapsed_ms = (time.perf_counter() - started) * 1000
    stop.set()
    thread.join(timeout=5)
    if thread.is_alive():
        raise RuntimeError("backup writer did not stop")
    validation = validate_database_file(
        backup_path,
        expected_project_id="default",
    )
    return {
        "writer_completed": completed,
        "writer_failure_types": failure_types,
        "backup_elapsed_ms": round(backup_elapsed_ms, 3),
        "validation": validation,
    }


def _atomic_failure(db_path: Path, destination: Path, root: Path) -> dict[str, Any]:
    backup_database(db_path, destination)
    before_hash = _sha256(destination)
    invalid_source = root / "invalid-source.sqlite3"
    invalid_source.write_bytes(b"not-a-sqlite-database")
    error_type = ""
    try:
        backup_database(invalid_source, destination)
    except Exception as exc:
        error_type = type(exc).__name__
    after_hash = _sha256(destination)
    partials = sorted(path.name for path in destination.parent.glob(f".{destination.name}.*.partial"))
    return {
        "error_type": error_type,
        "destination_preserved": before_hash == after_hash,
        "partial_files": partials,
    }


def _crash_rollback(db_path: Path) -> dict[str, Any]:
    code = r'''
import os, sqlite3, sys
path = sys.argv[1]
conn = sqlite3.connect(path, timeout=5.0)
conn.execute("PRAGMA busy_timeout=5000")
conn.execute("BEGIN IMMEDIATE")
conn.execute(
    "INSERT INTO system_metadata(key,value,updated_at) VALUES('runtime_crash_probe','uncommitted',CURRENT_TIMESTAMP) "
    "ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at"
)
os._exit(17)
'''
    result = subprocess.run(
        [sys.executable, "-c", code, str(db_path)],
        cwd=ROOT,
        timeout=15,
        check=False,
    )
    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            "SELECT value FROM system_metadata WHERE key='runtime_crash_probe'"
        ).fetchone()
    return {
        "returncode": int(result.returncode),
        "uncommitted_row_present": row is not None,
        "integrity": _integrity(db_path),
    }


def run_rehearsal(
    *,
    workers: int = 4,
    writes_per_worker: int = 8,
    work_root: Path | None = None,
) -> dict[str, Any]:
    owns_temp = work_root is None
    temporary = tempfile.TemporaryDirectory(prefix="vulnflow-runtime-fault-") if owns_temp else None
    root = Path(temporary.name) if temporary is not None else Path(work_root or "")
    root.mkdir(parents=True, exist_ok=True)
    db_path = root / "project.db"
    init_db(db_path)

    concurrent = _concurrent_writes(
        db_path,
        workers=max(2, int(workers)),
        writes_per_worker=max(2, int(writes_per_worker)),
    )
    count_after_concurrency = _finding_count(db_path)
    audit_after_concurrency = verify_audit_integrity(db_path)
    contention = _lock_contention(db_path)
    concurrent_backup_path = root / "backups" / "concurrent.sqlite3"
    backup_under_load = _backup_during_writes(db_path, concurrent_backup_path)
    stable_backup_path = root / "backups" / "stable.sqlite3"
    atomic_failure = _atomic_failure(db_path, stable_backup_path, root)
    crash = _crash_rollback(db_path)

    restored_path = root / "restored" / "project.db"
    restore_result = restore_database(
        restored_path,
        concurrent_backup_path,
        actor="runtime-fault-rehearsal",
        expected_project_id="default",
    )
    restored_validation = validate_database_file(
        restored_path,
        expected_project_id="default",
    )
    final_audit = verify_audit_integrity(db_path)
    final_integrity = _integrity(db_path)

    expected_concurrent = max(2, int(workers)) * max(2, int(writes_per_worker))
    checks = [
        {"name": "release_version_present", "passed": bool(CURRENT_APP_VERSION), "actual": CURRENT_APP_VERSION},
        {"name": "schema_version", "passed": CURRENT_SCHEMA_VERSION == 46, "actual": CURRENT_SCHEMA_VERSION},
        {"name": "concurrent_writes_complete", "passed": concurrent["completed"] == expected_concurrent and not concurrent["failure_types"], "actual": concurrent},
        {"name": "concurrent_finding_count", "passed": count_after_concurrency == expected_concurrent, "actual": count_after_concurrency, "expected": expected_concurrent},
        {"name": "audit_chain_after_concurrency", "passed": bool(audit_after_concurrency.get("valid")), "actual": {"valid": audit_after_concurrency.get("valid"), "issues": list(audit_after_concurrency.get("issues") or [])[:5]}},
        {"name": "held_lock_waiter_succeeds", "passed": contention["write_count"] == 1 and contention["holder_finished"], "actual": contention},
        {"name": "held_lock_wait_is_bounded", "passed": 250 <= float(contention["waited_ms"]) <= 5000, "actual_ms": contention["waited_ms"]},
        {"name": "backup_during_writes", "passed": backup_under_load["writer_completed"] > 0 and not backup_under_load["writer_failure_types"], "actual": {"writer_completed": backup_under_load["writer_completed"], "writer_failure_types": backup_under_load["writer_failure_types"], "backup_elapsed_ms": backup_under_load["backup_elapsed_ms"]}},
        {"name": "concurrent_backup_valid", "passed": int(backup_under_load["validation"].get("schema_version", -1)) == CURRENT_SCHEMA_VERSION and bool((backup_under_load["validation"].get("audit_integrity") or {}).get("valid")), "actual": {"schema_version": backup_under_load["validation"].get("schema_version"), "audit_valid": bool((backup_under_load["validation"].get("audit_integrity") or {}).get("valid"))}},
        {"name": "failed_backup_preserves_previous", "passed": bool(atomic_failure["error_type"]) and atomic_failure["destination_preserved"], "actual": atomic_failure},
        {"name": "failed_backup_cleans_partial", "passed": not atomic_failure["partial_files"], "actual": atomic_failure["partial_files"]},
        {"name": "crashed_transaction_rolls_back", "passed": crash["returncode"] == 17 and not crash["uncommitted_row_present"], "actual": crash},
        {"name": "database_integrity_after_crash", "passed": crash["integrity"] == "ok" and final_integrity == "ok", "actual": {"after_crash": crash["integrity"], "final": final_integrity}},
        {"name": "restored_backup_valid", "passed": int(restored_validation.get("schema_version", -1)) == CURRENT_SCHEMA_VERSION and bool((restored_validation.get("audit_integrity") or {}).get("valid")), "actual": {"schema_version": restored_validation.get("schema_version"), "finding_count": restored_validation.get("finding_count"), "audit_valid": bool((restored_validation.get("audit_integrity") or {}).get("valid")), "safety_backup": bool(restore_result.get("safety_backup"))}},
        {"name": "final_audit_chain_integrity", "passed": bool(final_audit.get("valid")), "actual": {"valid": final_audit.get("valid"), "issues": list(final_audit.get("issues") or [])[:5]}},
    ]
    result = {
        "title": f"VulnFlow {CURRENT_APP_VERSION} runtime fault rehearsal",
        "format": "vulnflow-runtime-fault-rehearsal/1",
        "version": CURRENT_APP_VERSION,
        "schema_version": CURRENT_SCHEMA_VERSION,
        "concurrency": concurrent,
        "contention": contention,
        "backup_under_load": {
            "writer_completed": backup_under_load["writer_completed"],
            "writer_failure_types": backup_under_load["writer_failure_types"],
            "backup_elapsed_ms": backup_under_load["backup_elapsed_ms"],
        },
        "atomic_failure": atomic_failure,
        "crash": crash,
        "checks": checks,
        "passed": all(bool(item["passed"]) for item in checks),
        "limitations": [
            "This is a bounded single-host SQLite rehearsal, not a production traffic endurance test.",
            "Process death is injected inside an uncommitted SQLite transaction; host power loss and filesystem corruption are not simulated.",
            "Disk-full behavior is represented by a failed source snapshot and atomic destination preservation, not a real exhausted filesystem.",
        ],
    }
    if temporary is not None:
        temporary.cleanup()
    return result


def _text(result: dict[str, Any]) -> str:
    lines = [
        result["title"],
        "",
        f"version: {result['version']}",
        f"schema_version: {result['schema_version']}",
        f"concurrent_writes: {result['concurrency']['completed']}/{result['concurrency']['requested']}",
        f"lock_wait_ms: {result['contention']['waited_ms']}",
        f"backup_under_load_ms: {result['backup_under_load']['backup_elapsed_ms']}",
        "",
    ]
    lines.extend(
        f"{'PASS' if item['passed'] else 'FAIL'}: {item['name']}"
        for item in result["checks"]
    )
    lines.extend(["", "overall: " + ("PASS" if result["passed"] else "FAIL")])
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="Run bounded SQLite fault and recovery checks.")
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--writes-per-worker", type=int, default=8)
    parser.add_argument("--json-output", default="reports/runtime_fault_rehearsal_verification.json")
    parser.add_argument("--text-output", default="reports/runtime_fault_rehearsal_verification.txt")
    args = parser.parse_args()
    result = run_rehearsal(
        workers=args.workers,
        writes_per_worker=args.writes_per_worker,
    )
    json_path = ROOT / args.json_output
    text_path = ROOT / args.text_output
    json_path.parent.mkdir(parents=True, exist_ok=True)
    text_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    text = _text(result)
    text_path.write_text(text, encoding="utf-8")
    print(text, end="")
    if not result["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
