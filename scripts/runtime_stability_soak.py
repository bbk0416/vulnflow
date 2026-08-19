from __future__ import annotations

"""Bounded runtime stability soak for a VulnFlow release.

The release profile repeats complete FastAPI lifespans against one persistent
SQLite database while exercising the real background worker, HMAC webhook
delivery, database maintenance, backup validation, and audit-chain checks.
It records structural resource metrics only; credentials, URLs, database paths,
and webhook payloads are never written to the report.
"""

import argparse
import gc
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import sqlite3
import socket
import sys
import shutil
import tempfile
import threading
import time
import tracemalloc
from typing import Any

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient

import app.main as app_main
from app.core.context import get_application_context
from app.core.project_scope import project_scope
from app.services.project_runtime import application_project_selections

_WEBHOOK_SECRET = "vulnflow-soak-secret-2026"


def current_rss_bytes() -> int | None:
    """Return current resident memory when the host exposes it.

    Linux /proc is preferred because resource.getrusage reports a high-water
    mark rather than current RSS. Unsupported hosts return None and the soak
    falls back to Python allocation tracking.
    """
    status = Path("/proc/self/status")
    if status.is_file():
        for line in status.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("VmRSS:"):
                parts = line.split()
                if len(parts) >= 2:
                    return int(parts[1]) * 1024
    return None


def sqlite_snapshot(db_path: Path) -> dict[str, Any]:
    wal_path = Path(str(db_path) + "-wal")
    with sqlite3.connect(db_path) as conn:
        integrity = str(conn.execute("PRAGMA integrity_check").fetchone()[0])
        schema_version = int(conn.execute("PRAGMA user_version").fetchone()[0])
        page_count = int(conn.execute("PRAGMA page_count").fetchone()[0])
        freelist_count = int(conn.execute("PRAGMA freelist_count").fetchone()[0])
        jobs = int(conn.execute("SELECT COUNT(*) FROM background_jobs").fetchone()[0])
        active_jobs = int(
            conn.execute(
                "SELECT COUNT(*) FROM background_jobs WHERE status IN ('PENDING','RETRY','RUNNING')"
            ).fetchone()[0]
        )
        delivered_webhooks = int(
            conn.execute("SELECT COUNT(*) FROM webhook_events WHERE status='DELIVERED'").fetchone()[0]
        )
    return {
        "integrity": integrity,
        "schema_version": schema_version,
        "database_bytes": db_path.stat().st_size if db_path.exists() else 0,
        "wal_bytes": wal_path.stat().st_size if wal_path.exists() else 0,
        "page_count": page_count,
        "freelist_count": freelist_count,
        "jobs": jobs,
        "active_jobs": active_jobs,
        "delivered_webhooks": delivered_webhooks,
    }


def _thread_snapshot() -> dict[str, Any]:
    threads = list(threading.enumerate())
    return {
        "count": len(threads),
        "portal_ids": sorted(
            int(thread.ident)
            for thread in threads
            if thread.ident is not None and "asyncio-portal" in thread.name.lower()
        ),
        "vulnflow_names": sorted(
            thread.name for thread in threads if "vulnflow" in thread.name.lower()
        ),
    }


class _WebhookRecorder:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.accepted_event_ids: list[str] = []
        self.rejected = 0

    def record(self, *, event_id: str, accepted: bool) -> None:
        with self.lock:
            if accepted:
                self.accepted_event_ids.append(event_id)
            else:
                self.rejected += 1

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            return {
                "accepted": len(self.accepted_event_ids),
                "unique_event_ids": len(set(self.accepted_event_ids)),
                "rejected": self.rejected,
            }


class _WebhookHandler(BaseHTTPRequestHandler):
    server_version = "VulnFlowSoakSink/1"
    protocol_version = "HTTP/1.1"

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        length = max(0, int(self.headers.get("Content-Length", "0") or 0))
        body = self.rfile.read(length)
        signature = str(self.headers.get("X-VulnFlow-Signature", ""))
        expected = "sha256=" + hmac.new(
            _WEBHOOK_SECRET.encode("utf-8"), body, hashlib.sha256
        ).hexdigest()
        event_id = str(self.headers.get("X-VulnFlow-Event-ID", ""))
        accepted = bool(event_id) and hmac.compare_digest(signature, expected)
        recorder: _WebhookRecorder = self.server.recorder  # type: ignore[attr-defined]
        recorder.record(event_id=event_id, accepted=accepted)
        status = 204 if accepted else 401
        self.send_response(status)
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True

    def log_message(self, _format: str, *_args: object) -> None:
        return


class WebhookSink:
    def __init__(self) -> None:
        self.recorder = _WebhookRecorder()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _WebhookHandler)
        self.server.daemon_threads = True
        self.server.recorder = self.recorder  # type: ignore[attr-defined]
        self.thread = threading.Thread(
            target=self.server.serve_forever,
            name="vulnflow-soak-webhook-sink",
            daemon=True,
        )

    @property
    def port(self) -> int:
        return int(self.server.server_address[1])

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        # BaseServer.shutdown() can wait indefinitely when serve_forever() is
        # alive but no longer polling its selector. Run it on a daemon helper,
        # wake the listening socket, and keep the caller's shutdown bounded.
        if self.thread.is_alive():
            finished = threading.Event()

            def request_shutdown() -> None:
                try:
                    self.server.shutdown()
                finally:
                    finished.set()

            helper = threading.Thread(
                target=request_shutdown,
                name="vulnflow-soak-webhook-shutdown",
                daemon=True,
            )
            helper.start()
            if not finished.wait(timeout=2.0):
                try:
                    with socket.create_connection(("127.0.0.1", self.port), timeout=0.5):
                        pass
                except OSError:
                    pass
                finished.wait(timeout=1.0)
        self.server.server_close()
        self.thread.join(timeout=3.0)
        if self.thread.is_alive():
            raise RuntimeError("webhook sink did not stop within 3 seconds")


def _settings(root: Path, *, port: int) -> dict[str, object]:
    default_root = root / "projects" / "default"
    return {
        "DATA_DIR": root,
        "LEGACY_DB_PATH": root / "legacy-vulnflow.db",
        "CONTROL_DB_PATH": root / "control.db",
        "DEFAULT_PROJECT_ROOT": default_root,
        "DEFAULT_PROJECT_DB_PATH": default_root / "vulnflow.db",
        "DB_PATH": default_root / "vulnflow.db",
        "PROJECTS_DIR": root / "projects",
        "EVIDENCE_DIR": default_root / "evidence",
        "EXPORT_DIR": default_root / "exports",
        "IMPORT_PREVIEW_DIR": default_root / "import-previews",
        "RECOVERY_DIR": default_root / "backups" / "recovery",
        "LEGACY_EVIDENCE_DIR": root / "legacy-evidence",
        "LEGACY_EXPORT_DIR": root / "legacy-exports",
        "LEGACY_IMPORT_PREVIEW_DIR": root / "legacy-previews",
        "LEGACY_RECOVERY_DIR": root / "legacy-recovery",
        "EXTERNAL_BACKUP_DIR": root / "external-backups",
        "COORDINATION_DB_ENV": str(root / "coordination.db"),
        "CLUSTER_COORDINATION_ENABLED": False,
        "DEMO_MODE": True,
        "ALLOW_LOCAL_ADMIN_FALLBACK": True,
        "JOB_WORKER_ENABLED": True,
        "JOB_WORKER_INTERVAL_SECONDS": 1,
        "JOB_LEASE_SECONDS": 30,
        "MAINTENANCE_INTERVAL_MINUTES": 60,
        "WEBHOOK_INTERVAL_SECONDS": 60,
        "BACKUP_INTERVAL_HOURS": 24,
        "WEBHOOK_ALLOW_INSECURE_HTTP": True,
        "OUTBOUND_ALLOW_PRIVATE_NETWORKS": True,
        "WEBHOOK_TIMEOUT_SECONDS": 3,
        "WEBHOOK_MAX_ATTEMPTS": 2,
        "WEBHOOKS_JSON": json.dumps(
            {
                "soak-sink": {
                    "url": f"http://127.0.0.1:{port}/events",
                    "secret": _WEBHOOK_SECRET,
                    "events": ["*"],
                }
            },
            separators=(",", ":"),
        ),
        "LIFECYCLE_SHUTDOWN_TIMEOUT_SECONDS": 2.0,
    }


def _wait_for_jobs(context: Any, job_ids: list[str], *, timeout_seconds: float) -> list[dict[str, Any]]:
    # Use one short-timeout polling query instead of the normal 30-second
    # repository busy timeout. Otherwise three sequential reads can exceed the
    # soak's declared deadline while a maintenance writer holds SQLite.
    db_path = Path(context.get("DB_PATH"))
    deadline = time.monotonic() + max(1.0, float(timeout_seconds))
    latest: list[dict[str, Any]] = []
    placeholders = ",".join("?" for _ in job_ids)
    while time.monotonic() < deadline:
        try:
            with sqlite3.connect(db_path, timeout=0.25) as conn:
                conn.row_factory = sqlite3.Row
                conn.execute("PRAGMA busy_timeout=250")
                rows = conn.execute(
                    f"SELECT job_id, status FROM background_jobs WHERE job_id IN ({placeholders})",
                    tuple(job_ids),
                ).fetchall()
            by_id = {str(row["job_id"]): dict(row) for row in rows}
            latest = [by_id.get(job_id, {"job_id": job_id, "status": "MISSING"}) for job_id in job_ids]
            if all(str(item.get("status")) in {"SUCCEEDED", "FAILED", "CANCELLED"} for item in latest):
                return latest
        except sqlite3.OperationalError as exc:
            if "locked" not in str(exc).lower() and "busy" not in str(exc).lower():
                raise
        time.sleep(0.05)
    raise TimeoutError(
        "background jobs did not finish: "
        + ", ".join(f"{item.get('job_id')}={item.get('status')}" for item in latest)
    )


def _truncate_wal(db_path: Path) -> None:
    with sqlite3.connect(db_path) as conn:
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")


def _evaluate(
    *,
    iterations: int,
    samples: list[dict[str, Any]],
    lifecycle_snapshots: list[dict[str, Any]],
    job_outcomes: list[dict[str, Any]],
    webhook: dict[str, Any],
    final_database: dict[str, Any],
    backup_validation: dict[str, Any],
    audit_integrity: dict[str, Any],
    baseline_threads: dict[str, Any],
    final_threads: dict[str, Any],
    max_rss_growth_bytes: int,
    max_python_growth_bytes: int,
    max_wal_bytes: int,
) -> list[dict[str, Any]]:
    rss_values = [int(item["rss_bytes"]) for item in samples if item.get("rss_bytes") is not None]
    rss_growth = max(0, rss_values[-1] - rss_values[0]) if len(rss_values) >= 2 else 0
    python_values = [
        int(item["python_current_bytes"])
        for item in samples
        if item.get("python_current_bytes") is not None
    ]
    python_growth = (
        max(0, python_values[-1] - python_values[0])
        if len(python_values) >= 2
        else 0
    )
    portal_baseline = set(baseline_threads.get("portal_ids") or [])
    portal_final = set(final_threads.get("portal_ids") or [])
    succeeded = sum(str(item.get("status")) == "SUCCEEDED" for item in job_outcomes)
    expected_jobs = iterations * 2 + ((iterations + 2) // 3)
    expected_webhooks = iterations
    checks = [
        {"name": "release_version", "passed": app_main.CURRENT_APP_VERSION == "72.0.93", "actual": app_main.CURRENT_APP_VERSION},
        {"name": "schema_version", "passed": app_main.CURRENT_SCHEMA_VERSION == 46, "actual": app_main.CURRENT_SCHEMA_VERSION},
        {"name": "iterations_completed", "passed": len(samples) == iterations, "actual": len(samples)},
        {"name": "worker_jobs_succeeded", "passed": succeeded == expected_jobs, "actual": succeeded, "expected": expected_jobs},
        {"name": "webhook_hmac_deliveries", "passed": int(webhook.get("accepted", 0)) >= expected_webhooks and int(webhook.get("rejected", 0)) == 0, "actual": webhook, "expected_minimum": expected_webhooks},
        {"name": "lifecycle_shutdown_clean", "passed": all(not bool(item.get("shutdown_timed_out")) and int(item.get("running_task_count", 0)) == 0 and not item.get("pending_task_stacks") for item in lifecycle_snapshots), "actual": len(lifecycle_snapshots)},
        {"name": "portal_threads_reclaimed", "passed": portal_final <= portal_baseline, "actual": len(portal_final), "baseline": len(portal_baseline)},
        {"name": "rss_growth_bounded", "passed": not rss_values or rss_growth <= max_rss_growth_bytes, "actual_bytes": rss_growth, "limit_bytes": max_rss_growth_bytes, "available": bool(rss_values)},
        {
            "name": "python_allocation_growth_bounded",
            "passed": len(python_values) < 2 or python_growth <= max_python_growth_bytes,
            "actual_bytes": python_growth,
            "limit_bytes": max_python_growth_bytes,
            "available": len(python_values) >= 2,
            "measured_samples": len(python_values),
        },
        {"name": "sqlite_integrity_and_wal", "passed": final_database.get("integrity") == "ok" and int(final_database.get("schema_version", -1)) == 46 and int(final_database.get("active_jobs", -1)) == 0 and int(final_database.get("wal_bytes", 0)) <= max_wal_bytes, "actual": final_database, "wal_limit_bytes": max_wal_bytes},
        {"name": "backup_restore_eligibility", "passed": int(backup_validation.get("schema_version", -1)) == 46 and bool((backup_validation.get("audit_integrity") or {}).get("valid")), "actual": {"schema_version": backup_validation.get("schema_version"), "audit_integrity_valid": bool((backup_validation.get("audit_integrity") or {}).get("valid")), "finding_count": int(backup_validation.get("finding_count", 0))}},
        {"name": "audit_chain_integrity", "passed": bool(audit_integrity.get("valid")), "actual": {"valid": bool(audit_integrity.get("valid")), "issues": list(audit_integrity.get("issues") or [])[:5]}},
    ]
    return checks


def run_soak(
    *,
    iterations: int = 12,
    job_timeout_seconds: float = 20.0,
    max_rss_growth_mib: float = 64.0,
    max_python_growth_mib: float = 24.0,
    max_wal_mib: float = 8.0,
    allocation_warmup_iterations: int = 3,
    work_root: Path | None = None,
) -> dict[str, Any]:
    iterations = max(2, int(iterations))
    allocation_warmup_iterations = min(
        max(1, int(allocation_warmup_iterations)), iterations - 1
    )
    owns_temp = work_root is None
    temp = tempfile.TemporaryDirectory(prefix="vulnflow-runtime-soak-") if owns_temp else None
    root = Path(temp.name) if temp is not None else Path(work_root or "")
    root.mkdir(parents=True, exist_ok=True)
    for sample_name in (
        "sample_findings.csv",
        "sample_product_release.cdx.json",
        "sample_sbom.cdx.json",
        "sample_sbom_v2.cdx.json",
    ):
        shutil.copy2(ROOT / "data" / sample_name, root / sample_name)

    baseline_threads = _thread_snapshot()
    samples: list[dict[str, Any]] = []
    lifecycle_snapshots: list[dict[str, Any]] = []
    job_outcomes: list[dict[str, Any]] = []
    health_statuses: list[list[int]] = []
    sink = WebhookSink()
    last_context: Any = None
    started = time.perf_counter()
    allocation_tracking_started_here = not tracemalloc.is_tracing()
    if allocation_tracking_started_here:
        tracemalloc.start()
    sink.start()
    try:
        settings = _settings(root, port=sink.port)
        db_path: Path | None = None
        selection = None
        for index in range(iterations):
            if index == allocation_warmup_iterations:
                gc.collect()
                if tracemalloc.is_tracing():
                    tracemalloc.reset_peak()
            application = app_main.create_app(setting_overrides=settings)
            context = get_application_context(application)
            last_context = context
            with TestClient(application) as client:
                selections = application_project_selections(context)
                selection = next((item for item in selections if item is not None), None)
                if selection is None:
                    raise RuntimeError("runtime soak could not resolve an explicit project scope")
                db_path = Path(selection.database)
                health = [
                    client.get("/health/live").status_code,
                    client.get("/health/ready").status_code,
                ]
                health_statuses.append(health)
                if health != [200, 200]:
                    raise RuntimeError(f"health check failed in cycle {index + 1}: {health}")

                with project_scope(selection):
                    queue_webhook = context.services.require("_queue_webhook")
                    queue_webhook(
                        "soak.cycle",
                        {"cycle": index + 1},
                        "runtime-soak",
                        context=context,
                        idempotency_key=f"runtime-soak-webhook:{index + 1}",
                    )
                    create_job = context.services.require("create_background_job")
                    common = {
                        "requested_by": "runtime-soak",
                        "max_attempts": 2,
                    }
                    job_ids: list[str] = []
                    # Online maintenance is scheduled on a slower cadence than the
                    # worker and webhook jobs. Running it every few seconds creates
                    # an unrealistic continuous-writer lock storm that does not
                    # match the configured 60-minute production interval.
                    if index % 3 == 0:
                        maintenance = create_job(
                            db_path,
                            job_type="DATABASE_MAINTENANCE",
                            payload={"truncate_wal": True, "optimize_fts": True},
                            priority=30,
                            dedupe_key=f"runtime-soak-maintenance:{index + 1}",
                            **common,
                        )
                        job_ids.append(maintenance["job_id"])
                    rescore = create_job(
                        db_path,
                        job_type="RESCORE_ALL",
                        priority=20,
                        dedupe_key=f"runtime-soak-rescore:{index + 1}",
                        **common,
                    )
                    delivery = create_job(
                        db_path,
                        job_type="WEBHOOK_DELIVERY",
                        priority=10,
                        dedupe_key=f"runtime-soak-delivery:{index + 1}",
                        **common,
                    )
                    job_ids.extend([rescore["job_id"], delivery["job_id"]])
                    outcomes = _wait_for_jobs(
                        context,
                        job_ids,
                        timeout_seconds=job_timeout_seconds,
                    )
                    if any(str(item.get("status")) != "SUCCEEDED" for item in outcomes):
                        raise RuntimeError(f"job failure in cycle {index + 1}: {outcomes}")
                    job_outcomes.extend(outcomes)

            shutdown = dict(context.get("LIFECYCLE_SHUTDOWN_SNAPSHOT") or {})
            lifecycle_snapshots.append(shutdown)
            gc.collect()
            time.sleep(0.05)
            if tracemalloc.is_tracing() and index >= allocation_warmup_iterations:
                python_current, python_peak = tracemalloc.get_traced_memory()
            else:
                python_current, python_peak = None, None
            sample = {
                "cycle": index + 1,
                "rss_bytes": current_rss_bytes(),
                "python_current_bytes": (
                    int(python_current) if python_current is not None else None
                ),
                "python_peak_bytes": (
                    int(python_peak) if python_peak is not None else None
                ),
                "thread_count": int(_thread_snapshot()["count"]),
                "shutdown_elapsed_ms": float(shutdown.get("shutdown_elapsed_ms", 0.0)),
                "database": sqlite_snapshot(db_path),
            }
            samples.append(sample)

        assert last_context is not None
        assert selection is not None
        assert db_path is not None
        with project_scope(selection):
            backup_path = root / "backup" / "soak-backup.db"
            last_context.services.require("backup_database")(db_path, backup_path)
            backup_validation = last_context.services.require("validate_database_file")(backup_path)
            signing = app_main._signing_config(last_context)
            audit_integrity = last_context.services.require("verify_audit_integrity")(
                db_path,
                signing_keys=signing.keys,
            )
            _truncate_wal(db_path)
            final_database = sqlite_snapshot(db_path)
    finally:
        sink.stop()
        gc.collect()
        time.sleep(0.1)
        final_threads = _thread_snapshot()
        webhook = sink.recorder.snapshot()
        if allocation_tracking_started_here and tracemalloc.is_tracing():
            tracemalloc.stop()

    checks = _evaluate(
        iterations=iterations,
        samples=samples,
        lifecycle_snapshots=lifecycle_snapshots,
        job_outcomes=job_outcomes,
        webhook=webhook,
        final_database=final_database,
        backup_validation=backup_validation,
        audit_integrity=audit_integrity,
        baseline_threads=baseline_threads,
        final_threads=final_threads,
        max_rss_growth_bytes=int(max_rss_growth_mib * 1024 * 1024),
        max_python_growth_bytes=int(max_python_growth_mib * 1024 * 1024),
        max_wal_bytes=int(max_wal_mib * 1024 * 1024),
    )
    result = {
        "title": f"VulnFlow {app_main.CURRENT_APP_VERSION} bounded runtime stability soak",
        "format": "vulnflow-runtime-soak/1",
        "version": app_main.CURRENT_APP_VERSION,
        "schema_version": app_main.CURRENT_SCHEMA_VERSION,
        "iterations": iterations,
        "allocation_warmup_iterations": allocation_warmup_iterations,
        "duration_seconds": round(time.perf_counter() - started, 3),
        "health_statuses": health_statuses,
        "samples": samples,
        "lifecycle": {
            "shutdown_count": len(lifecycle_snapshots),
            "max_shutdown_elapsed_ms": round(
                max((float(item.get("shutdown_elapsed_ms", 0.0)) for item in lifecycle_snapshots), default=0.0),
                3,
            ),
            "timeouts": sum(bool(item.get("shutdown_timed_out")) for item in lifecycle_snapshots),
        },
        "jobs": {
            "total": len(job_outcomes),
            "succeeded": sum(str(item.get("status")) == "SUCCEEDED" for item in job_outcomes),
            "failed": sum(str(item.get("status")) == "FAILED" for item in job_outcomes),
        },
        "webhook": webhook,
        "final_database": final_database,
        "thread_counts": {
            "baseline": baseline_threads["count"],
            "final": final_threads["count"],
            "baseline_portals": len(baseline_threads["portal_ids"]),
            "final_portals": len(final_threads["portal_ids"]),
        },
        "checks": checks,
        "passed": all(bool(item["passed"]) for item in checks),
        "limitations": [
            "This is a bounded release soak, not a 24-hour or production traffic endurance test.",
            "RSS is host-dependent; Python allocation tracking remains available when current RSS is unavailable.",
            "The webhook receiver is a loopback test sink and does not validate external network reliability.",
        ],
    }
    if temp is not None:
        temp.cleanup()
    return result


def _text(result: dict[str, Any]) -> str:
    lines = [
        result["title"],
        "",
        f"version: {result['version']}",
        f"schema_version: {result['schema_version']}",
        f"iterations: {result['iterations']}",
        f"duration_seconds: {result['duration_seconds']}",
        f"jobs_succeeded: {result['jobs']['succeeded']}/{result['jobs']['total']}",
        f"webhooks_accepted: {result['webhook']['accepted']}",
        f"max_shutdown_elapsed_ms: {result['lifecycle']['max_shutdown_elapsed_ms']}",
        f"final_wal_bytes: {result['final_database']['wal_bytes']}",
        "",
    ]
    for item in result["checks"]:
        detail = ""
        if "actual_bytes" in item and "limit_bytes" in item:
            detail = (
                f" (actual_bytes={item['actual_bytes']}; "
                f"limit_bytes={item['limit_bytes']}; "
                f"available={item.get('available', True)})"
            )
        lines.append(
            f"{'PASS' if item['passed'] else 'FAIL'}: {item['name']}{detail}"
        )
    lines.append("")
    lines.append("overall: " + ("PASS" if result["passed"] else "FAIL"))
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a bounded VulnFlow runtime stability soak.")
    parser.add_argument("--iterations", type=int, default=12)
    parser.add_argument("--job-timeout-seconds", type=float, default=20.0)
    parser.add_argument("--max-rss-growth-mib", type=float, default=64.0)
    parser.add_argument("--max-python-growth-mib", type=float, default=24.0)
    parser.add_argument("--allocation-warmup-iterations", type=int, default=3)
    parser.add_argument("--max-wal-mib", type=float, default=8.0)
    parser.add_argument(
        "--json-output",
        default="reports/runtime_stability_soak_verification.json",
    )
    parser.add_argument(
        "--text-output",
        default="reports/runtime_stability_soak_verification.txt",
    )
    args = parser.parse_args()
    result = run_soak(
        iterations=args.iterations,
        job_timeout_seconds=args.job_timeout_seconds,
        max_rss_growth_mib=args.max_rss_growth_mib,
        max_python_growth_mib=args.max_python_growth_mib,
        max_wal_mib=args.max_wal_mib,
        allocation_warmup_iterations=args.allocation_warmup_iterations,
    )
    json_path = ROOT / args.json_output
    text_path = ROOT / args.text_output
    json_path.parent.mkdir(parents=True, exist_ok=True)
    text_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(
        json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    text = _text(result)
    text_path.write_text(text, encoding="utf-8")
    print(text, end="")
    # The soak has already closed its application lifespans, webhook sink,
    # temporary database, and output files. Some third-party runtime resources
    # can still register interpreter-shutdown callbacks that keep a successful
    # standalone verifier alive after its final report is durable. Flush the
    # evidence streams and use a deterministic process exit so release gates do
    # not wait until their outer timeout after a completed soak.
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(0 if result["passed"] else 1)


if __name__ == "__main__":
    main()
