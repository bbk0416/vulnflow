from __future__ import annotations

"""Domain routes extracted from :mod:`app.main`.

The route module is intentionally dependency-injected by ``app.routers`` so the
historical compatibility surface in ``app.main`` remains available without creating
internal import cycles.
"""

from datetime import date
import hashlib
from pathlib import Path
from typing import Any

from fastapi import APIRouter, File, Form, Header, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response, StreamingResponse
from starlette.background import BackgroundTask

from app.api.models import *  # noqa: F403 - route request models

router = APIRouter()


def install_dependencies(namespace: dict[str, Any]) -> None:
    protected = {"router", "install_dependencies", "route_exports", "ROUTE_NAMES"}
    for name, value in namespace.items():
        if not name.startswith("__") and name not in protected:
            globals()[name] = value


def route_exports() -> dict[str, Any]:
    return {name: globals()[name] for name in ROUTE_NAMES}


ROUTE_NAMES = ('refresh_intel', 'rescore', 'maintenance_page', 'maintenance_run', 'database_maintenance_run', 'webhooks_page', 'webhooks_deliver', 'webhook_retry', 'execution_receipts_page', 'execution_receipt_replay', 'jobs_page', 'jobs_import_csv', 'jobs_queue', 'jobs_cancel', 'jobs_retry', 'reset_demo', 'import_history', 'api_webhooks', 'api_deliver_webhooks', 'api_jobs', 'api_job_detail', 'api_queue_import_job', 'api_queue_job', 'api_cancel_job', 'api_retry_job', 'api_execution_receipts', 'api_execution_receipt_archives', 'api_execution_receipt', 'api_execution_receipt_replay', 'api_imports', 'api_maintenance_runs', 'api_database_health', 'api_database_maintenance_runs', 'api_database_maintenance', 'cluster_page', 'api_cluster_state', 'api_prune_cluster_state', 'health_live', 'health_ready', 'health', 'metrics')

@router.post("/refresh-intel")
def refresh_intel(request: Request, csrf_token: str = Form(...)):
    _require_role(request, "operator")
    _verify_csrf(request, csrf_token)
    try:
        result = _refresh_intelligence_operation(actor=_actor(request))
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(502, str(exc)) from exc
    notice = "intel_partial" if result.get("errors") else "intel_ok"
    return RedirectResponse(url=f"/?notice={notice}", status_code=303)

@router.post("/rescore")
def rescore(request: Request, csrf_token: str = Form(...)):
    _require_role(request, "operator")
    _verify_csrf(request, csrf_token)
    rescore_all(actor=_actor(request))
    return RedirectResponse(url="/?notice=rescore_ok", status_code=303)

@router.get("/maintenance", response_class=HTMLResponse)
def maintenance_page(request: Request, notice: str = ""):
    _require_role(request, "admin")
    return templates.TemplateResponse(
        request=request, name="maintenance.html",
        context={
            "runs": list_maintenance_runs(DB_PATH, limit=100),
            "database_runs": list_database_maintenance_runs(DB_PATH, limit=50),
            "database_health": database_health(DB_PATH),
            "settings": _maintenance_settings() | {
                "interval_minutes": MAINTENANCE_INTERVAL_MINUTES,
                "db_wal_warn_bytes": DB_WAL_WARN_BYTES,
                "db_reclaim_warn_ratio": DB_RECLAIM_WARN_RATIO,
            },
            "notice_message": NOTICE_MESSAGES.get(notice, ""),
        },
    )

@router.post("/maintenance/run")
def maintenance_run(request: Request, csrf_token: str = Form(...)):
    _require_role(request, "admin")
    _verify_csrf(request, csrf_token)
    result = run_maintenance(DB_PATH, actor=_actor(request), **_maintenance_settings())
    result["purged_jobs"] = _purge_completed_jobs()
    result.update(purge_expired_export_artifacts(DB_PATH, EXPORT_DIR, actor=_actor(request)))
    result.update(enforce_export_storage_budget(
        DB_PATH, EXPORT_DIR, quota_bytes=EXPORT_QUOTA_BYTES, reserve_bytes=EXPORT_MIN_FREE_BYTES, actor=_actor(request),
    ))
    rescore_all(audit=False, actor=_actor(request))
    _queue_webhook("maintenance.completed", result, _actor(request))
    return RedirectResponse(url="/maintenance?notice=maintenance_ok", status_code=303)

@router.post("/maintenance/database/run")
def database_maintenance_run(
    request: Request, csrf_token: str = Form(...), rebuild_fts_on_mismatch: str = Form(""),
):
    _require_role(request, "admin")
    _verify_csrf(request, csrf_token)
    with _exclusive_operation("database-maintenance", "SQLite 온라인 유지관리"):
        result = run_database_maintenance(
            DB_PATH, actor=_actor(request), truncate_wal=True, optimize_fts=True,
            rebuild_fts_on_mismatch=str(rebuild_fts_on_mismatch).lower() in {"1", "true", "yes", "on"},
        )
    _queue_webhook("database.maintenance_completed", {
        "run_id": result.get("run_id"), "status": result.get("status"),
        "wal_before": (result.get("before") or {}).get("wal_bytes"),
        "wal_after": (result.get("after") or {}).get("wal_bytes"),
        "fts_in_sync": (result.get("after") or {}).get("fts_in_sync"),
    }, _actor(request))
    return RedirectResponse(url="/maintenance?notice=maintenance_ok", status_code=303)

@router.get("/webhooks", response_class=HTMLResponse)
def webhooks_page(request: Request, notice: str = ""):
    _require_role(request, "admin")
    events = list_webhook_events(DB_PATH, limit=500)
    return templates.TemplateResponse(
        request=request, name="webhooks.html",
        context={
            "events": events,
            "endpoint_count": len(WEBHOOK_ENDPOINTS),
            "pending_count": sum(1 for item in events if item.get("status") in {"PENDING", "RETRY"}),
            "delivered_count": sum(1 for item in events if item.get("status") == "DELIVERED"),
            "failed_count": sum(1 for item in events if item.get("status") == "FAILED"),
            "notice_message": NOTICE_MESSAGES.get(notice, ""),
        },
    )

@router.post("/webhooks/deliver")
def webhooks_deliver(request: Request, csrf_token: str = Form(...)):
    _require_role(request, "admin")
    _verify_csrf(request, csrf_token)
    summary = deliver_due_events(
        DB_PATH, endpoints=WEBHOOK_ENDPOINTS, timeout_seconds=WEBHOOK_TIMEOUT_SECONDS,
        max_attempts=WEBHOOK_MAX_ATTEMPTS, limit=200,
    )
    for outcome, count in summary.items():
        for _ in range(int(count)):
            METRICS.observe_webhook(outcome)
    return RedirectResponse(url="/webhooks?notice=webhook_ok", status_code=303)

@router.post("/webhooks/{event_id}/retry")
def webhook_retry(request: Request, event_id: str, csrf_token: str = Form(...)):
    _require_role(request, "admin")
    _verify_csrf(request, csrf_token)
    try:
        retry_webhook_event(DB_PATH, event_id, actor=_actor(request))
    except KeyError as exc:
        raise HTTPException(404, "웹훅 이벤트를 찾을 수 없습니다.") from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return RedirectResponse(url="/webhooks?notice=webhook_retry", status_code=303)

@router.get("/execution-receipts", response_class=HTMLResponse)
def execution_receipts_page(request: Request, operation_type: str = "", outcome: str = "", notice: str = ""):
    _require_role(request, "admin")
    return templates.TemplateResponse(
        request=request,
        name="execution_receipts.html",
        context={
            "receipts": list_execution_receipts(DB_PATH, operation_type=operation_type, outcome=outcome, limit=500),
            "operation_type": str(operation_type or "").upper(),
            "outcome": str(outcome or "").upper(),
            "counts": count_execution_receipts(DB_PATH),
            "archives": list_execution_receipt_archives(DB_PATH, limit=100),
            "notice_message": NOTICE_MESSAGES.get(notice, ""),
        },
    )

@router.post("/execution-receipts/{receipt_id}/replay")
def execution_receipt_replay(request: Request, receipt_id: str, reason: str = Form(...), csrf_token: str = Form(...)):
    _require_role(request, "admin")
    _verify_csrf(request, csrf_token)
    try:
        replay_execution_receipt(DB_PATH, receipt_id, actor=_actor(request), reason=reason)
    except KeyError as exc:
        raise HTTPException(404, "실행 영수증을 찾을 수 없습니다.") from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return RedirectResponse(url="/execution-receipts?notice=execution_replayed", status_code=303)

@router.get("/jobs", response_class=HTMLResponse)
def jobs_page(request: Request, status: str = "", job_type: str = "", notice: str = ""):
    return templates.TemplateResponse(
        request=request,
        name="jobs.html",
        context={
            "jobs": list_background_jobs(DB_PATH, status=status, job_type=job_type, limit=500),
            "status": str(status or "").upper(),
            "job_type": str(job_type or "").upper(),
            "notice_message": NOTICE_MESSAGES.get(notice, ""),
        },
    )

@router.post("/jobs/imports/csv")
async def jobs_import_csv(
    request: Request,
    file: UploadFile = File(...),
    scanner_source: str = Form("manual"),
    import_mode: str = Form("incremental"),
    csrf_token: str = Form(...),
):
    _require_role(request, "operator")
    _verify_csrf(request, csrf_token)
    source = _bounded_text(scanner_source, "scanner_source", 120) or "manual"
    mode = str(import_mode or "incremental").strip().lower()
    if mode not in {"incremental", "snapshot"}:
        raise HTTPException(400, "가져오기 방식은 incremental 또는 snapshot이어야 합니다.")
    if not (file.filename or "").lower().endswith(".csv"):
        raise HTTPException(400, "CSV 파일만 지원합니다.")
    content = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, "파일 크기는 최대 5MB입니다.")
    try:
        rows = _parse_findings_csv(content, scanner_source=source, allow_empty=(mode == "snapshot"))
        create_background_job(
            DB_PATH,
            job_type="CSV_IMPORT",
            payload={
                "rows": rows,
                "scanner_source": source,
                "filename": file.filename or "background.csv",
                "reconcile_missing": mode == "snapshot",
            },
            requested_by=_actor(request),
            max_attempts=JOB_MAX_ATTEMPTS,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return RedirectResponse(url="/jobs?notice=job_queued", status_code=303)

@router.post("/jobs/queue/{job_type}")
def jobs_queue(request: Request, job_type: str, csrf_token: str = Form(...)):
    _verify_csrf(request, csrf_token)
    try:
        _enqueue_simple_job(request, job_type)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return RedirectResponse(url="/jobs?notice=job_queued", status_code=303)

@router.post("/jobs/{job_id}/cancel")
def jobs_cancel(request: Request, job_id: str, csrf_token: str = Form(...)):
    _require_role(request, "admin")
    _verify_csrf(request, csrf_token)
    try:
        request_background_job_cancel(DB_PATH, job_id, actor=_actor(request))
    except KeyError as exc:
        raise HTTPException(404, "작업을 찾을 수 없습니다.") from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return RedirectResponse(url="/jobs?notice=job_cancelled", status_code=303)

@router.post("/jobs/{job_id}/retry")
def jobs_retry(request: Request, job_id: str, csrf_token: str = Form(...)):
    _require_role(request, "admin")
    _verify_csrf(request, csrf_token)
    try:
        retry_background_job(DB_PATH, job_id, actor=_actor(request))
    except KeyError as exc:
        raise HTTPException(404, "작업을 찾을 수 없습니다.") from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return RedirectResponse(url="/jobs?notice=job_retried", status_code=303)

@router.post("/reset-demo")
def reset_demo(request: Request, confirmation: str = Form(...), csrf_token: str = Form(...)):
    _require_role(request, "admin")
    _verify_csrf(request, csrf_token)
    if confirmation.strip() != "RESET":
        raise HTTPException(400, "초기화 확인란에 RESET을 입력해야 합니다.")
    try:
        delete_all_findings(DB_PATH, actor=_actor(request))
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    upsert_findings(DB_PATH, _load_sample_rows(SAMPLE_PATH), actor=_actor(request))
    return RedirectResponse(url="/?notice=reset_ok", status_code=303)

@router.get("/imports", response_class=HTMLResponse)
def import_history(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="imports.html",
        context={"batches": list_import_batches(DB_PATH, limit=200)},
    )

@router.get("/api/v1/webhooks")
def api_webhooks(request: Request, status: str = "", limit: int = 200):
    _require_role(request, "admin")
    items = list_webhook_events(DB_PATH, status=status, limit=limit)
    return {"count": len(items), "items": items}

@router.post("/api/v1/webhooks/deliver")
def api_deliver_webhooks(request: Request):
    _require_role(request, "admin")
    _require_api_token(request)
    summary = deliver_due_events(
        DB_PATH, endpoints=WEBHOOK_ENDPOINTS, timeout_seconds=WEBHOOK_TIMEOUT_SECONDS,
        max_attempts=WEBHOOK_MAX_ATTEMPTS, limit=200,
    )
    for outcome, count in summary.items():
        for _ in range(int(count)):
            METRICS.observe_webhook(outcome)
    return summary

@router.get("/api/v1/jobs")
def api_jobs(request: Request, status: str = "", job_type: str = "", limit: int = 200):
    _require_role(request, "viewer")
    items = [_public_job(item) for item in list_background_jobs(DB_PATH, status=status, job_type=job_type, limit=limit)]
    return {"count": len(items), "active": count_active_background_jobs(DB_PATH), "items": items}

@router.get("/api/v1/jobs/{job_id}")
def api_job_detail(request: Request, job_id: str):
    _require_role(request, "viewer")
    item = get_background_job(DB_PATH, job_id)
    if not item:
        raise HTTPException(404, "작업을 찾을 수 없습니다.")
    return _public_job(item)

@router.post("/api/v1/jobs/imports/csv")
async def api_queue_import_job(
    request: Request,
    file: UploadFile = File(...),
    scanner_source: str = "api",
    import_mode: str = "incremental",
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
):
    _require_role(request, "operator")
    _require_api_token(request)
    source = _bounded_text(scanner_source, "scanner_source", 120) or "api"
    mode = str(import_mode or "incremental").strip().lower()
    if mode not in {"incremental", "snapshot"}:
        raise HTTPException(400, "import_mode는 incremental 또는 snapshot이어야 합니다.")
    if not (file.filename or "").lower().endswith(".csv"):
        raise HTTPException(400, "CSV 파일만 지원합니다.")
    content = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, "파일 크기는 최대 5MB입니다.")
    try:
        rows = _parse_findings_csv(content, scanner_source=source)
        return create_background_job(
            DB_PATH,
            job_type="CSV_IMPORT",
            payload={
                "rows": rows,
                "scanner_source": source,
                "filename": file.filename or "api-background.csv",
                "reconcile_missing": mode == "snapshot",
            },
            requested_by=_actor(request),
            max_attempts=JOB_MAX_ATTEMPTS,
            idempotency_key=idempotency_key,
            idempotency_request={
                "job_type": "CSV_IMPORT",
                "content_sha256": hashlib.sha256(content).hexdigest(),
                "scanner_source": source,
                "import_mode": mode,
            },
            idempotency_retention_days=IDEMPOTENCY_RETENTION_DAYS,
        )
    except IdempotencyConflict as exc:
        raise HTTPException(409, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc

@router.post("/api/v1/jobs/queue/{job_type}")
def api_queue_job(
    request: Request, job_type: str,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
):
    _require_api_token(request)
    try:
        return _enqueue_simple_job(
            request, job_type, idempotency_key=idempotency_key
        )
    except IdempotencyConflict as exc:
        raise HTTPException(409, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc

@router.post("/api/v1/jobs/{job_id}/cancel")
def api_cancel_job(request: Request, job_id: str):
    _require_role(request, "admin")
    _require_api_token(request)
    try:
        return request_background_job_cancel(DB_PATH, job_id, actor=_actor(request))
    except KeyError as exc:
        raise HTTPException(404, "작업을 찾을 수 없습니다.") from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc

@router.post("/api/v1/jobs/{job_id}/retry")
def api_retry_job(request: Request, job_id: str):
    _require_role(request, "admin")
    _require_api_token(request)
    try:
        return retry_background_job(DB_PATH, job_id, actor=_actor(request))
    except KeyError as exc:
        raise HTTPException(404, "작업을 찾을 수 없습니다.") from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc

@router.get("/api/v1/execution-receipts")
def api_execution_receipts(request: Request, operation_type: str = "", outcome: str = "", limit: int = 200):
    _require_api_token(request)
    _require_role(request, "admin")
    items = list_execution_receipts(DB_PATH, operation_type=operation_type, outcome=outcome, limit=limit)
    return {"count": len(items), "summary": count_execution_receipts(DB_PATH), "items": items}

@router.get("/api/v1/execution-receipt-archives")
def api_execution_receipt_archives(request: Request, limit: int = 100):
    _require_api_token(request)
    _require_role(request, "admin")
    items = list_execution_receipt_archives(DB_PATH, limit=limit)
    return {"count": len(items), "items": items}

@router.get("/api/v1/execution-receipts/{receipt_id}")
def api_execution_receipt(request: Request, receipt_id: str):
    _require_api_token(request)
    _require_role(request, "admin")
    item = get_execution_receipt(DB_PATH, receipt_id)
    if not item:
        raise HTTPException(404, "실행 영수증을 찾을 수 없습니다.")
    return item

@router.post("/api/v1/execution-receipts/{receipt_id}/replay")
def api_execution_receipt_replay(request: Request, receipt_id: str, body: ApiExecutionReplay):
    _require_api_token(request)
    _require_role(request, "admin")
    try:
        return replay_execution_receipt(DB_PATH, receipt_id, actor=_actor(request), reason=body.reason)
    except KeyError as exc:
        raise HTTPException(404, "실행 영수증을 찾을 수 없습니다.") from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc

@router.get("/api/v1/imports")
def api_imports(limit: int = 100):
    items = list_import_batches(DB_PATH, limit=max(1, min(limit, 1000)))
    return {"count": len(items), "items": items}

@router.get("/api/v1/maintenance-runs")
def api_maintenance_runs(request: Request, limit: int = 100):
    _require_role(request, "admin")
    return {"items": list_maintenance_runs(DB_PATH, limit=limit)}

@router.get("/api/v1/system/database-health")
def api_database_health(request: Request):
    _require_api_token(request)
    _require_role(request, "admin")
    return database_health(DB_PATH)

@router.get("/api/v1/system/database-maintenance-runs")
def api_database_maintenance_runs(request: Request, limit: int = 100):
    _require_api_token(request)
    _require_role(request, "admin")
    return {"items": list_database_maintenance_runs(DB_PATH, limit=limit)}

@router.post("/api/v1/system/database-maintenance")
def api_database_maintenance(request: Request, rebuild_fts_on_mismatch: bool = False):
    _require_api_token(request)
    _require_role(request, "admin")
    with _exclusive_operation("database-maintenance", "SQLite 온라인 유지관리"):
        return run_database_maintenance(
            DB_PATH, actor=_actor(request), truncate_wal=True, optimize_fts=True,
            rebuild_fts_on_mismatch=bool(rebuild_fts_on_mismatch),
        )

@router.get("/cluster", response_class=HTMLResponse)
def cluster_page(request: Request):
    _require_role(request, "admin")
    return templates.TemplateResponse(
        request=request,
        name="cluster.html",
        context={"cluster": _cluster_snapshot()},
    )

@router.get("/api/v1/system/cluster")
def api_cluster_state(request: Request):
    _require_api_token(request)
    _require_role(request, "admin")
    return _cluster_snapshot()

@router.post("/api/v1/system/cluster/prune")
def api_prune_cluster_state(request: Request):
    from datetime import datetime, timedelta, timezone
    _require_api_token(request)
    _require_role(request, "admin")
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=INSTANCE_TTL_SECONDS)).replace(microsecond=0).isoformat()
    pruned = prune_stale_cluster_instances(_coordination_db_path(), stale_before=cutoff)
    return {"pruned": pruned, "cluster": _cluster_snapshot()}

@router.get("/health/live")
def health_live():
    return {"status": "alive", "version": app.version}

@router.get("/health/ready")
def health_ready():
    try:
        count_findings(DB_PATH)
        _policy()
    except Exception as exc:
        raise HTTPException(503, f"not ready: {type(exc).__name__}") from exc
    if CLUSTER_COORDINATION_ENABLED and get_cluster_instance(_coordination_db_path(), INSTANCE_ID) is None:
        raise HTTPException(503, "not ready: cluster registration missing")
    storage = export_storage_status(
        DB_PATH, EXPORT_DIR, quota_bytes=EXPORT_QUOTA_BYTES, reserve_bytes=EXPORT_MIN_FREE_BYTES
    )
    if storage["below_reserve"]:
        raise HTTPException(503, "not ready: export storage reserve exhausted")
    return {
        "status": "ready", "version": app.version, "database": "ready",
        "export_storage": {"managed_bytes": storage["managed_bytes"], "quota_bytes": storage["quota_bytes"], "disk_free_bytes": storage["disk_free_bytes"]},
        "instance_id": INSTANCE_ID,
        "scheduler_role": "leader" if _is_scheduler_leader() else "follower",
    }

@router.get("/health")
def health():
    # Compatibility probe with intentionally minimal information.
    count_findings(DB_PATH)
    return {
        "status": "ok",
        "version": app.version,
        "database": "ready",
        "maintenance_scheduler": "enabled" if MAINTENANCE_INTERVAL_MINUTES > 0 else "disabled",
        "webhook_scheduler": "enabled" if WEBHOOK_ENDPOINTS and WEBHOOK_INTERVAL_SECONDS > 0 else "disabled",
        "job_worker": "enabled" if JOB_WORKER_ENABLED else "disabled",
        "recovery_scheduler": "enabled" if BACKUP_INTERVAL_HOURS > 0 else "disabled",
        "cluster_coordination": "enabled" if CLUSTER_COORDINATION_ENABLED else "disabled",
        "scheduler_role": "leader" if _is_scheduler_leader() else "follower",
    }

@router.get("/metrics")
def metrics(request: Request):
    _require_role(request, "viewer")
    storage = export_storage_status(
        DB_PATH, EXPORT_DIR, quota_bytes=EXPORT_QUOTA_BYTES, reserve_bytes=EXPORT_MIN_FREE_BYTES
    )
    db_health = database_health(DB_PATH, deep_check=False)
    db_runs = list_database_maintenance_runs(DB_PATH, limit=1)
    config_audit = build_config_audit(db_path=DB_PATH, base_dir=BASE_DIR)
    config_drift = evaluate_change_control(DB_PATH, config_audit, evaluate_drift(DB_PATH, config_audit))
    config_changes = change_control_counts(DB_PATH)
    fts_metric = -1
    if db_runs:
        last_after = db_runs[0].get("after") or {}
        if last_after.get("fts_in_sync") is True:
            fts_metric = 1
        elif last_after.get("fts_in_sync") is False:
            fts_metric = 0
    return Response(
        METRICS.render_prometheus(
            finding_count=count_findings(DB_PATH), pending_webhooks=count_pending_webhooks(DB_PATH),
            active_jobs=count_active_background_jobs(DB_PATH),
            cluster_instances=(len([i for i in list_cluster_instances(_coordination_db_path()) if i.get("status") == "ACTIVE"]) if CLUSTER_COORDINATION_ENABLED else 1),
            scheduler_leader=1 if _is_scheduler_leader() else 0,
            export_storage_bytes=storage["managed_bytes"],
            export_storage_quota_bytes=EXPORT_QUOTA_BYTES,
            export_storage_pinned=storage["pinned_count"],
            export_storage_pressure=int(storage["pressure"]),
            database_bytes=db_health["database_bytes"],
            database_wal_bytes=db_health["wal_bytes"],
            database_reclaimable_bytes=db_health["reclaimable_bytes"],
            database_fts_in_sync=fts_metric,
            config_baseline_present=1 if config_drift["status"] != "NO_BASELINE" else 0,
            config_drift_changes=config_drift["change_count"],
            config_change_pending=config_changes.get("pending", 0),
            config_change_approved=config_changes.get("approved", 0),
            idempotency_records=count_idempotency_records(DB_PATH),
            execution_receipts=count_execution_receipts(DB_PATH)["total"],
            execution_dead_letters=count_execution_receipts(DB_PATH)["dead_letters"],
            execution_receipts_archived=count_execution_receipts(DB_PATH)["archived"],
        ),
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )
