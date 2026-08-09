from __future__ import annotations

"""Context-bound background job dispatch and handler execution.

This module never imports ``app.main``. Every setting and service dependency is
resolved from the owning :class:`ApplicationContext`, so additional app
instances and worker processes cannot silently fall back to the default app's
runtime namespace.
"""

import inspect
from typing import Any, Callable

from app.core.context import ApplicationContext
from app.core.project_scope import active_project
from app.core.transactions import context_transaction_scope


def _service(context: ApplicationContext, name: str) -> Any:
    assert context.services is not None
    return context.services.require(name)


def _setting(context: ApplicationContext, name: str, default: Any = None) -> Any:
    return context.get(name, default)


def _call_context_aware(function: Callable[..., Any], *args: Any, context: ApplicationContext, **kwargs: Any) -> Any:
    """Pass context only when the compatibility callable supports it."""
    try:
        parameters = inspect.signature(function).parameters
    except (TypeError, ValueError):
        parameters = {}
    if "context" in parameters:
        kwargs["context"] = context
    return function(*args, **kwargs)


@context_transaction_scope
def execute_background_job(
    context: ApplicationContext,
    job: dict[str, Any],
    *,
    worker_id: str,
) -> dict[str, Any]:
    db_path = _setting(context, "DB_PATH")
    job_id = str(job["job_id"])
    job_type = str(job["job_type"])
    payload = dict(job.get("payload") or {})
    actor = str(job.get("requested_by") or worker_id)
    lease_seconds = int(_setting(context, "JOB_LEASE_SECONDS"))

    heartbeat = _service(context, "heartbeat_background_job")
    heartbeat(
        db_path,
        job_id=job_id,
        worker_id=worker_id,
        lease_seconds=lease_seconds,
        progress_current=0,
        progress_total=1,
        progress_message="작업 실행 중",
    )

    queue_webhook = _service(context, "_queue_webhook")
    rescore_all = _service(context, "rescore_all")

    if job_type == "CSV_IMPORT":
        rows = payload.get("rows") or []
        if not isinstance(rows, list) or (not rows and not bool(payload.get("reconcile_missing"))):
            raise ValueError("증분 CSV_IMPORT 작업에 rows가 없습니다.")
        result = _service(context, "apply_import_batch")(
            db_path,
            rows,
            scanner_source=str(payload.get("scanner_source") or "job"),
            filename=str(payload.get("filename") or "background.csv"),
            reconcile_missing=bool(payload.get("reconcile_missing")),
            actor=actor,
            source_job_id=job_id,
            verification_absence_threshold=int(_setting(context, "VERIFICATION_ABSENCE_SCANS")),
        )
        _call_context_aware(queue_webhook, "import.completed", result, actor, context=context)
    elif job_type == "INTEL_REFRESH":
        result = _call_context_aware(
            _service(context, "_refresh_intelligence_operation"), actor=actor, context=context
        )
    elif job_type == "RESCORE_ALL":
        result = {"rescored": _call_context_aware(rescore_all, actor=actor, context=context)}
    elif job_type == "MAINTENANCE":
        settings = dict(
            payload.get("settings")
            or _call_context_aware(_service(context, "_maintenance_settings"), context=context)
        )
        result = _service(context, "run_maintenance")(db_path, actor=actor, **settings)
        result["rescored"] = _call_context_aware(rescore_all, audit=False, actor=actor, context=context)
        result["purged_jobs"] = _call_context_aware(
            _service(context, "_purge_completed_jobs"), context=context
        )
        export_dir = _setting(context, "EXPORT_DIR")
        result.update(_service(context, "purge_expired_export_artifacts")(db_path, export_dir, actor=actor))
        result.update(
            _service(context, "enforce_export_storage_budget")(
                db_path,
                export_dir,
                quota_bytes=int(_setting(context, "EXPORT_QUOTA_BYTES")),
                reserve_bytes=int(_setting(context, "EXPORT_MIN_FREE_BYTES")),
                actor=actor,
            )
        )
        _call_context_aware(queue_webhook, "maintenance.completed", result, actor, context=context)
    elif job_type == "WEBHOOK_DELIVERY":
        result = _service(context, "deliver_due_events")(
            db_path,
            endpoints=dict(_setting(context, "WEBHOOK_ENDPOINTS", {}) or {}),
            timeout_seconds=int(_setting(context, "WEBHOOK_TIMEOUT_SECONDS")),
            max_attempts=int(_setting(context, "WEBHOOK_MAX_ATTEMPTS")),
            allow_private_networks=bool(_setting(context, "OUTBOUND_ALLOW_PRIVATE_NETWORKS", False)),
            host_allowlist=str(_setting(context, "OUTBOUND_HOST_ALLOWLIST", "") or ""),
            max_response_bytes=int(_setting(context, "OUTBOUND_MAX_RESPONSE_BYTES", 1024 * 1024)),
        )
        for outcome, count in result.items():
            for _ in range(int(count)):
                context.metrics.observe_webhook(outcome)
    elif job_type == "COLLABORATION_DELIVERY":
        master_key = str(_setting(context, "INTEGRATION_SECRET_KEY", "") or "")
        if len(master_key) < 32:
            raise ValueError("VULNFLOW_INTEGRATION_SECRET_KEY는 최소 32자여야 합니다.")
        result = _service(context, "deliver_collaboration_events")(
            db_path,
            master_key=master_key,
            timeout_seconds=int(_setting(context, "COLLABORATION_TIMEOUT_SECONDS", 10)),
            max_attempts=int(_setting(context, "COLLABORATION_MAX_ATTEMPTS", 5)),
            due_soon_days=int(_setting(context, "COLLABORATION_DUE_SOON_DAYS", 3)),
            allow_private_networks=bool(_setting(context, "OUTBOUND_ALLOW_PRIVATE_NETWORKS", False)),
            host_allowlist=str(_setting(context, "OUTBOUND_HOST_ALLOWLIST", "") or ""),
            max_response_bytes=int(_setting(context, "OUTBOUND_MAX_RESPONSE_BYTES", 1024 * 1024)),
            smtp_allow_private_networks=bool(_setting(context, "SMTP_ALLOW_PRIVATE_NETWORKS", False)),
            smtp_host_allowlist=str(_setting(context, "SMTP_HOST_ALLOWLIST", "") or ""),
            smtp_allow_plain=bool(_setting(context, "SMTP_ALLOW_PLAIN", False)),
        )
    elif job_type == "EVIDENCE_SCAN":
        evidence_id = str(payload.get("evidence_id") or "").strip()
        if not evidence_id:
            raise ValueError("EVIDENCE_SCAN 작업에 evidence_id가 없습니다.")
        result = _service(context, "scan_evidence_artifact")(
            db_path,
            _setting(context, "EVIDENCE_DIR"),
            evidence_id,
            mode=str(_setting(context, "EVIDENCE_SCANNER_MODE")),
            clamscan_path=str(_setting(context, "EVIDENCE_CLAMSCAN_PATH")),
            timeout_seconds=int(_setting(context, "EVIDENCE_SCAN_TIMEOUT_SECONDS")),
            actor=actor,
        )
        _call_context_aware(
            queue_webhook,
            "remediation.evidence_scanned",
            {
                "evidence_id": evidence_id,
                "finding_id": result.get("finding_id"),
                "verification_id": result.get("verification_id"),
                "scan_status": result.get("scan_status"),
            },
            actor,
            context=context,
        )
    elif job_type == "OSV_SCAN":
        sbom_id = str(payload.get("sbom_id") or "").strip()
        if not sbom_id:
            raise ValueError("OSV_SCAN 작업에 sbom_id가 없습니다.")
        result = _service(context, "run_osv_scan")(
            str(db_path),
            sbom_id,
            actor=actor,
            api_base=str(_setting(context, "OSV_API_BASE")),
            timeout=int(_setting(context, "OSV_TIMEOUT_SECONDS")),
            retries=int(_setting(context, "OSV_RETRIES")),
            batch_size=int(_setting(context, "OSV_BATCH_SIZE")),
            source_job_id=job_id,
            allow_private_networks=bool(_setting(context, "OUTBOUND_ALLOW_PRIVATE_NETWORKS", False)),
            host_allowlist=str(_setting(context, "OUTBOUND_HOST_ALLOWLIST", "") or ""),
            max_response_bytes=int(_setting(context, "OSV_MAX_RESPONSE_BYTES", 4 * 1024 * 1024)),
        )
        _call_context_aware(
            queue_webhook,
            "sbom.osv_scan_completed",
            {
                "sbom_id": sbom_id,
                "scan_id": result.get("scan_id"),
                "matches": result.get("vulnerability_matches", 0),
                "new_candidates": result.get("new_candidates", 0),
            },
            actor,
            context=context,
        )
    elif job_type == "DATABASE_MAINTENANCE":
        result = _service(context, "run_database_maintenance")(
            db_path,
            actor=actor,
            truncate_wal=bool(payload.get("truncate_wal", True)),
            optimize_fts=bool(payload.get("optimize_fts", True)),
            rebuild_fts_on_mismatch=bool(payload.get("rebuild_fts_on_mismatch", False)),
        )
        _call_context_aware(
            queue_webhook,
            "database.maintenance_completed",
            {
                "run_id": result.get("run_id"),
                "status": result.get("status"),
                "wal_before": (result.get("before") or {}).get("wal_bytes"),
                "wal_after": (result.get("after") or {}).get("wal_bytes"),
                "fts_in_sync": (result.get("after") or {}).get("fts_in_sync"),
            },
            actor,
            context=context,
        )
    elif job_type == "FINDINGS_EXPORT":
        filters = dict(payload.get("filters") or {})

        def export_heartbeat(current: int, total: int, message: str) -> None:
            heartbeat(
                db_path,
                job_id=job_id,
                worker_id=worker_id,
                lease_seconds=lease_seconds,
                progress_current=current,
                progress_total=max(total, current),
                progress_message=message,
            )

        def export_cancelled() -> bool:
            current = _service(context, "get_background_job")(db_path, job_id) or {}
            return bool(current.get("cancel_requested"))

        result = _service(context, "create_findings_csv_export")(
            db_path,
            _setting(context, "EXPORT_DIR"),
            filters=filters,
            actor=actor,
            job_id=job_id,
            retention_days=int(_setting(context, "EXPORT_RETENTION_DAYS")),
            quota_bytes=int(_setting(context, "EXPORT_QUOTA_BYTES")),
            reserve_bytes=int(_setting(context, "EXPORT_MIN_FREE_BYTES")),
            heartbeat=export_heartbeat,
            cancel_check=export_cancelled,
        )
        _call_context_aware(
            queue_webhook,
            "export.findings_ready",
            {
                "artifact_id": result.get("artifact_id"),
                "row_count": result.get("row_count"),
                "size_bytes": result.get("size_bytes"),
                "sha256": result.get("sha256"),
                "expires_at": result.get("expires_at"),
            },
            actor,
            context=context,
        )
    elif job_type == "RECOVERY_BACKUP":
        signing, backup_key_id, backup_key = _call_context_aware(
            _service(context, "_backup_signing"), context=context
        )
        selection = active_project()
        project_id = selection.project_id if selection is not None else "default"
        project_name = selection.name if selection is not None else "기본 프로젝트"
        result = _service(context, "create_scheduled_recovery_bundle")(
            db_path,
            _setting(context, "RECOVERY_DIR"),
            signing_key=backup_key,
            signing_key_id=backup_key_id,
            signing_keys=signing.keys,
            audit_signing_keys=signing.keys,
            retention_count=int(_setting(context, "BACKUP_RETENTION_COUNT")),
            actor=actor,
            base_dir=_setting(context, "BASE_DIR"),
            evidence_dir=_setting(context, "EVIDENCE_DIR"),
            project_id=project_id,
            project_name=project_name,
        )
        external = _service(context, "mirror_recovery_bundle")(
            result["bundle_path"],
            external_root=_setting(context, "EXTERNAL_BACKUP_DIR"),
            project_id=project_id,
            retention_count=int(_setting(context, "EXTERNAL_BACKUP_RETENTION_COUNT", 30)),
        )
        result["external_backup"] = external
        webhook_result = {k: v for k, v in result.items() if k not in {"bundle_path"}}
        if isinstance(webhook_result.get("external_backup"), dict):
            webhook_result["external_backup"] = {
                key: value
                for key, value in webhook_result["external_backup"].items()
                if key != "bundle_path"
            }
        _call_context_aware(
            queue_webhook,
            "recovery.bundle_created",
            webhook_result,
            actor,
            context=context,
        )
    else:
        raise ValueError(f"지원하지 않는 작업 유형입니다: {job_type}")

    heartbeat(
        db_path,
        job_id=job_id,
        worker_id=worker_id,
        lease_seconds=lease_seconds,
        progress_current=1,
        progress_total=1,
        progress_message="결과 저장 중",
    )
    return result
