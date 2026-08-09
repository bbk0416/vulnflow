from __future__ import annotations

"""Project fan-out for scheduled maintenance, webhook, and recovery jobs."""

from contextlib import nullcontext
import time
from typing import Any, Literal

from app.core.context import ApplicationContext
from app.core.project_scope import ProjectSelection, project_scope
from app.services.operation_guard import bind_operation_guard
from app.services.project_runtime import application_project_selections, project_is_read_only

ScheduledKind = Literal["maintenance", "webhook", "backup", "collaboration"]


def _service(context: ApplicationContext, name: str) -> Any:
    assert context.services is not None
    return context.services.require(name)


def _maintenance_job(context: ApplicationContext, *, now: float | None) -> dict[str, Any]:
    interval = max(60, int(context.get("MAINTENANCE_INTERVAL_MINUTES")) * 60)
    bucket = int((time.time() if now is None else now) // interval)
    settings_function = _service(context, "_maintenance_settings")
    try:
        settings = settings_function(context=context)
    except TypeError:
        settings = settings_function()
    return _service(context, "create_background_job")(
        context.get("DB_PATH"), job_type="MAINTENANCE", payload={"settings": settings},
        requested_by="system-scheduler", priority=5,
        max_attempts=int(context.get("JOB_MAX_ATTEMPTS")),
        dedupe_key=f"scheduled-maintenance:{bucket}",
    )


def _webhook_job(context: ApplicationContext, *, now: float | None) -> dict[str, Any] | None:
    if _service(context, "count_pending_webhooks")(context.get("DB_PATH")) <= 0:
        return None
    interval = max(1, int(context.get("WEBHOOK_INTERVAL_SECONDS")))
    bucket = int((time.time() if now is None else now) // interval)
    return _service(context, "create_background_job")(
        context.get("DB_PATH"), job_type="WEBHOOK_DELIVERY", payload={},
        requested_by="system-scheduler", priority=10,
        max_attempts=int(context.get("JOB_MAX_ATTEMPTS")),
        dedupe_key=f"scheduled-webhook:{bucket}",
    )


def _collaboration_job(context: ApplicationContext, *, now: float | None) -> dict[str, Any] | None:
    if len(str(context.get("INTEGRATION_SECRET_KEY", "") or "")) < 32:
        return None
    pending = _service(context, "count_pending_collaboration_events")(context.get("DB_PATH"))
    interval = max(5, int(context.get("COLLABORATION_INTERVAL_SECONDS", 30)))
    bucket = int((time.time() if now is None else now) // interval)
    return _service(context, "create_background_job")(
        context.get("DB_PATH"), job_type="COLLABORATION_DELIVERY", payload={"scan_due": True},
        requested_by="system-scheduler", priority=10,
        max_attempts=int(context.get("JOB_MAX_ATTEMPTS")),
        dedupe_key=f"scheduled-collaboration:{bucket}:{1 if pending else 0}",
    )


def _backup_job(context: ApplicationContext, *, now: float | None) -> dict[str, Any]:
    interval = max(3600, int(context.get("BACKUP_INTERVAL_HOURS")) * 3600)
    bucket = int((time.time() if now is None else now) // interval)
    return _service(context, "create_background_job")(
        context.get("DB_PATH"), job_type="RECOVERY_BACKUP", payload={},
        requested_by="system-scheduler", priority=8,
        max_attempts=int(context.get("JOB_MAX_ATTEMPTS")),
        dedupe_key=f"scheduled-recovery:{bucket}",
    )


def _produce(
    context: ApplicationContext, kind: ScheduledKind, *, now: float | None
) -> dict[str, Any] | None:
    if bind_operation_guard(context).restore_in_progress():
        return None
    if kind == "maintenance":
        return _maintenance_job(context, now=now)
    if kind == "webhook":
        return _webhook_job(context, now=now)
    if kind == "collaboration":
        return _collaboration_job(context, now=now)
    return _backup_job(context, now=now)


def schedule_current_project(
    context: ApplicationContext,
    kind: ScheduledKind,
    *,
    now: float | None = None,
    scheduler_leader: bool,
) -> dict[str, Any] | None:
    if not scheduler_leader:
        return None
    return _produce(context, kind, now=now)


def schedule_all_projects(
    context: ApplicationContext,
    kind: ScheduledKind,
    *,
    now: float | None = None,
    scheduler_leader: bool,
) -> dict[str, Any]:
    if not scheduler_leader:
        return {"scheduled": [], "skipped": [], "failed": []}
    scheduled: list[dict[str, Any]] = []
    skipped: list[str] = []
    failed: list[dict[str, str]] = []
    for selection in application_project_selections(context):
        project_id = selection.project_id if isinstance(selection, ProjectSelection) else "default"
        if project_is_read_only(context, selection):
            skipped.append(project_id)
            continue
        scope = project_scope(selection) if isinstance(selection, ProjectSelection) else nullcontext()
        try:
            with scope:
                job = _produce(context, kind, now=now)
            if job is not None:
                scheduled.append({"project_id": project_id, "job": job})
        except Exception as exc:
            context.logger.exception(
                "scheduled project job production failed",
                extra={"project_id": project_id, "scheduled_kind": kind},
            )
            failed.append({"project_id": project_id, "error_type": type(exc).__name__})
    return {"scheduled": scheduled, "skipped": skipped, "failed": failed}
