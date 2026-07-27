from __future__ import annotations

"""Context-bound scheduler and cluster lifecycle orchestration."""

import asyncio
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
import os
import socket
import time
from typing import Any

from app.core.context import ApplicationContext
from app.core.transactions import context_transaction_scope
from app.services.cluster_leadership import verify_scheduler_leadership
from app.services.job_worker_runtime import job_worker_loop
from app.services.operation_guard import bind_operation_guard
from app.services.lifecycle_resources import LifecycleResourceTracker


def _service(context: ApplicationContext, name: str) -> Any:
    assert context.services is not None
    return context.services.require(name)


def coordination_db_path(context: ApplicationContext) -> Path:
    configured = str(context.get("COORDINATION_DB_ENV", "") or "").strip()
    if configured:
        return Path(configured)
    db_path = Path(context.get("DB_PATH"))
    return db_path.with_name(f"{db_path.stem}-coordination.db")


def instance_capabilities(context: ApplicationContext) -> list[str]:
    capabilities = ["api"]
    if bool(context.get("JOB_WORKER_ENABLED")):
        capabilities.append("worker")
    endpoints = dict(context.get("WEBHOOK_ENDPOINTS", {}) or {})
    if any(
        [
            int(context.get("MAINTENANCE_INTERVAL_MINUTES")) > 0,
            bool(endpoints and int(context.get("WEBHOOK_INTERVAL_SECONDS")) > 0),
            int(context.get("BACKUP_INTERVAL_HOURS")) > 0,
        ]
    ):
        capabilities.append("scheduler")
    return capabilities


@context_transaction_scope
def cluster_snapshot(context: ApplicationContext) -> dict[str, Any]:
    enabled = bool(context.get("CLUSTER_COORDINATION_ENABLED"))
    coord = coordination_db_path(context)
    active_lease: dict[str, Any] | None = None
    if enabled:
        instances = _service(context, "list_cluster_instances")(coord)
        leases = _service(context, "list_cluster_leases")(coord)
        write_activities = _service(context, "list_cluster_write_activities")(coord)
        active_lease = _service(context, "active_cluster_lease")(
            coord, str(context.get("SCHEDULER_LEASE_NAME"))
        )
        is_leader = verify_scheduler_leadership(context, active_lease=active_lease)
    else:
        instances, leases, write_activities = [], [], []
        is_leader = False
    return {
        "coordination_enabled": enabled,
        "instance_id": str(context.get("INSTANCE_ID")),
        "is_scheduler_leader": is_leader,
        "scheduler_fencing_token": (
            int(active_lease["fencing_token"]) if is_leader and active_lease else None
        ),
        "scheduler_lease_holder_id": (
            str(active_lease.get("holder_id") or "") if active_lease else None
        ),
        "scheduler_lease_fencing_token": (
            int(active_lease["fencing_token"]) if active_lease else None
        ),
        "scheduler_lease_expires_at": (
            str(active_lease.get("lease_expires_at") or "") if active_lease else None
        ),
        "instances": instances,
        "leases": leases,
        "write_activities": write_activities,
    }


@context_transaction_scope
def coordination_tick(context: ApplicationContext) -> dict[str, Any]:
    coord = coordination_db_path(context)
    stale_before = (
        datetime.now(timezone.utc)
        - timedelta(seconds=int(context.get("INSTANCE_TTL_SECONDS")))
    ).replace(microsecond=0).isoformat()
    _service(context, "prune_stale_cluster_instances")(coord, stale_before=stale_before)
    _service(context, "register_cluster_instance")(
        coord,
        instance_id=str(context.get("INSTANCE_ID")),
        hostname=socket.gethostname(),
        process_id=os.getpid(),
        app_version=str(context.get("CURRENT_APP_VERSION")),
        capabilities=instance_capabilities(context),
        metadata={"worker_enabled": bool(context.get("JOB_WORKER_ENABLED"))},
    )
    _service(context, "prune_stale_cluster_write_activities")(coord)
    lease = _service(context, "acquire_cluster_lease")(
        coord,
        lease_name=str(context.get("SCHEDULER_LEASE_NAME")),
        holder_id=str(context.get("INSTANCE_ID")),
        ttl_seconds=int(context.get("SCHEDULER_LEASE_SECONDS")),
        purpose="singleton scheduled job producer",
    )
    context.coordination_state["is_leader"] = bool(lease)
    context.coordination_state["scheduler_token"] = int(lease["fencing_token"]) if lease else None
    context.coordination_state["last_heartbeat"] = _service(context, "utc_now")()
    return cluster_snapshot(context)


@context_transaction_scope
def is_scheduler_leader(context: ApplicationContext) -> bool:
    if not bool(context.get("CLUSTER_COORDINATION_ENABLED")):
        return True
    coord = coordination_db_path(context)
    try:
        active_lease = _service(context, "active_cluster_lease")(
            coord, str(context.get("SCHEDULER_LEASE_NAME"))
        )
    except Exception:
        context.coordination_state["is_leader"] = False
        context.coordination_state["scheduler_token"] = None
        return False
    return verify_scheduler_leadership(context, active_lease=active_lease)


def restore_in_progress(context: ApplicationContext) -> bool:
    return bind_operation_guard(context).restore_in_progress()




@context_transaction_scope
def schedule_maintenance(context: ApplicationContext, *, now: float | None = None) -> dict[str, Any] | None:
    if not is_scheduler_leader(context) or restore_in_progress(context):
        return None
    interval = max(60, int(context.get("MAINTENANCE_INTERVAL_MINUTES")) * 60)
    bucket = int((time.time() if now is None else now) // interval)
    settings_function = _service(context, "_maintenance_settings")
    try:
        settings = settings_function(context=context)
    except TypeError:
        settings = settings_function()
    return _service(context, "create_background_job")(
        context.get("DB_PATH"),
        job_type="MAINTENANCE",
        payload={"settings": settings},
        requested_by="system-scheduler",
        priority=5,
        max_attempts=int(context.get("JOB_MAX_ATTEMPTS")),
        dedupe_key=f"scheduled-maintenance:{bucket}",
    )


@context_transaction_scope
def schedule_webhook_delivery(context: ApplicationContext, *, now: float | None = None) -> dict[str, Any] | None:
    if not is_scheduler_leader(context) or restore_in_progress(context):
        return None
    if _service(context, "count_pending_webhooks")(context.get("DB_PATH")) <= 0:
        return None
    interval = max(1, int(context.get("WEBHOOK_INTERVAL_SECONDS")))
    bucket = int((time.time() if now is None else now) // interval)
    return _service(context, "create_background_job")(
        context.get("DB_PATH"),
        job_type="WEBHOOK_DELIVERY",
        payload={},
        requested_by="system-scheduler",
        priority=10,
        max_attempts=int(context.get("JOB_MAX_ATTEMPTS")),
        dedupe_key=f"scheduled-webhook:{bucket}",
    )


@context_transaction_scope
def schedule_recovery_backup(context: ApplicationContext, *, now: float | None = None) -> dict[str, Any] | None:
    if not is_scheduler_leader(context) or restore_in_progress(context):
        return None
    interval = max(3600, int(context.get("BACKUP_INTERVAL_HOURS")) * 3600)
    bucket = int((time.time() if now is None else now) // interval)
    return _service(context, "create_background_job")(
        context.get("DB_PATH"),
        job_type="RECOVERY_BACKUP",
        payload={},
        requested_by="system-scheduler",
        priority=8,
        max_attempts=int(context.get("JOB_MAX_ATTEMPTS")),
        dedupe_key=f"scheduled-recovery:{bucket}",
    )

@context_transaction_scope
async def coordination_loop(
    context: ApplicationContext,
    *,
    tracker: LifecycleResourceTracker | None = None,
) -> None:
    interval = int(context.get("INSTANCE_HEARTBEAT_SECONDS"))
    while True:
        if tracker is not None and tracker.stop_event.is_set():
            return
        try:
            await asyncio.to_thread(coordination_tick, context)
        except asyncio.CancelledError:
            raise
        except Exception:
            context.coordination_state["is_leader"] = False
            context.logger.exception("cluster coordination heartbeat failed")
        if tracker is not None:
            if await tracker.wait_or_stop(interval):
                return
        else:
            await asyncio.sleep(interval)


@context_transaction_scope
async def maintenance_loop(
    context: ApplicationContext,
    *,
    tracker: LifecycleResourceTracker | None = None,
) -> None:
    interval = max(60, int(context.get("MAINTENANCE_INTERVAL_MINUTES")) * 60)
    while True:
        if tracker is not None:
            if await tracker.wait_or_stop(interval):
                return
        else:
            await asyncio.sleep(interval)
        try:
            await asyncio.to_thread(schedule_maintenance, context)
        except asyncio.CancelledError:
            raise
        except Exception:
            context.logger.exception("maintenance scheduling failed")


@context_transaction_scope
async def webhook_loop(
    context: ApplicationContext,
    *,
    tracker: LifecycleResourceTracker | None = None,
) -> None:
    interval = max(1, int(context.get("WEBHOOK_INTERVAL_SECONDS")))
    while True:
        if tracker is not None:
            if await tracker.wait_or_stop(interval):
                return
        else:
            await asyncio.sleep(interval)
        try:
            await asyncio.to_thread(schedule_webhook_delivery, context)
        except asyncio.CancelledError:
            raise
        except Exception:
            context.logger.exception("webhook scheduling failed")


@context_transaction_scope
async def backup_loop(
    context: ApplicationContext,
    *,
    tracker: LifecycleResourceTracker | None = None,
) -> None:
    interval = max(3600, int(context.get("BACKUP_INTERVAL_HOURS")) * 3600)
    while True:
        if tracker is not None:
            if await tracker.wait_or_stop(interval):
                return
        else:
            await asyncio.sleep(interval)
        try:
            await asyncio.to_thread(schedule_recovery_backup, context)
        except asyncio.CancelledError:
            raise
        except Exception:
            context.logger.exception("recovery backup scheduling failed")


@dataclass(slots=True)
class LifecycleSupervisor:
    context: ApplicationContext
    tracker: LifecycleResourceTracker | None = None

    @property
    def tasks(self) -> list[asyncio.Task[Any]]:
        if self.tracker is None:
            return []
        return list(self.tracker.tasks.values())

    def snapshot(self) -> dict[str, Any]:
        if self.tracker is None:
            return {
                "state": "NEW",
                "task_count": 0,
                "running_task_count": 0,
                "shutdown_timed_out": False,
            }
        return self.tracker.snapshot()

    def start(self) -> None:
        if self.tracker is not None and self.tracker.state == "RUNNING":
            return
        context = self.context
        tracker = LifecycleResourceTracker(
            runtime_id=str(context.router_runtime_id or context.get("INSTANCE_ID") or "default"),
            shutdown_timeout_seconds=float(
                context.get("LIFECYCLE_SHUTDOWN_TIMEOUT_SECONDS", 5.0)
            ),
        )
        tracker.start()
        self.tracker = tracker
        context.lifecycle_resources = tracker

        if bool(context.get("CLUSTER_COORDINATION_ENABLED")):
            coordination_tick(context)
            tracker.create_task("coordination", coordination_loop(context, tracker=tracker))
        else:
            context.coordination_state["is_leader"] = True
        if bool(context.get("JOB_WORKER_ENABLED")):
            tracker.create_task(
                "job-worker",
                job_worker_loop(context, stop_event=tracker.stop_event),
            )
        if int(context.get("MAINTENANCE_INTERVAL_MINUTES")) > 0:
            tracker.create_task("maintenance", maintenance_loop(context, tracker=tracker))
        endpoints = dict(context.get("WEBHOOK_ENDPOINTS", {}) or {})
        if endpoints and int(context.get("WEBHOOK_INTERVAL_SECONDS")) > 0:
            tracker.create_task("webhook", webhook_loop(context, tracker=tracker))
        if int(context.get("BACKUP_INTERVAL_HOURS")) > 0:
            tracker.create_task("backup", backup_loop(context, tracker=tracker))

    async def stop(self) -> dict[str, Any]:
        tracker = self.tracker
        if tracker is None:
            return self.snapshot()
        snapshot = await tracker.stop()
        context = self.context
        try:
            if bool(context.get("CLUSTER_COORDINATION_ENABLED")):
                token = context.coordination_state.get("scheduler_token")
                coord = coordination_db_path(context)
                if token is not None:
                    try:
                        _service(context, "release_cluster_lease")(
                            coord,
                            lease_name=str(context.get("SCHEDULER_LEASE_NAME")),
                            holder_id=str(context.get("INSTANCE_ID")),
                            fencing_token=int(token),
                        )
                    except Exception:
                        context.logger.exception("scheduler lease release failed")
                try:
                    _service(context, "deregister_cluster_instance")(
                        coord, instance_id=str(context.get("INSTANCE_ID"))
                    )
                except Exception:
                    context.logger.exception("cluster instance deregistration failed")
        finally:
            context.coordination_state["is_leader"] = False
            context.coordination_state["scheduler_token"] = None
            context.set("LIFECYCLE_SHUTDOWN_SNAPSHOT", snapshot)
        return snapshot
