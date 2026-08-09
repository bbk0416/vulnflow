from __future__ import annotations

"""Runtime application service exports."""

from app.service_registry.common import export_namespace
from app.services.job_dispatch import execute_background_job as execute_background_job_for_context
from app.services.job_worker_runtime import job_worker_loop as context_job_worker_loop
from app.services.lifecycle_runtime import (
    LifecycleSupervisor,
    backup_loop as context_backup_loop,
    cluster_snapshot as context_cluster_snapshot,
    coordination_db_path as context_coordination_db_path,
    coordination_loop as context_coordination_loop,
    coordination_tick as context_coordination_tick,
    instance_capabilities as context_instance_capabilities,
    is_scheduler_leader as context_is_scheduler_leader,
    maintenance_loop as context_maintenance_loop,
    restore_in_progress as context_restore_in_progress,
    webhook_loop as context_webhook_loop,
)
from app.services.operation_guard import (
    WriteBarrierActive,
    bind_operation_guard,
)
from app.core.transactions import transaction_scope

SERVICE_NAMES = (
    'execute_background_job_for_context',
    'context_job_worker_loop',
    'LifecycleSupervisor',
    'context_backup_loop',
    'context_cluster_snapshot',
    'context_coordination_db_path',
    'context_coordination_loop',
    'context_coordination_tick',
    'context_instance_capabilities',
    'context_is_scheduler_leader',
    'context_maintenance_loop',
    'context_restore_in_progress',
    'context_webhook_loop',
    'WriteBarrierActive',
    'bind_operation_guard',
    'transaction_scope',
)
SERVICE_EXPORTS = export_namespace(globals(), SERVICE_NAMES)

__all__ = ["SERVICE_EXPORTS", "SERVICE_NAMES"]
