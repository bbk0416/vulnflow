from __future__ import annotations

"""Non-secret structural diagnostics for an application context."""

from typing import Any

_DEFAULT_LIFECYCLE = {
    "state": "NEW",
    "task_count": 0,
    "running_task_count": 0,
    "shutdown_timed_out": False,
}
_DEFAULT_TRANSACTIONS = {"database_count": 0, "read_count": 0, "write_count": 0}


def application_runtime_snapshot(context: "ApplicationContext") -> dict[str, Any]:
    """Return names, counts, and lifecycle state without dependency values."""
    assert context.settings is not None and context.services is not None
    settings = context.settings.structural_snapshot()
    services = context.services.structural_snapshot()
    lifecycle = (
        context.lifecycle_resources.snapshot()
        if context.lifecycle_resources is not None
        else dict(_DEFAULT_LIFECYCLE)
    )
    transactions = (
        context.transaction_registry.structural_snapshot()
        if context.transaction_registry is not None
        else dict(_DEFAULT_TRANSACTIONS)
    )
    return {
        "created_at": context.created_at,
        **settings,
        "service_count": services["service_count"],
        "route_export_count": len(context.route_exports),
        "legacy_override_count": len(context.mutable_dependency_overrides()),
        "transaction_database_count": transactions["database_count"],
        "transaction_read_count": transactions["read_count"],
        "transaction_write_count": transactions["write_count"],
        "lifecycle_state": lifecycle.get("state", "NEW"),
        "lifecycle_task_count": int(lifecycle.get("task_count", 0)),
        "lifecycle_running_task_count": int(lifecycle.get("running_task_count", 0)),
        "lifecycle_shutdown_timed_out": bool(lifecycle.get("shutdown_timed_out", False)),
    }
