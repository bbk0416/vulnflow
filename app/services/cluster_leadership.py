from __future__ import annotations

"""Authoritative fenced scheduler-leadership validation."""

from typing import Any

from app.core.context import ApplicationContext


def verify_scheduler_leadership(
    context: ApplicationContext,
    *,
    active_lease: dict[str, Any] | None,
) -> bool:
    """Fail closed unless cached leadership matches the active fenced lease."""
    local_token = context.coordination_state.get("scheduler_token")
    verified = bool(
        context.coordination_state.get("is_leader")
        and active_lease
        and str(active_lease.get("holder_id") or "") == str(context.get("INSTANCE_ID"))
        and local_token is not None
        and int(active_lease.get("fencing_token") or 0) == int(local_token)
    )
    if not verified:
        context.coordination_state["is_leader"] = False
        context.coordination_state["scheduler_token"] = None
    return verified
