from __future__ import annotations

"""Scheduled collaboration delivery across isolated projects."""

import asyncio
from typing import Any, Callable

from app.core.context import ApplicationContext
from app.core.transactions import context_transaction_scope
from app.services.lifecycle_resources import LifecycleResourceTracker
from app.services.scheduled_project_jobs import schedule_all_projects


@context_transaction_scope
def schedule_all_project_collaboration(
    context: ApplicationContext, *, scheduler_leader: bool, now: float | None = None
) -> dict[str, Any]:
    return schedule_all_projects(
        context, "collaboration", now=now, scheduler_leader=bool(scheduler_leader)
    )


@context_transaction_scope
async def collaboration_loop(
    context: ApplicationContext,
    *,
    tracker: LifecycleResourceTracker | None = None,
    leader_check: Callable[[ApplicationContext], bool],
) -> None:
    interval = max(5, int(context.get("COLLABORATION_INTERVAL_SECONDS", 30)))
    while True:
        if tracker is not None:
            if await tracker.wait_or_stop(interval):
                return
        else:
            await asyncio.sleep(interval)
        try:
            await asyncio.to_thread(
                schedule_all_project_collaboration,
                context,
                scheduler_leader=leader_check(context),
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            context.logger.exception("collaboration scheduling failed")
