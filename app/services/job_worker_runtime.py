from __future__ import annotations

"""Context-bound background worker orchestration and result recording.

The worker owns claiming, dispatch scheduling, lease-aware completion, retry
classification, metrics, and cooperative shutdown. Job-type handlers remain in
:mod:`app.services.job_dispatch`.
"""

import asyncio
import os
import uuid
from typing import Any

from app.core.context import ApplicationContext
from app.core.db import ConcurrencyError
from app.core.retry import classify_operation_exception
from app.core.transactions import context_transaction_scope
from app.services.job_dispatch import _call_context_aware, _service, _setting
from app.services.operation_guard import bind_operation_guard

def _execute_for_context(context: ApplicationContext, job: dict[str, Any], *, worker_id: str) -> dict[str, Any]:
    compatibility_executor = _service(context, "_execute_background_job")
    return _call_context_aware(compatibility_executor, job, worker_id=worker_id, context=context)


@context_transaction_scope
async def job_worker_loop(context: ApplicationContext, *, stop_event: asyncio.Event | None = None) -> None:
    worker_id = f"worker-{os.getpid()}-{uuid.uuid4().hex[:8]}"
    interval = int(_setting(context, "JOB_WORKER_INTERVAL_SECONDS"))

    async def wait_interval() -> bool:
        if stop_event is None:
            await asyncio.sleep(interval)
            return False
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=interval)
            return True
        except asyncio.TimeoutError:
            return False

    while True:
        try:
            if stop_event is not None and stop_event.is_set():
                return
            if bind_operation_guard(context).restore_in_progress():
                if await wait_interval():
                    return
                continue
            job = await asyncio.to_thread(
                _service(context, "claim_background_job"),
                _setting(context, "DB_PATH"),
                worker_id=worker_id,
                lease_seconds=int(_setting(context, "JOB_LEASE_SECONDS")),
            )
            if not job:
                if await wait_interval():
                    return
                continue
            try:
                result = await asyncio.to_thread(_execute_for_context, context, job, worker_id=worker_id)
                await asyncio.to_thread(
                    _service(context, "complete_background_job"),
                    _setting(context, "DB_PATH"),
                    job_id=str(job["job_id"]),
                    worker_id=worker_id,
                    result=result,
                )
                context.metrics.observe_job(str(job.get("job_type") or "unknown"), "succeeded")
            except Exception as exc:
                context.logger.exception(
                    "background job failed",
                    extra={"job_id": job.get("job_id"), "job_type": job.get("job_type")},
                )
                try:
                    retryable, retry_after_seconds, failure_kind = classify_operation_exception(exc)
                    failed_job = await asyncio.to_thread(
                        _service(context, "fail_background_job"),
                        _setting(context, "DB_PATH"),
                        job_id=str(job["job_id"]),
                        worker_id=worker_id,
                        error=str(exc),
                        retryable=retryable,
                        retry_after_seconds=retry_after_seconds,
                        failure_kind=failure_kind,
                    )
                    outcome = "retry" if str(failed_job.get("status")) == "RETRY" else "failed"
                    context.metrics.observe_job(str(job.get("job_type") or "unknown"), outcome)
                except ConcurrencyError:
                    context.logger.warning("background job lease lost", extra={"job_id": job.get("job_id")})
        except asyncio.CancelledError:
            raise
        except Exception:
            context.logger.exception("background job worker loop failed")
            if await wait_interval():
                return
