from __future__ import annotations

import asyncio
import inspect
import time

import pytest

import app.services.job_worker_runtime as worker
from app.core.storage import init_db
from app.repositories import job_execution as job_execution_repo
from app.repositories.job_execution import claim_background_job, heartbeat_background_job
from app.repositories.job_records import create_background_job


class DummyContext:
    pass


def test_periodic_heartbeat_prevents_real_job_reclaim(tmp_path, monkeypatch):
    db = tmp_path / "heartbeat.sqlite3"
    init_db(db)
    created = create_background_job(
        db, job_type="INTEL_REFRESH", requested_by="p0-04", max_attempts=3
    )
    first = claim_background_job(db, worker_id="worker-a", lease_seconds=5)
    assert first is not None
    assert first["lease_owner"] == "worker-a"

    def slow_execute(context, job, *, worker_id):
        time.sleep(6.2)
        return {"ok": True}

    def service(context, name):
        if name == "heartbeat_background_job":
            return heartbeat_background_job
        raise AssertionError(name)

    monkeypatch.setattr(worker, "_execute_for_context", slow_execute)
    monkeypatch.setattr(worker, "_service", service)
    monkeypatch.setattr(
        worker, "_setting", lambda context, key: db if key == "DB_PATH" else None
    )

    async def scenario():
        running = asyncio.create_task(
            worker._execute_with_lease_heartbeat(
                DummyContext(), first, worker_id="worker-a", lease_seconds=5
            )
        )
        await asyncio.sleep(5.3)
        reclaimed = await asyncio.to_thread(
            claim_background_job, db, worker_id="worker-b", lease_seconds=5
        )
        result = await running
        return reclaimed, result

    reclaimed, result = asyncio.run(scenario())
    assert reclaimed is None
    assert result == {"ok": True}


def test_lease_loss_exception_is_propagated(monkeypatch):
    def slow_execute(context, job, *, worker_id):
        time.sleep(0.08)
        return {"ok": True}

    def lost(*args, **kwargs):
        raise job_execution_repo.ConcurrencyError("lease lost")

    monkeypatch.setattr(worker, "_execute_for_context", slow_execute)
    monkeypatch.setattr(
        worker, "_lease_heartbeat_interval", lambda lease_seconds: 0.02
    )
    monkeypatch.setattr(worker, "_setting", lambda context, key: "dummy.sqlite3")
    monkeypatch.setattr(worker, "_service", lambda context, name: lost)

    with pytest.raises(job_execution_repo.ConcurrencyError, match="lease lost"):
        asyncio.run(
            worker._execute_with_lease_heartbeat(
                DummyContext(),
                {"job_id": "JOB-LOST"},
                worker_id="worker-a",
                lease_seconds=5,
            )
        )


def test_worker_uses_heartbeat_wrapper_and_safe_interval():
    body = inspect.getsource(worker.job_worker_loop)
    assert "_execute_with_lease_heartbeat" in body
    assert "result = await asyncio.to_thread(_execute_for_context" not in body
    assert worker._lease_heartbeat_interval(5) < 5
    assert worker._lease_heartbeat_interval(120) <= 30
