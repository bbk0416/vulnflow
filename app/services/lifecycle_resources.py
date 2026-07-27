from __future__ import annotations

"""Deterministic lifecycle task ownership and shutdown diagnostics."""

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
import time
from typing import Any, Awaitable


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _task_stack(task: asyncio.Task[Any]) -> list[str]:
    frames = task.get_stack(limit=8)
    return [f"{frame.f_code.co_filename}:{frame.f_lineno}:{frame.f_code.co_name}" for frame in frames]


@dataclass(slots=True)
class LifecycleResourceTracker:
    """Own all long-running asyncio tasks for one application instance.

    The tracker exposes only structural diagnostics. It never includes database
    paths, credentials, payloads, URLs, or other runtime secrets.
    """

    runtime_id: str
    shutdown_timeout_seconds: float = 5.0
    stop_event: asyncio.Event = field(default_factory=asyncio.Event)
    tasks: dict[str, asyncio.Task[Any]] = field(default_factory=dict)
    started_task_names: list[str] = field(default_factory=list)
    started_at: str = ""
    stopped_at: str = ""
    state: str = "NEW"
    shutdown_elapsed_ms: float = 0.0
    shutdown_timed_out: bool = False
    task_failures: dict[str, str] = field(default_factory=dict)
    pending_task_stacks: dict[str, list[str]] = field(default_factory=dict)

    def start(self) -> None:
        if self.state == "RUNNING":
            return
        if self.state == "STOPPING":
            raise RuntimeError("lifecycle tracker is stopping")
        self.stop_event = asyncio.Event()
        self.tasks.clear()
        self.started_task_names.clear()
        self.started_at = _utc_now()
        self.stopped_at = ""
        self.state = "RUNNING"
        self.shutdown_elapsed_ms = 0.0
        self.shutdown_timed_out = False
        self.task_failures.clear()
        self.pending_task_stacks.clear()

    def create_task(self, name: str, awaitable: Awaitable[Any]) -> asyncio.Task[Any]:
        if self.state != "RUNNING":
            raise RuntimeError("lifecycle tracker must be running before tasks are created")
        label = str(name).strip()
        if not label or label in self.tasks:
            raise ValueError(f"duplicate or empty lifecycle task name: {label!r}")
        task = asyncio.create_task(
            awaitable,
            name=f"vulnflow:{self.runtime_id or 'default'}:{label}",
        )
        self.tasks[label] = task
        self.started_task_names.append(label)
        return task

    async def wait_or_stop(self, seconds: float) -> bool:
        if self.stop_event.is_set():
            return True
        try:
            await asyncio.wait_for(self.stop_event.wait(), timeout=max(0.0, float(seconds)))
            return True
        except asyncio.TimeoutError:
            return False

    async def stop(self) -> dict[str, Any]:
        if self.state == "STOPPED":
            return self.snapshot()
        started = time.perf_counter()
        self.state = "STOPPING"
        self.stop_event.set()
        active = {name: task for name, task in self.tasks.items() if not task.done()}
        for task in active.values():
            task.cancel()

        done: set[asyncio.Task[Any]] = set()
        pending: set[asyncio.Task[Any]] = set(active.values())
        if pending:
            done, pending = await asyncio.wait(
                pending,
                timeout=max(0.05, float(self.shutdown_timeout_seconds)),
            )

        task_names = {task: name for name, task in self.tasks.items()}
        for task in set(self.tasks.values()) - pending:
            name = task_names.get(task, task.get_name())
            if task.cancelled():
                continue
            try:
                error = task.exception()
            except asyncio.CancelledError:
                continue
            if error is not None:
                self.task_failures[name] = f"{type(error).__name__}: {error}"[:500]

        if pending:
            self.shutdown_timed_out = True
            self.pending_task_stacks = {
                task_names.get(task, task.get_name()): _task_stack(task) for task in pending
            }
            for task in pending:
                task.cancel()
            # Give cancellation one final event-loop turn without extending the
            # configured shutdown deadline indefinitely.
            await asyncio.sleep(0)

        self.shutdown_elapsed_ms = round((time.perf_counter() - started) * 1000.0, 3)
        self.stopped_at = _utc_now()
        self.state = "STOPPED"
        self.tasks.clear()
        return self.snapshot()

    def snapshot(self) -> dict[str, Any]:
        running = sum(not task.done() for task in self.tasks.values())
        completed = sum(task.done() for task in self.tasks.values())
        return {
            "state": self.state,
            "started_at": self.started_at,
            "stopped_at": self.stopped_at,
            "task_count": len(self.tasks),
            "started_task_count": len(self.started_task_names),
            "running_task_count": running,
            "completed_task_count": completed,
            "task_names": sorted(self.tasks),
            "started_task_names": sorted(self.started_task_names),
            "shutdown_timeout_seconds": float(self.shutdown_timeout_seconds),
            "shutdown_elapsed_ms": self.shutdown_elapsed_ms,
            "shutdown_timed_out": self.shutdown_timed_out,
            "task_failure_count": len(self.task_failures),
            "task_failures": dict(sorted(self.task_failures.items())),
            "pending_task_stacks": dict(sorted(self.pending_task_stacks.items())),
        }
