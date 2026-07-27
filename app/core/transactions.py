from __future__ import annotations

"""Consistent SQLite connection and transaction boundaries.

Repositories previously opened connections, selected transaction modes, and
committed or rolled back independently.  This module centralizes those rules
without changing repository call signatures or database schemas.
"""

from contextlib import contextmanager
from contextvars import ContextVar, Token
from dataclasses import dataclass, field
from pathlib import Path
from threading import Lock
from time import perf_counter
from typing import Any, Callable, Iterator, TypeVar
import sqlite3
import inspect
from functools import wraps

from app.core.db import connect

_ALLOWED_MODES = frozenset({"DEFERRED", "IMMEDIATE", "EXCLUSIVE"})


@dataclass(frozen=True, slots=True)
class SQLiteTransactionPolicy:
    """Immutable SQLite transaction policy shared by repository boundaries."""

    busy_timeout_ms: int = 30_000
    write_mode: str = "IMMEDIATE"

    def __post_init__(self) -> None:
        timeout = max(1, int(self.busy_timeout_ms))
        mode = str(self.write_mode or "IMMEDIATE").strip().upper()
        if mode not in _ALLOWED_MODES:
            raise ValueError(f"unsupported SQLite transaction mode: {mode}")
        object.__setattr__(self, "busy_timeout_ms", timeout)
        object.__setattr__(self, "write_mode", mode)


@dataclass(slots=True)
class _TransactionCounters:
    read_count: int = 0
    write_count: int = 0
    commit_count: int = 0
    rollback_count: int = 0
    failure_count: int = 0
    total_duration_ms: float = 0.0
    max_duration_ms: float = 0.0
    operations: dict[str, int] = field(default_factory=dict)


class SQLiteTransactionRuntime:
    """Open consistently configured SQLite connections and own transaction ends.

    A runtime is safe to share between threads because it does not share SQLite
    connection objects.  Each context manager opens one connection and closes
    it deterministically.  Only aggregate counters are shared and protected by
    a lock.
    """

    def __init__(
        self,
        db_path: str | Path,
        *,
        policy: SQLiteTransactionPolicy | None = None,
    ) -> None:
        self.db_path = Path(db_path)
        self.policy = policy or SQLiteTransactionPolicy()
        self._counters = _TransactionCounters()
        self._lock = Lock()

    def _record(self, *, kind: str, operation: str, elapsed_ms: float, outcome: str) -> None:
        label = str(operation or "unspecified")[:120]
        with self._lock:
            if kind == "read":
                self._counters.read_count += 1
            else:
                self._counters.write_count += 1
            if outcome == "commit":
                self._counters.commit_count += 1
            elif outcome == "rollback":
                self._counters.rollback_count += 1
                self._counters.failure_count += 1
            elif outcome == "failure":
                self._counters.failure_count += 1
            self._counters.total_duration_ms += elapsed_ms
            self._counters.max_duration_ms = max(self._counters.max_duration_ms, elapsed_ms)
            self._counters.operations[label] = self._counters.operations.get(label, 0) + 1

    def _connect(self) -> sqlite3.Connection:
        return connect(self.db_path, busy_timeout_ms=self.policy.busy_timeout_ms)

    @contextmanager
    def read(self, *, operation: str = "") -> Iterator[sqlite3.Connection]:
        started = perf_counter()
        conn = self._connect()
        outcome = "read"
        try:
            yield conn
        except Exception:
            outcome = "failure"
            raise
        finally:
            conn.close()
            self._record(
                kind="read",
                operation=operation,
                elapsed_ms=(perf_counter() - started) * 1000.0,
                outcome=outcome,
            )

    @contextmanager
    def write(
        self,
        *,
        operation: str = "",
        mode: str | None = None,
    ) -> Iterator[sqlite3.Connection]:
        transaction_mode = str(mode or self.policy.write_mode).strip().upper()
        if transaction_mode not in _ALLOWED_MODES:
            raise ValueError(f"unsupported SQLite transaction mode: {transaction_mode}")
        started = perf_counter()
        conn = self._connect()
        outcome = "failure"
        try:
            conn.execute(f"BEGIN {transaction_mode}")
            yield conn
            # A repository may explicitly roll back an optimistic claim.  In
            # that case commit() is a harmless no-op and preserves old behavior.
            conn.commit()
            outcome = "commit"
        except Exception:
            try:
                conn.rollback()
            finally:
                outcome = "rollback"
            raise
        finally:
            conn.close()
            self._record(
                kind="write",
                operation=operation,
                elapsed_ms=(perf_counter() - started) * 1000.0,
                outcome=outcome,
            )

    def structural_snapshot(self) -> dict[str, Any]:
        """Return non-secret policy and aggregate counters.

        The database path is deliberately omitted from diagnostics.
        """
        with self._lock:
            total = self._counters.read_count + self._counters.write_count
            return {
                "busy_timeout_ms": self.policy.busy_timeout_ms,
                "write_mode": self.policy.write_mode,
                "read_count": self._counters.read_count,
                "write_count": self._counters.write_count,
                "commit_count": self._counters.commit_count,
                "rollback_count": self._counters.rollback_count,
                "failure_count": self._counters.failure_count,
                "operation_count": len(self._counters.operations),
                "total_count": total,
                "total_duration_ms": round(self._counters.total_duration_ms, 3),
                "max_duration_ms": round(self._counters.max_duration_ms, 3),
            }



class SQLiteTransactionRegistry:
    """App-context-owned transaction runtimes, isolated by database path."""

    def __init__(self, *, policy: SQLiteTransactionPolicy | None = None) -> None:
        self.policy = policy or SQLiteTransactionPolicy()
        self._runtimes: dict[str, SQLiteTransactionRuntime] = {}
        self._lock = Lock()

    @staticmethod
    def _key(db_path: str | Path) -> str:
        return str(Path(db_path).resolve())

    def for_path(self, db_path: str | Path) -> SQLiteTransactionRuntime:
        key = self._key(db_path)
        with self._lock:
            runtime = self._runtimes.get(key)
            if runtime is None:
                runtime = SQLiteTransactionRuntime(db_path, policy=self.policy)
                self._runtimes[key] = runtime
            return runtime

    def structural_snapshot(self) -> dict[str, Any]:
        with self._lock:
            runtimes = list(self._runtimes.values())
        snapshots = [runtime.structural_snapshot() for runtime in runtimes]
        return {
            "database_count": len(snapshots),
            "read_count": sum(int(item["read_count"]) for item in snapshots),
            "write_count": sum(int(item["write_count"]) for item in snapshots),
            "commit_count": sum(int(item["commit_count"]) for item in snapshots),
            "rollback_count": sum(int(item["rollback_count"]) for item in snapshots),
            "failure_count": sum(int(item["failure_count"]) for item in snapshots),
            "write_mode": self.policy.write_mode,
            "busy_timeout_ms": self.policy.busy_timeout_ms,
        }


_ACTIVE_TRANSACTION_REGISTRY: ContextVar[SQLiteTransactionRegistry | None] = ContextVar(
    "vulnflow_transaction_registry", default=None
)


def activate_transaction_registry(registry: SQLiteTransactionRegistry) -> Token[SQLiteTransactionRegistry | None]:
    return _ACTIVE_TRANSACTION_REGISTRY.set(registry)


def reset_transaction_registry(token: Token[SQLiteTransactionRegistry | None]) -> None:
    _ACTIVE_TRANSACTION_REGISTRY.reset(token)


@contextmanager
def transaction_scope(registry: SQLiteTransactionRegistry) -> Iterator[SQLiteTransactionRegistry]:
    token = activate_transaction_registry(registry)
    try:
        yield registry
    finally:
        reset_transaction_registry(token)


_F = TypeVar("_F", bound=Callable[..., Any])


def context_transaction_scope(function: _F) -> _F:
    """Run a context-first callable inside its app-owned transaction registry."""
    if inspect.iscoroutinefunction(function):
        @wraps(function)
        async def async_wrapper(context: Any, *args: Any, **kwargs: Any) -> Any:
            registry = getattr(context, "transaction_registry", None)
            if registry is None:
                return await function(context, *args, **kwargs)
            with transaction_scope(registry):
                return await function(context, *args, **kwargs)
        return async_wrapper  # type: ignore[return-value]

    @wraps(function)
    def sync_wrapper(context: Any, *args: Any, **kwargs: Any) -> Any:
        registry = getattr(context, "transaction_registry", None)
        if registry is None:
            return function(context, *args, **kwargs)
        with transaction_scope(registry):
            return function(context, *args, **kwargs)
    return sync_wrapper  # type: ignore[return-value]

def transaction_runtime(
    db_path: str | Path,
    *,
    runtime: SQLiteTransactionRuntime | None = None,
) -> SQLiteTransactionRuntime:
    """Return the supplied runtime after validating its path, or create one."""
    if runtime is None:
        registry = _ACTIVE_TRANSACTION_REGISTRY.get()
        if registry is not None:
            return registry.for_path(db_path)
        return SQLiteTransactionRuntime(db_path)
    if runtime.db_path.resolve() != Path(db_path).resolve():
        raise ValueError("SQLite transaction runtime database path mismatch")
    return runtime


@contextmanager
def read_connection(
    db_path: str | Path,
    *,
    operation: str = "",
    runtime: SQLiteTransactionRuntime | None = None,
) -> Iterator[sqlite3.Connection]:
    with transaction_runtime(db_path, runtime=runtime).read(operation=operation) as conn:
        yield conn


@contextmanager
def write_transaction(
    db_path: str | Path,
    *,
    operation: str = "",
    mode: str | None = None,
    runtime: SQLiteTransactionRuntime | None = None,
) -> Iterator[sqlite3.Connection]:
    with transaction_runtime(db_path, runtime=runtime).write(operation=operation, mode=mode) as conn:
        yield conn


@contextmanager
def borrowed_or_write_transaction(
    db_path: str | Path,
    *,
    conn: sqlite3.Connection | None,
    operation: str,
    runtime: SQLiteTransactionRuntime | None = None,
) -> Iterator[sqlite3.Connection]:
    """Use a caller transaction or own one when no connection was supplied."""
    if conn is not None:
        yield conn
        return
    with write_transaction(db_path, operation=operation, runtime=runtime) as owned:
        yield owned
