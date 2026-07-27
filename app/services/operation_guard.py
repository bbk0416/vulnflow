from __future__ import annotations

"""Context-bound exclusive-operation leases and HTTP write barriers.

The guard is the single coordination boundary shared by HTTP middleware,
background workers, schedulers, and explicit administrative operations.  It
never imports :mod:`app.main`; every setting and repository function is
resolved from the owning :class:`~app.core.context.ApplicationContext`.
"""

from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from app.core.context import ApplicationContext
from app.core.db import ConcurrencyError

WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
RESTORE_PATHS = frozenset(
    {"/restore-backup", "/restore-recovery-bundle", "/api/v1/recovery/restore"}
)


class WriteBarrierActive(ConcurrencyError):
    """Raised when an active restore lease blocks a new write request."""


@dataclass(slots=True)
class WriteActivity:
    """A coordination record registered for one HTTP write request."""

    activity_id: str
    registered: bool = False
    closed: bool = False


@dataclass(slots=True)
class OperationGuard:
    """App-instance-specific exclusive operation and write barrier service."""

    context: ApplicationContext

    def _service(self, name: str) -> Any:
        assert self.context.services is not None
        return self.context.services.require(name)

    @property
    def enabled(self) -> bool:
        return bool(self.context.get("CLUSTER_COORDINATION_ENABLED"))

    @property
    def coordination_db_path(self) -> Path:
        configured = str(self.context.get("COORDINATION_DB_ENV", "") or "").strip()
        if configured:
            return Path(configured)
        db_path = Path(self.context.get("DB_PATH"))
        return db_path.with_name(f"{db_path.stem}-coordination.db")

    @property
    def instance_id(self) -> str:
        return str(self.context.get("INSTANCE_ID"))

    @property
    def restore_lease_name(self) -> str:
        return str(self.context.get("RESTORE_LEASE_NAME"))

    def active_lease(self, lease_name: str) -> dict[str, Any] | None:
        if not self.enabled:
            return None
        return self._service("active_cluster_lease")(
            self.coordination_db_path, str(lease_name)
        )

    def restore_in_progress(self) -> bool:
        try:
            return self.active_lease(self.restore_lease_name) is not None
        except Exception:
            # Preserve the historical scheduler/worker behavior: a transient
            # coordination read failure is logged by the caller and does not
            # permanently stop local processing.
            return False

    @contextmanager
    def exclusive_operation(self, lease_name: str, purpose: str) -> Iterator[dict[str, Any] | None]:
        """Acquire and fence an app-specific exclusive operation lease."""
        if not self.enabled:
            yield None
            return
        lease = self._service("acquire_cluster_lease")(
            self.coordination_db_path,
            lease_name=str(lease_name),
            holder_id=self.instance_id,
            ttl_seconds=int(self.context.get("EXCLUSIVE_OPERATION_LEASE_SECONDS")),
            purpose=str(purpose),
        )
        if not lease:
            current = self.active_lease(str(lease_name)) or {}
            raise ConcurrencyError(
                f"다른 인스턴스가 {purpose} 작업을 수행 중입니다: "
                f"{current.get('holder_id', 'unknown')}"
            )
        try:
            yield lease
        finally:
            self._service("release_cluster_lease")(
                self.coordination_db_path,
                lease_name=str(lease_name),
                holder_id=self.instance_id,
                fencing_token=int(lease["fencing_token"]),
            )

    def begin_http_write(
        self,
        *,
        activity_id: str,
        actor: str,
        method: str,
        path: str,
    ) -> WriteActivity:
        """Register a write request and close the restore acquisition race."""
        activity = WriteActivity(activity_id=str(activity_id))
        normalized_method = str(method).upper()
        normalized_path = str(path)
        if not self.enabled or normalized_method not in WRITE_METHODS or normalized_path in RESTORE_PATHS:
            return activity
        if self.restore_in_progress():
            raise WriteBarrierActive(
                "데이터베이스 복원 작업 중에는 쓰기 요청을 처리할 수 없습니다."
            )
        self._service("begin_cluster_write_activity")(
            self.coordination_db_path,
            activity_id=activity.activity_id,
            instance_id=self.instance_id,
            actor=str(actor),
            method=normalized_method,
            path=normalized_path,
            ttl_seconds=int(self.context.get("WRITE_ACTIVITY_TTL_SECONDS")),
        )
        activity.registered = True
        # Close the check/register race with restore lease acquisition.
        if self.restore_in_progress():
            self.end_http_write(activity)
            raise WriteBarrierActive(
                "데이터베이스 복원 작업 중에는 쓰기 요청을 처리할 수 없습니다."
            )
        return activity

    def end_http_write(self, activity: WriteActivity | None) -> None:
        if activity is None or not activity.registered or activity.closed:
            return
        self._service("end_cluster_write_activity")(
            self.coordination_db_path, activity_id=activity.activity_id
        )
        activity.closed = True

    def dependency_mapping(self) -> dict[str, Any]:
        """Dependencies injected into the router runtime owned by this app."""
        return {
            "OPERATION_GUARD": self,
            "_exclusive_operation": self.exclusive_operation,
            "_restore_in_progress": self.restore_in_progress,
        }


def bind_operation_guard(context: ApplicationContext) -> OperationGuard:
    """Create or return the guard owned by one application context."""
    guard = context.operation_guard
    if isinstance(guard, OperationGuard) and guard.context is context:
        return guard
    guard = OperationGuard(context)
    context.operation_guard = guard
    return guard
