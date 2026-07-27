from __future__ import annotations

"""Explicit application and request runtime contexts.

Composition and non-secret diagnostics live in dedicated modules so this file
remains the stable public type boundary used by routers, services, and tests.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping, MutableMapping

from app.core.context_composition import (
    build_dependency_mapping,
    clone_application_context,
    context_value,
    initialize_context_dependencies,
    mutable_dependency_overrides,
    require_context_value,
    set_context_value,
)
from app.core.context_diagnostics import application_runtime_snapshot
from app.core.runtime import RuntimeSettings, ServiceContainer
from app.core.transactions import SQLiteTransactionRegistry


@dataclass(slots=True)
class ApplicationContext:
    namespace: MutableMapping[str, Any]
    templates: Any
    metrics: Any
    logger: Any
    coordination_state: MutableMapping[str, Any]
    settings: RuntimeSettings | None = None
    services: ServiceContainer | None = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    route_exports: dict[str, Any] = field(default_factory=dict)
    app: Any | None = None
    router_modules: tuple[Any, ...] = field(default_factory=tuple)
    router_runtime_id: str = ""
    operation_guard: Any | None = None
    transaction_registry: SQLiteTransactionRegistry | None = None
    lifecycle_resources: Any | None = None

    def __post_init__(self) -> None:
        initialize_context_dependencies(self)

    def get(self, name: str, default: Any = None) -> Any:
        return context_value(self, name, default)

    def require(self, name: str) -> Any:
        return require_context_value(self, name)

    def set(self, name: str, value: Any) -> None:
        set_context_value(self, name, value)

    def dependency_mapping(self) -> dict[str, Any]:
        return build_dependency_mapping(self)

    def mutable_dependency_overrides(self) -> dict[str, Any]:
        return mutable_dependency_overrides(self)

    def clone(
        self,
        *,
        namespace: MutableMapping[str, Any] | None = None,
        setting_overrides: Mapping[str, Any] | None = None,
        service_overrides: Mapping[str, Any] | None = None,
        coordination_state: MutableMapping[str, Any] | None = None,
    ) -> "ApplicationContext":
        return clone_application_context(
            self,
            namespace=namespace,
            setting_overrides=setting_overrides,
            service_overrides=service_overrides,
            coordination_state=coordination_state,
        )

    def runtime_snapshot(self) -> dict[str, Any]:
        return application_runtime_snapshot(self)


@dataclass(frozen=True, slots=True)
class RequestRuntime:
    """Per-request immutable view of the owning application context and principal."""

    application: ApplicationContext
    actor: str
    role: str
    auth_method: str
    request_id: str

    @property
    def settings(self) -> RuntimeSettings:
        assert self.application.settings is not None
        return self.application.settings

    @property
    def services(self) -> ServiceContainer:
        assert self.application.services is not None
        return self.application.services

    def get(self, name: str, default: Any = None) -> Any:
        return self.application.get(name, default)


def get_request_runtime(request: Any) -> RequestRuntime:
    runtime = getattr(getattr(request, "state", None), "vulnflow_runtime", None)
    if not isinstance(runtime, RequestRuntime):
        raise RuntimeError("VulnFlow request runtime is not installed")
    return runtime


def get_application_context(app: Any) -> ApplicationContext:
    context = getattr(getattr(app, "state", None), "vulnflow_context", None)
    if not isinstance(context, ApplicationContext):
        raise RuntimeError("VulnFlow application context is not installed")
    return context
