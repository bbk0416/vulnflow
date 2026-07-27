from __future__ import annotations

"""Application-context dependency composition.

This module owns immutable runtime-container initialization, compatibility
namespace overlays, route dependency mapping, and isolated context cloning.
It intentionally avoids importing :mod:`app.main`.
"""

from typing import Any, Mapping, MutableMapping

from app.core.runtime import RuntimeSettings, ServiceContainer
from app.core.transactions import SQLiteTransactionRegistry

LEGACY_SERVICE_OVERRIDES = frozenset({"fetch_kev_catalog", "fetch_epss"})


def initialize_context_dependencies(context: "ApplicationContext") -> None:
    """Install immutable dependency containers and a transaction registry."""
    if context.settings is None:
        context.settings = RuntimeSettings.from_namespace(context.namespace)
    if context.services is None:
        context.services = ServiceContainer.from_namespace(context.namespace)
    if context.transaction_registry is None:
        context.transaction_registry = SQLiteTransactionRegistry()


def context_value(context: "ApplicationContext", name: str, default: Any = None) -> Any:
    """Resolve a compatibility overlay before immutable dependencies."""
    if name in context.namespace:
        return context.namespace[name]
    assert context.settings is not None and context.services is not None
    if name.isupper():
        return context.settings.get(name, default)
    return context.services.get(name, default)


def require_context_value(context: "ApplicationContext", name: str) -> Any:
    value = context_value(context, name, None)
    if value is None and name not in context.namespace:
        raise KeyError(f"application context dependency is missing: {name}")
    return value


def set_context_value(context: "ApplicationContext", name: str, value: Any) -> None:
    """Mutate only the compatibility namespace, never immutable containers."""
    context.namespace[name] = value


def mutable_dependency_overrides(context: "ApplicationContext") -> dict[str, Any]:
    assert context.settings is not None
    names = set(context.settings.values) | set(LEGACY_SERVICE_OVERRIDES)
    return {name: context.namespace[name] for name in names if name in context.namespace}


def build_dependency_mapping(context: "ApplicationContext") -> dict[str, Any]:
    """Build the complete route dependency mapping for one app instance."""
    assert context.settings is not None and context.services is not None
    dependencies = context.services.as_dict()
    dependencies.update(context.settings.as_dict())
    dependencies.update(mutable_dependency_overrides(context))
    if context.operation_guard is not None:
        dependencies.update(context.operation_guard.dependency_mapping())
    dependencies["TRANSACTION_REGISTRY"] = context.transaction_registry
    return dependencies


def clone_application_context(
    context: "ApplicationContext",
    *,
    namespace: MutableMapping[str, Any] | None = None,
    setting_overrides: Mapping[str, Any] | None = None,
    service_overrides: Mapping[str, Any] | None = None,
    coordination_state: MutableMapping[str, Any] | None = None,
) -> "ApplicationContext":
    """Create an isolated app context while preserving immutable baselines."""
    assert context.settings is not None and context.services is not None
    cloned_namespace = namespace if namespace is not None else dict(context.namespace)
    cloned_settings = context.settings.with_overrides(setting_overrides)
    cloned_services = context.services.with_overrides(service_overrides)
    cloned_namespace.update(cloned_settings.as_dict())
    cloned_namespace.update(dict(service_overrides or {}))
    return type(context)(
        namespace=cloned_namespace,
        templates=context.templates,
        metrics=context.metrics,
        logger=context.logger,
        coordination_state=(
            coordination_state if coordination_state is not None else dict(context.coordination_state)
        ),
        settings=cloned_settings,
        services=cloned_services,
        transaction_registry=SQLiteTransactionRegistry(
            policy=context.transaction_registry.policy if context.transaction_registry is not None else None
        ),
    )
