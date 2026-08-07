from __future__ import annotations

"""Router registration and isolated in-memory runtime namespaces."""

from dataclasses import dataclass
from threading import RLock
from typing import Any
import uuid

from fastapi import FastAPI
from fastapi.routing import APIRoute, request_response

from app.core.context import ApplicationContext
from app.fastapi_runtime_cache import clear_callable_classification_caches
from app.router_cloning import clone_router_module
from . import (
    accounts, assets, evidence, exports, findings, imports, integrations,
    governance, governance_controls, governance_policy, operations, pilot,
    projects, supply_chain, trust, trust_observability,
)

ROUTER_MODULES = (
    accounts, projects, pilot, findings, imports, integrations, supply_chain,
    assets, evidence, governance_policy, governance, governance_controls,
    trust, trust_observability, exports, operations,
)
CONTEXT_ROUTER_MODULES = (pilot,)
_ROUTER_ASSEMBLY_LOCK = RLock()
_PRIMARY_RUNTIME_CLAIMED = False


@dataclass(frozen=True, slots=True)
class RouterRuntime:
    runtime_id: str
    modules: tuple[Any, ...]
    exports: dict[str, Any]
    isolated: bool


def _route_exports(modules: tuple[Any, ...]) -> dict[str, Any]:
    exports: dict[str, Any] = {}
    for module in modules:
        exports.update(module.route_exports())
    return exports


def _clone_router_module(template: Any, runtime_id: str) -> Any:
    """Compatibility alias retained for focused runtime tests."""
    return clone_router_module(template, runtime_id)


def _build_runtime_modules() -> tuple[tuple[Any, ...], str, bool]:
    global _PRIMARY_RUNTIME_CLAIMED
    runtime_id = uuid.uuid4().hex[:12]
    if not _PRIMARY_RUNTIME_CLAIMED:
        _PRIMARY_RUNTIME_CLAIMED = True
        return tuple(ROUTER_MODULES), runtime_id, False
    modules = tuple(
        module if module in CONTEXT_ROUTER_MODULES else clone_router_module(module, runtime_id)
        for module in ROUTER_MODULES
    )
    return modules, runtime_id, True


def refresh_runtime_dependencies(context: ApplicationContext) -> None:
    dependencies = context.mutable_dependency_overrides()
    if context.app is not None:
        dependencies["app"] = context.app
    for module in context.router_modules:
        module.install_dependencies(dependencies)


def release_runtime_application(context: ApplicationContext) -> bool:
    modules = tuple(context.router_modules)
    if not modules or modules == tuple(ROUTER_MODULES):
        return False
    application = context.app
    for module in modules:
        if module.__dict__.get("app") is application:
            module.__dict__.pop("app", None)
    if context.namespace.get("app") is application:
        context.namespace.pop("app", None)
    context.app = None
    clear_callable_classification_caches()
    return True


def _move_isolated_routes(app: FastAPI, module: Any) -> None:
    routes = tuple(module.router.routes)
    if not all(isinstance(route, APIRoute) for route in routes):
        raise RuntimeError("isolated routers must contain only APIRoute entries")
    for route in routes:
        route.dependency_overrides_provider = app
        route.app = request_response(route.get_route_handler())
    app.router.routes.extend(routes)
    mark_changed = getattr(app.router, "_mark_routes_changed", None)
    if callable(mark_changed):
        mark_changed()
    module.router.routes.clear()


def install_routers(app: FastAPI, context: ApplicationContext) -> dict[str, Any]:
    """Install one complete router graph without concurrent schema mutation."""
    with _ROUTER_ASSEMBLY_LOCK:
        return _install_routers_unlocked(app, context)


def _install_routers_unlocked(app: FastAPI, context: ApplicationContext) -> dict[str, Any]:
    modules, runtime_id, isolated = _build_runtime_modules()
    exports = _route_exports(modules)
    dependencies = context.dependency_mapping()
    dependencies["app"] = app
    dependencies.update(exports)
    for module in modules:
        module.install_dependencies(dependencies)
    context.namespace.update(exports)
    context.router_modules = modules
    context.router_runtime_id = runtime_id
    for module in modules:
        if module in CONTEXT_ROUTER_MODULES:
            app.include_router(module.router)
        elif isolated:
            _move_isolated_routes(app, module)
        else:
            app.include_router(module.router)
    return exports


def router_runtime(context: ApplicationContext) -> RouterRuntime:
    return RouterRuntime(
        runtime_id=context.router_runtime_id,
        modules=tuple(context.router_modules),
        exports=dict(context.route_exports),
        isolated=tuple(context.router_modules) != tuple(ROUTER_MODULES),
    )


def route_inventory() -> dict[str, tuple[str, ...]]:
    return {module.__name__.rsplit(".", 1)[-1]: tuple(module.ROUTE_NAMES) for module in ROUTER_MODULES}
