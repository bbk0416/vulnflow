from __future__ import annotations

"""Router registration, isolated runtime modules, and compatibility exports."""

from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any
import uuid

from fastapi import FastAPI

from app.core.context import ApplicationContext

from . import (
    assets,
    evidence,
    exports,
    findings,
    governance,
    governance_controls,
    governance_policy,
    operations,
    supply_chain,
    trust,
    trust_observability,
)

ROUTER_MODULES = (
    findings,
    supply_chain,
    assets,
    evidence,
    governance_policy,
    governance,
    governance_controls,
    trust,
    trust_observability,
    exports,
    operations,
)

_PRIMARY_RUNTIME_CLAIMED = False


@dataclass(frozen=True, slots=True)
class RouterRuntime:
    runtime_id: str
    modules: tuple[ModuleType, ...]
    exports: dict[str, Any]
    isolated: bool


def _route_exports(modules: tuple[ModuleType, ...]) -> dict[str, Any]:
    exports: dict[str, Any] = {}
    for module in modules:
        exports.update(module.route_exports())
    return exports


def _clone_router_module(template: ModuleType, runtime_id: str) -> ModuleType:
    """Execute a router source file in a private module namespace.

    FastAPI route functions resolve their injected globals from that private
    namespace, preventing a second ``create_app()`` instance from overwriting
    the first application's route settings and service hooks.
    """
    source_path = Path(str(template.__file__))
    module = ModuleType(f"{template.__name__}.__runtime_{runtime_id}")
    module.__file__ = str(source_path)
    module.__package__ = template.__package__
    module.__loader__ = template.__loader__
    module.__dict__["__builtins__"] = __builtins__
    code = compile(source_path.read_text(encoding="utf-8"), str(source_path), "exec")
    exec(code, module.__dict__)
    return module


def _build_runtime_modules() -> tuple[tuple[ModuleType, ...], str, bool]:
    global _PRIMARY_RUNTIME_CLAIMED
    runtime_id = uuid.uuid4().hex[:12]
    if not _PRIMARY_RUNTIME_CLAIMED:
        _PRIMARY_RUNTIME_CLAIMED = True
        return tuple(ROUTER_MODULES), runtime_id, False
    return tuple(_clone_router_module(module, runtime_id) for module in ROUTER_MODULES), runtime_id, True


def refresh_runtime_dependencies(context: ApplicationContext) -> None:
    """Refresh only the router modules owned by the target application."""
    mutable = context.mutable_dependency_overrides()
    for module in context.router_modules:
        module.install_dependencies(mutable)


def install_routers(app: FastAPI, context: ApplicationContext) -> dict[str, Any]:
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
