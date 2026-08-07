from __future__ import annotations

"""In-memory cloning for compatibility router namespaces and APIRoutes."""

from copy import deepcopy
from types import FunctionType, ModuleType, SimpleNamespace
from typing import Any

from fastapi import APIRouter
from fastapi.routing import APIRoute


def _clone_parameter_value(value: Any) -> Any:
    """Copy one default and restore constructor-time FastAPI field metadata."""
    clone = deepcopy(value)
    attributes_set = getattr(clone, "_attributes_set", None)
    if isinstance(attributes_set, dict):
        for name in ("alias", "validation_alias", "serialization_alias", "annotation"):
            if name in attributes_set:
                setattr(clone, name, deepcopy(attributes_set[name]))
    return clone


def clone_function(
    function: FunctionType,
    namespace: dict[str, Any],
    module_name: str,
) -> FunctionType:
    defaults = (
        tuple(_clone_parameter_value(value) for value in function.__defaults__)
        if function.__defaults__ is not None
        else None
    )
    clone = FunctionType(
        function.__code__,
        namespace,
        function.__name__,
        defaults,
        function.__closure__,
    )
    clone.__kwdefaults__ = {
        name: _clone_parameter_value(value)
        for name, value in (function.__kwdefaults__ or {}).items()
    }
    clone.__annotations__ = dict(function.__annotations__)
    clone.__dict__.update(function.__dict__)
    clone.__doc__ = function.__doc__
    clone.__qualname__ = function.__qualname__
    clone.__module__ = module_name
    return clone


def clone_api_route(route: APIRoute, endpoint: Any) -> APIRoute:
    return APIRoute(
        path=route.path,
        endpoint=endpoint,
        response_model=route.response_model,
        status_code=route.status_code,
        tags=list(route.tags),
        dependencies=list(route.dependencies),
        summary=route.summary,
        description=route.description,
        response_description=route.response_description,
        responses=dict(route.responses),
        deprecated=route.deprecated,
        name=route.name,
        methods=set(route.methods or ()),
        operation_id=route.operation_id,
        response_model_include=route.response_model_include,
        response_model_exclude=route.response_model_exclude,
        response_model_by_alias=route.response_model_by_alias,
        response_model_exclude_unset=route.response_model_exclude_unset,
        response_model_exclude_defaults=route.response_model_exclude_defaults,
        response_model_exclude_none=route.response_model_exclude_none,
        include_in_schema=route.include_in_schema,
        response_class=route.response_class,
        dependency_overrides_provider=None,
        callbacks=list(route.callbacks),
        openapi_extra=dict(route.openapi_extra) if route.openapi_extra else None,
        generate_unique_id_function=route.generate_unique_id_function,
    )


def clone_router_module(template: ModuleType, runtime_id: str) -> Any:
    """Clone an imported router without opening, compiling, or executing source."""
    module = SimpleNamespace()
    namespace = module.__dict__
    runtime_name = f"{template.__name__}.__runtime_{runtime_id}"
    for name, value in template.__dict__.items():
        if name != "router":
            namespace[name] = value
    namespace.update(
        __name__=runtime_name,
        __file__=str(template.__file__),
        __package__=template.__package__,
        __loader__=template.__loader__,
        __builtins__=template.__dict__.get("__builtins__", __builtins__),
    )
    function_clones: dict[FunctionType, FunctionType] = {}
    for name, value in tuple(template.__dict__.items()):
        if isinstance(value, FunctionType) and value.__globals__ is template.__dict__:
            clone = clone_function(value, namespace, runtime_name)
            namespace[name] = clone
            function_clones[value] = clone
    router = APIRouter()
    for route in template.router.routes:
        if not isinstance(route, APIRoute):
            raise RuntimeError("router templates must contain only APIRoute entries")
        router.routes.append(clone_api_route(route, function_clones.get(route.endpoint, route.endpoint)))
    namespace["router"] = router
    return module
