from __future__ import annotations

"""Version-tolerant inspection of effective FastAPI API routes.

FastAPI 0.140.x keeps included routers as lazy route-context branches instead
of flattening every included APIRoute into ``app.router.routes``.  Older
versions flatten them.  This module uses FastAPI's public ``iter_route_contexts``
API when available and falls back to direct routes for older supported builds.
"""

from dataclasses import dataclass
from typing import Any, Iterable, Iterator

from fastapi.routing import APIRoute

try:  # FastAPI 0.140+
    from fastapi.routing import iter_route_contexts
except ImportError:  # FastAPI versions that flatten include_router eagerly
    iter_route_contexts = None  # type: ignore[assignment]


@dataclass(frozen=True, slots=True)
class EffectiveAPIRoute:
    original_route: APIRoute
    endpoint: Any
    name: str | None
    path: str | None


def iter_effective_api_routes(routes: Iterable[Any]) -> Iterator[EffectiveAPIRoute]:
    route_list = list(routes)
    if iter_route_contexts is None:
        for route in route_list:
            if isinstance(route, APIRoute):
                yield EffectiveAPIRoute(
                    original_route=route,
                    endpoint=route.endpoint,
                    name=route.name,
                    path=route.path,
                )
        return

    for context in iter_route_contexts(route_list):
        original = context.original_route
        if not isinstance(original, APIRoute):
            continue
        yield EffectiveAPIRoute(
            original_route=original,
            endpoint=context.endpoint or original.endpoint,
            name=context.name or original.name,
            path=context.path or original.path,
        )


def effective_api_routes(application: Any) -> list[EffectiveAPIRoute]:
    return list(iter_effective_api_routes(application.router.routes))


def effective_api_route(application: Any, name: str) -> EffectiveAPIRoute:
    return next(route for route in effective_api_routes(application) if route.name == name)
