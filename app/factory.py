from __future__ import annotations

"""FastAPI application assembly.

This module owns framework construction while domain helpers remain importable
from :mod:`app.main` for backward compatibility.
"""

from pathlib import Path
from typing import Any, Awaitable, Callable

from fastapi import FastAPI, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.openapi.utils import get_openapi

from app.core.context import ApplicationContext
from app.routers import install_routers

MiddlewareCallable = Callable[[Request, Callable[..., Awaitable[Any]]], Awaitable[Any]]


def _install_openapi(app: FastAPI) -> None:
    def custom_openapi() -> dict[str, Any]:
        if app.openapi_schema:
            return app.openapi_schema
        schema = get_openapi(title=app.title, version=app.version, routes=app.routes)
        components = schema.setdefault("components", {}).setdefault("securitySchemes", {})
        components["BasicAuth"] = {"type": "http", "scheme": "basic"}
        components["BearerAuth"] = {
            "type": "http", "scheme": "bearer", "bearerFormat": "opaque API token"
        }
        for path, operations in schema.get("paths", {}).items():
            for method, operation in operations.items():
                if method.lower() not in {"get", "post", "put", "patch", "delete"}:
                    continue
                if path in {"/health", "/health/live", "/health/ready"}:
                    operation["security"] = []
                elif path.startswith("/api/v1/") and method.lower() in {"post", "put", "patch", "delete"}:
                    operation["security"] = [{"BearerAuth": []}]
                else:
                    operation["security"] = [{"BasicAuth": []}, {"BearerAuth": []}]
        app.openapi_schema = schema
        return schema

    app.openapi = custom_openapi


def create_application(
    *,
    context: ApplicationContext,
    version: str,
    lifespan: Any,
    middleware: MiddlewareCallable,
    http_exception_handler: Callable[..., Awaitable[Any]],
    app_dir: str | Path,
    title: str = "VulnFlow",
) -> FastAPI:
    """Create and fully assemble a VulnFlow FastAPI application."""
    app = FastAPI(title=title, version=version, lifespan=lifespan)
    context.app = app
    context.namespace["app"] = app
    app.state.vulnflow_context = context
    app.mount("/static", StaticFiles(directory=Path(app_dir) / "static"), name="static")
    app.middleware("http")(middleware)
    app.add_exception_handler(HTTPException, http_exception_handler)
    context.route_exports = install_routers(app, context)
    _install_openapi(app)
    return app
