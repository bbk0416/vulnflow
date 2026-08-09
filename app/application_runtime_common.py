from __future__ import annotations

"""Shared callback resolution for the ASGI runtime boundaries."""

from collections.abc import Callable, Mapping
from typing import Any

from app.core.project_scope import configure_project_scoped_settings

Namespace = Mapping[str, Any]


def runtime_callback(namespace: Namespace, name: str) -> Callable[..., Any]:
    value = namespace.get(name)
    if not callable(value):
        raise RuntimeError(f"application runtime callback is missing: {name}")
    return value


def prepare_application_context(context: Any) -> Any:
    """Install request-scoped project paths before runtime services bind."""
    configure_project_scoped_settings(context)
    return context


# Historical private helper retained for compatibility through
# :mod:`app.application_runtime`.
_callback = runtime_callback
