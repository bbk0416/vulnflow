from __future__ import annotations

"""Shared callback resolution for the ASGI runtime boundaries."""

from collections.abc import Callable, Mapping
from typing import Any

Namespace = Mapping[str, Any]


def runtime_callback(namespace: Namespace, name: str) -> Callable[..., Any]:
    value = namespace.get(name)
    if not callable(value):
        raise RuntimeError(f"application runtime callback is missing: {name}")
    return value


# Historical private helper retained for compatibility through
# :mod:`app.application_runtime`.
_callback = runtime_callback
