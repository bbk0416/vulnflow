from __future__ import annotations

"""Compatibility facade for the split ASGI runtime boundaries."""

from app.application_lifespan import application_lifespan, lifespan_scoped
from app.application_runtime_common import Namespace, _callback, runtime_callback
from app.http_runtime import friendly_http_error, local_security, local_security_scoped

__all__ = [
    "Namespace",
    "_callback",
    "runtime_callback",
    "lifespan_scoped",
    "application_lifespan",
    "local_security_scoped",
    "local_security",
    "friendly_http_error",
]
