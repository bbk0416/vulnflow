from __future__ import annotations

"""Request-scoped FastAPI dependencies for router modules.

Routers migrated to this boundary resolve the owning :class:`ApplicationContext`
from ``request.app.state`` instead of reading mutable module globals.  The
module is intentionally small so additional router migrations can share one
stable dependency without importing :mod:`app.main`.
"""

from fastapi import Request

from app.core.context import ApplicationContext, get_application_context


def application_context(request: Request) -> ApplicationContext:
    """Return the immutable owning application context for this request."""
    return get_application_context(request.app)
