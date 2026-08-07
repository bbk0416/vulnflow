from __future__ import annotations

"""Compatibility cleanup for FastAPI callable-classification caches.

FastAPI versions with cached callable classification keep strong references to
callables through private ``_CallIdentity`` keys. VulnFlow creates private
router functions for isolated application instances, so those cache entries
must be released when the isolated application lifespan ends.
"""

from importlib import import_module
from typing import Any

_CACHE_MODULES = (
    "fastapi.dependencies.models",
    "fastapi.dependencies.utils",
)
_CACHE_FUNCTIONS = (
    "_is_gen_callable_cached",
    "_is_async_gen_callable_cached",
    "_is_coroutine_callable_cached",
)


def clear_callable_classification_caches() -> tuple[str, ...]:
    """Clear available FastAPI callable caches and return their identities.

    The private function locations differ between FastAPI releases. Missing
    modules or uncached functions are treated as a supported no-op.
    """
    cleared: list[str] = []
    seen: set[int] = set()
    for module_name in _CACHE_MODULES:
        try:
            module: Any = import_module(module_name)
        except ImportError:
            continue
        for function_name in _CACHE_FUNCTIONS:
            function = getattr(module, function_name, None)
            cache_clear = getattr(function, "cache_clear", None)
            if not callable(cache_clear) or id(function) in seen:
                continue
            cache_clear()
            seen.add(id(function))
            cleared.append(f"{module_name}.{function_name}")
    return tuple(cleared)
