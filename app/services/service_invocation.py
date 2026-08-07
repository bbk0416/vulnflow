from __future__ import annotations

"""Compatibility helpers for service overrides with evolving keyword options."""

import inspect
from typing import Any, Callable


def call_with_supported_options(
    function: Callable[..., Any], *args: Any, **options: Any
) -> Any:
    try:
        parameters = inspect.signature(function).parameters
    except (TypeError, ValueError):
        parameters = {}
    if any(item.kind is inspect.Parameter.VAR_KEYWORD for item in parameters.values()):
        return function(*args, **options)
    supported = {name: value for name, value in options.items() if name in parameters}
    return function(*args, **supported)
