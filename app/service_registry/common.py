from __future__ import annotations

"""Shared helpers for explicit application service export groups."""

from collections.abc import Iterable, Mapping
from types import MappingProxyType
from typing import Any


def export_namespace(namespace: Mapping[str, Any], names: Iterable[str]) -> Mapping[str, Any]:
    """Build an immutable export map and fail fast on missing declarations."""
    ordered = tuple(names)
    missing = [name for name in ordered if name not in namespace]
    if missing:
        raise RuntimeError("application service declarations missing: " + ", ".join(missing))
    if len(set(ordered)) != len(ordered):
        raise RuntimeError("duplicate application service name inside export group")
    return MappingProxyType({name: namespace[name] for name in ordered})


def merge_export_groups(*groups: Mapping[str, Any]) -> dict[str, Any]:
    """Merge service groups while rejecting ambiguous ownership."""
    merged: dict[str, Any] = {}
    for group in groups:
        duplicates = sorted(set(merged).intersection(group))
        if duplicates:
            raise RuntimeError("application service export duplicated across groups: " + ", ".join(duplicates))
        merged.update(group)
    return merged
