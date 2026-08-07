from __future__ import annotations

"""Stable composition root for domain-owned application service registries."""

from collections.abc import MutableMapping
import hashlib
import json
from types import MappingProxyType
from typing import Any

from app.service_registry import (
    APPLICATION_SERVICE_NAMES,
    SERVICE_EXPORT_GROUPS,
    merge_export_groups,
)

_APPLICATION_SERVICE_EXPORTS = merge_export_groups(*SERVICE_EXPORT_GROUPS)
missing_service_names = sorted(set(APPLICATION_SERVICE_NAMES) - set(_APPLICATION_SERVICE_EXPORTS))
if missing_service_names:
    raise RuntimeError("application service catalog entries missing: " + ", ".join(missing_service_names))
APPLICATION_SERVICE_EXPORTS = MappingProxyType(_APPLICATION_SERVICE_EXPORTS)


def install_application_services(namespace: MutableMapping[str, Any]) -> dict[str, Any]:
    """Install services while rejecting incompatible name collisions."""
    for name, value in APPLICATION_SERVICE_EXPORTS.items():
        existing = namespace.get(name)
        if existing is not None and existing is not value:
            raise RuntimeError(f"application service export collision: {name}")
        namespace[name] = value
    return dict(APPLICATION_SERVICE_EXPORTS)


def application_service_snapshot() -> dict[str, Any]:
    """Return non-secret structural metadata for architecture diagnostics."""
    names = sorted(APPLICATION_SERVICE_EXPORTS)
    payload = json.dumps(names, ensure_ascii=False, separators=(",", ":"))
    return {
        "service_export_count": len(names),
        "service_export_names": names,
        "service_export_name_sha256": hashlib.sha256(payload.encode("utf-8")).hexdigest(),
    }


__all__ = [
    "APPLICATION_SERVICE_EXPORTS",
    "APPLICATION_SERVICE_NAMES",
    "application_service_snapshot",
    "install_application_services",
]
