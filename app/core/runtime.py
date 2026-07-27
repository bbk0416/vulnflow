from __future__ import annotations

"""Immutable runtime settings and dependency containers.

The containers copy their source mappings and expose read-only views.  Secret
values are never returned by diagnostic helpers.  The legacy ``app.main``
namespace can still be overlaid by :class:`ApplicationContext` while tests and
local integrations migrate to explicit dependencies.
"""

from dataclasses import dataclass
import hashlib
import json
from types import MappingProxyType
from typing import Any, Iterable, Mapping

_SECRET_MARKERS = ("PASSWORD", "TOKEN", "SECRET", "SIGNING_KEY", "PRIVATE_KEY", "USERS_JSON")


def _readonly(values: Mapping[str, Any]) -> Mapping[str, Any]:
    return MappingProxyType(dict(values))


def _is_secret_name(name: str) -> bool:
    upper = str(name).upper()
    return any(marker in upper for marker in _SECRET_MARKERS)


@dataclass(frozen=True, slots=True)
class RuntimeSettings:
    """Immutable snapshot of environment-derived application settings."""

    values: Mapping[str, Any]

    def __post_init__(self) -> None:
        object.__setattr__(self, "values", _readonly(self.values))

    @classmethod
    def from_namespace(cls, namespace: Mapping[str, Any]) -> "RuntimeSettings":
        return cls({name: value for name, value in namespace.items() if name.isupper()})

    def get(self, name: str, default: Any = None) -> Any:
        return self.values.get(name, default)

    def require(self, name: str) -> Any:
        if name not in self.values:
            raise KeyError(f"runtime setting is missing: {name}")
        return self.values[name]

    def as_dict(self) -> dict[str, Any]:
        return dict(self.values)

    def with_overrides(self, overrides: Mapping[str, Any] | None = None) -> "RuntimeSettings":
        merged = self.as_dict()
        for name, value in dict(overrides or {}).items():
            if not str(name).isupper():
                raise ValueError(f"runtime setting names must be uppercase: {name}")
            merged[str(name)] = value
        return RuntimeSettings(merged)

    def structural_snapshot(self) -> dict[str, Any]:
        names = sorted(self.values)
        payload = json.dumps(names, ensure_ascii=False, separators=(",", ":"))
        return {
            "setting_names": names,
            "setting_count": len(names),
            "protected_setting_count": sum(_is_secret_name(name) for name in names),
            "name_fingerprint": hashlib.sha256(payload.encode("utf-8")).hexdigest(),
        }


@dataclass(frozen=True, slots=True)
class ServiceContainer:
    """Immutable mapping of application service dependencies.

    The container intentionally stores objects by name so the historical route
    modules can be injected without importing ``app.main``.  Creating an
    overridden container returns a new object and never mutates the original.
    """

    services: Mapping[str, Any]

    def __post_init__(self) -> None:
        object.__setattr__(self, "services", _readonly(self.services))

    @classmethod
    def from_namespace(
        cls,
        namespace: Mapping[str, Any],
        *,
        exclude: Iterable[str] = ("app",),
    ) -> "ServiceContainer":
        excluded = set(exclude)
        return cls(
            {
                name: value
                for name, value in namespace.items()
                if not name.startswith("__") and not name.isupper() and name not in excluded
            }
        )

    def get(self, name: str, default: Any = None) -> Any:
        return self.services.get(name, default)

    def require(self, name: str) -> Any:
        if name not in self.services:
            raise KeyError(f"service dependency is missing: {name}")
        return self.services[name]

    def as_dict(self) -> dict[str, Any]:
        return dict(self.services)

    def with_overrides(self, overrides: Mapping[str, Any] | None = None) -> "ServiceContainer":
        merged = self.as_dict()
        merged.update(dict(overrides or {}))
        return ServiceContainer(merged)

    def structural_snapshot(self) -> dict[str, Any]:
        names = sorted(self.services)
        return {
            "service_names": names,
            "service_count": len(names),
        }
