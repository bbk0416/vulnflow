from __future__ import annotations

"""Collaboration application service exports."""

from app.services.collaboration_registry import COLLABORATION_SERVICE_EXPORTS

SERVICE_EXPORTS = COLLABORATION_SERVICE_EXPORTS
SERVICE_NAMES = tuple(SERVICE_EXPORTS)

__all__ = ["SERVICE_EXPORTS", "SERVICE_NAMES"]
