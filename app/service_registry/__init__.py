from __future__ import annotations

"""Domain-owned application service registry groups."""

from app.service_registry.catalog import APPLICATION_SERVICE_NAMES
from app.service_registry.collaboration import SERVICE_EXPORTS as COLLABORATION_EXPORTS
from app.service_registry.foundation import SERVICE_EXPORTS as FOUNDATION_EXPORTS, SERVICE_NAMES as FOUNDATION_NAMES
from app.service_registry.governance import SERVICE_EXPORTS as GOVERNANCE_EXPORTS, SERVICE_NAMES as GOVERNANCE_NAMES
from app.service_registry.repositories import SERVICE_EXPORTS as REPOSITORY_EXPORTS, SERVICE_NAMES as REPOSITORY_NAMES
from app.service_registry.runtime import SERVICE_EXPORTS as RUNTIME_EXPORTS, SERVICE_NAMES as RUNTIME_NAMES
from app.service_registry.workflow import SERVICE_EXPORTS as WORKFLOW_EXPORTS, SERVICE_NAMES as WORKFLOW_NAMES
from app.service_registry.common import merge_export_groups

SERVICE_EXPORT_GROUPS = (
    FOUNDATION_EXPORTS,
    REPOSITORY_EXPORTS,
    WORKFLOW_EXPORTS,
    GOVERNANCE_EXPORTS,
    RUNTIME_EXPORTS,
    COLLABORATION_EXPORTS,
)

__all__ = [
    "APPLICATION_SERVICE_NAMES",
    "SERVICE_EXPORT_GROUPS",
    "merge_export_groups",
]
