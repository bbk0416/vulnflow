from __future__ import annotations

"""Composition exports for project collaboration services."""

from types import MappingProxyType

from app.repositories.collaboration import (
    count_pending_collaboration_events,
    get_finding_external_link,
    get_integration,
    list_collaboration_events,
    list_integrations,
    save_integration,
)
from app.services.collaboration import (
    CollaborationConfigError,
    deliver_collaboration_events,
    queue_event_for_integrations,
    queue_jira_issue_create,
    validate_email_config,
    validate_jira_config,
)
from app.services.integration_crypto import IntegrationSecretError, encrypt_secret
from app.services.integration_diagnostics import diagnose_saved_integration

COLLABORATION_SERVICE_EXPORTS = MappingProxyType({
    name: value
    for name, value in {
        "CollaborationConfigError": CollaborationConfigError,
        "IntegrationSecretError": IntegrationSecretError,
        "count_pending_collaboration_events": count_pending_collaboration_events,
        "get_finding_external_link": get_finding_external_link,
        "get_integration": get_integration,
        "list_collaboration_events": list_collaboration_events,
        "list_integrations": list_integrations,
        "save_integration": save_integration,
        "deliver_collaboration_events": deliver_collaboration_events,
        "queue_event_for_integrations": queue_event_for_integrations,
        "queue_jira_issue_create": queue_jira_issue_create,
        "validate_email_config": validate_email_config,
        "validate_jira_config": validate_jira_config,
        "encrypt_secret": encrypt_secret,
        "diagnose_saved_integration": diagnose_saved_integration,
    }.items()
})
