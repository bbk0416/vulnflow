from __future__ import annotations

"""Compatibility facade for finding write repositories.

Concrete ingestion/reconciliation, workflow/verification and risk-approval
operations live in dedicated repository modules. Existing imports from
``app.repositories.finding_writes`` remain supported.
"""

from app.repositories.finding_approvals import (
    APPROVAL_STATUSES,
    create_risk_approval_request,
    decide_risk_approval_request,
    get_risk_approval_request,
    list_risk_approval_requests,
)
from app.repositories.finding_ingestion import (
    apply_import_batch,
    get_source_reconciliation,
    list_import_batches,
    list_reconciliation_findings,
    list_source_finding_records,
    resolve_source_conflict,
    retire_source_conflict_resolution,
    update_scores,
    upsert_findings,
)
from app.repositories.finding_workflow import (
    RECORD_STATES,
    VERIFICATION_METHODS,
    VERIFICATION_STATUSES,
    _bulk_update_workflow_conn,
    _cancel_pending_verifications_conn,
    bulk_update_intel,
    bulk_update_workflow,
    create_remediation_verification_request,
    decide_remediation_verification_request,
    delete_all_findings,
    list_finding_observations,
    list_remediation_verification_requests,
    update_record_state,
    update_workflow,
)

__all__ = [
    "APPROVAL_STATUSES",
    "RECORD_STATES",
    "VERIFICATION_METHODS",
    "VERIFICATION_STATUSES",
    "_bulk_update_workflow_conn",
    "_cancel_pending_verifications_conn",
    "apply_import_batch",
    "bulk_update_intel",
    "bulk_update_workflow",
    "create_remediation_verification_request",
    "create_risk_approval_request",
    "decide_remediation_verification_request",
    "decide_risk_approval_request",
    "delete_all_findings",
    "get_risk_approval_request",
    "get_source_reconciliation",
    "list_finding_observations",
    "list_import_batches",
    "list_reconciliation_findings",
    "list_remediation_verification_requests",
    "list_risk_approval_requests",
    "list_source_finding_records",
    "resolve_source_conflict",
    "retire_source_conflict_resolution",
    "update_record_state",
    "update_scores",
    "update_workflow",
    "upsert_findings",
]
