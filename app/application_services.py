from __future__ import annotations

"""Application composition service registry.

This module is the explicit composition root for repository and domain service
objects historically re-exported from :mod:`app.main`.  Keeping these imports
out of the ASGI entrypoint reduces change fan-out while preserving the legacy
attribute surface and router dependency injection contract.
"""

from collections.abc import MutableMapping
import hashlib
import json
from types import MappingProxyType
from typing import Any

from app.core.auth import authenticate_request, has_role, parse_accounts, parse_api_tokens
from app.core.observability import Metrics, REQUEST_ID_RE, configure_json_logging
from app.core.signing import build_signing_config, collect_signing_key_usage
from app.core.public_signing import build_ed25519_signing_config
from app.core.scoring import (
    ACTIVE_STATUSES,
    ALLOWED_STATUSES,
    as_bool,
    exception_state,
    is_overdue,
    load_policy,
    parse_policy_text,
    policy_digest,
    parse_date,
    prioritize_finding,
)
from app.core.database_schema import CURRENT_APP_VERSION, CURRENT_SCHEMA_VERSION, get_schema_info, init_coordination_db, init_db
from app.core.db import ConcurrencyError, utc_now
from app.repositories.asset_identity_writes import (
    add_asset_identifier,
    get_asset_identity_candidate,
    list_asset_identifiers,
    list_asset_identity_candidates,
    reject_asset_identity_candidate,
)
from app.repositories.asset_inventory import apply_asset_inventory
from app.repositories.asset_merge import (
    analyze_asset_merge,
    approve_asset_merge_request,
    create_asset_merge_request,
    get_asset_merge_request,
    list_asset_merge_history,
    list_asset_merge_requests,
    preflight_asset_merge_request,
    reject_asset_merge_request,
)
from app.repositories.asset_merge_rollback import (
    analyze_asset_merge_rollback,
    approve_asset_merge_rollback_request,
    create_asset_merge_rollback_request,
    get_asset_merge_rollback_request,
    list_asset_merge_rollback_requests,
    reject_asset_merge_rollback_request,
)
from app.repositories.assets import get_asset, list_assets, list_exposure_groups
from app.repositories.audit import (
    create_audit_checkpoint,
    list_audit_checkpoints,
    list_audit_events,
    list_audit_prune_history,
    verify_audit_integrity,
)
from app.repositories.campaigns import (
    add_campaign_findings,
    create_campaign,
    get_campaign,
    list_campaigns,
    remove_campaign_finding,
    update_campaign_status,
)
from app.repositories.cluster import (
    acquire_cluster_lease,
    active_cluster_lease,
    begin_cluster_write_activity,
    count_cluster_write_activities,
    deregister_cluster_instance,
    end_cluster_write_activity,
    get_cluster_instance,
    get_cluster_lease,
    heartbeat_cluster_instance,
    list_cluster_instances,
    list_cluster_leases,
    list_cluster_write_activities,
    prune_stale_cluster_instances,
    prune_stale_cluster_write_activities,
    register_cluster_instance,
    release_cluster_lease,
)
from app.repositories.execution_receipt_retention import list_execution_receipt_archives
from app.repositories.execution_receipts import (
    count_execution_receipts,
    get_execution_receipt,
    list_execution_receipts,
    replay_execution_receipt,
)
from app.repositories.finding_approvals import (
    create_risk_approval_request,
    decide_risk_approval_request,
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
from app.repositories.findings import count_findings, get_finding, list_findings
from app.repositories.idempotency import IdempotencyConflict, count_idempotency_records
from app.repositories.job_execution import (
    claim_background_job, complete_background_job, fail_background_job,
    heartbeat_background_job,
)
from app.repositories.job_records import (
    count_active_background_jobs, create_background_job, get_background_job,
    list_background_jobs, purge_background_jobs, request_background_job_cancel,
    retry_background_job,
)
from app.repositories.policies import (
    approve_policy_activation_request,
    create_policy_activation_request,
    create_policy_version,
    get_active_policy_version,
    get_policy_activation_request,
    get_policy_version,
    list_policy_activation_requests,
    list_policy_versions,
    reject_policy_activation_request,
)
from app.repositories.webhook_queue import count_pending_webhooks, list_webhook_events, retry_webhook_event
from app.services.database_lifecycle import backup_database, list_maintenance_runs, restore_database, validate_database_file
from app.services.evidence import (
    get_evidence_artifact,
    list_evidence_artifacts,
    resolve_evidence_path,
    retire_evidence_artifact,
    store_verification_evidence,
    scan_evidence_artifact,
    waive_evidence_scan,
    evidence_download_allowed,
    verify_evidence_artifact,
    verify_evidence_store,
    list_evidence_custody_events,
    verify_evidence_custody_chain,
    transfer_evidence_custody,
    record_evidence_access,
)
from app.services.intel import IntelligenceError, fetch_epss, fetch_kev_catalog
from app.services.maintenance import record_maintenance_failure, run_maintenance
from app.services.database_maintenance import database_health, list_database_maintenance_runs, run_database_maintenance
from app.services.report import generate_html_report, report_summary
from app.services.finding_query import finding_summary, list_scanner_sources, operational_counts, query_findings
from app.services.exports import (
    create_findings_csv_export,
    enforce_export_storage_budget,
    expire_export_artifact,
    export_storage_status,
    get_export_artifact,
    list_export_artifacts,
    mark_export_artifact_corrupt,
    purge_expired_export_artifacts,
    reconcile_export_artifacts,
    record_export_download,
    resolve_export_artifact_path,
    set_export_artifact_pinned,
    stream_findings_csv,
    verify_export_artifact,
)
from app.services.integrity_proof_bundle import create_integrity_proof_bundle
from app.services.integrity_proof_verifier import verify_integrity_proof_bundle
from app.services.proof_transitions import (
    create_integrity_proof_key_transition,
    export_integrity_proof_key_transitions,
    list_integrity_proof_key_transitions,
)
from app.services.proof_revocation import (
    create_integrity_proof_key_revocation,
    export_integrity_proof_key_revocations,
    list_integrity_proof_key_revocations,
)
from app.services.proof_checkpoint import (
    create_integrity_proof_revocation_checkpoint,
    export_integrity_proof_revocation_checkpoints,
    list_integrity_proof_revocation_checkpoints,
)
from app.services.proof_witness import (
    create_integrity_proof_checkpoint_witness,
    export_integrity_proof_checkpoint_witnesses,
    list_integrity_proof_checkpoint_witnesses,
)
from app.services.proof_transparency import (
    export_integrity_proof_transparency_entries,
    export_integrity_proof_transparency_heads,
    list_integrity_proof_transparency_entries,
    list_integrity_proof_transparency_heads,
    publish_integrity_proof_transparency_head,
)
from app.services.proof_mirror import (
    create_integrity_proof_transparency_mirror_receipt,
    export_integrity_proof_transparency_mirror_receipts,
    list_integrity_proof_transparency_mirror_receipts,
)
from app.services.proof_consistency import (
    create_integrity_proof_mirror_consistency_checkpoint,
    export_integrity_proof_mirror_consistency_checkpoints,
    list_integrity_proof_mirror_consistency_checkpoints,
)
from app.services.recovery import (
    build_config_audit,
    create_recovery_bundle,
    create_scheduled_recovery_bundle,
    list_recovery_bundles,
    restore_recovery_bundle,
    validate_recovery_bundle,
)
from app.services.config_drift import (
    create_baseline,
    evaluate_drift,
    list_baselines,
    list_drift_checks,
    record_drift_check,
)
from app.services.config_changes import (
    change_control_counts,
    create_change_request,
    decide_change_request,
    evaluate_change_control,
    get_change_request,
    list_change_requests,
    promote_change_request,
)
from app.services.sbom import (
    SbomError, VEX_JUSTIFICATIONS, VEX_RESPONSES, VEX_STATES, compare_cyclonedx,
    create_vex_revision, decide_sbom_finding_link, decide_vex_statement, export_cyclonedx_vex, get_sbom_document,
    get_vex_statement, list_sbom_documents, list_vex_approval_requests, parse_cyclonedx_json,
    reconcile_sbom_findings, request_vex_approval, store_cyclonedx_document,
    run_osv_scan, list_osv_scans, list_osv_matches, decide_osv_match,
)
from app.services.policies import compare_policy_impact, parse_and_describe_policy, score_with_policy
from app.services.osv import OsvError
from app.services.webhooks import (
    WebhookConfigError, deliver_due_events, parse_webhook_endpoints, queue_event,
)
from app.services.job_dispatch import execute_background_job as execute_background_job_for_context
from app.services.job_worker_runtime import job_worker_loop as context_job_worker_loop
from app.services.lifecycle_runtime import (
    LifecycleSupervisor,
    backup_loop as context_backup_loop,
    cluster_snapshot as context_cluster_snapshot,
    coordination_db_path as context_coordination_db_path,
    coordination_loop as context_coordination_loop,
    coordination_tick as context_coordination_tick,
    instance_capabilities as context_instance_capabilities,
    is_scheduler_leader as context_is_scheduler_leader,
    maintenance_loop as context_maintenance_loop,
    restore_in_progress as context_restore_in_progress,
    webhook_loop as context_webhook_loop,
)
from app.services.operation_guard import (
    WriteBarrierActive,
    bind_operation_guard,
)
from app.core.transactions import transaction_scope

APPLICATION_SERVICE_NAMES = (
    'authenticate_request',
    'has_role',
    'parse_accounts',
    'parse_api_tokens',
    'Metrics',
    'REQUEST_ID_RE',
    'configure_json_logging',
    'build_signing_config',
    'collect_signing_key_usage',
    'build_ed25519_signing_config',
    'ACTIVE_STATUSES',
    'ALLOWED_STATUSES',
    'as_bool',
    'exception_state',
    'is_overdue',
    'load_policy',
    'parse_policy_text',
    'policy_digest',
    'parse_date',
    'prioritize_finding',
    'CURRENT_APP_VERSION',
    'CURRENT_SCHEMA_VERSION',
    'get_schema_info',
    'init_coordination_db',
    'init_db',
    'ConcurrencyError',
    'utc_now',
    'add_asset_identifier',
    'analyze_asset_merge',
    'analyze_asset_merge_rollback',
    'apply_asset_inventory',
    'approve_asset_merge_request',
    'approve_asset_merge_rollback_request',
    'create_asset_merge_request',
    'create_asset_merge_rollback_request',
    'get_asset_identity_candidate',
    'get_asset_merge_request',
    'get_asset_merge_rollback_request',
    'list_asset_identifiers',
    'list_asset_identity_candidates',
    'list_asset_merge_history',
    'list_asset_merge_requests',
    'list_asset_merge_rollback_requests',
    'preflight_asset_merge_request',
    'reject_asset_identity_candidate',
    'reject_asset_merge_request',
    'reject_asset_merge_rollback_request',
    'get_asset',
    'list_assets',
    'list_exposure_groups',
    'create_audit_checkpoint',
    'list_audit_checkpoints',
    'list_audit_events',
    'list_audit_prune_history',
    'verify_audit_integrity',
    'add_campaign_findings',
    'create_campaign',
    'get_campaign',
    'list_campaigns',
    'remove_campaign_finding',
    'update_campaign_status',
    'acquire_cluster_lease',
    'active_cluster_lease',
    'begin_cluster_write_activity',
    'count_cluster_write_activities',
    'deregister_cluster_instance',
    'end_cluster_write_activity',
    'get_cluster_instance',
    'get_cluster_lease',
    'heartbeat_cluster_instance',
    'list_cluster_instances',
    'list_cluster_leases',
    'list_cluster_write_activities',
    'prune_stale_cluster_instances',
    'prune_stale_cluster_write_activities',
    'register_cluster_instance',
    'release_cluster_lease',
    'list_execution_receipt_archives',
    'count_execution_receipts',
    'get_execution_receipt',
    'list_execution_receipts',
    'replay_execution_receipt',
    'apply_import_batch',
    'bulk_update_intel',
    'bulk_update_workflow',
    'create_remediation_verification_request',
    'create_risk_approval_request',
    'decide_remediation_verification_request',
    'decide_risk_approval_request',
    'delete_all_findings',
    'get_source_reconciliation',
    'list_finding_observations',
    'list_import_batches',
    'list_reconciliation_findings',
    'list_remediation_verification_requests',
    'list_risk_approval_requests',
    'list_source_finding_records',
    'resolve_source_conflict',
    'retire_source_conflict_resolution',
    'update_record_state',
    'update_scores',
    'update_workflow',
    'upsert_findings',
    'count_findings',
    'get_finding',
    'list_findings',
    'IdempotencyConflict',
    'count_idempotency_records',
    'claim_background_job',
    'complete_background_job',
    'count_active_background_jobs',
    'create_background_job',
    'fail_background_job',
    'get_background_job',
    'heartbeat_background_job',
    'list_background_jobs',
    'purge_background_jobs',
    'request_background_job_cancel',
    'retry_background_job',
    'approve_policy_activation_request',
    'create_policy_activation_request',
    'create_policy_version',
    'get_active_policy_version',
    'get_policy_activation_request',
    'get_policy_version',
    'list_policy_activation_requests',
    'list_policy_versions',
    'reject_policy_activation_request',
    'count_pending_webhooks',
    'list_webhook_events',
    'retry_webhook_event',
    'backup_database',
    'list_maintenance_runs',
    'restore_database',
    'validate_database_file',
    'get_evidence_artifact',
    'list_evidence_artifacts',
    'resolve_evidence_path',
    'retire_evidence_artifact',
    'store_verification_evidence',
    'scan_evidence_artifact',
    'waive_evidence_scan',
    'evidence_download_allowed',
    'verify_evidence_artifact',
    'verify_evidence_store',
    'list_evidence_custody_events',
    'verify_evidence_custody_chain',
    'transfer_evidence_custody',
    'record_evidence_access',
    'IntelligenceError',
    'fetch_epss',
    'fetch_kev_catalog',
    'record_maintenance_failure',
    'run_maintenance',
    'database_health',
    'list_database_maintenance_runs',
    'run_database_maintenance',
    'generate_html_report',
    'report_summary',
    'finding_summary',
    'list_scanner_sources',
    'operational_counts',
    'query_findings',
    'create_findings_csv_export',
    'enforce_export_storage_budget',
    'expire_export_artifact',
    'export_storage_status',
    'get_export_artifact',
    'list_export_artifacts',
    'mark_export_artifact_corrupt',
    'purge_expired_export_artifacts',
    'reconcile_export_artifacts',
    'record_export_download',
    'resolve_export_artifact_path',
    'set_export_artifact_pinned',
    'stream_findings_csv',
    'verify_export_artifact',
    'create_integrity_proof_bundle',
    'verify_integrity_proof_bundle',
    'create_integrity_proof_key_transition',
    'export_integrity_proof_key_transitions',
    'list_integrity_proof_key_transitions',
    'create_integrity_proof_key_revocation',
    'export_integrity_proof_key_revocations',
    'list_integrity_proof_key_revocations',
    'create_integrity_proof_revocation_checkpoint',
    'export_integrity_proof_revocation_checkpoints',
    'list_integrity_proof_revocation_checkpoints',
    'create_integrity_proof_checkpoint_witness',
    'export_integrity_proof_checkpoint_witnesses',
    'list_integrity_proof_checkpoint_witnesses',
    'export_integrity_proof_transparency_entries',
    'export_integrity_proof_transparency_heads',
    'list_integrity_proof_transparency_entries',
    'list_integrity_proof_transparency_heads',
    'publish_integrity_proof_transparency_head',
    'create_integrity_proof_transparency_mirror_receipt',
    'export_integrity_proof_transparency_mirror_receipts',
    'list_integrity_proof_transparency_mirror_receipts',
    'create_integrity_proof_mirror_consistency_checkpoint',
    'export_integrity_proof_mirror_consistency_checkpoints',
    'list_integrity_proof_mirror_consistency_checkpoints',
    'build_config_audit',
    'create_recovery_bundle',
    'create_scheduled_recovery_bundle',
    'list_recovery_bundles',
    'restore_recovery_bundle',
    'validate_recovery_bundle',
    'create_baseline',
    'evaluate_drift',
    'list_baselines',
    'list_drift_checks',
    'record_drift_check',
    'change_control_counts',
    'create_change_request',
    'decide_change_request',
    'evaluate_change_control',
    'get_change_request',
    'list_change_requests',
    'promote_change_request',
    'SbomError',
    'VEX_JUSTIFICATIONS',
    'VEX_RESPONSES',
    'VEX_STATES',
    'compare_cyclonedx',
    'create_vex_revision',
    'decide_sbom_finding_link',
    'decide_vex_statement',
    'export_cyclonedx_vex',
    'get_sbom_document',
    'get_vex_statement',
    'list_sbom_documents',
    'list_vex_approval_requests',
    'parse_cyclonedx_json',
    'reconcile_sbom_findings',
    'request_vex_approval',
    'store_cyclonedx_document',
    'run_osv_scan',
    'list_osv_scans',
    'list_osv_matches',
    'decide_osv_match',
    'compare_policy_impact',
    'parse_and_describe_policy',
    'score_with_policy',
    'OsvError',
    'WebhookConfigError',
    'deliver_due_events',
    'parse_webhook_endpoints',
    'queue_event',
    'execute_background_job_for_context',
    'context_job_worker_loop',
    'LifecycleSupervisor',
    'context_backup_loop',
    'context_cluster_snapshot',
    'context_coordination_db_path',
    'context_coordination_loop',
    'context_coordination_tick',
    'context_instance_capabilities',
    'context_is_scheduler_leader',
    'context_maintenance_loop',
    'context_restore_in_progress',
    'context_webhook_loop',
    'WriteBarrierActive',
    'bind_operation_guard',
    'transaction_scope',
)

_APPLICATION_SERVICE_EXPORTS = {name: globals()[name] for name in APPLICATION_SERVICE_NAMES}
APPLICATION_SERVICE_EXPORTS = MappingProxyType(_APPLICATION_SERVICE_EXPORTS)


def install_application_services(namespace: MutableMapping[str, Any]) -> dict[str, Any]:
    """Install the canonical application services into a compatibility namespace.

    Existing names may only be reused when they point at the same object.  This
    prevents silent shadowing while allowing deterministic module reloads.
    """
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
