from __future__ import annotations

"""Compatibility facade for VulnFlow persistence APIs.

Concrete schema initialization, campaign persistence and database lifecycle
operations live in dedicated modules. Existing imports from app.core.storage
remain supported while new code should import the owning module directly.
"""

from app.core.db import ConcurrencyError, connect, utc_now
from app.core.fields import SCORE_FIELDS
from app.services.asset_identity import append_identifier as _append_identifier, extract_asset_identifiers
from app.repositories.assets import get_asset, list_assets, list_exposure_groups
from app.repositories.reconciliation import (
    FIELDS, RECONCILABLE_FIELDS, SOURCE_SNAPSHOT_FIELDS,
    _active_reconciliation_values, _aggregate_canonical_row, _apply_authoritative_asset_context,
    _asset_ref_from_identifiers, _candidate_pair, _canonical_conflicts,
    _create_asset_identity_candidate_conn, _load_source_records_conn,
    _register_asset_identifiers_conn, _resolve_asset_identity_conn,
    _score_canonical_from_active_policy, _source_snapshot, _sync_asset_row,
    asset_ref_id_for, canonical_key_for, source_record_id_for,
)
from app.repositories.asset_identity_writes import (
    add_asset_identifier, get_asset_identity_candidate, list_asset_identifiers,
    list_asset_identity_candidates, reject_asset_identity_candidate,
)
from app.repositories.asset_inventory import (
    ASSET_STATUSES, _resolve_inventory_asset_ref_conn, apply_asset_inventory,
    extract_inventory_identifiers,
)
from app.repositories.asset_merge import (
    ASSET_MERGE_REQUEST_STATUSES, _asset_merge_impact_conn, _asset_merge_impact_digest,
    _decode_asset_merge_request, _merge_assets_conn, _persist_canonical_aggregate_conn,
    _preflight_asset_merge_request_conn, analyze_asset_merge, approve_asset_merge_request,
    create_asset_merge_request, get_asset_merge_request, list_asset_merge_history,
    list_asset_merge_requests, merge_assets, preflight_asset_merge_request,
    reject_asset_merge_request,
)
from app.repositories.asset_merge_rollback import (
    ASSET_MERGE_ROLLBACK_REQUEST_STATUSES, _asset_merge_rollback_impact_conn,
    _decode_asset_merge_rollback_journal, _decode_asset_merge_rollback_request,
    _preflight_asset_merge_rollback_request_conn, analyze_asset_merge_rollback,
    approve_asset_merge_rollback_request, create_asset_merge_rollback_request,
    get_asset_merge_rollback_request, list_asset_merge_rollback_requests,
    reject_asset_merge_rollback_request,
)
from app.repositories.finding_approvals import (
    APPROVAL_STATUSES, create_risk_approval_request, decide_risk_approval_request,
    get_risk_approval_request, list_risk_approval_requests,
)
from app.repositories.finding_ingestion import (
    apply_import_batch, get_source_reconciliation, list_import_batches,
    list_reconciliation_findings, list_source_finding_records, resolve_source_conflict,
    retire_source_conflict_resolution, update_scores, upsert_findings,
)
from app.repositories.finding_workflow import (
    RECORD_STATES, VERIFICATION_METHODS, VERIFICATION_STATUSES,
    _bulk_update_workflow_conn, _cancel_pending_verifications_conn,
    bulk_update_intel, bulk_update_workflow, create_remediation_verification_request,
    decide_remediation_verification_request, delete_all_findings,
    list_finding_observations, list_remediation_verification_requests,
    update_record_state, update_workflow,
)
from app.repositories.findings import count_findings, get_finding, list_findings
from app.repositories.policies import (
    POLICY_REQUEST_STATUSES, POLICY_STATUSES, approve_policy_activation_request,
    create_policy_activation_request, create_policy_version, get_active_policy_version,
    get_policy_activation_request, get_policy_version, list_policy_activation_requests,
    list_policy_versions, reject_policy_activation_request,
)
from app.repositories.audit import (
    AUDIT_GENESIS_HASH, _audit_event_digest, _canonical_audit_details, add_audit_event,
    create_audit_checkpoint, list_audit_checkpoints, list_audit_events,
    list_audit_prune_history, prune_audit_prefix, verify_audit_integrity,
)
from app.repositories.cluster import (
    acquire_cluster_lease, active_cluster_lease, begin_cluster_write_activity,
    count_cluster_write_activities, deregister_cluster_instance, end_cluster_write_activity,
    get_cluster_instance, get_cluster_lease, heartbeat_cluster_instance,
    list_cluster_instances, list_cluster_leases, list_cluster_write_activities,
    prune_stale_cluster_instances, prune_stale_cluster_write_activities,
    register_cluster_instance, release_cluster_lease, renew_cluster_lease,
)
from app.repositories.job_execution import (
    claim_background_job, complete_background_job, fail_background_job, heartbeat_background_job,
)
from app.repositories.job_records import (
    JOB_TYPES, count_active_background_jobs, create_background_job, get_background_job,
    list_background_jobs, purge_background_jobs, request_background_job_cancel, retry_background_job,
)
from app.repositories.execution_receipts import (
    count_execution_receipts, get_execution_receipt, list_execution_receipts,
    record_execution_receipt, replay_execution_receipt,
)
from app.repositories.execution_receipt_retention import (
    archive_execution_receipts, list_execution_receipt_archives,
)
from app.repositories.idempotency import (
    IdempotencyConflict, canonical_json as canonical_idempotency_json,
    count_idempotency_records, key_sha256 as idempotency_key_sha256, purge_expired_idempotency_records,
    replay_result as replay_idempotency_result, request_sha256 as idempotency_request_sha256,
    store_result as store_idempotency_result,
)
from app.repositories.webhook_delivery import list_due_webhook_events, record_webhook_delivery
from app.repositories.webhook_queue import (
    WEBHOOK_STATUSES, count_pending_webhooks, enqueue_webhook_events, list_webhook_events,
    retry_webhook_event,
)


from app.core.database_schema import (
    CURRENT_APP_VERSION, CURRENT_SCHEMA_VERSION, _initialize_sqlite_database,
    get_schema_info, init_coordination_db, init_db,
)
from app.core.schema import COORDINATION_SCHEMA, MIGRATION_COLUMNS, SCHEMA
from app.repositories.campaigns import (
    CAMPAIGN_STATUSES, add_campaign_findings, create_campaign, get_campaign, list_campaigns,
    remove_campaign_finding, update_campaign_status,
)
from app.services.database_lifecycle import (
    backup_database, list_maintenance_runs, restore_database, validate_database_file,
)

JOB_STATUSES = {"PENDING", "RETRY", "RUNNING", "SUCCEEDED", "FAILED", "CANCELLED"}
