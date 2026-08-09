from __future__ import annotations

"""Governance application service exports."""

from app.service_registry.common import export_namespace
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
from app.services.recovery_operations import (
    external_project_backup_dir,
    list_external_recovery_bundles,
    list_local_recovery_bundles,
    list_recovery_drills,
    mirror_recovery_bundle,
    resolve_stored_recovery_bundle,
    run_recovery_drill,
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
    SbomError,
    VEX_JUSTIFICATIONS,
    VEX_RESPONSES,
    VEX_STATES,
    compare_cyclonedx,
    create_vex_revision,
    decide_sbom_finding_link,
    decide_vex_statement,
    export_cyclonedx_vex,
    get_sbom_document,
    get_vex_statement,
    list_sbom_documents,
    list_vex_approval_requests,
    parse_cyclonedx_json,
    reconcile_sbom_findings,
    request_vex_approval,
    store_cyclonedx_document,
    run_osv_scan,
    list_osv_scans,
    list_osv_matches,
    decide_osv_match,
)
from app.services.policies import (
    compare_policy_impact,
    parse_and_describe_policy,
    score_with_policy,
)
from app.services.osv import OsvError
from app.services.webhooks import (
    WebhookConfigError,
    deliver_due_events,
    parse_webhook_endpoints,
    queue_event,
)

SERVICE_NAMES = (
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
    'external_project_backup_dir',
    'list_external_recovery_bundles',
    'list_local_recovery_bundles',
    'list_recovery_drills',
    'mirror_recovery_bundle',
    'resolve_stored_recovery_bundle',
    'run_recovery_drill',
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
)
SERVICE_EXPORTS = export_namespace(globals(), SERVICE_NAMES)

__all__ = ["SERVICE_EXPORTS", "SERVICE_NAMES"]
