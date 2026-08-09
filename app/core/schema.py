from __future__ import annotations

"""SQLite schema declarations and compatibility columns.

Kept separate from storage operations so schema review does not require
navigating transactional domain logic.
"""

SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT PRIMARY KEY,
    product TEXT NOT NULL,
    product_version TEXT,
    asset_id TEXT,
    asset_ref_id TEXT,
    asset_name TEXT,
    environment TEXT,
    cve_id TEXT NOT NULL,
    component TEXT,
    component_version TEXT,
    cvss REAL DEFAULT 0,
    epss REAL DEFAULT 0,
    epss_percentile REAL DEFAULT 0,
    kev INTEGER DEFAULT 0,
    internet_exposed INTEGER DEFAULT 0,
    asset_criticality INTEGER DEFAULT 1,
    data_sensitivity INTEGER DEFAULT 1,
    patch_available INTEGER DEFAULT 0,
    compensating_control INTEGER DEFAULT 0,
    status TEXT DEFAULT 'OPEN',
    owner TEXT,
    due_date TEXT,
    exception_expiry TEXT,
    risk_acceptance_reason TEXT,
    risk_acceptance_approver TEXT,
    notes TEXT,
    intel_source TEXT DEFAULT 'manual',
    intel_updated_at TEXT,
    score INTEGER DEFAULT 0,
    threat_score INTEGER DEFAULT 0,
    asset_context_score INTEGER DEFAULT 0,
    remediation_urgency_score INTEGER DEFAULT 0,
    decision TEXT,
    decision_label TEXT,
    sla_days INTEGER,
    target_date TEXT,
    mitigation_required INTEGER DEFAULT 0,
    reasons TEXT,
    policy_version TEXT,
    policy_id TEXT,
    first_seen_at TEXT,
    first_scored_at TEXT,
    last_scored_at TEXT,
    resolved_at TEXT,
    scanner_source TEXT DEFAULT 'manual',
    source_last_seen_at TEXT,
    record_state TEXT DEFAULT 'ACTIVE',
    stale_since TEXT,
    archived_at TEXT,
    import_batch_id TEXT,
    canonical_key TEXT,
    source_count INTEGER NOT NULL DEFAULT 1,
    source_conflict_count INTEGER NOT NULL DEFAULT 0,
    merged_into_finding_id TEXT,
    resolution_state TEXT NOT NULL DEFAULT 'UNVERIFIED',
    resolution_requested_at TEXT,
    verified_at TEXT,
    verified_by TEXT,
    verification_method TEXT,
    verification_note TEXT,
    consecutive_absent_scans INTEGER NOT NULL DEFAULT 0,
    last_reopened_at TEXT,
    reopen_count INTEGER NOT NULL DEFAULT 0,
    row_version INTEGER DEFAULT 1,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS import_batches (
    batch_id TEXT PRIMARY KEY,
    scanner_source TEXT NOT NULL,
    filename TEXT,
    import_mode TEXT NOT NULL,
    row_count INTEGER NOT NULL DEFAULT 0,
    inserted_count INTEGER NOT NULL DEFAULT 0,
    updated_count INTEGER NOT NULL DEFAULT 0,
    stale_count INTEGER NOT NULL DEFAULT 0,
    actor TEXT DEFAULT 'local-user',
    created_at TEXT NOT NULL,
    source_job_id TEXT
);

CREATE TABLE IF NOT EXISTS source_finding_records (
    source_record_id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL,
    scanner_source TEXT NOT NULL,
    source_finding_id TEXT NOT NULL,
    canonical_key TEXT NOT NULL,
    observed_state TEXT NOT NULL DEFAULT 'PRESENT',
    consecutive_absent_scans INTEGER NOT NULL DEFAULT 0,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    last_batch_id TEXT,
    snapshot_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(finding_id) REFERENCES findings(finding_id) ON DELETE CASCADE,
    FOREIGN KEY(last_batch_id) REFERENCES import_batches(batch_id) ON DELETE SET NULL,
    UNIQUE(scanner_source, source_finding_id)
);

CREATE TABLE IF NOT EXISTS finding_reconciliation_decisions (
    decision_id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL,
    field_name TEXT NOT NULL,
    chosen_value_json TEXT NOT NULL,
    chosen_source_record_id TEXT,
    reason TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    retired_by TEXT,
    retired_at TEXT,
    FOREIGN KEY(finding_id) REFERENCES findings(finding_id) ON DELETE CASCADE,
    FOREIGN KEY(chosen_source_record_id) REFERENCES source_finding_records(source_record_id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id TEXT,
    event_type TEXT NOT NULL,
    actor TEXT DEFAULT 'local-user',
    summary TEXT NOT NULL,
    details_json TEXT,
    created_at TEXT NOT NULL,
    chain_seq INTEGER,
    prev_hash TEXT,
    event_hash TEXT
);

CREATE TABLE IF NOT EXISTS audit_chain_state (
    singleton_id INTEGER PRIMARY KEY CHECK(singleton_id=1),
    anchor_seq INTEGER NOT NULL DEFAULT 0,
    anchor_hash TEXT NOT NULL,
    last_seq INTEGER NOT NULL DEFAULT 0,
    last_hash TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_checkpoints (
    checkpoint_id TEXT PRIMARY KEY,
    chain_seq INTEGER NOT NULL,
    event_hash TEXT NOT NULL,
    signature TEXT,
    key_id TEXT,
    algorithm TEXT NOT NULL DEFAULT 'HMAC-SHA256',
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_prune_history (
    prune_id TEXT PRIMARY KEY,
    from_seq INTEGER NOT NULL,
    to_seq INTEGER NOT NULL,
    anchor_hash TEXT NOT NULL,
    deleted_count INTEGER NOT NULL,
    cutoff_at TEXT NOT NULL,
    actor TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS risk_approval_requests (
    request_id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    reason TEXT NOT NULL,
    exception_expiry TEXT NOT NULL,
    notes TEXT,
    status TEXT NOT NULL DEFAULT 'PENDING',
    finding_row_version INTEGER NOT NULL,
    decided_by TEXT,
    decision_note TEXT,
    requested_at TEXT NOT NULL,
    decided_at TEXT,
    FOREIGN KEY(finding_id) REFERENCES findings(finding_id)
);

CREATE TABLE IF NOT EXISTS maintenance_runs (
    run_id TEXT PRIMARY KEY,
    actor TEXT NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    status TEXT NOT NULL,
    details_json TEXT
);

CREATE TABLE IF NOT EXISTS database_maintenance_runs (
    run_id TEXT PRIMARY KEY,
    actor TEXT NOT NULL,
    mode TEXT NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    status TEXT NOT NULL,
    before_json TEXT NOT NULL DEFAULT '{}',
    after_json TEXT NOT NULL DEFAULT '{}',
    details_json TEXT NOT NULL DEFAULT '{}',
    error TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS idempotency_records (
    scope TEXT NOT NULL,
    key_sha256 TEXT NOT NULL,
    request_sha256 TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    response_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL DEFAULT '',
    expires_at TEXT NOT NULL,
    PRIMARY KEY(scope, key_sha256)
);

CREATE TABLE IF NOT EXISTS execution_receipts (
    receipt_id TEXT PRIMARY KEY,
    operation_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    resource_subtype TEXT NOT NULL DEFAULT '',
    receipt_sequence INTEGER NOT NULL,
    attempt_no INTEGER NOT NULL DEFAULT 0,
    outcome TEXT NOT NULL,
    request_sha256 TEXT NOT NULL,
    result_sha256 TEXT NOT NULL DEFAULT '',
    error_sha256 TEXT NOT NULL DEFAULT '',
    error_class TEXT NOT NULL DEFAULT '',
    actor_sha256 TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    UNIQUE(operation_type, resource_id, receipt_sequence)
);

CREATE TABLE IF NOT EXISTS execution_replays (
    replay_id TEXT PRIMARY KEY,
    receipt_id TEXT NOT NULL UNIQUE,
    source_resource_id TEXT NOT NULL,
    new_resource_type TEXT NOT NULL,
    new_resource_id TEXT NOT NULL UNIQUE,
    requested_by TEXT NOT NULL,
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(receipt_id) REFERENCES execution_receipts(receipt_id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS execution_receipt_archives (
    archive_id TEXT PRIMARY KEY,
    cutoff_at TEXT NOT NULL,
    receipt_count INTEGER NOT NULL,
    first_created_at TEXT NOT NULL,
    last_created_at TEXT NOT NULL,
    receipt_digest_sha256 TEXT NOT NULL,
    operation_summary_json TEXT NOT NULL DEFAULT '{}',
    outcome_summary_json TEXT NOT NULL DEFAULT '{}',
    subtype_summary_json TEXT NOT NULL DEFAULT '{}',
    actor_sha256 TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS integrity_proof_key_transitions (
    transition_id TEXT PRIMARY KEY,
    from_key_id TEXT NOT NULL,
    from_public_key_base64 TEXT NOT NULL,
    from_public_key_sha256 TEXT NOT NULL,
    to_key_id TEXT NOT NULL,
    to_public_key_base64 TEXT NOT NULL,
    to_public_key_sha256 TEXT NOT NULL,
    effective_at TEXT NOT NULL,
    reason_sha256 TEXT NOT NULL,
    statement_json TEXT NOT NULL,
    from_signature TEXT NOT NULL,
    to_signature TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(from_public_key_sha256,to_public_key_sha256)
);

CREATE TABLE IF NOT EXISTS integrity_proof_key_revocations (
    revocation_id TEXT PRIMARY KEY,
    revoked_key_id TEXT NOT NULL,
    revoked_public_key_base64 TEXT NOT NULL,
    revoked_public_key_sha256 TEXT NOT NULL UNIQUE,
    replacement_key_id TEXT NOT NULL,
    replacement_public_key_base64 TEXT NOT NULL,
    replacement_public_key_sha256 TEXT NOT NULL,
    recovery_key_id TEXT NOT NULL,
    recovery_public_key_base64 TEXT NOT NULL,
    recovery_public_key_sha256 TEXT NOT NULL,
    invalid_after TEXT NOT NULL,
    effective_at TEXT NOT NULL,
    reason_sha256 TEXT NOT NULL,
    statement_json TEXT NOT NULL,
    recovery_signature TEXT NOT NULL,
    replacement_signature TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS integrity_proof_revocation_checkpoints (
    checkpoint_id TEXT PRIMARY KEY,
    sequence INTEGER NOT NULL UNIQUE,
    previous_checkpoint_sha256 TEXT NOT NULL,
    revocation_count INTEGER NOT NULL,
    revocation_registry_sha256 TEXT NOT NULL,
    transition_count INTEGER NOT NULL,
    transition_registry_sha256 TEXT NOT NULL,
    recovery_key_id TEXT NOT NULL,
    recovery_public_key_base64 TEXT NOT NULL,
    recovery_public_key_sha256 TEXT NOT NULL,
    statement_json TEXT NOT NULL,
    signature TEXT NOT NULL,
    document_sha256 TEXT NOT NULL UNIQUE,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS integrity_proof_checkpoint_witnesses (
    attestation_id TEXT PRIMARY KEY,
    checkpoint_id TEXT NOT NULL REFERENCES integrity_proof_revocation_checkpoints(checkpoint_id),
    checkpoint_sequence INTEGER NOT NULL,
    checkpoint_document_sha256 TEXT NOT NULL,
    revocation_registry_sha256 TEXT NOT NULL,
    transition_registry_sha256 TEXT NOT NULL,
    witness_key_id TEXT NOT NULL,
    witness_public_key_base64 TEXT NOT NULL,
    witness_public_key_sha256 TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    statement_json TEXT NOT NULL,
    signature TEXT NOT NULL,
    document_sha256 TEXT NOT NULL UNIQUE,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(witness_public_key_sha256,checkpoint_sequence),
    UNIQUE(witness_public_key_sha256,checkpoint_document_sha256)
);

CREATE TABLE IF NOT EXISTS integrity_proof_transparency_entries (
    entry_id TEXT PRIMARY KEY,
    sequence INTEGER NOT NULL UNIQUE,
    previous_entry_sha256 TEXT NOT NULL,
    checkpoint_id TEXT NOT NULL REFERENCES integrity_proof_revocation_checkpoints(checkpoint_id),
    checkpoint_sequence INTEGER NOT NULL,
    checkpoint_document_sha256 TEXT NOT NULL UNIQUE,
    witness_count INTEGER NOT NULL,
    witness_registry_sha256 TEXT NOT NULL,
    statement_json TEXT NOT NULL,
    document_sha256 TEXT NOT NULL UNIQUE,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS integrity_proof_transparency_heads (
    head_id TEXT PRIMARY KEY,
    tree_size INTEGER NOT NULL UNIQUE,
    latest_entry_sha256 TEXT NOT NULL UNIQUE,
    previous_head_sha256 TEXT NOT NULL,
    log_key_id TEXT NOT NULL,
    log_public_key_base64 TEXT NOT NULL,
    log_public_key_sha256 TEXT NOT NULL,
    statement_json TEXT NOT NULL,
    signature TEXT NOT NULL,
    document_sha256 TEXT NOT NULL UNIQUE,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS integrity_proof_transparency_mirror_receipts (
    receipt_id TEXT PRIMARY KEY,
    head_id TEXT NOT NULL REFERENCES integrity_proof_transparency_heads(head_id),
    tree_size INTEGER NOT NULL,
    head_document_sha256 TEXT NOT NULL,
    previous_tree_size INTEGER NOT NULL,
    previous_receipt_sha256 TEXT NOT NULL,
    mirror_key_id TEXT NOT NULL,
    mirror_public_key_base64 TEXT NOT NULL,
    mirror_public_key_sha256 TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    statement_json TEXT NOT NULL,
    signature TEXT NOT NULL,
    document_sha256 TEXT NOT NULL UNIQUE,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(mirror_public_key_sha256,tree_size),
    UNIQUE(mirror_public_key_sha256,head_document_sha256)
);

CREATE TABLE IF NOT EXISTS integrity_proof_mirror_consistency_checkpoints (
    checkpoint_id TEXT PRIMARY KEY,
    sequence INTEGER NOT NULL UNIQUE,
    previous_checkpoint_sha256 TEXT NOT NULL,
    head_id TEXT NOT NULL REFERENCES integrity_proof_transparency_heads(head_id),
    tree_size INTEGER NOT NULL,
    head_document_sha256 TEXT NOT NULL UNIQUE,
    mirror_quorum INTEGER NOT NULL,
    mirror_count INTEGER NOT NULL,
    mirror_set_sha256 TEXT NOT NULL,
    statement_json TEXT NOT NULL,
    signatures_json TEXT NOT NULL,
    document_sha256 TEXT NOT NULL UNIQUE,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS collaboration_integrations (
    channel TEXT PRIMARY KEY,
    enabled INTEGER NOT NULL DEFAULT 0,
    config_json TEXT NOT NULL DEFAULT '{}',
    secret_ciphertext TEXT NOT NULL DEFAULT '',
    updated_by TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK(channel IN ('EMAIL','JIRA'))
);

CREATE TABLE IF NOT EXISTS collaboration_events (
    event_id TEXT PRIMARY KEY,
    channel TEXT NOT NULL,
    event_type TEXT NOT NULL,
    finding_id TEXT NOT NULL DEFAULT '',
    payload_json TEXT NOT NULL DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'PENDING',
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TEXT NOT NULL,
    last_attempt_at TEXT,
    delivered_at TEXT,
    response_status INTEGER,
    last_error TEXT NOT NULL DEFAULT '',
    external_key TEXT NOT NULL DEFAULT '',
    external_url TEXT NOT NULL DEFAULT '',
    dedupe_key TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    CHECK(channel IN ('EMAIL','JIRA')),
    CHECK(status IN ('PENDING','RETRY','SENDING','DELIVERED','FAILED','SKIPPED'))
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_collaboration_events_dedupe
    ON collaboration_events(dedupe_key) WHERE dedupe_key<>'';
CREATE INDEX IF NOT EXISTS idx_collaboration_events_due
    ON collaboration_events(status,next_attempt_at,created_at);

CREATE TABLE IF NOT EXISTS finding_external_links (
    finding_id TEXT NOT NULL REFERENCES findings(finding_id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    external_key TEXT NOT NULL,
    external_url TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY(finding_id,provider),
    UNIQUE(provider,external_key)
);

CREATE TABLE IF NOT EXISTS webhook_events (
    event_id TEXT PRIMARY KEY,
    endpoint_name TEXT NOT NULL,
    event_type TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'PENDING',
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TEXT NOT NULL,
    last_attempt_at TEXT,
    delivered_at TEXT,
    response_status INTEGER,
    last_error TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS policy_versions (
    policy_id TEXT PRIMARY KEY,
    version TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    content_yaml TEXT NOT NULL,
    content_sha256 TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'DRAFT',
    notes TEXT,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    activated_by TEXT,
    activated_at TEXT,
    retired_at TEXT,
    supersedes_policy_id TEXT,
    FOREIGN KEY(supersedes_policy_id) REFERENCES policy_versions(policy_id)
);

CREATE TABLE IF NOT EXISTS policy_activation_requests (
    request_id TEXT PRIMARY KEY,
    policy_id TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    reason TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'PENDING',
    active_policy_id_at_request TEXT,
    impact_json TEXT NOT NULL,
    requested_at TEXT NOT NULL,
    decided_by TEXT,
    decision_note TEXT,
    decided_at TEXT,
    FOREIGN KEY(policy_id) REFERENCES policy_versions(policy_id),
    FOREIGN KEY(active_policy_id_at_request) REFERENCES policy_versions(policy_id)
);


CREATE TABLE IF NOT EXISTS app_users (
    username TEXT PRIMARY KEY COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('viewer','operator','approver','admin')),
    is_active INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0,1)),
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT NOT NULL DEFAULT '',
    last_login_at TEXT NOT NULL DEFAULT '',
    password_changed_at TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_sessions (
    session_hash TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT NOT NULL DEFAULT '',
    user_agent_hash TEXT NOT NULL DEFAULT '',
    client_hash TEXT NOT NULL DEFAULT '',
    FOREIGN KEY(username) REFERENCES app_users(username) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS auth_login_attempts (
    attempt_id INTEGER PRIMARY KEY AUTOINCREMENT,
    username_key TEXT NOT NULL,
    client_key TEXT NOT NULL DEFAULT '',
    succeeded INTEGER NOT NULL DEFAULT 0 CHECK(succeeded IN (0,1)),
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS projects (
    project_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK(status IN ('ACTIVE','INACTIVE')),
    is_default INTEGER NOT NULL DEFAULT 0 CHECK(is_default IN (0,1)),
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS project_memberships (
    project_id TEXT NOT NULL,
    username TEXT NOT NULL COLLATE NOCASE,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY(project_id,username),
    FOREIGN KEY(project_id) REFERENCES projects(project_id) ON DELETE CASCADE,
    FOREIGN KEY(username) REFERENCES app_users(username) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS pilot_project_profile (
    singleton_id INTEGER PRIMARY KEY CHECK(singleton_id=1),
    customer_name TEXT NOT NULL DEFAULT '',
    engagement_name TEXT NOT NULL DEFAULT '',
    contact_name TEXT NOT NULL DEFAULT '',
    contact_email TEXT NOT NULL DEFAULT '',
    scope_notes TEXT NOT NULL DEFAULT '',
    default_due_days INTEGER NOT NULL DEFAULT 30 CHECK(default_due_days BETWEEN 1 AND 365),
    report_footer TEXT NOT NULL DEFAULT '',
    updated_by TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    applied_at TEXT NOT NULL,
    app_version TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS system_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS config_baselines (
    baseline_id TEXT PRIMARY KEY,
    config_hash TEXT NOT NULL,
    snapshot_json TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    note TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    retired_by TEXT,
    retired_at TEXT,
    CHECK(status IN ('ACTIVE','RETIRED'))
);

CREATE TABLE IF NOT EXISTS config_drift_checks (
    check_id TEXT PRIMARY KEY,
    baseline_id TEXT NOT NULL,
    current_hash TEXT NOT NULL,
    status TEXT NOT NULL,
    change_count INTEGER NOT NULL DEFAULT 0,
    severity TEXT NOT NULL DEFAULT 'NONE',
    changes_json TEXT NOT NULL DEFAULT '[]',
    checked_by TEXT NOT NULL,
    checked_at TEXT NOT NULL,
    FOREIGN KEY(baseline_id) REFERENCES config_baselines(baseline_id),
    CHECK(status IN ('IN_SYNC','DRIFT')),
    CHECK(severity IN ('NONE','LOW','MEDIUM','HIGH'))
);

CREATE TABLE IF NOT EXISTS config_change_requests (
    request_id TEXT PRIMARY KEY,
    baseline_id TEXT NOT NULL,
    baseline_hash TEXT NOT NULL,
    target_hash TEXT NOT NULL,
    target_snapshot_json TEXT NOT NULL,
    impact_json TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'PENDING',
    title TEXT NOT NULL,
    reason TEXT NOT NULL,
    rollback_plan TEXT NOT NULL,
    window_start TEXT NOT NULL,
    window_end TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    requested_at TEXT NOT NULL,
    decided_by TEXT,
    decision_note TEXT,
    decided_at TEXT,
    applied_by TEXT,
    applied_at TEXT,
    applied_baseline_id TEXT,
    row_version INTEGER NOT NULL DEFAULT 1,
    FOREIGN KEY(baseline_id) REFERENCES config_baselines(baseline_id),
    FOREIGN KEY(applied_baseline_id) REFERENCES config_baselines(baseline_id),
    CHECK(status IN ('PENDING','APPROVED','REJECTED','APPLIED','CANCELLED')),
    CHECK(row_version >= 1)
);

CREATE TABLE IF NOT EXISTS background_jobs (
    job_id TEXT PRIMARY KEY,
    job_type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'PENDING',
    payload_json TEXT NOT NULL DEFAULT '{}',
    result_json TEXT,
    requested_by TEXT NOT NULL,
    priority INTEGER NOT NULL DEFAULT 0,
    attempts INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 3,
    progress_current INTEGER NOT NULL DEFAULT 0,
    progress_total INTEGER NOT NULL DEFAULT 0,
    progress_message TEXT,
    dedupe_key TEXT,
    cancel_requested INTEGER NOT NULL DEFAULT 0,
    lease_owner TEXT,
    lease_expires_at TEXT,
    next_attempt_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    started_at TEXT,
    completed_at TEXT,
    last_error TEXT
);

CREATE TABLE IF NOT EXISTS export_artifacts (
    artifact_id TEXT PRIMARY KEY,
    job_id TEXT UNIQUE,
    export_type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'READY',
    stored_filename TEXT NOT NULL UNIQUE,
    download_filename TEXT NOT NULL,
    content_type TEXT NOT NULL,
    row_count INTEGER NOT NULL DEFAULT 0,
    size_bytes INTEGER NOT NULL DEFAULT 0,
    sha256 TEXT NOT NULL,
    filters_json TEXT NOT NULL DEFAULT '{}',
    snapshot_at TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT,
    downloaded_count INTEGER NOT NULL DEFAULT 0,
    last_downloaded_at TEXT,
    expired_by TEXT,
    expired_at TEXT,
    pinned INTEGER NOT NULL DEFAULT 0,
    pinned_by TEXT,
    pinned_at TEXT,
    evicted_by TEXT,
    evicted_at TEXT,
    eviction_reason TEXT,
    FOREIGN KEY(job_id) REFERENCES background_jobs(job_id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS assets (
    asset_ref_id TEXT PRIMARY KEY,
    external_asset_id TEXT,
    asset_name TEXT NOT NULL,
    service_name TEXT,
    business_unit TEXT,
    owner TEXT,
    environment TEXT,
    criticality INTEGER NOT NULL DEFAULT 1,
    data_sensitivity INTEGER NOT NULL DEFAULT 1,
    internet_exposed INTEGER NOT NULL DEFAULT 0,
    tags TEXT,
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    source TEXT NOT NULL DEFAULT 'finding-derived',
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    row_version INTEGER NOT NULL DEFAULT 1,
    merged_into_asset_ref_id TEXT,
    FOREIGN KEY(merged_into_asset_ref_id) REFERENCES assets(asset_ref_id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS asset_identifiers (
    identifier_id TEXT PRIMARY KEY,
    asset_ref_id TEXT NOT NULL,
    identifier_type TEXT NOT NULL,
    scope TEXT NOT NULL DEFAULT 'global',
    normalized_value TEXT NOT NULL,
    display_value TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'system',
    confidence INTEGER NOT NULL DEFAULT 50,
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    retired_by TEXT,
    retired_at TEXT,
    FOREIGN KEY(asset_ref_id) REFERENCES assets(asset_ref_id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS asset_identity_candidates (
    candidate_id TEXT PRIMARY KEY,
    asset_ref_id_a TEXT NOT NULL,
    asset_ref_id_b TEXT NOT NULL,
    fingerprint TEXT NOT NULL UNIQUE,
    score INTEGER NOT NULL,
    reasons_json TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'PENDING',
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    decided_by TEXT,
    decided_at TEXT,
    decision_reason TEXT NOT NULL DEFAULT '',
    FOREIGN KEY(asset_ref_id_a) REFERENCES assets(asset_ref_id) ON DELETE RESTRICT,
    FOREIGN KEY(asset_ref_id_b) REFERENCES assets(asset_ref_id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS asset_merge_history (
    merge_id TEXT PRIMARY KEY,
    source_asset_ref_id TEXT NOT NULL,
    target_asset_ref_id TEXT NOT NULL,
    moved_findings_count INTEGER NOT NULL DEFAULT 0,
    consolidated_findings_count INTEGER NOT NULL DEFAULT 0,
    moved_identifiers_count INTEGER NOT NULL DEFAULT 0,
    source_snapshot_json TEXT NOT NULL,
    target_snapshot_json TEXT NOT NULL,
    reason TEXT NOT NULL,
    actor TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(source_asset_ref_id) REFERENCES assets(asset_ref_id) ON DELETE RESTRICT,
    FOREIGN KEY(target_asset_ref_id) REFERENCES assets(asset_ref_id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS asset_merge_requests (
    request_id TEXT PRIMARY KEY,
    candidate_id TEXT,
    source_asset_ref_id TEXT NOT NULL,
    target_asset_ref_id TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    reason TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'PENDING',
    source_row_version INTEGER NOT NULL,
    target_row_version INTEGER NOT NULL,
    impact_json TEXT NOT NULL,
    impact_sha256 TEXT NOT NULL,
    requested_at TEXT NOT NULL,
    decided_by TEXT,
    decision_note TEXT,
    decided_at TEXT,
    recovery_bundle_path TEXT,
    recovery_bundle_sha256 TEXT,
    merge_id TEXT,
    FOREIGN KEY(candidate_id) REFERENCES asset_identity_candidates(candidate_id) ON DELETE RESTRICT,
    FOREIGN KEY(source_asset_ref_id) REFERENCES assets(asset_ref_id) ON DELETE RESTRICT,
    FOREIGN KEY(target_asset_ref_id) REFERENCES assets(asset_ref_id) ON DELETE RESTRICT,
    FOREIGN KEY(merge_id) REFERENCES asset_merge_history(merge_id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS asset_merge_rollback_journals (
    merge_id TEXT PRIMARY KEY,
    source_asset_ref_id TEXT NOT NULL,
    target_asset_ref_id TEXT NOT NULL,
    snapshot_json TEXT NOT NULL,
    snapshot_sha256 TEXT NOT NULL,
    post_guard_json TEXT NOT NULL,
    post_guard_sha256 TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(merge_id) REFERENCES asset_merge_history(merge_id) ON DELETE RESTRICT,
    FOREIGN KEY(source_asset_ref_id) REFERENCES assets(asset_ref_id) ON DELETE RESTRICT,
    FOREIGN KEY(target_asset_ref_id) REFERENCES assets(asset_ref_id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS asset_merge_rollback_requests (
    rollback_request_id TEXT PRIMARY KEY,
    merge_id TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    reason TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'PENDING',
    impact_json TEXT NOT NULL,
    impact_sha256 TEXT NOT NULL,
    requested_at TEXT NOT NULL,
    decided_by TEXT,
    decision_note TEXT,
    decided_at TEXT,
    FOREIGN KEY(merge_id) REFERENCES asset_merge_history(merge_id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS remediation_campaigns (
    campaign_id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT,
    owner TEXT,
    due_date TEXT,
    status TEXT NOT NULL DEFAULT 'PLANNED',
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    completed_at TEXT,
    row_version INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS campaign_findings (
    campaign_id TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    added_by TEXT NOT NULL,
    added_at TEXT NOT NULL,
    PRIMARY KEY(campaign_id, finding_id),
    FOREIGN KEY(campaign_id) REFERENCES remediation_campaigns(campaign_id) ON DELETE CASCADE,
    FOREIGN KEY(finding_id) REFERENCES findings(finding_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS finding_observations (
    observation_id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL,
    batch_id TEXT,
    scanner_source TEXT NOT NULL,
    observation TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    details_json TEXT NOT NULL DEFAULT '{}',
    source_record_id TEXT,
    FOREIGN KEY(finding_id) REFERENCES findings(finding_id) ON DELETE CASCADE,
    FOREIGN KEY(batch_id) REFERENCES import_batches(batch_id) ON DELETE SET NULL,
    FOREIGN KEY(source_record_id) REFERENCES source_finding_records(source_record_id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS remediation_verification_requests (
    verification_id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL,
    method TEXT NOT NULL,
    evidence_note TEXT NOT NULL,
    source_batch_id TEXT,
    observed_absence_count INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'PENDING',
    requested_by TEXT NOT NULL,
    requested_at TEXT NOT NULL,
    finding_row_version INTEGER NOT NULL,
    decided_by TEXT,
    decision_note TEXT,
    decided_at TEXT,
    FOREIGN KEY(finding_id) REFERENCES findings(finding_id) ON DELETE CASCADE,
    FOREIGN KEY(source_batch_id) REFERENCES import_batches(batch_id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS verification_evidence_artifacts (
    evidence_id TEXT PRIMARY KEY,
    verification_id TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    stored_filename TEXT NOT NULL UNIQUE,
    original_filename TEXT NOT NULL,
    content_type TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    notes TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    uploaded_by TEXT NOT NULL,
    uploaded_at TEXT NOT NULL,
    retired_by TEXT,
    retired_at TEXT,
    retire_reason TEXT,
    scan_status TEXT NOT NULL DEFAULT 'PENDING',
    scan_engine TEXT NOT NULL DEFAULT '',
    scan_signature TEXT NOT NULL DEFAULT '',
    scan_details TEXT NOT NULL DEFAULT '',
    scanned_at TEXT NOT NULL DEFAULT '',
    scan_error TEXT NOT NULL DEFAULT '',
    scan_waived_by TEXT NOT NULL DEFAULT '',
    scan_waived_at TEXT NOT NULL DEFAULT '',
    scan_waiver_reason TEXT NOT NULL DEFAULT '',
    source_type TEXT NOT NULL DEFAULT 'USER_UPLOAD',
    source_reference TEXT NOT NULL DEFAULT '',
    acquisition_method TEXT NOT NULL DEFAULT 'UPLOAD',
    collected_by TEXT NOT NULL DEFAULT '',
    collected_at TEXT NOT NULL DEFAULT '',
    current_custodian TEXT NOT NULL DEFAULT '',
    custody_last_seq INTEGER NOT NULL DEFAULT 0,
    custody_last_hash TEXT NOT NULL DEFAULT '',
    FOREIGN KEY(verification_id) REFERENCES remediation_verification_requests(verification_id) ON DELETE RESTRICT,
    FOREIGN KEY(finding_id) REFERENCES findings(finding_id) ON DELETE RESTRICT
);


CREATE TABLE IF NOT EXISTS sbom_documents (
    sbom_id TEXT PRIMARY KEY,
    serial_number TEXT NOT NULL DEFAULT '',
    spec_version TEXT NOT NULL,
    product_name TEXT NOT NULL,
    product_version TEXT NOT NULL DEFAULT '',
    document_sha256 TEXT NOT NULL UNIQUE,
    source_filename TEXT NOT NULL,
    uploaded_by TEXT NOT NULL,
    uploaded_at TEXT NOT NULL,
    component_count INTEGER NOT NULL DEFAULT 0,
    duplicate_identities INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    notes TEXT NOT NULL DEFAULT '',
    row_version INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS sbom_components (
    component_id TEXT PRIMARY KEY,
    sbom_id TEXT NOT NULL,
    component_key TEXT NOT NULL,
    identity TEXT NOT NULL,
    identity_occurrence INTEGER NOT NULL DEFAULT 1,
    bom_ref TEXT NOT NULL DEFAULT '',
    component_type TEXT NOT NULL DEFAULT '',
    component_group TEXT NOT NULL DEFAULT '',
    name TEXT NOT NULL,
    version TEXT NOT NULL DEFAULT '',
    purl TEXT NOT NULL DEFAULT '',
    licenses TEXT NOT NULL DEFAULT '',
    hash_count INTEGER NOT NULL DEFAULT 0,
    scope TEXT NOT NULL DEFAULT '',
    FOREIGN KEY(sbom_id) REFERENCES sbom_documents(sbom_id) ON DELETE CASCADE,
    UNIQUE(sbom_id, component_key)
);

CREATE TABLE IF NOT EXISTS sbom_finding_links (
    link_id TEXT PRIMARY KEY,
    sbom_id TEXT NOT NULL,
    component_id TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    match_method TEXT NOT NULL,
    match_confidence INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'CANDIDATE',
    linked_by TEXT NOT NULL,
    linked_at TEXT NOT NULL,
    FOREIGN KEY(sbom_id) REFERENCES sbom_documents(sbom_id) ON DELETE CASCADE,
    FOREIGN KEY(component_id) REFERENCES sbom_components(component_id) ON DELETE CASCADE,
    FOREIGN KEY(finding_id) REFERENCES findings(finding_id) ON DELETE CASCADE,
    UNIQUE(sbom_id, component_id, finding_id)
);

CREATE TABLE IF NOT EXISTS vex_statements (
    vex_id TEXT PRIMARY KEY,
    sbom_id TEXT NOT NULL,
    component_id TEXT NOT NULL,
    cve_id TEXT NOT NULL,
    finding_id TEXT,
    revision_no INTEGER NOT NULL,
    analysis_state TEXT NOT NULL,
    justification TEXT NOT NULL DEFAULT '',
    response_json TEXT NOT NULL DEFAULT '[]',
    impact_statement TEXT NOT NULL DEFAULT '',
    action_statement TEXT NOT NULL DEFAULT '',
    detail TEXT NOT NULL DEFAULT '',
    review_status TEXT NOT NULL DEFAULT 'DRAFT',
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    requested_by TEXT,
    requested_at TEXT,
    decided_by TEXT,
    decision_note TEXT,
    decided_at TEXT,
    supersedes_vex_id TEXT,
    FOREIGN KEY(sbom_id) REFERENCES sbom_documents(sbom_id) ON DELETE CASCADE,
    FOREIGN KEY(component_id) REFERENCES sbom_components(component_id) ON DELETE CASCADE,
    FOREIGN KEY(finding_id) REFERENCES findings(finding_id) ON DELETE SET NULL,
    FOREIGN KEY(supersedes_vex_id) REFERENCES vex_statements(vex_id) ON DELETE SET NULL,
    UNIQUE(sbom_id, component_id, cve_id, revision_no)
);

CREATE TABLE IF NOT EXISTS osv_scan_runs (
    scan_id TEXT PRIMARY KEY,
    sbom_id TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'PENDING',
    source_name TEXT NOT NULL DEFAULT 'OSV.dev',
    source_url TEXT NOT NULL DEFAULT '',
    requested_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    started_at TEXT NOT NULL DEFAULT '',
    completed_at TEXT NOT NULL DEFAULT '',
    component_total INTEGER NOT NULL DEFAULT 0,
    eligible_components INTEGER NOT NULL DEFAULT 0,
    skipped_components INTEGER NOT NULL DEFAULT 0,
    vulnerability_matches INTEGER NOT NULL DEFAULT 0,
    new_candidates INTEGER NOT NULL DEFAULT 0,
    cache_hits INTEGER NOT NULL DEFAULT 0,
    api_requests INTEGER NOT NULL DEFAULT 0,
    error_count INTEGER NOT NULL DEFAULT 0,
    errors_json TEXT NOT NULL DEFAULT '[]',
    source_job_id TEXT,
    FOREIGN KEY(sbom_id) REFERENCES sbom_documents(sbom_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS osv_vulnerability_records (
    osv_id TEXT PRIMARY KEY,
    modified TEXT NOT NULL DEFAULT '',
    published TEXT NOT NULL DEFAULT '',
    withdrawn TEXT NOT NULL DEFAULT '',
    summary TEXT NOT NULL DEFAULT '',
    details TEXT NOT NULL DEFAULT '',
    aliases_json TEXT NOT NULL DEFAULT '[]',
    severity_json TEXT NOT NULL DEFAULT '[]',
    affected_json TEXT NOT NULL DEFAULT '[]',
    references_json TEXT NOT NULL DEFAULT '[]',
    raw_json TEXT NOT NULL,
    content_sha256 TEXT NOT NULL,
    fetched_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sbom_osv_matches (
    match_id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    sbom_id TEXT NOT NULL,
    component_id TEXT NOT NULL,
    osv_id TEXT NOT NULL,
    cve_id TEXT NOT NULL DEFAULT '',
    aliases_json TEXT NOT NULL DEFAULT '[]',
    severity_label TEXT NOT NULL DEFAULT '',
    severity_vector TEXT NOT NULL DEFAULT '',
    severity_numeric REAL NOT NULL DEFAULT 0,
    fixed_versions_json TEXT NOT NULL DEFAULT '[]',
    match_method TEXT NOT NULL DEFAULT 'OSV_PURL_VERSION',
    status TEXT NOT NULL DEFAULT 'CANDIDATE',
    finding_id TEXT,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    decided_by TEXT,
    decided_at TEXT,
    decision_reason TEXT NOT NULL DEFAULT '',
    FOREIGN KEY(scan_id) REFERENCES osv_scan_runs(scan_id) ON DELETE CASCADE,
    FOREIGN KEY(sbom_id) REFERENCES sbom_documents(sbom_id) ON DELETE CASCADE,
    FOREIGN KEY(component_id) REFERENCES sbom_components(component_id) ON DELETE CASCADE,
    FOREIGN KEY(osv_id) REFERENCES osv_vulnerability_records(osv_id) ON DELETE RESTRICT,
    FOREIGN KEY(finding_id) REFERENCES findings(finding_id) ON DELETE SET NULL,
    UNIQUE(sbom_id,component_id,osv_id)
);

CREATE TABLE IF NOT EXISTS evidence_custody_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id TEXT NOT NULL,
    event_seq INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    actor TEXT NOT NULL,
    from_custodian TEXT NOT NULL DEFAULT '',
    to_custodian TEXT NOT NULL DEFAULT '',
    purpose TEXT NOT NULL DEFAULT '',
    details_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL,
    UNIQUE(evidence_id,event_seq),
    FOREIGN KEY(evidence_id) REFERENCES verification_evidence_artifacts(evidence_id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_source_records_finding_state ON source_finding_records(finding_id, observed_state, scanner_source);
CREATE INDEX IF NOT EXISTS idx_source_records_source_state ON source_finding_records(scanner_source, observed_state, last_seen_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_reconciliation_active_field ON finding_reconciliation_decisions(finding_id,field_name) WHERE status='ACTIVE';
CREATE INDEX IF NOT EXISTS idx_reconciliation_finding ON finding_reconciliation_decisions(finding_id,status,created_at DESC);
CREATE INDEX IF NOT EXISTS idx_findings_cve ON findings(cve_id);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_decision ON findings(decision);
CREATE INDEX IF NOT EXISTS idx_assets_status_owner ON assets(status, owner);
CREATE INDEX IF NOT EXISTS idx_assets_external_id ON assets(external_asset_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_asset_identifiers_active_unique ON asset_identifiers(identifier_type,scope,normalized_value) WHERE status='ACTIVE';
CREATE INDEX IF NOT EXISTS idx_asset_identifiers_asset ON asset_identifiers(asset_ref_id,status,identifier_type);
CREATE INDEX IF NOT EXISTS idx_asset_identity_candidates_status ON asset_identity_candidates(status,score DESC,created_at DESC);
CREATE INDEX IF NOT EXISTS idx_asset_identity_candidates_pair ON asset_identity_candidates(asset_ref_id_a,asset_ref_id_b,status);
CREATE INDEX IF NOT EXISTS idx_asset_merge_history_assets ON asset_merge_history(source_asset_ref_id,target_asset_ref_id,created_at DESC);
CREATE INDEX IF NOT EXISTS idx_asset_merge_requests_status ON asset_merge_requests(status,requested_at DESC);
CREATE INDEX IF NOT EXISTS idx_asset_merge_requests_assets ON asset_merge_requests(source_asset_ref_id,target_asset_ref_id,status);
CREATE UNIQUE INDEX IF NOT EXISTS idx_asset_merge_requests_candidate_pending ON asset_merge_requests(candidate_id) WHERE candidate_id IS NOT NULL AND status='PENDING';
CREATE INDEX IF NOT EXISTS idx_asset_merge_rollback_requests_status ON asset_merge_rollback_requests(status,requested_at DESC);
CREATE INDEX IF NOT EXISTS idx_asset_merge_rollback_requests_merge ON asset_merge_rollback_requests(merge_id,status);
CREATE UNIQUE INDEX IF NOT EXISTS idx_asset_merge_rollback_requests_pending ON asset_merge_rollback_requests(merge_id) WHERE status='PENDING';
CREATE INDEX IF NOT EXISTS idx_campaigns_status_due ON remediation_campaigns(status, due_date);
CREATE INDEX IF NOT EXISTS idx_campaign_findings_finding ON campaign_findings(finding_id);
CREATE INDEX IF NOT EXISTS idx_observations_finding_time ON finding_observations(finding_id, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_observations_batch ON finding_observations(batch_id, observation);
CREATE INDEX IF NOT EXISTS idx_verification_status_time ON remediation_verification_requests(status, requested_at DESC);
CREATE INDEX IF NOT EXISTS idx_verification_finding_time ON remediation_verification_requests(finding_id, requested_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_verification_one_pending ON remediation_verification_requests(finding_id) WHERE status='PENDING';
CREATE INDEX IF NOT EXISTS idx_evidence_verification_time ON verification_evidence_artifacts(verification_id, uploaded_at DESC);
CREATE INDEX IF NOT EXISTS idx_evidence_finding_time ON verification_evidence_artifacts(finding_id, uploaded_at DESC);
CREATE INDEX IF NOT EXISTS idx_evidence_status ON verification_evidence_artifacts(status, uploaded_at DESC);
CREATE INDEX IF NOT EXISTS idx_evidence_scan_status ON verification_evidence_artifacts(scan_status, uploaded_at DESC);
CREATE INDEX IF NOT EXISTS idx_custody_evidence_seq ON evidence_custody_events(evidence_id,event_seq);
CREATE INDEX IF NOT EXISTS idx_custody_created ON evidence_custody_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_sbom_documents_product ON sbom_documents(product_name, product_version, uploaded_at DESC);
CREATE INDEX IF NOT EXISTS idx_sbom_components_sbom ON sbom_components(sbom_id, name, version);
CREATE INDEX IF NOT EXISTS idx_sbom_components_purl ON sbom_components(purl);
CREATE INDEX IF NOT EXISTS idx_sbom_links_finding ON sbom_finding_links(finding_id, status);
CREATE INDEX IF NOT EXISTS idx_vex_component_cve ON vex_statements(component_id, cve_id, revision_no DESC);
CREATE INDEX IF NOT EXISTS idx_vex_review_status ON vex_statements(review_status, requested_at DESC);
CREATE INDEX IF NOT EXISTS idx_osv_scan_sbom_created ON osv_scan_runs(sbom_id, created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_osv_scan_source_job ON osv_scan_runs(source_job_id) WHERE source_job_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_osv_matches_sbom_status ON sbom_osv_matches(sbom_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_osv_matches_component ON sbom_osv_matches(component_id, status);
CREATE INDEX IF NOT EXISTS idx_osv_matches_cve ON sbom_osv_matches(cve_id, status);
CREATE INDEX IF NOT EXISTS idx_audit_finding ON audit_events(finding_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_import_batches_created ON import_batches(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_approvals_status ON risk_approval_requests(status, requested_at DESC);
CREATE INDEX IF NOT EXISTS idx_approvals_finding ON risk_approval_requests(finding_id, requested_at DESC);
CREATE INDEX IF NOT EXISTS idx_maintenance_created ON maintenance_runs(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_idempotency_expiry ON idempotency_records(expires_at);
CREATE INDEX IF NOT EXISTS idx_execution_receipts_resource ON execution_receipts(operation_type,resource_id,receipt_sequence);
CREATE INDEX IF NOT EXISTS idx_execution_receipts_outcome ON execution_receipts(outcome,created_at);
CREATE INDEX IF NOT EXISTS idx_execution_replays_created ON execution_replays(created_at);
CREATE INDEX IF NOT EXISTS idx_execution_receipt_archives_created ON execution_receipt_archives(created_at DESC);
CREATE TRIGGER IF NOT EXISTS execution_receipts_no_update BEFORE UPDATE ON execution_receipts
BEGIN SELECT RAISE(ABORT, 'execution receipts are immutable'); END;
CREATE TRIGGER IF NOT EXISTS execution_receipts_no_delete BEFORE DELETE ON execution_receipts
BEGIN SELECT RAISE(ABORT, 'execution receipts cannot be deleted'); END;
CREATE TRIGGER IF NOT EXISTS execution_replays_no_update BEFORE UPDATE ON execution_replays
BEGIN SELECT RAISE(ABORT, 'execution replays are immutable'); END;
CREATE TRIGGER IF NOT EXISTS execution_replays_no_delete BEFORE DELETE ON execution_replays
BEGIN SELECT RAISE(ABORT, 'execution replays cannot be deleted'); END;
CREATE TRIGGER IF NOT EXISTS execution_receipt_archives_no_update BEFORE UPDATE ON execution_receipt_archives
BEGIN SELECT RAISE(ABORT, 'execution receipt archives are immutable'); END;
CREATE TRIGGER IF NOT EXISTS execution_receipt_archives_no_delete BEFORE DELETE ON execution_receipt_archives
BEGIN SELECT RAISE(ABORT, 'execution receipt archives cannot be deleted'); END;
CREATE INDEX IF NOT EXISTS idx_integrity_proof_key_transitions_to ON integrity_proof_key_transitions(to_key_id,effective_at,created_at);
CREATE INDEX IF NOT EXISTS idx_integrity_proof_key_transitions_from ON integrity_proof_key_transitions(from_key_id,effective_at,created_at);
CREATE TRIGGER IF NOT EXISTS integrity_proof_key_transitions_no_update BEFORE UPDATE ON integrity_proof_key_transitions
BEGIN SELECT RAISE(ABORT, 'integrity proof key transitions are immutable'); END;
CREATE TRIGGER IF NOT EXISTS integrity_proof_key_transitions_no_delete BEFORE DELETE ON integrity_proof_key_transitions
BEGIN SELECT RAISE(ABORT, 'integrity proof key transitions cannot be deleted'); END;
CREATE INDEX IF NOT EXISTS idx_integrity_proof_key_revocations_replacement ON integrity_proof_key_revocations(replacement_key_id,effective_at,created_at);
CREATE INDEX IF NOT EXISTS idx_integrity_proof_key_revocations_recovery ON integrity_proof_key_revocations(recovery_key_id,effective_at,created_at);
CREATE INDEX IF NOT EXISTS idx_integrity_proof_revocation_checkpoints_created ON integrity_proof_revocation_checkpoints(created_at,sequence);
CREATE TRIGGER IF NOT EXISTS integrity_proof_revocation_checkpoints_no_update BEFORE UPDATE ON integrity_proof_revocation_checkpoints
BEGIN SELECT RAISE(ABORT, 'integrity proof revocation checkpoints are immutable'); END;
CREATE TRIGGER IF NOT EXISTS integrity_proof_revocation_checkpoints_no_delete BEFORE DELETE ON integrity_proof_revocation_checkpoints
BEGIN SELECT RAISE(ABORT, 'integrity proof revocation checkpoints cannot be deleted'); END;
CREATE INDEX IF NOT EXISTS idx_integrity_proof_checkpoint_witnesses_checkpoint ON integrity_proof_checkpoint_witnesses(checkpoint_sequence,checkpoint_id,observed_at);
CREATE INDEX IF NOT EXISTS idx_integrity_proof_checkpoint_witnesses_key ON integrity_proof_checkpoint_witnesses(witness_key_id,observed_at);
CREATE TRIGGER IF NOT EXISTS integrity_proof_checkpoint_witnesses_no_update BEFORE UPDATE ON integrity_proof_checkpoint_witnesses
BEGIN SELECT RAISE(ABORT, 'integrity proof checkpoint witnesses are immutable'); END;
CREATE TRIGGER IF NOT EXISTS integrity_proof_checkpoint_witnesses_no_delete BEFORE DELETE ON integrity_proof_checkpoint_witnesses
BEGIN SELECT RAISE(ABORT, 'integrity proof checkpoint witnesses cannot be deleted'); END;
CREATE INDEX IF NOT EXISTS idx_integrity_proof_transparency_entries_checkpoint ON integrity_proof_transparency_entries(checkpoint_sequence,checkpoint_id,sequence);
CREATE INDEX IF NOT EXISTS idx_integrity_proof_transparency_heads_key ON integrity_proof_transparency_heads(log_key_id,tree_size);
CREATE TRIGGER IF NOT EXISTS integrity_proof_transparency_entries_no_update BEFORE UPDATE ON integrity_proof_transparency_entries
BEGIN SELECT RAISE(ABORT, 'integrity proof transparency entries are immutable'); END;
CREATE TRIGGER IF NOT EXISTS integrity_proof_transparency_entries_no_delete BEFORE DELETE ON integrity_proof_transparency_entries
BEGIN SELECT RAISE(ABORT, 'integrity proof transparency entries cannot be deleted'); END;
CREATE TRIGGER IF NOT EXISTS integrity_proof_transparency_heads_no_update BEFORE UPDATE ON integrity_proof_transparency_heads
BEGIN SELECT RAISE(ABORT, 'integrity proof transparency heads are immutable'); END;
CREATE TRIGGER IF NOT EXISTS integrity_proof_transparency_heads_no_delete BEFORE DELETE ON integrity_proof_transparency_heads
BEGIN SELECT RAISE(ABORT, 'integrity proof transparency heads cannot be deleted'); END;
CREATE INDEX IF NOT EXISTS idx_integrity_proof_transparency_mirror_head ON integrity_proof_transparency_mirror_receipts(tree_size,head_id,observed_at);
CREATE INDEX IF NOT EXISTS idx_integrity_proof_transparency_mirror_key ON integrity_proof_transparency_mirror_receipts(mirror_key_id,tree_size);
CREATE TRIGGER IF NOT EXISTS integrity_proof_transparency_mirror_receipts_no_update BEFORE UPDATE ON integrity_proof_transparency_mirror_receipts
BEGIN SELECT RAISE(ABORT, 'integrity proof transparency mirror receipts are immutable'); END;
CREATE TRIGGER IF NOT EXISTS integrity_proof_transparency_mirror_receipts_no_delete BEFORE DELETE ON integrity_proof_transparency_mirror_receipts
BEGIN SELECT RAISE(ABORT, 'integrity proof transparency mirror receipts cannot be deleted'); END;
CREATE INDEX IF NOT EXISTS idx_integrity_proof_mirror_consistency_head ON integrity_proof_mirror_consistency_checkpoints(tree_size,head_id,sequence);
CREATE TRIGGER IF NOT EXISTS integrity_proof_mirror_consistency_checkpoints_no_update BEFORE UPDATE ON integrity_proof_mirror_consistency_checkpoints
BEGIN SELECT RAISE(ABORT, 'integrity proof mirror consistency checkpoints are immutable'); END;
CREATE TRIGGER IF NOT EXISTS integrity_proof_mirror_consistency_checkpoints_no_delete BEFORE DELETE ON integrity_proof_mirror_consistency_checkpoints
BEGIN SELECT RAISE(ABORT, 'integrity proof mirror consistency checkpoints cannot be deleted'); END;
CREATE TRIGGER IF NOT EXISTS integrity_proof_key_revocations_no_update BEFORE UPDATE ON integrity_proof_key_revocations
BEGIN SELECT RAISE(ABORT, 'integrity proof key revocations are immutable'); END;
CREATE TRIGGER IF NOT EXISTS integrity_proof_key_revocations_no_delete BEFORE DELETE ON integrity_proof_key_revocations
BEGIN SELECT RAISE(ABORT, 'integrity proof key revocations cannot be deleted'); END;
CREATE INDEX IF NOT EXISTS idx_webhook_due ON webhook_events(status, next_attempt_at);
CREATE INDEX IF NOT EXISTS idx_webhook_created ON webhook_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_policy_status ON policy_versions(status, created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_policy_single_active ON policy_versions(status) WHERE status='ACTIVE';
CREATE INDEX IF NOT EXISTS idx_policy_requests_status ON policy_activation_requests(status, requested_at DESC);
CREATE INDEX IF NOT EXISTS idx_jobs_status_due ON background_jobs(status, next_attempt_at, priority DESC, created_at);
CREATE INDEX IF NOT EXISTS idx_jobs_created ON background_jobs(created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_jobs_active_dedupe ON background_jobs(dedupe_key)
    WHERE dedupe_key IS NOT NULL AND status IN ('PENDING','RETRY','RUNNING');
"""

COORDINATION_SCHEMA = """
CREATE TABLE IF NOT EXISTS cluster_instances (
    instance_id TEXT PRIMARY KEY,
    hostname TEXT NOT NULL,
    process_id INTEGER NOT NULL,
    app_version TEXT NOT NULL,
    capabilities_json TEXT NOT NULL DEFAULT '[]',
    metadata_json TEXT NOT NULL DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    started_at TEXT NOT NULL,
    last_heartbeat_at TEXT NOT NULL,
    stopped_at TEXT
);

CREATE TABLE IF NOT EXISTS cluster_leases (
    lease_name TEXT PRIMARY KEY,
    holder_id TEXT NOT NULL,
    fencing_token INTEGER NOT NULL,
    purpose TEXT,
    acquired_at TEXT NOT NULL,
    renewed_at TEXT NOT NULL,
    lease_expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cluster_write_activities (
    activity_id TEXT PRIMARY KEY,
    instance_id TEXT NOT NULL,
    actor TEXT,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    started_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_cluster_instances_heartbeat
    ON cluster_instances(status, last_heartbeat_at DESC);
CREATE INDEX IF NOT EXISTS idx_cluster_leases_expiry
    ON cluster_leases(lease_expires_at);
CREATE INDEX IF NOT EXISTS idx_cluster_write_expiry
    ON cluster_write_activities(expires_at);
"""

MIGRATION_COLUMNS = {
    "risk_acceptance_reason": "TEXT",
    "risk_acceptance_approver": "TEXT",
    "intel_updated_at": "TEXT",
    "policy_version": "TEXT",
    "resolved_at": "TEXT",
    "scanner_source": "TEXT DEFAULT 'manual'",
    "source_last_seen_at": "TEXT",
    "record_state": "TEXT DEFAULT 'ACTIVE'",
    "stale_since": "TEXT",
    "archived_at": "TEXT",
    "import_batch_id": "TEXT",
    "row_version": "INTEGER DEFAULT 1",
    "policy_id": "TEXT",
    "asset_ref_id": "TEXT",
    "resolution_state": "TEXT NOT NULL DEFAULT 'UNVERIFIED'",
    "resolution_requested_at": "TEXT",
    "verified_at": "TEXT",
    "verified_by": "TEXT",
    "verification_method": "TEXT",
    "verification_note": "TEXT",
    "consecutive_absent_scans": "INTEGER NOT NULL DEFAULT 0",
    "last_reopened_at": "TEXT",
    "reopen_count": "INTEGER NOT NULL DEFAULT 0",
    "canonical_key": "TEXT",
    "source_count": "INTEGER NOT NULL DEFAULT 1",
    "source_conflict_count": "INTEGER NOT NULL DEFAULT 0",
    "merged_into_finding_id": "TEXT",
}
