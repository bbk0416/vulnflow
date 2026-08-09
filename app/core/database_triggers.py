from __future__ import annotations

"""Immutable audit, evidence, export, and governance trigger installation."""

import sqlite3

def _install_audit_triggers(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TRIGGER IF NOT EXISTS audit_events_require_chain
        BEFORE INSERT ON audit_events
        WHEN NEW.chain_seq IS NULL OR NEW.prev_hash IS NULL OR NEW.event_hash IS NULL
        BEGIN
            SELECT RAISE(ABORT, 'audit chain fields are required');
        END;
        CREATE TRIGGER IF NOT EXISTS audit_events_immutable
        BEFORE UPDATE ON audit_events
        BEGIN
            SELECT RAISE(ABORT, 'audit events are immutable');
        END;
        CREATE TRIGGER IF NOT EXISTS audit_checkpoints_immutable_update
        BEFORE UPDATE ON audit_checkpoints
        BEGIN
            SELECT RAISE(ABORT, 'audit checkpoints are immutable');
        END;
        CREATE TRIGGER IF NOT EXISTS audit_checkpoints_immutable_delete
        BEFORE DELETE ON audit_checkpoints
        BEGIN
            SELECT RAISE(ABORT, 'audit checkpoints are immutable');
        END;
        CREATE TRIGGER IF NOT EXISTS verification_evidence_core_immutable
        BEFORE UPDATE ON verification_evidence_artifacts
        WHEN OLD.evidence_id != NEW.evidence_id
          OR OLD.verification_id != NEW.verification_id
          OR OLD.finding_id != NEW.finding_id
          OR OLD.stored_filename != NEW.stored_filename
          OR OLD.original_filename != NEW.original_filename
          OR OLD.content_type != NEW.content_type
          OR OLD.size_bytes != NEW.size_bytes
          OR OLD.sha256 != NEW.sha256
          OR OLD.notes != NEW.notes
          OR OLD.source_type != NEW.source_type
          OR OLD.source_reference != NEW.source_reference
          OR OLD.acquisition_method != NEW.acquisition_method
          OR OLD.collected_by != NEW.collected_by
          OR OLD.collected_at != NEW.collected_at
          OR OLD.uploaded_by != NEW.uploaded_by
          OR OLD.uploaded_at != NEW.uploaded_at
        BEGIN
            SELECT RAISE(ABORT, 'evidence core fields are immutable');
        END;
        CREATE TRIGGER IF NOT EXISTS verification_evidence_no_delete
        BEFORE DELETE ON verification_evidence_artifacts
        BEGIN
            SELECT RAISE(ABORT, 'evidence records cannot be deleted');
        END;
        CREATE TRIGGER IF NOT EXISTS evidence_custody_immutable_update
        BEFORE UPDATE ON evidence_custody_events
        BEGIN
            SELECT RAISE(ABORT, 'evidence custody events are immutable');
        END;
        CREATE TRIGGER IF NOT EXISTS evidence_custody_immutable_delete
        BEFORE DELETE ON evidence_custody_events
        BEGIN
            SELECT RAISE(ABORT, 'evidence custody events are immutable');
        END;
        CREATE TRIGGER IF NOT EXISTS export_artifacts_core_immutable
        BEFORE UPDATE ON export_artifacts
        WHEN OLD.artifact_id != NEW.artifact_id
          OR COALESCE(OLD.job_id,'') != COALESCE(NEW.job_id,'')
          OR OLD.export_type != NEW.export_type
          OR OLD.stored_filename != NEW.stored_filename
          OR OLD.download_filename != NEW.download_filename
          OR OLD.content_type != NEW.content_type
          OR OLD.row_count != NEW.row_count
          OR OLD.size_bytes != NEW.size_bytes
          OR OLD.sha256 != NEW.sha256
          OR OLD.filters_json != NEW.filters_json
          OR OLD.snapshot_at != NEW.snapshot_at
          OR OLD.created_by != NEW.created_by
          OR OLD.created_at != NEW.created_at
          OR COALESCE(OLD.expires_at,'') != COALESCE(NEW.expires_at,'')
        BEGIN
            SELECT RAISE(ABORT, 'export artifact core fields are immutable');
        END;
        CREATE TRIGGER IF NOT EXISTS export_artifacts_no_delete
        BEFORE DELETE ON export_artifacts
        BEGIN
            SELECT RAISE(ABORT, 'export artifacts cannot be deleted');
        END;
        CREATE TRIGGER IF NOT EXISTS config_baselines_core_immutable
        BEFORE UPDATE ON config_baselines
        WHEN OLD.baseline_id != NEW.baseline_id
          OR OLD.config_hash != NEW.config_hash
          OR OLD.snapshot_json != NEW.snapshot_json
          OR OLD.note != NEW.note
          OR OLD.created_by != NEW.created_by
          OR OLD.created_at != NEW.created_at
        BEGIN
            SELECT RAISE(ABORT, 'config baseline core fields are immutable');
        END;
        CREATE TRIGGER IF NOT EXISTS config_baselines_no_delete
        BEFORE DELETE ON config_baselines
        BEGIN
            SELECT RAISE(ABORT, 'config baselines cannot be deleted');
        END;
        CREATE TRIGGER IF NOT EXISTS config_drift_checks_immutable_update
        BEFORE UPDATE ON config_drift_checks
        BEGIN
            SELECT RAISE(ABORT, 'config drift checks are immutable');
        END;
        CREATE TRIGGER IF NOT EXISTS config_drift_checks_immutable_delete
        BEFORE DELETE ON config_drift_checks
        BEGIN
            SELECT RAISE(ABORT, 'config drift checks cannot be deleted');
        END;
        CREATE TRIGGER IF NOT EXISTS config_change_requests_core_immutable
        BEFORE UPDATE ON config_change_requests
        WHEN OLD.request_id != NEW.request_id
          OR OLD.baseline_id != NEW.baseline_id
          OR OLD.baseline_hash != NEW.baseline_hash
          OR OLD.target_hash != NEW.target_hash
          OR OLD.target_snapshot_json != NEW.target_snapshot_json
          OR OLD.impact_json != NEW.impact_json
          OR OLD.title != NEW.title
          OR OLD.reason != NEW.reason
          OR OLD.rollback_plan != NEW.rollback_plan
          OR OLD.window_start != NEW.window_start
          OR OLD.window_end != NEW.window_end
          OR OLD.requested_by != NEW.requested_by
          OR OLD.requested_at != NEW.requested_at
        BEGIN
            SELECT RAISE(ABORT, 'config change request core fields are immutable');
        END;
        CREATE TRIGGER IF NOT EXISTS config_change_requests_no_delete
        BEFORE DELETE ON config_change_requests
        BEGIN
            SELECT RAISE(ABORT, 'config change requests cannot be deleted');
        END;
        CREATE TRIGGER IF NOT EXISTS asset_identifiers_core_immutable
        BEFORE UPDATE ON asset_identifiers
        WHEN OLD.identifier_id != NEW.identifier_id
          OR OLD.identifier_type != NEW.identifier_type
          OR OLD.scope != NEW.scope
          OR OLD.normalized_value != NEW.normalized_value
          OR OLD.display_value != NEW.display_value
          OR OLD.source != NEW.source
          OR OLD.created_by != NEW.created_by
          OR OLD.created_at != NEW.created_at
        BEGIN
            SELECT RAISE(ABORT, 'asset identifier identity fields are immutable');
        END;
        CREATE TRIGGER IF NOT EXISTS asset_identifiers_no_delete
        BEFORE DELETE ON asset_identifiers
        BEGIN
            SELECT RAISE(ABORT, 'asset identifiers cannot be deleted');
        END;
        CREATE TRIGGER IF NOT EXISTS asset_identity_candidates_core_immutable
        BEFORE UPDATE ON asset_identity_candidates
        WHEN OLD.candidate_id != NEW.candidate_id
          OR OLD.asset_ref_id_a != NEW.asset_ref_id_a
          OR OLD.asset_ref_id_b != NEW.asset_ref_id_b
          OR OLD.fingerprint != NEW.fingerprint
          OR OLD.score != NEW.score
          OR OLD.reasons_json != NEW.reasons_json
          OR OLD.created_by != NEW.created_by
          OR OLD.created_at != NEW.created_at
        BEGIN
            SELECT RAISE(ABORT, 'asset identity candidate core fields are immutable');
        END;
        CREATE TRIGGER IF NOT EXISTS asset_identity_candidates_no_delete
        BEFORE DELETE ON asset_identity_candidates
        BEGIN
            SELECT RAISE(ABORT, 'asset identity candidates cannot be deleted');
        END;
        CREATE TRIGGER IF NOT EXISTS asset_merge_history_immutable_update
        BEFORE UPDATE ON asset_merge_history
        BEGIN
            SELECT RAISE(ABORT, 'asset merge history is immutable');
        END;
        CREATE TRIGGER IF NOT EXISTS asset_merge_history_immutable_delete
        BEFORE DELETE ON asset_merge_history
        BEGIN
            SELECT RAISE(ABORT, 'asset merge history is immutable');
        END;
        CREATE TRIGGER IF NOT EXISTS asset_merge_requests_core_immutable
        BEFORE UPDATE ON asset_merge_requests
        WHEN OLD.request_id != NEW.request_id
          OR COALESCE(OLD.candidate_id,'') != COALESCE(NEW.candidate_id,'')
          OR OLD.source_asset_ref_id != NEW.source_asset_ref_id
          OR OLD.target_asset_ref_id != NEW.target_asset_ref_id
          OR OLD.requested_by != NEW.requested_by
          OR OLD.reason != NEW.reason
          OR OLD.source_row_version != NEW.source_row_version
          OR OLD.target_row_version != NEW.target_row_version
          OR OLD.impact_json != NEW.impact_json
          OR OLD.impact_sha256 != NEW.impact_sha256
          OR OLD.requested_at != NEW.requested_at
        BEGIN
            SELECT RAISE(ABORT, 'asset merge request core fields are immutable');
        END;
        CREATE TRIGGER IF NOT EXISTS asset_merge_requests_no_delete
        BEFORE DELETE ON asset_merge_requests
        BEGIN
            SELECT RAISE(ABORT, 'asset merge requests cannot be deleted');
        END;
        CREATE TRIGGER IF NOT EXISTS asset_merge_rollback_journals_immutable_update
        BEFORE UPDATE ON asset_merge_rollback_journals
        BEGIN
            SELECT RAISE(ABORT, 'asset merge rollback journals are immutable');
        END;
        CREATE TRIGGER IF NOT EXISTS asset_merge_rollback_journals_immutable_delete
        BEFORE DELETE ON asset_merge_rollback_journals
        BEGIN
            SELECT RAISE(ABORT, 'asset merge rollback journals cannot be deleted');
        END;
        CREATE TRIGGER IF NOT EXISTS asset_merge_rollback_requests_core_immutable
        BEFORE UPDATE ON asset_merge_rollback_requests
        WHEN OLD.rollback_request_id != NEW.rollback_request_id
          OR OLD.merge_id != NEW.merge_id
          OR OLD.requested_by != NEW.requested_by
          OR OLD.reason != NEW.reason
          OR OLD.impact_json != NEW.impact_json
          OR OLD.impact_sha256 != NEW.impact_sha256
          OR OLD.requested_at != NEW.requested_at
        BEGIN
            SELECT RAISE(ABORT, 'asset merge rollback request core fields are immutable');
        END;
        CREATE TRIGGER IF NOT EXISTS asset_merge_rollback_requests_no_delete
        BEFORE DELETE ON asset_merge_rollback_requests
        BEGIN
            SELECT RAISE(ABORT, 'asset merge rollback requests cannot be deleted');
        END;
        """
    )


__all__ = ["_install_audit_triggers"]
