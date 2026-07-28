from __future__ import annotations

import sqlite3

REQUIRED_FINDING_COLUMNS = {"finding_id", "product", "cve_id", "status"}
REQUIRED_AUDIT_COLUMNS = {"id", "event_type", "summary", "created_at"}

def _validate_schema_v18_to_v31(conn: sqlite3.Connection, tables: set[str], schema_version: int) -> None:
    if schema_version >= 18:
        required_v18_tables = {"sbom_documents", "sbom_components", "sbom_finding_links", "vex_statements"}
        missing_v18 = required_v18_tables - tables
        if missing_v18:
            raise ValueError("18 이상 백업 필수 테이블이 없습니다: " + ", ".join(sorted(missing_v18)))
    if schema_version >= 19:
        required_v19_tables = {"osv_scan_runs", "osv_vulnerability_records", "sbom_osv_matches"}
        missing_v19 = required_v19_tables - tables
        if missing_v19:
            raise ValueError("19 이상 백업 필수 테이블이 없습니다: " + ", ".join(sorted(missing_v19)))
    if schema_version >= 20:
        required_v20_tables = {"source_finding_records", "finding_reconciliation_decisions"}
        missing_v20 = required_v20_tables - tables
        if missing_v20:
            raise ValueError("20 이상 백업 필수 테이블이 없습니다: " + ", ".join(sorted(missing_v20)))
    if schema_version >= 21:
        required_v21_tables = {"asset_identifiers", "asset_identity_candidates", "asset_merge_history"}
        missing_v21 = required_v21_tables - tables
        if missing_v21:
            raise ValueError("21 이상 백업 필수 테이블이 없습니다: " + ", ".join(sorted(missing_v21)))
        asset_columns = {row[1] for row in conn.execute("PRAGMA table_info(assets)").fetchall()}
        finding_columns_v21 = {row[1] for row in conn.execute("PRAGMA table_info(findings)").fetchall()}
        if "merged_into_asset_ref_id" not in asset_columns:
            raise ValueError("21 이상 백업 assets 필수 컬럼이 없습니다: merged_into_asset_ref_id")
        if "merged_into_finding_id" not in finding_columns_v21:
            raise ValueError("21 이상 백업 findings 필수 컬럼이 없습니다: merged_into_finding_id")
    if schema_version >= 22:
        required_v22_tables = {"asset_merge_requests"}
        missing_v22 = required_v22_tables - tables
        if missing_v22:
            raise ValueError("22 이상 백업 필수 테이블이 없습니다: " + ", ".join(sorted(missing_v22)))
    if schema_version >= 23:
        required_v23_tables = {"asset_merge_rollback_journals", "asset_merge_rollback_requests"}
        missing_v23 = required_v23_tables - tables
        if missing_v23:
            raise ValueError("23 이상 백업 필수 테이블이 없습니다: " + ", ".join(sorted(missing_v23)))
    if schema_version >= 25 and "findings_fts" not in tables:
        raise ValueError("25 이상 백업에 findings_fts 검색 인덱스가 없습니다.")
    if schema_version >= 26 and "export_artifacts" not in tables:
        raise ValueError("26 이상 백업에 export_artifacts 테이블이 없습니다.")
    if schema_version >= 29:
        required_v29_tables = {"config_baselines", "config_drift_checks"}
        missing_v29 = required_v29_tables - tables
        if missing_v29:
            raise ValueError("29 이상 백업 필수 테이블이 없습니다: " + ", ".join(sorted(missing_v29)))
    if schema_version >= 30:
        required_v30_tables = {"config_change_requests"}
        missing_v30 = required_v30_tables - tables
        if missing_v30:
            raise ValueError("30 이상 백업 필수 테이블이 없습니다: " + ", ".join(sorted(missing_v30)))
    if schema_version >= 31:
        required_v31_tables = {"idempotency_records"}
        missing_v31 = required_v31_tables - tables
        if missing_v31:
            raise ValueError("31 이상 백업 필수 테이블이 없습니다: " + ", ".join(sorted(missing_v31)))
        idempotency_columns = {row[1] for row in conn.execute("PRAGMA table_info(idempotency_records)").fetchall()}
        required_idempotency_columns = {
            "scope", "key_sha256", "request_sha256", "resource_type", "resource_id",
            "response_json", "created_at", "expires_at",
        }
        missing_idempotency_columns = required_idempotency_columns - idempotency_columns
        if missing_idempotency_columns:
            raise ValueError(
                "31 이상 백업 idempotency_records 필수 컬럼이 없습니다: "
                + ", ".join(sorted(missing_idempotency_columns))
            )
        if "idempotency_key" in idempotency_columns:
            raise ValueError("31 이상 백업은 원시 idempotency key 컬럼을 포함할 수 없습니다.")

def _validate_schema_v32_to_v35_and_core(conn: sqlite3.Connection, tables: set[str], schema_version: int) -> None:
    if schema_version >= 32:
        receipt_tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        missing_receipt_tables = {"execution_receipts", "execution_replays"} - receipt_tables
        if missing_receipt_tables:
            raise ValueError("32 이상 백업 실행 영수증 테이블이 없습니다: " + ", ".join(sorted(missing_receipt_tables)))
        receipt_columns = {row[1] for row in conn.execute("PRAGMA table_info(execution_receipts)").fetchall()}
        required_receipt_columns = {"receipt_id","operation_type","resource_id","receipt_sequence","outcome","request_sha256","result_sha256","error_sha256","actor_sha256","metadata_json","created_at"}
        missing_receipt_columns = required_receipt_columns - receipt_columns
        if missing_receipt_columns:
            raise ValueError("32 이상 백업 execution_receipts 필수 컬럼이 없습니다: " + ", ".join(sorted(missing_receipt_columns)))
        forbidden_receipt_columns = {"payload_json","result_json","error","worker_id","actor"} & receipt_columns
        if forbidden_receipt_columns:
            raise ValueError("32 이상 백업 실행 영수증은 원문 민감 컬럼을 포함할 수 없습니다: " + ", ".join(sorted(forbidden_receipt_columns)))
    if schema_version >= 33:
        if "execution_receipt_archives" not in tables:
            raise ValueError("33 이상 백업에 execution_receipt_archives 테이블이 없습니다.")
        archive_columns = {row[1] for row in conn.execute("PRAGMA table_info(execution_receipt_archives)").fetchall()}
        required_archive_columns = {
            "archive_id", "cutoff_at", "receipt_count", "first_created_at", "last_created_at",
            "receipt_digest_sha256", "operation_summary_json", "outcome_summary_json",
            "subtype_summary_json", "actor_sha256", "created_at",
        }
        missing_archive_columns = required_archive_columns - archive_columns
        if missing_archive_columns:
            raise ValueError(
                "33 이상 백업 execution_receipt_archives 필수 컬럼이 없습니다: "
                + ", ".join(sorted(missing_archive_columns))
            )
    if schema_version >= 34:
        if "integrity_proof_key_transitions" not in tables:
            raise ValueError("34 이상 백업에 integrity_proof_key_transitions 테이블이 없습니다.")
        transition_columns = {
            row[1] for row in conn.execute("PRAGMA table_info(integrity_proof_key_transitions)").fetchall()
        }
        required_transition_columns = {
            "transition_id", "from_key_id", "from_public_key_base64",
            "from_public_key_sha256", "to_key_id", "to_public_key_base64",
            "to_public_key_sha256", "effective_at", "reason_sha256",
            "statement_json", "from_signature", "to_signature", "created_by", "created_at",
        }
        missing_transition_columns = required_transition_columns - transition_columns
        if missing_transition_columns:
            raise ValueError(
                "34 이상 백업 integrity_proof_key_transitions 필수 컬럼이 없습니다: "
                + ", ".join(sorted(missing_transition_columns))
            )
        forbidden_transition_columns = {"from_private_key", "to_private_key", "reason"} & transition_columns
        if forbidden_transition_columns:
            raise ValueError(
                "34 이상 백업 키 전환 테이블은 private key 또는 원문 사유 컬럼을 포함할 수 없습니다: "
                + ", ".join(sorted(forbidden_transition_columns))
            )
    if schema_version >= 35:
        if "integrity_proof_key_revocations" not in tables:
            raise ValueError("35 이상 백업에 integrity_proof_key_revocations 테이블이 없습니다.")
        revocation_columns = {
            row[1] for row in conn.execute("PRAGMA table_info(integrity_proof_key_revocations)").fetchall()
        }
        required_revocation_columns = {
            "revocation_id", "revoked_key_id", "revoked_public_key_base64",
            "revoked_public_key_sha256", "replacement_key_id",
            "replacement_public_key_base64", "replacement_public_key_sha256",
            "recovery_key_id", "recovery_public_key_base64",
            "recovery_public_key_sha256", "invalid_after", "effective_at",
            "reason_sha256", "statement_json", "recovery_signature",
            "replacement_signature", "created_by", "created_at",
        }
        missing_revocation_columns = required_revocation_columns - revocation_columns
        if missing_revocation_columns:
            raise ValueError(
                "35 이상 백업 integrity_proof_key_revocations 필수 컬럼이 없습니다: "
                + ", ".join(sorted(missing_revocation_columns))
            )
        forbidden_revocation_columns = {
            "revoked_private_key", "replacement_private_key",
            "recovery_private_key", "reason",
        } & revocation_columns
        if forbidden_revocation_columns:
            raise ValueError(
                "35 이상 백업 키 폐기 테이블은 private key 또는 원문 사유 컬럼을 포함할 수 없습니다: "
                + ", ".join(sorted(forbidden_revocation_columns))
            )
    if schema_version >= 27:
        export_columns = {row[1] for row in conn.execute("PRAGMA table_info(export_artifacts)").fetchall()}
        required_export_columns = {"pinned", "pinned_by", "pinned_at", "evicted_by", "evicted_at", "eviction_reason"}
        missing_export_columns = required_export_columns - export_columns
        if missing_export_columns:
            raise ValueError("27 이상 백업 export_artifacts 필수 컬럼이 없습니다: " + ", ".join(sorted(missing_export_columns)))
    if schema_version >= 17:
        required_v17_tables = {"verification_evidence_artifacts", "evidence_custody_events"}
        missing_v17 = required_v17_tables - tables
        if missing_v17:
            raise ValueError("17 이상 백업 필수 테이블이 없습니다: " + ", ".join(sorted(missing_v17)))
        evidence_columns = {row[1] for row in conn.execute("PRAGMA table_info(verification_evidence_artifacts)").fetchall()}
        required_evidence_columns = {"source_type","source_reference","acquisition_method","collected_by","collected_at","current_custodian","custody_last_seq","custody_last_hash"}
        missing_evidence = required_evidence_columns - evidence_columns
        if missing_evidence:
            raise ValueError("증거 보관 사슬 필수 컬럼이 없습니다: " + ", ".join(sorted(missing_evidence)))
    columns = {row[1] for row in conn.execute("PRAGMA table_info(findings)").fetchall()}
    missing_columns = REQUIRED_FINDING_COLUMNS - columns
    if missing_columns:
        raise ValueError("findings 필수 컬럼이 없습니다: " + ", ".join(sorted(missing_columns)))
    audit_columns = {row[1] for row in conn.execute("PRAGMA table_info(audit_events)").fetchall()}
    missing_audit_columns = REQUIRED_AUDIT_COLUMNS - audit_columns
    if missing_audit_columns:
        raise ValueError("audit_events 필수 컬럼이 없습니다: " + ", ".join(sorted(missing_audit_columns)))

def _validate_schema_v36_to_v38(conn: sqlite3.Connection, tables: set[str], schema_version: int) -> None:
    if schema_version >= 36:
        if "integrity_proof_revocation_checkpoints" not in tables:
            raise ValueError("36 이상 백업에 integrity_proof_revocation_checkpoints 테이블이 없습니다.")
        checkpoint_columns = {
            row[1] for row in conn.execute("PRAGMA table_info(integrity_proof_revocation_checkpoints)").fetchall()
        }
        required_checkpoint_columns = {
            "checkpoint_id", "sequence", "previous_checkpoint_sha256",
            "revocation_count", "revocation_registry_sha256",
            "transition_count", "transition_registry_sha256",
            "recovery_key_id", "recovery_public_key_base64", "recovery_public_key_sha256",
            "statement_json", "signature", "document_sha256", "created_by", "created_at",
        }
        missing_checkpoint_columns = required_checkpoint_columns - checkpoint_columns
        if missing_checkpoint_columns:
            raise ValueError(
                "36 이상 백업 registry checkpoint 필수 컬럼이 없습니다: "
                + ", ".join(sorted(missing_checkpoint_columns))
            )
        forbidden_checkpoint_columns = {
            "private_key", "recovery_private_key", "secret", "token",
        } & checkpoint_columns
        if forbidden_checkpoint_columns:
            raise ValueError(
                "registry checkpoint 테이블에 금지된 비밀정보 컬럼이 있습니다: "
                + ", ".join(sorted(forbidden_checkpoint_columns))
            )
    if schema_version >= 37:
        if "integrity_proof_checkpoint_witnesses" not in tables:
            raise ValueError("37 이상 백업에 integrity_proof_checkpoint_witnesses 테이블이 없습니다.")
        witness_columns = {
            row[1] for row in conn.execute("PRAGMA table_info(integrity_proof_checkpoint_witnesses)").fetchall()
        }
        required_witness_columns = {
            "attestation_id", "checkpoint_id", "checkpoint_sequence", "checkpoint_document_sha256",
            "revocation_registry_sha256", "transition_registry_sha256", "witness_key_id",
            "witness_public_key_base64", "witness_public_key_sha256", "observed_at",
            "statement_json", "signature", "document_sha256", "created_by", "created_at",
        }
        missing_witness_columns = required_witness_columns - witness_columns
        if missing_witness_columns:
            raise ValueError(
                "37 이상 백업 checkpoint witness 필수 컬럼이 없습니다: "
                + ", ".join(sorted(missing_witness_columns))
            )
        forbidden_witness_columns = {"private_key", "secret", "token"} & witness_columns
        if forbidden_witness_columns:
            raise ValueError(
                "checkpoint witness 테이블에 금지된 비밀정보 컬럼이 있습니다: "
                + ", ".join(sorted(forbidden_witness_columns))
            )
    if schema_version >= 38:
        required_tables = {
            "integrity_proof_transparency_entries", "integrity_proof_transparency_heads"
        }
        missing_transparency_tables = required_tables - tables
        if missing_transparency_tables:
            raise ValueError(
                "38 이상 백업 transparency log 필수 테이블이 없습니다: "
                + ", ".join(sorted(missing_transparency_tables))
            )
        entry_columns = {
            row[1] for row in conn.execute("PRAGMA table_info(integrity_proof_transparency_entries)").fetchall()
        }
        required_entry_columns = {
            "entry_id", "sequence", "previous_entry_sha256", "checkpoint_id", "checkpoint_sequence",
            "checkpoint_document_sha256", "witness_count", "witness_registry_sha256",
            "statement_json", "document_sha256", "created_by", "created_at",
        }
        missing_entry_columns = required_entry_columns - entry_columns
        if missing_entry_columns:
            raise ValueError(
                "38 이상 백업 transparency entry 필수 컬럼이 없습니다: "
                + ", ".join(sorted(missing_entry_columns))
            )
        head_columns = {
            row[1] for row in conn.execute("PRAGMA table_info(integrity_proof_transparency_heads)").fetchall()
        }
        required_head_columns = {
            "head_id", "tree_size", "latest_entry_sha256", "previous_head_sha256",
            "log_key_id", "log_public_key_base64", "log_public_key_sha256",
            "statement_json", "signature", "document_sha256", "created_by", "created_at",
        }
        missing_head_columns = required_head_columns - head_columns
        if missing_head_columns:
            raise ValueError(
                "38 이상 백업 transparency head 필수 컬럼이 없습니다: "
                + ", ".join(sorted(missing_head_columns))
            )
        forbidden_transparency_columns = {"private_key", "secret", "token"} & (entry_columns | head_columns)
        if forbidden_transparency_columns:
            raise ValueError(
                "transparency log 테이블에 금지된 비밀정보 컬럼이 있습니다: "
                + ", ".join(sorted(forbidden_transparency_columns))
            )

def _validate_schema_v39_to_v40(conn: sqlite3.Connection, tables: set[str], schema_version: int) -> None:
    if schema_version >= 39:
        if "integrity_proof_transparency_mirror_receipts" not in tables:
            raise ValueError("39 이상 백업에 integrity_proof_transparency_mirror_receipts 테이블이 없습니다.")
        mirror_columns = {
            row[1] for row in conn.execute(
                "PRAGMA table_info(integrity_proof_transparency_mirror_receipts)"
            ).fetchall()
        }
        required_mirror_columns = {
            "receipt_id", "head_id", "tree_size", "head_document_sha256",
            "previous_tree_size", "previous_receipt_sha256", "mirror_key_id",
            "mirror_public_key_base64", "mirror_public_key_sha256", "observed_at",
            "statement_json", "signature", "document_sha256", "created_by", "created_at",
        }
        missing_mirror_columns = required_mirror_columns - mirror_columns
        if missing_mirror_columns:
            raise ValueError(
                "39 이상 백업 transparency mirror receipt 필수 컬럼이 없습니다: "
                + ", ".join(sorted(missing_mirror_columns))
            )
        forbidden_mirror_columns = {"private_key", "secret", "token"} & mirror_columns
        if forbidden_mirror_columns:
            raise ValueError(
                "transparency mirror receipt 테이블에 금지된 비밀정보 컬럼이 있습니다: "
                + ", ".join(sorted(forbidden_mirror_columns))
            )
    if schema_version >= 40:
        if "integrity_proof_mirror_consistency_checkpoints" not in tables:
            raise ValueError("40 이상 백업에 integrity_proof_mirror_consistency_checkpoints 테이블이 없습니다.")
        consistency_columns = {
            row[1] for row in conn.execute(
                "PRAGMA table_info(integrity_proof_mirror_consistency_checkpoints)"
            ).fetchall()
        }
        required_consistency_columns = {
            "checkpoint_id", "sequence", "previous_checkpoint_sha256", "head_id", "tree_size",
            "head_document_sha256", "mirror_quorum", "mirror_count", "mirror_set_sha256",
            "statement_json", "signatures_json", "document_sha256", "created_by", "created_at",
        }
        missing_consistency_columns = required_consistency_columns - consistency_columns
        if missing_consistency_columns:
            raise ValueError(
                "40 이상 백업 mirror consistency checkpoint 필수 컬럼이 없습니다: "
                + ", ".join(sorted(missing_consistency_columns))
            )
        forbidden_consistency_columns = {"private_key", "secret", "token"} & consistency_columns
        if forbidden_consistency_columns:
            raise ValueError(
                "mirror consistency checkpoint 테이블에 금지된 비밀정보 컬럼이 있습니다: "
                + ", ".join(sorted(forbidden_consistency_columns))
            )

def _validate_restore_triggers(conn: sqlite3.Connection, tables: set[str], schema_version: int) -> None:
    trigger_names = {str(row[0]) for row in conn.execute("SELECT name FROM sqlite_master WHERE type='trigger'").fetchall()}
    allowed_triggers = {
        "audit_events_require_chain", "audit_events_immutable",
        "audit_checkpoints_immutable_update", "audit_checkpoints_immutable_delete",
        "verification_evidence_core_immutable", "verification_evidence_no_delete",
        "evidence_custody_immutable_update", "evidence_custody_immutable_delete",
        "asset_identifiers_core_immutable", "asset_identifiers_no_delete",
        "asset_identity_candidates_core_immutable", "asset_identity_candidates_no_delete",
        "asset_merge_history_immutable_update", "asset_merge_history_immutable_delete",
        "asset_merge_requests_core_immutable", "asset_merge_requests_no_delete",
        "asset_merge_rollback_journals_immutable_update", "asset_merge_rollback_journals_immutable_delete",
        "asset_merge_rollback_requests_core_immutable", "asset_merge_rollback_requests_no_delete",
        "findings_fts_after_insert", "findings_fts_after_delete", "findings_fts_after_update",
        "export_artifacts_core_immutable", "export_artifacts_no_delete",
        "config_baselines_core_immutable", "config_baselines_no_delete",
        "config_drift_checks_immutable_update", "config_drift_checks_immutable_delete",
        "config_change_requests_core_immutable", "config_change_requests_no_delete",
        "execution_receipts_no_update", "execution_receipts_no_delete",
        "execution_replays_no_update", "execution_replays_no_delete",
        "execution_receipt_archives_no_update", "execution_receipt_archives_no_delete",
        "integrity_proof_key_transitions_no_update", "integrity_proof_key_transitions_no_delete",
        "integrity_proof_key_revocations_no_update", "integrity_proof_key_revocations_no_delete",
        "integrity_proof_revocation_checkpoints_no_update", "integrity_proof_revocation_checkpoints_no_delete",
        "integrity_proof_checkpoint_witnesses_no_update", "integrity_proof_checkpoint_witnesses_no_delete",
        "integrity_proof_transparency_entries_no_update", "integrity_proof_transparency_entries_no_delete",
        "integrity_proof_transparency_heads_no_update", "integrity_proof_transparency_heads_no_delete",
        "integrity_proof_transparency_mirror_receipts_no_update",
        "integrity_proof_transparency_mirror_receipts_no_delete",
        "integrity_proof_mirror_consistency_checkpoints_no_update",
        "integrity_proof_mirror_consistency_checkpoints_no_delete",
    }
    unexpected_triggers = trigger_names - allowed_triggers
    if unexpected_triggers:
        raise ValueError("복원 백업에 허용되지 않은 SQLite 트리거가 포함되어 있습니다: " + ", ".join(sorted(unexpected_triggers)))

def _collect_restore_counts(conn: sqlite3.Connection, tables: set[str]) -> tuple[int, int, int]:
    finding_count = int(conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0])
    audit_count = int(conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0])
    evidence_count = int(conn.execute(
        "SELECT COUNT(*) FROM verification_evidence_artifacts WHERE status!='PURGED'"
    ).fetchone()[0]) if "verification_evidence_artifacts" in tables else 0
    return finding_count, audit_count, evidence_count


def validate_schema_contents(
    conn: sqlite3.Connection,
    tables: set[str],
    schema_version: int,
) -> tuple[int, int, int]:
    _validate_schema_v18_to_v31(conn, tables, schema_version)
    _validate_schema_v32_to_v35_and_core(conn, tables, schema_version)
    _validate_schema_v36_to_v38(conn, tables, schema_version)
    _validate_schema_v39_to_v40(conn, tables, schema_version)
    _validate_restore_triggers(conn, tables, schema_version)
    return _collect_restore_counts(conn, tables)
