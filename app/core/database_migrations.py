from __future__ import annotations

"""Schema migration and logical-version history for project databases."""

import hashlib
import json
import sqlite3

from app.core.db import utc_now
from app.core.schema import MIGRATION_COLUMNS
from app.core.schema_versions import CURRENT_APP_VERSION, CURRENT_SCHEMA_VERSION
from app.repositories.audit import AUDIT_GENESIS_HASH, _audit_event_digest, _canonical_audit_details

def _migrate(conn: sqlite3.Connection, previous_version: int) -> None:
    existing = {row[1] for row in conn.execute("PRAGMA table_info(findings)").fetchall()}
    for name, ddl in MIGRATION_COLUMNS.items():
        if name not in existing:
            conn.execute(f"ALTER TABLE findings ADD COLUMN {name} {ddl}")
    asset_columns = {row[1] for row in conn.execute("PRAGMA table_info(assets)").fetchall()}
    if "merged_into_asset_ref_id" not in asset_columns:
        conn.execute("ALTER TABLE assets ADD COLUMN merged_into_asset_ref_id TEXT")
    import_columns = {row[1] for row in conn.execute("PRAGMA table_info(import_batches)").fetchall()}
    if "source_job_id" not in import_columns:
        conn.execute("ALTER TABLE import_batches ADD COLUMN source_job_id TEXT")
    observation_columns = {row[1] for row in conn.execute("PRAGMA table_info(finding_observations)").fetchall()}
    if "source_record_id" not in observation_columns:
        conn.execute("ALTER TABLE finding_observations ADD COLUMN source_record_id TEXT")
    audit_columns = {row[1] for row in conn.execute("PRAGMA table_info(audit_events)").fetchall()}
    for name, ddl in {"chain_seq": "INTEGER", "prev_hash": "TEXT", "event_hash": "TEXT"}.items():
        if name not in audit_columns:
            conn.execute(f"ALTER TABLE audit_events ADD COLUMN {name} {ddl}")
    checkpoint_columns = {row[1] for row in conn.execute("PRAGMA table_info(audit_checkpoints)").fetchall()}
    if "key_id" not in checkpoint_columns:
        conn.execute("ALTER TABLE audit_checkpoints ADD COLUMN key_id TEXT")
    export_columns = {row[1] for row in conn.execute("PRAGMA table_info(export_artifacts)").fetchall()}
    for name, ddl in {
        "pinned": "INTEGER NOT NULL DEFAULT 0",
        "pinned_by": "TEXT",
        "pinned_at": "TEXT",
        "evicted_by": "TEXT",
        "evicted_at": "TEXT",
        "eviction_reason": "TEXT",
    }.items():
        if name not in export_columns:
            conn.execute(f"ALTER TABLE export_artifacts ADD COLUMN {name} {ddl}")

    evidence_columns = {row[1] for row in conn.execute("PRAGMA table_info(verification_evidence_artifacts)").fetchall()}
    for name, ddl in {
        "scan_status": "TEXT NOT NULL DEFAULT 'PENDING'",
        "scan_engine": "TEXT NOT NULL DEFAULT ''",
        "scan_signature": "TEXT NOT NULL DEFAULT ''",
        "scan_details": "TEXT NOT NULL DEFAULT ''",
        "scanned_at": "TEXT NOT NULL DEFAULT ''",
        "scan_error": "TEXT NOT NULL DEFAULT ''",
        "scan_waived_by": "TEXT NOT NULL DEFAULT ''",
        "scan_waived_at": "TEXT NOT NULL DEFAULT ''",
        "scan_waiver_reason": "TEXT NOT NULL DEFAULT ''",
        "source_type": "TEXT NOT NULL DEFAULT 'USER_UPLOAD'",
        "source_reference": "TEXT NOT NULL DEFAULT ''",
        "acquisition_method": "TEXT NOT NULL DEFAULT 'UPLOAD'",
        "collected_by": "TEXT NOT NULL DEFAULT ''",
        "collected_at": "TEXT NOT NULL DEFAULT ''",
        "current_custodian": "TEXT NOT NULL DEFAULT ''",
        "custody_last_seq": "INTEGER NOT NULL DEFAULT 0",
        "custody_last_hash": "TEXT NOT NULL DEFAULT ''",
    }.items():
        if name not in evidence_columns:
            conn.execute(f"ALTER TABLE verification_evidence_artifacts ADD COLUMN {name} {ddl}")

    # The built-in scanner only performs an EICAR baseline check. Historical
    # rows must not retain a full CLEAN verdict after upgrading to 72.0.11.
    conn.execute(
        """UPDATE verification_evidence_artifacts
               SET scan_status='BASELINE_ONLY',
                   scan_details=CASE WHEN scan_details='' THEN
                       'EICAR baseline completed; this is not a full malware clean verdict'
                   ELSE scan_details END
             WHERE scan_engine='builtin-baseline' AND scan_status='CLEAN'"""
    )

    # Backfill provenance and a verifiable genesis custody event for pre-17 evidence.
    legacy_rows = conn.execute(
        """SELECT evidence_id,uploaded_by,uploaded_at,current_custodian,custody_last_seq,custody_last_hash
             FROM verification_evidence_artifacts
            WHERE COALESCE(custody_last_seq,0)=0"""
    ).fetchall()
    for row in legacy_rows:
        actor = str(row["uploaded_by"] or "legacy-import")
        created_at = str(row["uploaded_at"] or utc_now())
        prev_hash = "0" * 64
        details_json = json.dumps({"migration": "v17", "legacy": True}, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        payload = {
            "evidence_id": row["evidence_id"], "event_seq": 1, "event_type": "LEGACY_IMPORTED",
            "actor": actor, "from_custodian": "", "to_custodian": actor,
            "purpose": "VulnFlow 17.0 custody migration", "details_json": details_json,
            "created_at": created_at, "prev_hash": prev_hash,
        }
        event_hash = hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
        conn.execute(
            """INSERT OR IGNORE INTO evidence_custody_events(
                   evidence_id,event_seq,event_type,actor,from_custodian,to_custodian,purpose,details_json,created_at,prev_hash,event_hash
               ) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
            (row["evidence_id"], 1, "LEGACY_IMPORTED", actor, "", actor,
             "VulnFlow 17.0 custody migration", details_json, created_at, prev_hash, event_hash),
        )
        conn.execute(
            """UPDATE verification_evidence_artifacts
                   SET collected_by=CASE WHEN collected_by='' THEN uploaded_by ELSE collected_by END,
                       collected_at=CASE WHEN collected_at='' THEN uploaded_at ELSE collected_at END,
                       current_custodian=CASE WHEN current_custodian='' THEN ? ELSE current_custodian END,
                       custody_last_seq=1,custody_last_hash=?
                 WHERE evidence_id=?""",
            (actor, event_hash, row["evidence_id"]),
        )

    state = conn.execute("SELECT * FROM audit_chain_state WHERE singleton_id=1").fetchone()
    event_count = int(conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0])
    if previous_version < 11:
        conn.execute("DROP TRIGGER IF EXISTS audit_events_require_chain")
        conn.execute("DROP TRIGGER IF EXISTS audit_events_immutable")
        prev_hash = AUDIT_GENESIS_HASH
        seq = 0
        rows = conn.execute(
            "SELECT id,finding_id,event_type,actor,summary,details_json,created_at FROM audit_events ORDER BY id"
        ).fetchall()
        for row in rows:
            seq += 1
            details_json = _canonical_audit_details(raw=row["details_json"])
            event_hash = _audit_event_digest(
                chain_seq=seq, finding_id=row["finding_id"], event_type=row["event_type"],
                actor=row["actor"], summary=row["summary"], details_json=details_json,
                created_at=row["created_at"], prev_hash=prev_hash,
            )
            conn.execute(
                "UPDATE audit_events SET details_json=?,chain_seq=?,prev_hash=?,event_hash=? WHERE id=?",
                (details_json, seq, prev_hash, event_hash, row["id"]),
            )
            prev_hash = event_hash
        now = utc_now()
        conn.execute(
            """INSERT INTO audit_chain_state(singleton_id,anchor_seq,anchor_hash,last_seq,last_hash,updated_at)
               VALUES(1,0,?,?,?,?)
               ON CONFLICT(singleton_id) DO UPDATE SET anchor_seq=0,anchor_hash=excluded.anchor_hash,
                   last_seq=excluded.last_seq,last_hash=excluded.last_hash,updated_at=excluded.updated_at""",
            (AUDIT_GENESIS_HASH, seq, prev_hash, now),
        )
    elif state is None:
        if event_count:
            raise RuntimeError("audit chain state is missing for an initialized database")
        conn.execute(
            "INSERT INTO audit_chain_state(singleton_id,anchor_seq,anchor_hash,last_seq,last_hash,updated_at) VALUES(1,0,?,0,?,?)",
            (AUDIT_GENESIS_HASH, AUDIT_GENESIS_HASH, utc_now()),
        )


def _record_schema_version(conn: sqlite3.Connection) -> None:
    previous = int(conn.execute("PRAGMA user_version").fetchone()[0])
    now = utc_now()
    # Preserve intermediate migration history when an older database jumps directly
    # to the current release. Schema creation is idempotent, but operators still need
    # an accurate audit trail of the logical versions that were applied.
    if previous < 23:
        conn.execute(
            "INSERT OR IGNORE INTO schema_migrations(version,name,applied_at,app_version) VALUES(?,?,?,?)",
            (23, "asset_merge_scoped_rollback", now, "23.0.0"),
        )
    if previous < 24:
        conn.execute(
            "INSERT OR IGNORE INTO schema_migrations(version,name,applied_at,app_version) VALUES(?,?,?,?)",
            (24, "sql_query_pagination_performance", now, "24.0.0"),
        )
    if previous < 25:
        conn.execute(
            "INSERT OR IGNORE INTO schema_migrations(version,name,applied_at,app_version) VALUES(?,?,?,?)",
            (25, "fts_cursor_pagination", now, "25.0.0"),
        )
    if previous < 26:
        conn.execute(
            "INSERT OR IGNORE INTO schema_migrations(version,name,applied_at,app_version) VALUES(?,?,?,?)",
            (26, "snapshot_export_artifacts", now, "26.0.0"),
        )
    if previous < 27:
        conn.execute(
            "INSERT OR IGNORE INTO schema_migrations(version,name,applied_at,app_version) VALUES(?,?,?,?)",
            (27, "export_storage_governance", now, "27.0.0"),
        )
    if previous < 28:
        conn.execute(
            "INSERT OR IGNORE INTO schema_migrations(version,name,applied_at,app_version) VALUES(?,?,?,?)",
            (28, "sqlite_online_maintenance", now, "28.0.0"),
        )
    if previous < 29:
        conn.execute(
            "INSERT OR IGNORE INTO schema_migrations(version,name,applied_at,app_version) VALUES(?,?,?,?)",
            (29, "configuration_baseline_drift", now, "29.0.0"),
        )
    if previous < 30:
        conn.execute(
            "INSERT OR IGNORE INTO schema_migrations(version,name,applied_at,app_version) VALUES(?,?,?,?)",
            (30, "configuration_change_control", now, "30.0.0"),
        )
    if previous < 31:
        conn.execute(
            "INSERT OR IGNORE INTO schema_migrations(version,name,applied_at,app_version) VALUES(?,?,?,?)",
            (31, "durable_idempotency_ledger", now, "42.0.0"),
        )
    if previous < 32:
        conn.execute(
            "INSERT OR IGNORE INTO schema_migrations(version,name,applied_at,app_version) VALUES(?,?,?,?)",
            (32, "redacted_execution_receipts", now, "43.0.0"),
        )
    if previous < 33:
        conn.execute(
            "INSERT OR IGNORE INTO schema_migrations(version,name,applied_at,app_version) VALUES(?,?,?,?)",
            (33, "execution_receipt_retention_archives", now, "44.0.0"),
        )
    if previous < 34:
        conn.execute(
            "INSERT OR IGNORE INTO schema_migrations(version,name,applied_at,app_version) VALUES(?,?,?,?)",
            (34, "integrity_proof_key_trust_transitions", now, "47.0.0"),
        )
    if previous < 35:
        conn.execute(
            "INSERT OR IGNORE INTO schema_migrations(version,name,applied_at,app_version) VALUES(?,?,?,?)",
            (35, "integrity_proof_emergency_key_revocation", now, "48.0.0"),
        )
    if previous < 36:
        conn.execute(
            "INSERT OR IGNORE INTO schema_migrations(version,name,applied_at,app_version) VALUES(?,?,?,?)",
            (36, "integrity_proof_revocation_registry_checkpoints", now, "49.0.0"),
        )
    if previous < 37:
        conn.execute(
            "INSERT OR IGNORE INTO schema_migrations(version,name,applied_at,app_version) VALUES(?,?,?,?)",
            (37, "integrity_proof_checkpoint_witness_quorum", now, "50.0.0"),
        )
    if previous < 38:
        conn.execute(
            "INSERT OR IGNORE INTO schema_migrations(version,name,applied_at,app_version) VALUES(?,?,?,?)",
            (38, "integrity_proof_append_only_transparency_log", now, "51.0.0"),
        )
    if previous < 39:
        conn.execute(
            "INSERT OR IGNORE INTO schema_migrations(version,name,applied_at,app_version) VALUES(?,?,?,?)",
            (39, "integrity_proof_transparency_mirror_gossip", now, "52.0.0"),
        )
    if previous < 40:
        conn.execute(
            "INSERT OR IGNORE INTO schema_migrations(version,name,applied_at,app_version) VALUES(?,?,?,?)",
            (40, "integrity_proof_mirror_consistency_checkpoints", now, "53.0.0"),
        )
    if previous < 41:
        conn.execute(
            "INSERT OR IGNORE INTO schema_migrations(version,name,applied_at,app_version) VALUES(?,?,?,?)",
            (41, "database_backed_user_sessions", now, "72.0.14"),
        )
    if previous < 42:
        conn.execute(
            """INSERT OR IGNORE INTO projects(
                   project_id,name,slug,status,is_default,created_by,created_at,updated_at
               ) VALUES('default','기본 프로젝트','default','ACTIVE',1,'system-migration',?,?)""",
            (now, now),
        )
        conn.execute(
            """INSERT OR IGNORE INTO project_memberships(project_id,username,created_by,created_at)
               SELECT 'default',username,'system-migration',? FROM app_users""",
            (now,),
        )
        conn.execute(
            "INSERT OR IGNORE INTO schema_migrations(version,name,applied_at,app_version) VALUES(?,?,?,?)",
            (42, "physically_isolated_projects", now, "72.0.16"),
        )
    if previous < 43:
        conn.execute(
            "INSERT OR IGNORE INTO schema_migrations(version,name,applied_at,app_version) VALUES(?,?,?,?)",
            (43, "project collaboration integrations", utc_now(), CURRENT_APP_VERSION),
        )
    if previous < 44:
        conn.execute(
            "INSERT OR IGNORE INTO schema_migrations(version,name,applied_at,app_version) VALUES(?,?,?,?)",
            (44, "pilot onboarding profile and readiness", utc_now(), CURRENT_APP_VERSION),
        )
    if previous < 45:
        conn.execute("UPDATE app_users SET failed_attempts=0,locked_until='' ")
        conn.execute(
            "INSERT OR IGNORE INTO schema_migrations(version,name,applied_at,app_version) VALUES(?,?,?,?)",
            (45, "authentication sliding-window rate limits", utc_now(), CURRENT_APP_VERSION),
        )
    if previous < 46:
        session_columns = {row[1] for row in conn.execute("PRAGMA table_info(auth_sessions)").fetchall()}
        if "last_seen_at" not in session_columns:
            conn.execute("ALTER TABLE auth_sessions ADD COLUMN last_seen_at TEXT NOT NULL DEFAULT ''")
        conn.execute("UPDATE auth_sessions SET last_seen_at=created_at WHERE last_seen_at='' ")
        conn.execute(
            "INSERT OR IGNORE INTO schema_migrations(version,name,applied_at,app_version) VALUES(?,?,?,?)",
            (46, "session idle timeout and request binding", utc_now(), CURRENT_APP_VERSION),
        )
    if previous < CURRENT_SCHEMA_VERSION:
        conn.execute(f"PRAGMA user_version={CURRENT_SCHEMA_VERSION}")
    for key, value in {
        "schema_version": str(CURRENT_SCHEMA_VERSION),
        "app_version": CURRENT_APP_VERSION,
    }.items():
        conn.execute(
            "INSERT INTO system_metadata(key,value,updated_at) VALUES(?,?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at",
            (key, value, now),
        )
    for key, value in {
        "database_role": "project-data",
        "project_id": "default",
        "project_name": "기본 프로젝트",
    }.items():
        conn.execute(
            "INSERT OR IGNORE INTO system_metadata(key,value,updated_at) VALUES(?,?,?)",
            (key, value, now),
        )


__all__ = ["_migrate", "_record_schema_version"]
