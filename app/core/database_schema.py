from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from pathlib import Path
from typing import Any

from app.core.db import connect, utc_now
from app.core.schema import COORDINATION_SCHEMA, MIGRATION_COLUMNS, SCHEMA
from app.repositories.audit import AUDIT_GENESIS_HASH, _audit_event_digest, _canonical_audit_details
from app.repositories.reconciliation import (
    _register_asset_identifiers_conn, _source_snapshot, _sync_asset_row,
    canonical_key_for, source_record_id_for,
)
from app.services.asset_identity import append_identifier as _append_identifier, extract_asset_identifiers

CURRENT_SCHEMA_VERSION = 40
CURRENT_APP_VERSION = "72.0.13"

def init_coordination_db(db_path: str | Path) -> None:
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    def initialize(conn: sqlite3.Connection) -> None:
        conn.executescript(COORDINATION_SCHEMA)

    _initialize_sqlite_database(path, initialize)

def _backfill_asset_identifiers(conn: sqlite3.Connection) -> None:
    now = utc_now()
    assets = conn.execute("SELECT * FROM assets ORDER BY asset_ref_id").fetchall()
    for raw in assets:
        asset = dict(raw)
        identifiers: list[dict[str, Any]] = []
        external = str(asset.get("external_asset_id") or "").strip()
        if external:
            _append_identifier(identifiers, "INVENTORY_ID", external, scanner_source="inventory",
                               environment=str(asset.get("environment") or ""), source="migration:inventory")
        name = str(asset.get("asset_name") or "").strip()
        if name:
            name_row = {"asset_name": name, "environment": asset.get("environment") or ""}
            identifiers.extend(extract_asset_identifiers(name_row, scanner_source="inventory"))
        _register_asset_identifiers_conn(conn, asset_ref_id=asset["asset_ref_id"], identifiers=identifiers,
                                         actor="migration-v21", now=now)
    records = conn.execute(
        """SELECT r.scanner_source,r.snapshot_json,f.asset_ref_id
             FROM source_finding_records r JOIN findings f ON f.finding_id=r.finding_id
            WHERE f.asset_ref_id IS NOT NULL AND f.asset_ref_id!=''"""
    ).fetchall()
    for raw in records:
        try:
            snapshot = json.loads(raw["snapshot_json"] or "{}")
        except json.JSONDecodeError:
            snapshot = {}
        identifiers = extract_asset_identifiers(snapshot, scanner_source=str(raw["scanner_source"] or "manual"))
        _register_asset_identifiers_conn(conn, asset_ref_id=str(raw["asset_ref_id"]), identifiers=identifiers,
                                         actor="migration-v21", now=now)

def _backfill_asset_inventory(conn: sqlite3.Connection) -> None:
    now = utc_now()
    rows = conn.execute("SELECT * FROM findings").fetchall()
    for raw in rows:
        _sync_asset_row(conn, dict(raw), now=now)

def _backfill_canonical_sources(conn: sqlite3.Connection) -> None:
    now = utc_now()
    rows = conn.execute("SELECT * FROM findings ORDER BY finding_id").fetchall()
    for raw in rows:
        item = dict(raw)
        key = str(item.get("canonical_key") or "").strip() or canonical_key_for(item)
        conn.execute(
            "UPDATE findings SET canonical_key=?,source_count=MAX(COALESCE(source_count,0),1) WHERE finding_id=?",
            (key, item["finding_id"]),
        )
        source = str(item.get("scanner_source") or "manual").split(",")[0].strip() or "manual"
        source_id = str(item.get("finding_id") or "")
        record_id = source_record_id_for(source, source_id)
        state = "PRESENT" if str(item.get("record_state") or "ACTIVE") == "ACTIVE" else "ABSENT"
        snapshot = json.dumps(_source_snapshot(item), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        first_seen = str(item.get("first_seen_at") or now)
        last_seen = str(item.get("source_last_seen_at") or item.get("updated_at") or now)
        requested_batch = str(item.get("import_batch_id") or "").strip()
        valid_batch = requested_batch if requested_batch and conn.execute(
            "SELECT 1 FROM import_batches WHERE batch_id=?", (requested_batch,)
        ).fetchone() else None
        conn.execute(
            """INSERT OR IGNORE INTO source_finding_records(
                   source_record_id,finding_id,scanner_source,source_finding_id,canonical_key,observed_state,consecutive_absent_scans,
                   first_seen_at,last_seen_at,last_batch_id,snapshot_json,created_at,updated_at
               ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (record_id, item["finding_id"], source, source_id, key, state,
             int(item.get("consecutive_absent_scans") or 0), first_seen, last_seen, valid_batch, snapshot, now, now),
        )

def _initialize_sqlite_database(
    db_path: str | Path,
    initializer,
    *,
    attempts: int = 40,
) -> None:
    """Initialize a local SQLite database safely during concurrent first start.

    SQLite persists WAL mode, so only initialization needs to negotiate the
    journal mode. A second process may briefly observe SQLITE_BUSY/LOCKED or
    SQLITE_SCHEMA or an FTS virtual-table constructor race while the first process creates the schema. It closes its connection and retries
    with bounded exponential backoff instead of failing application startup.
    """
    last_error: sqlite3.OperationalError | None = None
    for attempt in range(attempts):
        try:
            with connect(db_path) as conn:
                conn.execute("PRAGMA journal_mode=WAL").fetchone()
                initializer(conn)
                conn.commit()
            return
        except sqlite3.OperationalError as exc:
            message = str(exc).lower()
            retryable = ("locked", "busy", "schema has changed", "vtable constructor failed")
            if not any(marker in message for marker in retryable):
                raise
            last_error = exc
            time.sleep(min(0.05 * (2 ** min(attempt, 5)), 1.0))
    raise sqlite3.OperationalError(
        f"SQLite initialization remained locked after {attempts} attempts: {db_path}"
    ) from last_error

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

def _install_finding_fts(conn: sqlite3.Connection, *, rebuild: bool = False) -> None:
    """Install the external-content FTS5 index and transactional sync triggers."""
    conn.execute(
        """CREATE VIRTUAL TABLE IF NOT EXISTS findings_fts USING fts5(
               finding_id,product,asset_name,cve_id,component,owner,
               content='findings',content_rowid='rowid',tokenize='unicode61 remove_diacritics 2'
           )"""
    )
    conn.executescript(
        """
        CREATE TRIGGER IF NOT EXISTS findings_fts_after_insert AFTER INSERT ON findings BEGIN
            INSERT INTO findings_fts(rowid,finding_id,product,asset_name,cve_id,component,owner)
            VALUES(new.rowid,new.finding_id,new.product,new.asset_name,new.cve_id,new.component,new.owner);
        END;
        CREATE TRIGGER IF NOT EXISTS findings_fts_after_delete AFTER DELETE ON findings BEGIN
            INSERT INTO findings_fts(findings_fts,rowid,finding_id,product,asset_name,cve_id,component,owner)
            VALUES('delete',old.rowid,old.finding_id,old.product,old.asset_name,old.cve_id,old.component,old.owner);
        END;
        CREATE TRIGGER IF NOT EXISTS findings_fts_after_update
        AFTER UPDATE OF finding_id,product,asset_name,cve_id,component,owner ON findings BEGIN
            INSERT INTO findings_fts(findings_fts,rowid,finding_id,product,asset_name,cve_id,component,owner)
            VALUES('delete',old.rowid,old.finding_id,old.product,old.asset_name,old.cve_id,old.component,old.owner);
            INSERT INTO findings_fts(rowid,finding_id,product,asset_name,cve_id,component,owner)
            VALUES(new.rowid,new.finding_id,new.product,new.asset_name,new.cve_id,new.component,new.owner);
        END;
        """
    )
    if rebuild:
        conn.execute("INSERT INTO findings_fts(findings_fts) VALUES('rebuild')")

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

def init_db(db_path: str | Path) -> None:
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    def initialize(conn: sqlite3.Connection) -> None:
        previous_version = int(conn.execute("PRAGMA user_version").fetchone()[0])
        conn.executescript(SCHEMA)
        _migrate(conn, previous_version)
        _install_audit_triggers(conn)
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_chain_seq ON audit_events(chain_seq) WHERE chain_seq IS NOT NULL")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_checkpoints_seq ON audit_checkpoints(chain_seq DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_prune_created ON audit_prune_history(created_at DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_source_state ON findings(scanner_source, record_state)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_asset_ref ON findings(asset_ref_id)")
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_import_batches_source_job ON import_batches(source_job_id) WHERE source_job_id IS NOT NULL")
        _backfill_asset_inventory(conn)
        _backfill_canonical_sources(conn)
        _backfill_asset_identifiers(conn)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_canonical_key ON findings(canonical_key)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_list_state_score ON findings(score DESC,kev DESC,epss DESC,cve_id,finding_id) WHERE record_state!='ARCHIVED'")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_list_filters ON findings(status,decision,scanner_source,score DESC,kev DESC,epss DESC,cve_id,finding_id) WHERE record_state!='ARCHIVED'")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_active_due ON findings(record_state,status,due_date,target_date) WHERE status IN ('OPEN','IN_PROGRESS')")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_exception_expiry ON findings(record_state,status,exception_expiry) WHERE status='RISK_ACCEPTED'")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_export_artifacts_created ON export_artifacts(status,created_at DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_export_artifacts_expiry ON export_artifacts(status,expires_at) WHERE status='READY'")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_export_artifacts_lru ON export_artifacts(status,pinned,last_downloaded_at,created_at)")
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_config_baseline_active ON config_baselines(status) WHERE status='ACTIVE'")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_config_baselines_hash ON config_baselines(config_hash,created_at DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_config_drift_checks_time ON config_drift_checks(checked_at DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_config_change_requests_status ON config_change_requests(status,window_start,window_end,requested_at DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_config_change_requests_target ON config_change_requests(baseline_id,target_hash,status)")
        _install_finding_fts(conn, rebuild=previous_version < 25)
        _record_schema_version(conn)

    _initialize_sqlite_database(path, initialize)

def get_schema_info(db_path: str | Path) -> dict[str, Any]:
    with connect(db_path) as conn:
        version = int(conn.execute("PRAGMA user_version").fetchone()[0])
        migrations = [dict(row) for row in conn.execute(
            "SELECT version,name,applied_at,app_version FROM schema_migrations ORDER BY version"
        ).fetchall()]
        metadata = {row["key"]: row["value"] for row in conn.execute(
            "SELECT key,value FROM system_metadata"
        ).fetchall()}
    return {
        "schema_version": version,
        "current_schema_version": CURRENT_SCHEMA_VERSION,
        "app_version": metadata.get("app_version", CURRENT_APP_VERSION),
        "migrations": migrations,
    }
