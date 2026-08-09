from __future__ import annotations

"""SQLite database initialization facade.

Migration, trigger, and backfill implementations live in dedicated modules so
future schema changes do not turn this public compatibility facade back into a
monolith.
"""

import sqlite3
import time
from pathlib import Path
from typing import Any

from app.core.database_backfills import (
    _backfill_asset_identifiers,
    _backfill_asset_inventory,
    _backfill_canonical_sources,
)
from app.core.database_migrations import _migrate, _record_schema_version
from app.core.database_search import _install_finding_fts
from app.core.database_triggers import _install_audit_triggers
from app.core.db import connect
from app.core.schema import COORDINATION_SCHEMA, SCHEMA
from app.core.schema_versions import CURRENT_APP_VERSION, CURRENT_SCHEMA_VERSION


def init_coordination_db(db_path: str | Path) -> None:
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    def initialize(conn: sqlite3.Connection) -> None:
        conn.executescript(COORDINATION_SCHEMA)

    _initialize_sqlite_database(path, initialize)


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
        conn.execute("CREATE INDEX IF NOT EXISTS idx_auth_sessions_user_active ON auth_sessions(username,revoked_at,expires_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_auth_sessions_expiry ON auth_sessions(expires_at,revoked_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_auth_login_attempts_created ON auth_login_attempts(created_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_auth_login_attempts_subject ON auth_login_attempts(username_key,client_key,created_at DESC)")
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_projects_single_default ON projects(is_default) WHERE is_default=1")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_projects_status_name ON projects(status,name,project_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_project_memberships_user ON project_memberships(username,project_id)")
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


__all__ = [
    "CURRENT_APP_VERSION",
    "CURRENT_SCHEMA_VERSION",
    "get_schema_info",
    "init_coordination_db",
    "init_db",
]
