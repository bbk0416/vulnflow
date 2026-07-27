from __future__ import annotations

import json
import os
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Any

from app.core.db import connect, utc_now
from app.repositories.audit import add_audit_event


def _file_size(path: Path) -> int:
    try:
        return int(path.stat().st_size)
    except FileNotFoundError:
        return 0


def database_health(db_path: str | Path, *, deep_check: bool = True) -> dict[str, Any]:
    path = Path(db_path)
    with connect(path) as conn:
        page_size = int(conn.execute("PRAGMA page_size").fetchone()[0])
        page_count = int(conn.execute("PRAGMA page_count").fetchone()[0])
        freelist_count = int(conn.execute("PRAGMA freelist_count").fetchone()[0])
        journal_mode = str(conn.execute("PRAGMA journal_mode").fetchone()[0]).upper()
        auto_vacuum = int(conn.execute("PRAGMA auto_vacuum").fetchone()[0])
        integrity = str(conn.execute("PRAGMA quick_check(1)").fetchone()[0]) if deep_check else "NOT_CHECKED"
        fts_rows = int(conn.execute("SELECT COUNT(*) FROM findings_fts").fetchone()[0])
        finding_rows = int(conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0])
        fts_in_sync: bool | None = None
        if deep_check:
            try:
                conn.execute("INSERT INTO findings_fts(findings_fts, rank) VALUES('integrity-check', 1)")
                fts_in_sync = True
            except sqlite3.DatabaseError:
                fts_in_sync = False
            finally:
                conn.rollback()
    database_bytes = _file_size(path)
    wal_bytes = _file_size(Path(str(path) + "-wal"))
    shm_bytes = _file_size(Path(str(path) + "-shm"))
    reclaimable_bytes = freelist_count * page_size
    allocated_bytes = page_count * page_size
    return {
        "database_path": str(path),
        "database_bytes": database_bytes,
        "wal_bytes": wal_bytes,
        "shm_bytes": shm_bytes,
        "page_size": page_size,
        "page_count": page_count,
        "freelist_count": freelist_count,
        "reclaimable_bytes": reclaimable_bytes,
        "allocated_bytes": allocated_bytes,
        "reclaimable_ratio": round((reclaimable_bytes / allocated_bytes) if allocated_bytes else 0.0, 6),
        "journal_mode": journal_mode,
        "auto_vacuum": auto_vacuum,
        "integrity": integrity,
        "finding_rows": finding_rows,
        "fts_rows": fts_rows,
        "fts_in_sync": fts_in_sync,
    }


def list_database_maintenance_runs(db_path: str | Path, *, limit: int = 100) -> list[dict[str, Any]]:
    limit = max(1, min(int(limit), 1000))
    with connect(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM database_maintenance_runs ORDER BY started_at DESC LIMIT ?", (limit,)
        ).fetchall()
    result: list[dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        for source, target in (("before_json", "before"), ("after_json", "after"), ("details_json", "details")):
            raw = item.pop(source, "{}")
            try:
                item[target] = json.loads(raw or "{}")
            except json.JSONDecodeError:
                item[target] = {}
        result.append(item)
    return result


def run_database_maintenance(
    db_path: str | Path,
    *,
    actor: str = "system-database-maintenance",
    truncate_wal: bool = True,
    optimize_fts: bool = True,
    rebuild_fts_on_mismatch: bool = False,
) -> dict[str, Any]:
    """Run online-safe SQLite maintenance.

    This deliberately avoids VACUUM because VACUUM requires an exclusive rewrite
    and can amplify outage/disk pressure. Operators can use the recorded
    reclaimable_bytes to decide on an offline compaction window separately.
    """
    path = Path(db_path)
    run_id = f"DBM-{uuid.uuid4().hex[:16].upper()}"
    started_at = utc_now()
    before = database_health(path)
    details: dict[str, Any] = {
        "checkpoint": {}, "pragma_optimize": False, "fts_integrity": "NOT_RUN",
        "fts_optimized": False, "fts_rebuilt": False, "duration_ms": 0.0,
    }
    started = time.perf_counter()
    try:
        # PASSIVE never blocks writers. TRUNCATE is attempted only when requested;
        # SQLite returns a busy count rather than corrupting/forcing active readers.
        with connect(path) as conn:
            passive = conn.execute("PRAGMA wal_checkpoint(PASSIVE)").fetchone()
            details["checkpoint"]["passive"] = {
                "busy": int(passive[0]), "log_frames": int(passive[1]), "checkpointed_frames": int(passive[2]),
            }
            if truncate_wal:
                truncated = conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
                details["checkpoint"]["truncate"] = {
                    "busy": int(truncated[0]), "log_frames": int(truncated[1]), "checkpointed_frames": int(truncated[2]),
                }
            conn.execute("PRAGMA optimize")
            details["pragma_optimize"] = True
            try:
                conn.execute("INSERT INTO findings_fts(findings_fts, rank) VALUES('integrity-check', 1)")
                details["fts_integrity"] = "PASS"
            except sqlite3.DatabaseError as exc:
                details["fts_integrity"] = "FAIL"
                details["fts_error"] = str(exc)[:500]
            if details["fts_integrity"] == "FAIL" and rebuild_fts_on_mismatch:
                conn.execute("INSERT INTO findings_fts(findings_fts) VALUES('rebuild')")
                details["fts_rebuilt"] = True
                conn.execute("INSERT INTO findings_fts(findings_fts, rank) VALUES('integrity-check', 1)")
                details["fts_integrity"] = "PASS_AFTER_REBUILD"
            elif details["fts_integrity"] == "FAIL":
                raise sqlite3.DatabaseError("FTS external-content integrity check failed")
            elif optimize_fts and details["fts_integrity"] == "PASS":
                conn.execute("INSERT INTO findings_fts(findings_fts) VALUES('optimize')")
                details["fts_optimized"] = True
            conn.commit()
        after = database_health(path)
        details["duration_ms"] = round((time.perf_counter() - started) * 1000, 3)
        completed_at = utc_now()
        with connect(path) as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """INSERT INTO database_maintenance_runs(
                       run_id,actor,mode,started_at,completed_at,status,before_json,after_json,details_json,error
                   ) VALUES(?,?,?,?,?,'SUCCESS',?,?,?,'')""",
                (run_id, actor, "ONLINE", started_at, completed_at,
                 json.dumps(before, ensure_ascii=False, sort_keys=True),
                 json.dumps(after, ensure_ascii=False, sort_keys=True),
                 json.dumps(details, ensure_ascii=False, sort_keys=True)),
            )
            add_audit_event(
                path, finding_id=None, event_type="database_maintenance_run",
                summary="SQLite 온라인 유지관리 완료",
                details={"run_id": run_id, "before": before, "after": after, "operations": details},
                actor=actor, conn=conn,
            )
            conn.commit()
        return {"run_id": run_id, "status": "SUCCESS", "before": before, "after": after, "details": details}
    except Exception as exc:
        details["duration_ms"] = round((time.perf_counter() - started) * 1000, 3)
        completed_at = utc_now()
        try:
            with connect(path) as conn:
                conn.execute(
                    """INSERT INTO database_maintenance_runs(
                           run_id,actor,mode,started_at,completed_at,status,before_json,after_json,details_json,error
                       ) VALUES(?,?,?,?,?,'FAILED',?,'{}',?,?)""",
                    (run_id, actor, "ONLINE", started_at, completed_at,
                     json.dumps(before, ensure_ascii=False, sort_keys=True),
                     json.dumps(details, ensure_ascii=False, sort_keys=True), str(exc)[:1000]),
                )
                conn.commit()
        finally:
            raise
