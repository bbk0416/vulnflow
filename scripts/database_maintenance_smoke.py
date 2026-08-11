from __future__ import annotations

import json
import sqlite3
import tempfile
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.core.storage import connect, init_db, upsert_findings
from app.services.database_maintenance import database_health, run_database_maintenance


def row() -> dict:
    return {
        "finding_id": "DBM-SMOKE-1", "product": "SQLite online maintenance",
        "asset_name": "db-node-01", "cve_id": "CVE-2026-88001", "component": "fts-demo",
        "owner": "platform", "cvss": 7.5, "epss": 0.4, "kev": 0,
        "internet_exposed": 0, "asset_criticality": 3, "data_sensitivity": 2,
        "patch_available": 1, "compensating_control": 0, "status": "OPEN",
        "record_state": "ACTIVE",
    }


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="vulnflow_db_maintenance_") as temp_dir:
        db = Path(temp_dir) / "vulnflow.sqlite3"
        init_db(db)
        upsert_findings(db, [row()], audit=False)
        # Grow WAL deterministically without allowing SQLite's automatic threshold
        # to checkpoint it before the maintenance operation observes it.
        with connect(db) as conn:
            conn.execute("PRAGMA wal_autocheckpoint=0")
            for index in range(300):
                conn.execute(
                    "UPDATE findings SET notes=?,row_version=row_version+1 WHERE finding_id='DBM-SMOKE-1'",
                    (("wal-growth-%04d-" % index) + ("x" * 4096),),
                )
                conn.commit()
        before = database_health(db)
        if before["wal_bytes"] <= 0:
            raise SystemExit("database maintenance smoke failed: WAL did not grow")
        maintained = run_database_maintenance(db, actor="smoke-admin")
        after = maintained["after"]
        if maintained["status"] != "SUCCESS" or after["integrity"] != "ok" or not after["fts_in_sync"]:
            raise SystemExit("database maintenance smoke failed: online maintenance result")
        if after["wal_bytes"] > before["wal_bytes"]:
            raise SystemExit("database maintenance smoke failed: WAL did not shrink")

        # Deliberately desynchronize the external-content index. Default operation
        # must refuse silent repair; explicit rebuild restores it.
        with connect(db) as conn:
            current = conn.execute(
                "SELECT rowid,finding_id,product,asset_name,cve_id,component,owner FROM findings WHERE finding_id='DBM-SMOKE-1'"
            ).fetchone()
            conn.execute(
                "INSERT INTO findings_fts(findings_fts,rowid,finding_id,product,asset_name,cve_id,component,owner) VALUES('delete',?,?,?,?,?,?,?)",
                tuple(current),
            )
            conn.commit()
        if database_health(db)["fts_in_sync"]:
            raise SystemExit("database maintenance smoke failed: FTS mismatch not detected")
        refused = False
        try:
            run_database_maintenance(db, actor="smoke-admin", rebuild_fts_on_mismatch=False)
        except sqlite3.DatabaseError:
            refused = True
        if not refused:
            raise SystemExit("database maintenance smoke failed: implicit repair was not refused")
        rebuilt = run_database_maintenance(db, actor="smoke-admin", rebuild_fts_on_mismatch=True)
        if not rebuilt["details"]["fts_rebuilt"] or not rebuilt["after"]["fts_in_sync"]:
            raise SystemExit("database maintenance smoke failed: explicit FTS rebuild")

        final_health = dict(rebuilt["after"])
        final_health["database_path"] = Path(str(final_health.get("database_path") or "vulnflow.sqlite3")).name
        payload = {
            "wal_bytes_before": before["wal_bytes"],
            "wal_bytes_after": after["wal_bytes"],
            "checkpoint": maintained["details"]["checkpoint"],
            "pragma_optimize": maintained["details"]["pragma_optimize"],
            "fts_default_repair_refused": refused,
            "fts_rebuilt": rebuilt["details"]["fts_rebuilt"],
            "final_health": final_health,
        }
        reports = ROOT / "reports"
        reports.mkdir(exist_ok=True)
        (reports / "database_maintenance_verification.json").write_text(
            json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        lines = [
            "VulnFlow 72.0.76 SQLite online maintenance verification", "",
            f"WAL before: {payload['wal_bytes_before']} bytes",
            f"WAL after: {payload['wal_bytes_after']} bytes",
            f"PASSIVE checkpoint: {payload['checkpoint']['passive']}",
            f"TRUNCATE checkpoint: {payload['checkpoint'].get('truncate')}",
            f"PRAGMA optimize: {payload['pragma_optimize']}",
            f"Implicit FTS repair refused: {payload['fts_default_repair_refused']}",
            f"Explicit FTS rebuild: {payload['fts_rebuilt']}",
            f"Final quick_check: {payload['final_health']['integrity']}",
            f"Final FTS sync: {payload['final_health']['fts_in_sync']}",
        ]
        (reports / "database_maintenance_verification.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
        print("\n".join(lines))


if __name__ == "__main__":
    main()
