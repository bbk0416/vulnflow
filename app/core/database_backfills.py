from __future__ import annotations

"""Idempotent data backfills used during SQLite initialization and upgrades."""

import json
import sqlite3
from typing import Any

from app.core.db import utc_now
from app.repositories.reconciliation import (
    _register_asset_identifiers_conn,
    _source_snapshot,
    _sync_asset_row,
    canonical_key_for,
    source_record_id_for,
)
from app.services.asset_identity import append_identifier as _append_identifier, extract_asset_identifiers

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


__all__ = [
    "_backfill_asset_identifiers",
    "_backfill_asset_inventory",
    "_backfill_canonical_sources",
]
