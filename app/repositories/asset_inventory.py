from __future__ import annotations

"""Asset inventory ingestion and authoritative identifier resolution."""

import sqlite3
from pathlib import Path
from typing import Any, Iterable

from app.core.db import connect, utc_now
from app.repositories.audit import add_audit_event
from app.repositories.reconciliation import (
    _asset_ref_from_identifiers,
    _register_asset_identifiers_conn,
)
from app.services.asset_identity import (
    append_identifier as _append_identifier,
    extract_asset_identifiers,
)

ASSET_STATUSES = {"ACTIVE", "RETIRED"}

def extract_inventory_identifiers(row: dict[str, Any]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    environment = str(row.get("environment") or "")
    external = row.get("external_asset_id") or row.get("asset_id")
    _append_identifier(items, "INVENTORY_ID", external, scanner_source="inventory",
                       environment=environment, source="inventory")
    for kind, field in (
        ("CMDB_ID", "cmdb_id"), ("CLOUD_INSTANCE_ID", "cloud_instance_id"),
        ("FQDN", "fqdn"), ("IP_ADDRESS", "ip_address"), ("MAC_ADDRESS", "mac_address"),
    ):
        _append_identifier(items, kind, row.get(field), scanner_source="inventory",
                           environment=environment, source="inventory")
    name = str(row.get("asset_name") or "").strip()
    if name:
        items.extend(extract_asset_identifiers(
            {"asset_name": name, "environment": environment}, scanner_source="inventory"
        ))
    # Inventory names are supporting identifiers, not scanner-native IDs.
    return [item for item in items if item["identifier_type"] != "SCANNER_ASSET_ID"]


def _resolve_inventory_asset_ref_conn(conn: sqlite3.Connection, row: dict[str, Any],
                                      identifiers: list[dict[str, Any]]) -> str:
    explicit = str(row.get("asset_ref_id") or "").strip()
    if explicit and conn.execute("SELECT 1 FROM assets WHERE asset_ref_id=?", (explicit,)).fetchone():
        return explicit
    matched: set[str] = set()
    for item in identifiers:
        if item["identifier_type"] not in {"INVENTORY_ID", "CMDB_ID", "CLOUD_INSTANCE_ID"}:
            continue
        found = conn.execute(
            """SELECT asset_ref_id FROM asset_identifiers
                 WHERE identifier_type=? AND scope=? AND normalized_value=? AND status='ACTIVE'""",
            (item["identifier_type"], item["scope"], item["normalized_value"]),
        ).fetchone()
        if found:
            matched.add(str(found["asset_ref_id"]))
    if len(matched) > 1:
        raise ValueError("자산 인벤토리의 권위 식별자가 서로 다른 기존 자산을 가리킵니다.")
    if matched:
        return next(iter(matched))
    return _asset_ref_from_identifiers(identifiers, row)


def apply_asset_inventory(db_path: str | Path, rows: Iterable[dict[str, Any]], *, actor: str = "local-user") -> dict[str, int]:
    prepared = [dict(row) for row in rows]
    if not prepared:
        raise ValueError("가져올 자산이 없습니다.")
    inserted = updated = linked = 0
    identity_candidate_ids: set[str] = set()
    now = utc_now()
    with connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        existing = {r[0] for r in conn.execute("SELECT asset_ref_id FROM assets").fetchall()}
        for row in prepared:
            inventory_identifiers = extract_inventory_identifiers(row)
            ref = _resolve_inventory_asset_ref_conn(conn, row, inventory_identifiers)
            status = str(row.get("status") or "ACTIVE").upper()
            if status not in ASSET_STATUSES:
                raise ValueError(f"허용되지 않은 자산 상태: {status}")
            conn.execute(
                """
                INSERT INTO assets(
                    asset_ref_id,external_asset_id,asset_name,service_name,business_unit,owner,environment,
                    criticality,data_sensitivity,internet_exposed,tags,status,source,first_seen_at,last_seen_at,updated_at,row_version
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1)
                ON CONFLICT(asset_ref_id) DO UPDATE SET
                    external_asset_id=excluded.external_asset_id,asset_name=excluded.asset_name,
                    service_name=excluded.service_name,business_unit=excluded.business_unit,owner=excluded.owner,
                    environment=excluded.environment,criticality=excluded.criticality,
                    data_sensitivity=excluded.data_sensitivity,internet_exposed=excluded.internet_exposed,
                    tags=excluded.tags,status=excluded.status,source='inventory',last_seen_at=excluded.last_seen_at,
                    updated_at=excluded.updated_at,row_version=assets.row_version+1
                """,
                (
                    ref, str(row.get("asset_id") or row.get("external_asset_id") or "").strip(),
                    str(row.get("asset_name") or row.get("asset_id") or ref).strip(),
                    str(row.get("service_name") or "").strip(), str(row.get("business_unit") or "").strip(),
                    str(row.get("owner") or "").strip(), str(row.get("environment") or "").strip(),
                    max(1, min(5, int(row.get("criticality") or row.get("asset_criticality") or 1))),
                    max(1, min(5, int(row.get("data_sensitivity") or 1))),
                    1 if bool(row.get("internet_exposed")) else 0, str(row.get("tags") or "").strip(),
                    status, "inventory", now, now, now,
                ),
            )
            inserted += 0 if ref in existing else 1
            updated += 1 if ref in existing else 0
            identity_candidate_ids.update(_register_asset_identifiers_conn(
                conn, asset_ref_id=ref, identifiers=inventory_identifiers, actor=actor, now=now
            ))
            external = str(row.get("asset_id") or row.get("external_asset_id") or "").strip()
            if external:
                cursor = conn.execute(
                    """UPDATE findings SET asset_ref_id=?,asset_name=COALESCE(NULLIF(?,''),asset_name),
                              environment=COALESCE(NULLIF(?,''),environment),asset_criticality=?,
                              data_sensitivity=?,internet_exposed=?,row_version=row_version+1,updated_at=CURRENT_TIMESTAMP
                         WHERE asset_id=?""",
                    (ref, str(row.get("asset_name") or ""), str(row.get("environment") or ""),
                     max(1, min(5, int(row.get("criticality") or row.get("asset_criticality") or 1))),
                     max(1, min(5, int(row.get("data_sensitivity") or 1))),
                     1 if bool(row.get("internet_exposed")) else 0, external),
                )
                linked += int(cursor.rowcount or 0)
        add_audit_event(
            db_path, finding_id=None, event_type="asset_inventory_import",
            summary=f"자산 인벤토리 {len(prepared)}건 반영",
            details={"inserted": inserted, "updated": updated, "linked_findings": linked,
                     "identity_candidates": len(identity_candidate_ids)},
            actor=actor, conn=conn,
        )
        conn.commit()
    return {"row_count": len(prepared), "inserted": inserted, "updated": updated,
            "linked_findings": linked, "identity_candidates": len(identity_candidate_ids)}
