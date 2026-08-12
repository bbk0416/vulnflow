from __future__ import annotations

import hashlib
import json
import sqlite3
import unicodedata
import uuid
from datetime import date
from typing import Any

from app.core.db import utc_now
from app.core.scoring import parse_policy_text, prioritize_finding
from app.repositories.policies import get_active_policy_version
from app.services.asset_identity import (
    ASSET_IDENTIFIER_TYPES, AUTHORITATIVE_IDENTIFIER_TYPES, IDENTIFIER_CONFIDENCE,
    append_identifier as _append_identifier, extract_asset_identifiers, fqdn_equivalent_values,
    identifier_scope as _identifier_scope, normalize_asset_identifier,
)

FIELDS = [
    "finding_id", "product", "product_version", "asset_id", "asset_ref_id", "asset_name",
    "environment", "cve_id", "component", "component_version", "cvss",
    "epss", "epss_percentile", "kev", "internet_exposed",
    "asset_criticality", "data_sensitivity", "patch_available",
    "compensating_control", "status", "owner", "due_date",
    "exception_expiry", "risk_acceptance_reason", "risk_acceptance_approver",
    "notes", "intel_source", "intel_updated_at", "score", "threat_score",
    "asset_context_score", "remediation_urgency_score", "decision",
    "decision_label", "sla_days", "target_date", "mitigation_required",
    "reasons", "policy_version", "policy_id", "first_seen_at", "first_scored_at",
    "last_scored_at", "resolved_at", "scanner_source", "source_last_seen_at",
    "record_state", "stale_since", "archived_at", "import_batch_id", "canonical_key",
    "source_count", "source_conflict_count", "merged_into_finding_id", "row_version"
]

SOURCE_SNAPSHOT_FIELDS = (
    "product", "product_version", "asset_id", "asset_ref_id", "asset_name", "environment",
    "cve_id", "component", "component_version", "cvss", "epss", "epss_percentile", "kev",
    "internet_exposed", "asset_criticality", "data_sensitivity", "patch_available",
    "compensating_control", "intel_source", "intel_updated_at",
)

RECONCILABLE_FIELDS = {"product_version", "component_version", "cvss", "patch_available"}

def asset_ref_id_for(row: dict[str, Any]) -> str:
    """Return a stable internal asset identifier without changing scanner IDs."""
    external = unicodedata.normalize("NFC", str(row.get("asset_id") or "").strip()).casefold()
    if external:
        identity = "external|" + external
    else:
        parts = [
            unicodedata.normalize("NFC", str(row.get("asset_name") or "").strip()).casefold(),
            unicodedata.normalize("NFC", str(row.get("product") or "").strip()).casefold(),
            unicodedata.normalize("NFC", str(row.get("environment") or "").strip()).casefold(),
        ]
        identity = "derived|" + "|".join(parts)
    return "AST-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16].upper()


def canonical_key_for(row: dict[str, Any]) -> str:
    """Build a scanner-independent identity for one vulnerability instance.

    The key intentionally excludes scanner source and scanner-native IDs. Component
    version is also excluded so differing scanner observations can be surfaced as a
    reconciliation conflict instead of becoming duplicate canonical findings.
    """
    asset_ref = str(row.get("asset_ref_id") or "").strip() or asset_ref_id_for(row)
    cve_id = str(row.get("cve_id") or "").strip().upper()
    component = unicodedata.normalize(
        "NFC", str(row.get("component") or row.get("product") or "").strip()
    ).casefold()
    identity = "|".join([asset_ref.casefold(), cve_id.casefold(), component])
    return "CK-" + hashlib.sha256(identity.encode("utf-8")).hexdigest().upper()


def scanner_source_key(value: Any) -> str:
    return unicodedata.normalize("NFC", str(value or "").strip()).casefold()


def source_finding_id_key(value: Any) -> str:
    return unicodedata.normalize("NFC", str(value or "").strip()).casefold()


def source_record_id_for(scanner_source: str, source_finding_id: str) -> str:
    native_key = source_finding_id_key(source_finding_id)
    identity = f"{scanner_source_key(scanner_source)}|{native_key}"
    return "SRC-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:24].upper()


def _active_identifier_matches_conn(conn: sqlite3.Connection, item: dict[str, Any]) -> list[sqlite3.Row]:
    values = (str(item["normalized_value"]),)
    if item["identifier_type"] == "FQDN":
        values = fqdn_equivalent_values(item["normalized_value"])
    placeholders = ",".join("?" for _ in values)
    return conn.execute(
        f"""SELECT * FROM asset_identifiers
              WHERE identifier_type=? AND scope=? AND normalized_value IN ({placeholders})
                AND status='ACTIVE'
              ORDER BY identifier_id""",
        (item["identifier_type"], item["scope"], *values),
    ).fetchall()


def _asset_ref_from_identifiers(identifiers: list[dict[str, Any]], row: dict[str, Any]) -> str:
    preference = ("CMDB_ID", "CLOUD_INSTANCE_ID", "SCANNER_ASSET_ID", "EXTERNAL_ASSET_ID", "FQDN", "IP_ADDRESS", "MAC_ADDRESS", "HOSTNAME")
    for kind in preference:
        for item in identifiers:
            if item["identifier_type"] == kind:
                identity = f"{kind}|{item['scope']}|{item['normalized_value']}"
                return "AST-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16].upper()
    return asset_ref_id_for(row)


def _candidate_pair(a: str, b: str) -> tuple[str, str]:
    left, right = sorted([str(a), str(b)])
    return left, right


def _create_asset_identity_candidate_conn(conn: sqlite3.Connection, *, asset_ref_id_a: str,
                                           asset_ref_id_b: str, identifier: dict[str, Any],
                                           actor: str, now: str) -> dict[str, Any] | None:
    if asset_ref_id_a == asset_ref_id_b:
        return None
    left, right = _candidate_pair(asset_ref_id_a, asset_ref_id_b)
    fingerprint_payload = {
        "a": left, "b": right, "identifier_type": identifier["identifier_type"],
        "scope": identifier["scope"], "normalized_value": identifier["normalized_value"],
    }
    fingerprint = hashlib.sha256(json.dumps(
        fingerprint_payload, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")).hexdigest()
    reason = {
        "identifier_type": identifier["identifier_type"], "scope": identifier["scope"],
        "normalized_value": identifier["normalized_value"], "display_value": identifier["display_value"],
        "source": identifier.get("source", "system"),
    }
    existing = conn.execute("SELECT * FROM asset_identity_candidates WHERE fingerprint=?", (fingerprint,)).fetchone()
    if existing is not None:
        return dict(existing)
    candidate_id = "AIC-" + uuid.uuid4().hex[:20].upper()
    score = int(identifier.get("confidence") or IDENTIFIER_CONFIDENCE.get(identifier["identifier_type"], 50))
    conn.execute(
        """INSERT INTO asset_identity_candidates(
               candidate_id,asset_ref_id_a,asset_ref_id_b,fingerprint,score,reasons_json,status,
               created_by,created_at,decision_reason
           ) VALUES(?,?,?,?,?,?,'PENDING',?,?, '')""",
        (candidate_id, left, right, fingerprint, score,
         json.dumps([reason], ensure_ascii=False, sort_keys=True), actor, now),
    )
    return dict(conn.execute("SELECT * FROM asset_identity_candidates WHERE candidate_id=?", (candidate_id,)).fetchone())


def _resolve_asset_identity_conn(conn: sqlite3.Connection, row: dict[str, Any], *, scanner_source: str,
                                 actor: str, now: str) -> tuple[str, list[dict[str, Any]]]:
    explicit = str(row.get("asset_ref_id") or "").strip()
    if explicit:
        existing = conn.execute("SELECT asset_ref_id FROM assets WHERE asset_ref_id=?", (explicit,)).fetchone()
        if existing is not None:
            return explicit, extract_asset_identifiers(row, scanner_source=scanner_source)
    identifiers = extract_asset_identifiers(row, scanner_source=scanner_source)
    authoritative_assets: set[str] = set()
    external_asset_id = str(row.get("asset_id") or "").strip()
    if external_asset_id:
        inventory_match = conn.execute(
            """SELECT asset_ref_id FROM assets
                 WHERE source='inventory' AND LOWER(COALESCE(external_asset_id,''))=LOWER(?)
                   AND status='ACTIVE' ORDER BY updated_at DESC LIMIT 1""",
            (external_asset_id,),
        ).fetchone()
        if inventory_match is not None:
            authoritative_assets.add(str(inventory_match["asset_ref_id"]))
    for item in identifiers:
        if item["identifier_type"] not in AUTHORITATIVE_IDENTIFIER_TYPES:
            continue
        for match in _active_identifier_matches_conn(conn, item):
            authoritative_assets.add(str(match["asset_ref_id"]))
    if len(authoritative_assets) > 1:
        assets = sorted(authoritative_assets)
        for idx, left in enumerate(assets):
            for right in assets[idx + 1:]:
                _create_asset_identity_candidate_conn(
                    conn, asset_ref_id_a=left, asset_ref_id_b=right,
                    identifier={"identifier_type": "CMDB_ID", "scope": "conflict", "normalized_value": "multiple-authoritative-matches",
                                "display_value": "multiple authoritative identifiers", "source": f"scanner:{scanner_source}", "confidence": 100},
                    actor=actor, now=now,
                )
        raise ValueError("입력 자산의 권위 식별자가 서로 다른 기존 자산을 가리킵니다. 자산 식별 후보를 먼저 검토하세요.")
    if authoritative_assets:
        return next(iter(authoritative_assets)), identifiers
    supporting_scores: dict[str, int] = {}
    supporting_keys: dict[str, set[tuple[str, str, str]]] = {}
    fqdn_match_assets: set[str] = set()
    has_authoritative_input = any(
        item["identifier_type"] in AUTHORITATIVE_IDENTIFIER_TYPES for item in identifiers
    )
    for item in identifiers:
        if item["identifier_type"] in AUTHORITATIVE_IDENTIFIER_TYPES:
            continue
        matches = _active_identifier_matches_conn(conn, item)
        if item["identifier_type"] == "FQDN":
            fqdn_match_assets.update(str(match["asset_ref_id"]) for match in matches)
        for match in matches:
            asset_id = str(match["asset_ref_id"])
            key = (item["identifier_type"], item["scope"], item["normalized_value"])
            supporting_keys.setdefault(asset_id, set())
            if key not in supporting_keys[asset_id]:
                supporting_keys[asset_id].add(key)
                supporting_scores[asset_id] = supporting_scores.get(asset_id, 0) + int(item.get("confidence") or 0)
    if not has_authoritative_input and len(fqdn_match_assets) == 1:
        return next(iter(fqdn_match_assets)), identifiers
    if supporting_scores:
        ranked = sorted(supporting_scores.items(), key=lambda pair: (-pair[1], pair[0]))
        best_asset, best_score = ranked[0]
        second_score = ranked[1][1] if len(ranked) > 1 else -1
        if best_score >= 150 and best_score > second_score:
            return best_asset, identifiers
    return _asset_ref_from_identifiers(identifiers, row), identifiers


def _register_asset_identifiers_conn(conn: sqlite3.Connection, *, asset_ref_id: str,
                                     identifiers: list[dict[str, Any]], actor: str, now: str) -> list[str]:
    candidate_ids: list[str] = []
    for item in identifiers:
        existing_matches = _active_identifier_matches_conn(conn, item)
        if existing_matches:
            for existing in existing_matches:
                if str(existing["asset_ref_id"]) == asset_ref_id:
                    conn.execute(
                        "UPDATE asset_identifiers SET last_seen_at=?,confidence=MAX(confidence,?) WHERE identifier_id=?",
                        (now, int(item.get("confidence") or 50), existing["identifier_id"]),
                    )
                else:
                    candidate = _create_asset_identity_candidate_conn(
                        conn, asset_ref_id_a=str(existing["asset_ref_id"]), asset_ref_id_b=asset_ref_id,
                        identifier=item, actor=actor, now=now,
                    )
                    if candidate is not None:
                        candidate_ids.append(str(candidate["candidate_id"]))
            continue
        identifier_id = "AID-" + uuid.uuid4().hex[:20].upper()
        conn.execute(
            """INSERT INTO asset_identifiers(
                   identifier_id,asset_ref_id,identifier_type,scope,normalized_value,display_value,source,
                   confidence,status,created_by,created_at,last_seen_at
               ) VALUES(?,?,?,?,?,?,?,?, 'ACTIVE',?,?,?)""",
            (identifier_id, asset_ref_id, item["identifier_type"], item["scope"], item["normalized_value"],
             item["display_value"], item.get("source") or "system", int(item.get("confidence") or 50), actor, now, now),
        )
    return list(dict.fromkeys(candidate_ids))


def _source_snapshot(row: dict[str, Any]) -> dict[str, Any]:
    return {field: row.get(field) for field in SOURCE_SNAPSHOT_FIELDS}


def _canonical_conflicts(source_rows: list[dict[str, Any]]) -> dict[str, list[Any]]:
    conflicts: dict[str, list[Any]] = {}
    for field in sorted(RECONCILABLE_FIELDS):
        values: list[Any] = []
        for record in source_rows:
            snapshot = record.get("snapshot") or {}
            value = snapshot.get(field)
            if value in (None, ""):
                continue
            if value not in values:
                values.append(value)
        if len(values) > 1:
            conflicts[field] = values
    return conflicts


def _active_reconciliation_values(conn: sqlite3.Connection, finding_id: str) -> dict[str, Any]:
    rows = conn.execute(
        """SELECT d.field_name,d.chosen_value_json,d.chosen_source_record_id,r.snapshot_json
             FROM finding_reconciliation_decisions d
             LEFT JOIN source_finding_records r ON r.source_record_id=d.chosen_source_record_id
             WHERE d.finding_id=? AND d.status='ACTIVE' AND r.observed_state='PRESENT'""",
        (finding_id,),
    ).fetchall()
    result: dict[str, Any] = {}
    for row in rows:
        field = str(row["field_name"])
        value: Any = None
        if row["snapshot_json"]:
            try:
                snapshot = json.loads(row["snapshot_json"] or "{}")
                value = snapshot.get(field)
            except json.JSONDecodeError:
                value = None
        if value is None:
            try:
                value = json.loads(row["chosen_value_json"])
            except json.JSONDecodeError:
                value = row["chosen_value_json"]
        result[field] = value
    return result


def _load_source_records_conn(conn: sqlite3.Connection, finding_id: str, *, present_only: bool = False) -> list[dict[str, Any]]:
    sql = "SELECT * FROM source_finding_records WHERE finding_id=?"
    params: list[Any] = [finding_id]
    if present_only:
        sql += " AND observed_state='PRESENT'"
    sql += " ORDER BY scanner_source,source_finding_id"
    rows = []
    for raw in conn.execute(sql, params).fetchall():
        item = dict(raw)
        try:
            item["snapshot"] = json.loads(item.get("snapshot_json") or "{}")
        except json.JSONDecodeError:
            item["snapshot"] = {}
        rows.append(item)
    return rows


def _aggregate_canonical_row(conn: sqlite3.Connection, finding_id: str, *, fallback: dict[str, Any] | None = None) -> tuple[dict[str, Any], dict[str, list[Any]]]:
    existing_row = conn.execute("SELECT * FROM findings WHERE finding_id=?", (finding_id,)).fetchone()
    existing = dict(existing_row) if existing_row is not None else dict(fallback or {})
    records = _load_source_records_conn(conn, finding_id, present_only=True)
    if not records:
        existing["source_count"] = 0
        existing["source_conflict_count"] = 0
        return existing, {}
    snapshots = [record["snapshot"] for record in records]
    merged = dict(existing)
    first = snapshots[0]
    for field in ("product", "asset_id", "asset_ref_id", "asset_name", "environment", "cve_id", "component"):
        if not str(merged.get(field) or "").strip():
            merged[field] = first.get(field) or ""
    for field in ("product_version", "component_version"):
        values = [snapshot.get(field) for snapshot in snapshots if snapshot.get(field) not in (None, "")]
        if values and not str(merged.get(field) or "").strip():
            merged[field] = values[0]
    cvss_values = [float(snapshot.get("cvss") or 0) for snapshot in snapshots]
    merged["cvss"] = max(cvss_values) if cvss_values else float(existing.get("cvss") or 0)
    for field in ("epss", "epss_percentile"):
        values = [float(snapshot.get(field) or 0) for snapshot in snapshots]
        merged[field] = max([float(existing.get(field) or 0), *values])
    for field in ("kev", "internet_exposed", "asset_criticality", "data_sensitivity"):
        values = [int(snapshot.get(field) or 0) for snapshot in snapshots]
        merged[field] = max([int(existing.get(field) or 0), *values])
    patch_values = [int(snapshot.get("patch_available") or 0) for snapshot in snapshots]
    merged["patch_available"] = max(patch_values) if patch_values else int(existing.get("patch_available") or 0)
    # Compensating controls are workflow-owned; scanner imports cannot weaken or create them.
    merged["compensating_control"] = int(existing.get("compensating_control") or 0)
    source_names: dict[str, tuple[str, str]] = {}
    for record in records:
        name = str(record["scanner_source"] or "").strip()
        key = scanner_source_key(name)
        seen_at = str(record.get("last_seen_at") or "")
        current = source_names.get(key)
        if current is None or seen_at >= current[0]:
            source_names[key] = (seen_at, name)
    merged["scanner_source"] = ",".join(source_names[key][1] for key in sorted(source_names))[:120]
    merged["source_last_seen_at"] = max(str(record.get("last_seen_at") or "") for record in records)
    merged["record_state"] = "ACTIVE"
    merged["stale_since"] = ""
    merged["archived_at"] = ""
    merged["source_count"] = len(source_names)
    conflicts = _canonical_conflicts(records)
    resolved_values = _active_reconciliation_values(conn, finding_id)
    for field, value in resolved_values.items():
        if field in RECONCILABLE_FIELDS:
            merged[field] = value
    merged["source_conflict_count"] = len([field for field in conflicts if field not in resolved_values])
    return merged, conflicts


def _score_canonical_from_active_policy(conn: sqlite3.Connection, row: dict[str, Any]) -> dict[str, Any]:
    policy_row = conn.execute(
        "SELECT policy_id,version,content_yaml FROM policy_versions WHERE status='ACTIVE' ORDER BY created_at DESC LIMIT 1"
    ).fetchone()
    if policy_row is None:
        return row
    policy = parse_policy_text(str(policy_row["content_yaml"]))
    result = prioritize_finding(row, policy)
    today = date.today().isoformat()
    row.update({
        "score": result.score, "threat_score": result.threat_score,
        "asset_context_score": result.asset_context_score,
        "remediation_urgency_score": result.remediation_urgency_score,
        "decision": result.decision, "decision_label": result.decision_label,
        "sla_days": result.sla_days, "target_date": result.target_date,
        "mitigation_required": int(result.mitigation_required),
        "reasons": " | ".join(result.reasons),
        "policy_version": result.policy_version, "policy_id": str(policy_row["policy_id"]),
        "last_scored_at": today,
    })
    return row


def _apply_authoritative_asset_context(conn: sqlite3.Connection, row: dict[str, Any]) -> dict[str, Any]:
    """Apply inventory-owned asset context before a finding is persisted.

    Scanner imports may contain stale or lower-confidence asset attributes. Once an
    asset was explicitly loaded through the inventory, the inventory remains the
    authority for environment, criticality, data sensitivity, and exposure.
    """
    item = dict(row)
    asset_ref = str(item.get("asset_ref_id") or "").strip() or asset_ref_id_for(item)
    asset = conn.execute("SELECT * FROM assets WHERE asset_ref_id=?", (asset_ref,)).fetchone()
    if asset is not None and str(asset["source"] or "") == "inventory":
        item["asset_ref_id"] = asset_ref
        item["asset_name"] = str(asset["asset_name"] or item.get("asset_name") or "")
        item["environment"] = str(asset["environment"] or item.get("environment") or "")
        item["asset_criticality"] = int(asset["criticality"] or 1)
        item["data_sensitivity"] = int(asset["data_sensitivity"] or 1)
        item["internet_exposed"] = int(asset["internet_exposed"] or 0)
    else:
        item["asset_ref_id"] = asset_ref
    return item


def _sync_asset_row(conn: sqlite3.Connection, row: dict[str, Any], *, now: str | None = None) -> str:
    now = now or utc_now()
    asset_ref = str(row.get("asset_ref_id") or "").strip() or asset_ref_id_for(row)
    asset_name = str(row.get("asset_name") or row.get("asset_id") or row.get("product") or asset_ref).strip()
    external_id = str(row.get("asset_id") or "").strip()
    conn.execute(
        """
        INSERT INTO assets(
            asset_ref_id,external_asset_id,asset_name,service_name,business_unit,owner,environment,
            criticality,data_sensitivity,internet_exposed,tags,status,source,first_seen_at,last_seen_at,updated_at,row_version
        ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1)
        ON CONFLICT(asset_ref_id) DO UPDATE SET
            external_asset_id=COALESCE(NULLIF(excluded.external_asset_id,''),assets.external_asset_id),
            asset_name=COALESCE(NULLIF(excluded.asset_name,''),assets.asset_name),
            service_name=CASE WHEN assets.source='finding-derived' THEN COALESCE(NULLIF(excluded.service_name,''),assets.service_name) ELSE assets.service_name END,
            owner=CASE WHEN assets.source='finding-derived' THEN COALESCE(NULLIF(excluded.owner,''),assets.owner) ELSE assets.owner END,
            environment=COALESCE(NULLIF(excluded.environment,''),assets.environment),
            criticality=MAX(assets.criticality,excluded.criticality),
            data_sensitivity=MAX(assets.data_sensitivity,excluded.data_sensitivity),
            internet_exposed=MAX(assets.internet_exposed,excluded.internet_exposed),
            last_seen_at=excluded.last_seen_at,updated_at=excluded.updated_at,
            row_version=assets.row_version+1
        """,
        (
            asset_ref, external_id, asset_name, str(row.get("product") or "").strip(), "",
            str(row.get("owner") or "").strip(), str(row.get("environment") or "").strip(),
            max(1, min(5, int(row.get("asset_criticality") or 1))),
            max(1, min(5, int(row.get("data_sensitivity") or 1))),
            1 if bool(row.get("internet_exposed")) else 0, "", "ACTIVE", "finding-derived",
            str(row.get("first_seen_at") or now), str(row.get("source_last_seen_at") or now), now,
        ),
    )
    conn.execute("UPDATE findings SET asset_ref_id=? WHERE finding_id=?", (asset_ref, row.get("finding_id")))
    return asset_ref
