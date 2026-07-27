from __future__ import annotations

"""Finding ingestion, scanner reconciliation and score-update persistence."""

import hashlib
import json
import uuid
from pathlib import Path
from typing import Any, Iterable

from app.core.db import connect, utc_now
from app.core.fields import SCORE_FIELDS
from app.repositories.audit import add_audit_event
from app.repositories.finding_workflow import _cancel_pending_verifications_conn
from app.repositories.reconciliation import (
    FIELDS,
    RECONCILABLE_FIELDS,
    _aggregate_canonical_row,
    _apply_authoritative_asset_context,
    _canonical_conflicts,
    _load_source_records_conn,
    _register_asset_identifiers_conn,
    _resolve_asset_identity_conn,
    _score_canonical_from_active_policy,
    _source_snapshot,
    _sync_asset_row,
    canonical_key_for,
    source_record_id_for,
)

def upsert_findings(db_path: str | Path, rows: Iterable[dict[str, Any]], *, actor: str = "local-user", audit: bool = True) -> tuple[int, int]:
    rows = list(rows)
    placeholders = ",".join(["?"] * len(FIELDS))
    ordinary = [f for f in FIELDS if f not in {"finding_id", "first_seen_at", "first_scored_at", "row_version"}]
    updates = [f"{field}=excluded.{field}" for field in ordinary]
    updates += [
        "first_seen_at=COALESCE(NULLIF(findings.first_seen_at,''), excluded.first_seen_at)",
        "first_scored_at=COALESCE(NULLIF(findings.first_scored_at,''), excluded.first_scored_at)",
        "row_version=COALESCE(findings.row_version, 0) + 1",
    ]
    sql = (
        f"INSERT INTO findings ({','.join(FIELDS)}) VALUES ({placeholders}) "
        f"ON CONFLICT(finding_id) DO UPDATE SET {','.join(updates)}, updated_at=CURRENT_TIMESTAMP"
    )
    inserted = 0
    updated = 0
    with connect(db_path) as conn:
        existing = {row[0] for row in conn.execute("SELECT finding_id FROM findings").fetchall()} if rows else set()
        for row in rows:
            row = _apply_authoritative_asset_context(conn, dict(row))
            row.setdefault("row_version", 1)
            row.setdefault("record_state", "ACTIVE")
            row.setdefault("scanner_source", "manual")
            row.setdefault("canonical_key", canonical_key_for(row))
            row.setdefault("source_count", 1)
            row.setdefault("source_conflict_count", 0)
            conn.execute(sql, [row.get(field) for field in FIELDS])
            _sync_asset_row(conn, row)
            source = str(row.get("scanner_source") or "manual").split(",")[0].strip() or "manual"
            source_id = str(row.get("finding_id") or "")
            source_record_id = source_record_id_for(source, source_id)
            now = utc_now()
            requested_batch = str(row.get("import_batch_id") or "").strip()
            valid_batch = requested_batch if requested_batch and conn.execute(
                "SELECT 1 FROM import_batches WHERE batch_id=?", (requested_batch,)
            ).fetchone() else None
            conn.execute(
                """INSERT OR IGNORE INTO source_finding_records(
                       source_record_id,finding_id,scanner_source,source_finding_id,canonical_key,observed_state,
                       consecutive_absent_scans,first_seen_at,last_seen_at,last_batch_id,snapshot_json,created_at,updated_at
                   ) VALUES(?,?,?,?,?,'PRESENT',0,?,?,?,?,?,?)""",
                (source_record_id, source_id, source, source_id, row["canonical_key"],
                 str(row.get("first_seen_at") or now), str(row.get("source_last_seen_at") or now),
                 valid_batch, json.dumps(_source_snapshot(row), ensure_ascii=False, sort_keys=True, separators=(",", ":")), now, now),
            )
            if row.get("finding_id") in existing:
                updated += 1
            else:
                inserted += 1
        if audit and rows:
            add_audit_event(
                db_path,
                finding_id=None,
                event_type="import",
                summary=f"취약점 {len(rows)}건 반영",
                details={"inserted": inserted, "updated": updated},
                actor=actor,
                conn=conn,
            )
        conn.commit()
    return inserted, updated


def apply_import_batch(
    db_path: str | Path,
    rows: Iterable[dict[str, Any]],
    *,
    scanner_source: str,
    filename: str,
    reconcile_missing: bool = False,
    actor: str = "local-user",
    source_job_id: str | None = None,
    verification_absence_threshold: int = 2,
) -> dict[str, Any]:
    """Apply one scanner import as source observations over canonical findings.

    Scanner-native IDs remain in source_finding_records. A scanner-independent
    canonical key collapses equivalent observations from multiple scanners into
    one workflow finding. Snapshot absence is tracked per source and the canonical
    finding becomes STALE only when every known source is absent.
    """
    prepared = [dict(row) for row in rows]
    if not prepared and not reconcile_missing:
        raise ValueError("증분 가져오기에는 취약점 데이터가 필요합니다.")
    source = str(scanner_source or "manual").strip()
    if not source:
        raise ValueError("스캐너·원천 이름이 필요합니다.")
    threshold = max(1, int(verification_absence_threshold))
    normalized_job_id = str(source_job_id or "").strip() or None
    if normalized_job_id:
        with connect(db_path) as conn:
            existing_batch = conn.execute(
                "SELECT * FROM import_batches WHERE source_job_id=?", (normalized_job_id,)
            ).fetchone()
        if existing_batch is not None:
            item = dict(existing_batch)
            return {
                "batch_id": item["batch_id"], "scanner_source": item["scanner_source"],
                "mode": item["import_mode"], "row_count": int(item["row_count"] or 0),
                "inserted": int(item["inserted_count"] or 0), "updated": int(item["updated_count"] or 0),
                "stale": int(item["stale_count"] or 0), "reopened": 0, "verification_ready": 0,
                "merged": 0, "conflicts": 0, "identity_candidates": 0, "idempotent_replay": True,
            }

    batch_id = f"IMP-{uuid.uuid4().hex[:16].upper()}"
    now = utc_now()
    source_native_ids = [str(row.get("finding_id") or "").strip() for row in prepared]
    if any(not item for item in source_native_ids):
        raise ValueError("finding_id가 없는 항목이 있습니다.")
    if len(set(source_native_ids)) != len(source_native_ids):
        raise ValueError("가져오기 데이터에 중복 finding_id가 있습니다.")

    placeholders = ",".join(["?"] * len(FIELDS))
    insert_sql = f"INSERT INTO findings ({','.join(FIELDS)}) VALUES ({placeholders})"
    source_managed_fields = [
        "product", "product_version", "asset_id", "asset_ref_id", "asset_name", "environment",
        "cve_id", "component", "component_version", "cvss", "epss", "epss_percentile", "kev",
        "internet_exposed", "asset_criticality", "data_sensitivity", "patch_available",
        "compensating_control", "intel_source", "intel_updated_at", "score", "threat_score",
        "asset_context_score", "remediation_urgency_score", "decision", "decision_label", "sla_days",
        "target_date", "mitigation_required", "reasons", "policy_version", "policy_id",
        "last_scored_at", "scanner_source", "source_last_seen_at", "record_state", "stale_since",
        "archived_at", "import_batch_id", "canonical_key", "source_count", "source_conflict_count",
    ]

    inserted = updated = reopened = verification_ready = merged = 0
    identity_candidate_ids: set[str] = set()
    stale_ids: list[str] = []
    observations: list[tuple[Any, ...]] = []
    conflict_fields_total = 0
    with connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            """INSERT INTO import_batches(
                batch_id,scanner_source,filename,import_mode,row_count,inserted_count,updated_count,
                stale_count,actor,created_at,source_job_id
            ) VALUES(?,?,?,?,?,0,0,0,?,?,?)""",
            (batch_id, source, filename, "snapshot" if reconcile_missing else "incremental",
             len(prepared), actor, now, normalized_job_id),
        )
        canonical_for_source: dict[str, str] = {}
        source_record_for_native: dict[str, str] = {}
        present_canonical_ids: set[str] = set()
        affected_canonical_ids: set[str] = set()
        newly_present_canonical_ids: set[str] = set()
        seen_batch_keys: set[str] = set()
        fallback_rows: dict[str, dict[str, Any]] = {}

        for raw_row, source_native_id in zip(prepared, source_native_ids):
            row = dict(raw_row)
            old_record = conn.execute(
                "SELECT * FROM source_finding_records WHERE scanner_source=? AND source_finding_id=?",
                (source, source_native_id),
            ).fetchone()
            if old_record is not None:
                canonical_id = str(old_record["finding_id"])
                canonical_row = conn.execute("SELECT * FROM findings WHERE finding_id=?", (canonical_id,)).fetchone()
                if canonical_row is None:
                    raise ValueError(f"원천 관측의 canonical finding이 없습니다: {source_native_id}")
                canonical_existing = dict(canonical_row)
                # Partial scanner exports often omit identity context. Fill only blanks
                # from the established canonical record before checking identity drift.
                incoming_has_asset_identity = bool(str(row.get("asset_id") or "").strip() or str(row.get("asset_name") or "").strip())
                for field in ("product", "product_version", "asset_id", "asset_name", "environment", "cve_id", "component"):
                    if not str(row.get(field) or "").strip():
                        row[field] = canonical_existing.get(field)
                if not incoming_has_asset_identity and not str(row.get("asset_ref_id") or "").strip():
                    row["asset_ref_id"] = canonical_existing.get("asset_ref_id")
                resolved_asset_ref, asset_identifiers = _resolve_asset_identity_conn(
                    conn, row, scanner_source=source, actor=actor, now=now
                )
                row["asset_ref_id"] = resolved_asset_ref
                row = _apply_authoritative_asset_context(conn, row)
                proposed_key = canonical_key_for(row)
                key = str(old_record["canonical_key"] or canonical_existing.get("canonical_key") or proposed_key)
                if proposed_key != key:
                    raise ValueError(f"스캐너 원본 ID가 다른 canonical finding으로 변경되었습니다: {source_native_id}")
            else:
                resolved_asset_ref, asset_identifiers = _resolve_asset_identity_conn(
                    conn, row, scanner_source=source, actor=actor, now=now
                )
                row["asset_ref_id"] = resolved_asset_ref
                row = _apply_authoritative_asset_context(conn, row)
                key = canonical_key_for(row)
                existing_canonical = conn.execute(
                    "SELECT finding_id FROM findings WHERE canonical_key=? ORDER BY first_seen_at,finding_id LIMIT 1",
                    (key,),
                ).fetchone()
                if existing_canonical is not None:
                    canonical_id = str(existing_canonical["finding_id"])
                else:
                    collision = conn.execute("SELECT canonical_key FROM findings WHERE finding_id=?", (source_native_id,)).fetchone()
                    canonical_id = source_native_id
                    if collision is not None and str(collision["canonical_key"] or "") != key:
                        canonical_id = "CAN-" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:20].upper()
                    row["finding_id"] = canonical_id
                    row["canonical_key"] = key
                    row["source_count"] = 1
                    row["source_conflict_count"] = 0
                    row["scanner_source"] = source
                    row["source_last_seen_at"] = now
                    row["record_state"] = "ACTIVE"
                    row["stale_since"] = ""
                    row["archived_at"] = ""
                    row["import_batch_id"] = batch_id
                    row.setdefault("row_version", 1)
                    conn.execute(insert_sql, [row.get(field) for field in FIELDS])
                    _sync_asset_row(conn, row, now=now)
                    inserted += 1
                    fallback_rows[canonical_id] = dict(row)

            if conn.execute("SELECT 1 FROM assets WHERE asset_ref_id=?", (row.get("asset_ref_id"),)).fetchone() is None:
                row_for_asset = dict(row)
                row_for_asset["finding_id"] = canonical_id
                _sync_asset_row(conn, row_for_asset, now=now)
            identity_candidate_ids.update(_register_asset_identifiers_conn(
                conn, asset_ref_id=str(row.get("asset_ref_id") or ""), identifiers=asset_identifiers,
                actor=actor, now=now,
            ))

            if key in seen_batch_keys:
                raise ValueError("같은 스캐너 배치에 동일 canonical finding 후보가 중복되었습니다.")
            seen_batch_keys.add(key)
            canonical_for_source[source_native_id] = canonical_id
            present_canonical_ids.add(canonical_id)
            affected_canonical_ids.add(canonical_id)
            source_record_id = source_record_id_for(source, source_native_id)
            source_record_for_native[source_native_id] = source_record_id
            if old_record is None or str(old_record["observed_state"]) != "PRESENT":
                newly_present_canonical_ids.add(canonical_id)
            snapshot_json = json.dumps(_source_snapshot(row), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            conn.execute(
                """INSERT INTO source_finding_records(
                       source_record_id,finding_id,scanner_source,source_finding_id,canonical_key,observed_state,
                       consecutive_absent_scans,first_seen_at,last_seen_at,last_batch_id,snapshot_json,created_at,updated_at
                   ) VALUES(?,?,?,?,?,'PRESENT',0,?,?,?,?,?,?)
                   ON CONFLICT(scanner_source,source_finding_id) DO UPDATE SET
                       finding_id=excluded.finding_id,canonical_key=excluded.canonical_key,observed_state='PRESENT',
                       consecutive_absent_scans=0,last_seen_at=excluded.last_seen_at,last_batch_id=excluded.last_batch_id,
                       snapshot_json=excluded.snapshot_json,updated_at=excluded.updated_at""",
                (source_record_id, canonical_id, source, source_native_id, key,
                 now, now, batch_id, snapshot_json, now, now),
            )
            observations.append((
                f"OBS-{uuid.uuid4().hex[:16].upper()}", canonical_id, batch_id, source,
                "PRESENT", now, "{}", source_record_id,
            ))

        if reconcile_missing:
            uploaded_record_ids = set(source_record_for_native.values())
            source_rows = conn.execute(
                "SELECT * FROM source_finding_records WHERE scanner_source=? AND observed_state IN ('PRESENT','ABSENT')",
                (source,),
            ).fetchall()
            for raw_record in source_rows:
                record = dict(raw_record)
                if record["source_record_id"] in uploaded_record_ids:
                    continue
                next_absence = int(record.get("consecutive_absent_scans") or 0) + 1
                conn.execute(
                    """UPDATE source_finding_records SET observed_state='ABSENT',consecutive_absent_scans=?,
                               last_batch_id=?,updated_at=? WHERE source_record_id=?""",
                    (next_absence, batch_id, now, record["source_record_id"]),
                )
                canonical_id = str(record["finding_id"])
                affected_canonical_ids.add(canonical_id)
                observations.append((
                    f"OBS-{uuid.uuid4().hex[:16].upper()}", canonical_id, batch_id, source,
                    "ABSENT", now,
                    json.dumps({"source_consecutive_absent_scans": next_absence}, separators=(",", ":")),
                    record["source_record_id"],
                ))

        for canonical_id in sorted(affected_canonical_ids):
            before_row = conn.execute("SELECT * FROM findings WHERE finding_id=?", (canonical_id,)).fetchone()
            before = dict(before_row) if before_row is not None else {}
            present_records = _load_source_records_conn(conn, canonical_id, present_only=True)
            if present_records:
                merged_row, conflicts = _aggregate_canonical_row(
                    conn, canonical_id, fallback=fallback_rows.get(canonical_id)
                )
                merged_row["finding_id"] = canonical_id
                merged_row["canonical_key"] = str(merged_row.get("canonical_key") or canonical_key_for(merged_row))
                merged_row["import_batch_id"] = batch_id
                merged_row = _apply_authoritative_asset_context(conn, merged_row)
                merged_row = _score_canonical_from_active_policy(conn, merged_row)
                assignments = ",".join(f"{field}=?" for field in source_managed_fields)
                conn.execute(
                    f"UPDATE findings SET {assignments},row_version=COALESCE(row_version,0)+1,updated_at=CURRENT_TIMESTAMP WHERE finding_id=?",
                    [merged_row.get(field) for field in source_managed_fields] + [canonical_id],
                )
                _sync_asset_row(conn, merged_row, now=now)
                if canonical_id not in fallback_rows and canonical_id in present_canonical_ids:
                    updated += 1
                if len(present_records) > 1:
                    merged += 1
                conflict_fields_total += len(conflicts)

                previous_status = str(before.get("status") or "OPEN")
                previous_resolution = str(before.get("resolution_state") or "UNVERIFIED")
                should_reopen = canonical_id in newly_present_canonical_ids and (
                    (previous_status == "CLOSED" and previous_resolution == "VERIFIED")
                    or (previous_status == "MITIGATED" and previous_resolution in {"PENDING", "READY_FOR_VERIFICATION"})
                )
                if should_reopen:
                    next_count = int(before.get("reopen_count") or 0) + 1
                    conn.execute(
                        """UPDATE findings SET status='OPEN',resolution_state='REOPENED',resolution_requested_at='',
                                   verified_at='',verified_by='',verification_method='',verification_note='',resolved_at='',
                                   consecutive_absent_scans=0,last_reopened_at=?,reopen_count=?,
                                   row_version=COALESCE(row_version,0)+1,updated_at=CURRENT_TIMESTAMP WHERE finding_id=?""",
                        (now, next_count, canonical_id),
                    )
                    _cancel_pending_verifications_conn(
                        conn, canonical_id, actor=actor,
                        reason="다중 스캐너 관측에서 취약점이 다시 탐지됨", db_path=db_path,
                    )
                    add_audit_event(
                        db_path, finding_id=canonical_id, event_type="finding_reopened",
                        summary="스캐너 재탐지로 canonical finding 자동 재개방",
                        details={"batch_id": batch_id, "scanner_source": source, "reopen_count": next_count},
                        actor=actor, conn=conn,
                    )
                    reopened += 1
                elif int(before.get("consecutive_absent_scans") or 0) or previous_resolution == "READY_FOR_VERIFICATION":
                    conn.execute(
                        """UPDATE findings SET consecutive_absent_scans=0,
                                   resolution_state=CASE WHEN resolution_state='READY_FOR_VERIFICATION'
                                                         THEN 'UNVERIFIED' ELSE resolution_state END
                             WHERE finding_id=?""",
                        (canonical_id,),
                    )
            elif reconcile_missing:
                all_records = _load_source_records_conn(conn, canonical_id, present_only=False)
                if not all_records:
                    continue
                absence_counts = [int(record.get("consecutive_absent_scans") or 0) for record in all_records]
                canonical_absence = min(absence_counts) if absence_counts else 0
                next_resolution = str(before.get("resolution_state") or "UNVERIFIED")
                became_ready = False
                if str(before.get("status") or "OPEN") == "MITIGATED" and canonical_absence >= threshold and next_resolution not in {"PENDING", "VERIFIED"}:
                    became_ready = next_resolution != "READY_FOR_VERIFICATION"
                    next_resolution = "READY_FOR_VERIFICATION"
                conn.execute(
                    """UPDATE findings SET record_state='STALE',stale_since=COALESCE(NULLIF(stale_since,''),?),
                               source_count=0,source_conflict_count=0,consecutive_absent_scans=?,resolution_state=?,
                               row_version=COALESCE(row_version,0)+1,updated_at=CURRENT_TIMESTAMP WHERE finding_id=?""",
                    (now, canonical_absence, next_resolution, canonical_id),
                )
                stale_ids.append(canonical_id)
                add_audit_event(
                    db_path, finding_id=canonical_id, event_type="all_sources_missing",
                    summary="모든 스캐너 관측에서 누락되어 canonical finding을 STALE로 표시",
                    details={"batch_id": batch_id, "scanner_source": source,
                             "consecutive_absent_scans": canonical_absence, "verification_ready": became_ready},
                    actor=actor, conn=conn,
                )
                if became_ready:
                    add_audit_event(
                        db_path, finding_id=canonical_id, event_type="remediation_verification_ready",
                        summary=f"모든 원천 연속 미탐지 {canonical_absence}회로 조치 검증 가능",
                        details={"batch_id": batch_id, "threshold": threshold}, actor=actor, conn=conn,
                    )
                    verification_ready += 1

        conn.execute(
            """UPDATE import_batches SET inserted_count=?,updated_count=?,stale_count=? WHERE batch_id=?""",
            (inserted, updated, len(set(stale_ids)), batch_id),
        )
        conn.executemany(
            """INSERT INTO finding_observations(
                   observation_id,finding_id,batch_id,scanner_source,observation,observed_at,details_json,source_record_id
               ) VALUES(?,?,?,?,?,?,?,?)""",
            observations,
        )
        add_audit_event(
            db_path, finding_id=None, event_type="import_batch",
            summary=f"{source} 취약점 {len(prepared)}건 가져오기",
            details={"batch_id": batch_id, "filename": filename,
                     "mode": "snapshot" if reconcile_missing else "incremental",
                     "inserted": inserted, "updated": updated, "stale": len(set(stale_ids)),
                     "reopened": reopened, "verification_ready": verification_ready,
                     "canonical_merged": merged, "conflict_fields": conflict_fields_total,
                     "identity_candidates": len(identity_candidate_ids)},
            actor=actor, conn=conn,
        )
        conn.commit()
    return {
        "batch_id": batch_id, "scanner_source": source,
        "mode": "snapshot" if reconcile_missing else "incremental", "row_count": len(prepared),
        "inserted": inserted, "updated": updated, "stale": len(set(stale_ids)),
        "reopened": reopened, "verification_ready": verification_ready,
        "merged": merged, "conflicts": conflict_fields_total,
        "identity_candidates": len(identity_candidate_ids),
    }


def list_source_finding_records(db_path: str | Path, finding_id: str, *, include_absent: bool = True) -> list[dict[str, Any]]:
    with connect(db_path) as conn:
        items = _load_source_records_conn(conn, finding_id, present_only=not include_absent)
    return items


def get_source_reconciliation(db_path: str | Path, finding_id: str) -> dict[str, Any]:
    with connect(db_path) as conn:
        finding_row = conn.execute("SELECT * FROM findings WHERE finding_id=?", (finding_id,)).fetchone()
        if finding_row is None:
            raise KeyError(finding_id)
        records = _load_source_records_conn(conn, finding_id, present_only=False)
        present_records = [item for item in records if item.get("observed_state") == "PRESENT"]
        conflicts = _canonical_conflicts(present_records)
        decisions = [dict(row) for row in conn.execute(
            """SELECT d.*,r.scanner_source,r.source_finding_id,r.observed_state
                 FROM finding_reconciliation_decisions d
                 LEFT JOIN source_finding_records r ON r.source_record_id=d.chosen_source_record_id
                WHERE d.finding_id=? ORDER BY d.created_at DESC""",
            (finding_id,),
        ).fetchall()]
        active = {str(item["field_name"]): item for item in decisions if item.get("status") == "ACTIVE"}
        conflict_items = []
        for field, values in conflicts.items():
            options = []
            for record in present_records:
                value = (record.get("snapshot") or {}).get(field)
                if value in (None, ""):
                    continue
                options.append({
                    "source_record_id": record["source_record_id"],
                    "scanner_source": record["scanner_source"],
                    "source_finding_id": record["source_finding_id"],
                    "value": value,
                })
            conflict_items.append({
                "field_name": field,
                "values": values,
                "options": options,
                "active_decision": active.get(field),
                "resolved": field in active,
            })
        return {
            "finding": dict(finding_row),
            "records": records,
            "conflicts": conflict_items,
            "decisions": decisions,
            "unresolved_count": sum(1 for item in conflict_items if not item["resolved"]),
        }


def list_reconciliation_findings(db_path: str | Path, *, unresolved_only: bool = False, limit: int = 500) -> list[dict[str, Any]]:
    limit = max(1, min(int(limit), 5000))
    with connect(db_path) as conn:
        rows = conn.execute(
            """SELECT * FROM findings
                WHERE source_count>1 OR source_conflict_count>0
                ORDER BY source_conflict_count DESC,score DESC,finding_id LIMIT ?""",
            (limit,),
        ).fetchall()
    items = []
    for row in rows:
        item = dict(row)
        detail = get_source_reconciliation(db_path, item["finding_id"])
        item["source_records"] = detail["records"]
        item["conflicts"] = detail["conflicts"]
        item["unresolved_count"] = detail["unresolved_count"]
        if unresolved_only and not item["unresolved_count"]:
            continue
        items.append(item)
    return items


def resolve_source_conflict(
    db_path: str | Path,
    finding_id: str,
    *,
    field_name: str,
    chosen_source_record_id: str,
    reason: str,
    actor: str = "local-user",
) -> dict[str, Any]:
    field = str(field_name or "").strip()
    if field not in RECONCILABLE_FIELDS:
        raise ValueError("조정할 수 없는 필드입니다.")
    reason = str(reason or "").strip()
    if not reason:
        raise ValueError("충돌 조정 사유가 필요합니다.")
    with connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        finding_row = conn.execute("SELECT * FROM findings WHERE finding_id=?", (finding_id,)).fetchone()
        if finding_row is None:
            raise KeyError(finding_id)
        record_row = conn.execute(
            "SELECT * FROM source_finding_records WHERE source_record_id=? AND finding_id=?",
            (chosen_source_record_id, finding_id),
        ).fetchone()
        if record_row is None:
            raise ValueError("선택한 원천 관측이 해당 finding에 속하지 않습니다.")
        record = dict(record_row)
        if str(record.get("observed_state") or "") != "PRESENT":
            raise ValueError("현재 PRESENT 상태인 원천 관측만 선택할 수 있습니다.")
        try:
            snapshot = json.loads(record.get("snapshot_json") or "{}")
        except json.JSONDecodeError as exc:
            raise ValueError("원천 관측 스냅샷을 읽을 수 없습니다.") from exc
        value = snapshot.get(field)
        if value in (None, ""):
            raise ValueError("선택한 원천에는 해당 필드 값이 없습니다.")
        now = utc_now()
        conn.execute(
            """UPDATE finding_reconciliation_decisions SET status='RETIRED',retired_by=?,retired_at=?
                 WHERE finding_id=? AND field_name=? AND status='ACTIVE'""",
            (actor, now, finding_id, field),
        )
        decision_id = f"REC-{uuid.uuid4().hex[:16].upper()}"
        conn.execute(
            """INSERT INTO finding_reconciliation_decisions(
                   decision_id,finding_id,field_name,chosen_value_json,chosen_source_record_id,reason,status,created_by,created_at
               ) VALUES(?,?,?,?,?,?,'ACTIVE',?,?)""",
            (decision_id, finding_id, field,
             json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
             chosen_source_record_id, reason, actor, now),
        )
        merged, conflicts = _aggregate_canonical_row(conn, finding_id)
        merged = _score_canonical_from_active_policy(conn, merged)
        assignments = ",".join(f"{name}=?" for name in [
            field, "score", "threat_score", "asset_context_score", "remediation_urgency_score",
            "decision", "decision_label", "sla_days", "target_date", "mitigation_required", "reasons",
            "policy_version", "policy_id", "last_scored_at", "source_conflict_count",
        ])
        values = [merged.get(name) for name in [
            field, "score", "threat_score", "asset_context_score", "remediation_urgency_score",
            "decision", "decision_label", "sla_days", "target_date", "mitigation_required", "reasons",
            "policy_version", "policy_id", "last_scored_at", "source_conflict_count",
        ]]
        conn.execute(
            f"UPDATE findings SET {assignments},row_version=COALESCE(row_version,0)+1,updated_at=CURRENT_TIMESTAMP WHERE finding_id=?",
            values + [finding_id],
        )
        add_audit_event(
            db_path, finding_id=finding_id, event_type="source_conflict_resolved",
            summary=f"다중 스캐너 충돌 조정: {field}",
            details={
                "decision_id": decision_id, "field_name": field, "chosen_value": value,
                "source_record_id": chosen_source_record_id, "scanner_source": record["scanner_source"],
                "reason": reason, "remaining_conflicts": int(merged.get("source_conflict_count") or 0),
            },
            actor=actor, conn=conn,
        )
        conn.commit()
    return get_source_reconciliation(db_path, finding_id)


def retire_source_conflict_resolution(
    db_path: str | Path, finding_id: str, *, field_name: str, actor: str = "local-user"
) -> dict[str, Any]:
    field = str(field_name or "").strip()
    if field not in RECONCILABLE_FIELDS:
        raise ValueError("조정할 수 없는 필드입니다.")
    with connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        now = utc_now()
        cur = conn.execute(
            """UPDATE finding_reconciliation_decisions SET status='RETIRED',retired_by=?,retired_at=?
                 WHERE finding_id=? AND field_name=? AND status='ACTIVE'""",
            (actor, now, finding_id, field),
        )
        if not cur.rowcount:
            raise ValueError("활성 조정 결정이 없습니다.")
        merged, _ = _aggregate_canonical_row(conn, finding_id)
        merged = _score_canonical_from_active_policy(conn, merged)
        conn.execute(
            """UPDATE findings SET product_version=?,component_version=?,cvss=?,patch_available=?,
                       score=?,threat_score=?,asset_context_score=?,remediation_urgency_score=?,decision=?,decision_label=?,
                       sla_days=?,target_date=?,mitigation_required=?,reasons=?,policy_version=?,policy_id=?,last_scored_at=?,
                       source_conflict_count=?,row_version=COALESCE(row_version,0)+1,updated_at=CURRENT_TIMESTAMP
                 WHERE finding_id=?""",
            (
                merged.get("product_version"), merged.get("component_version"), merged.get("cvss"), merged.get("patch_available"),
                merged.get("score"), merged.get("threat_score"), merged.get("asset_context_score"),
                merged.get("remediation_urgency_score"), merged.get("decision"), merged.get("decision_label"),
                merged.get("sla_days"), merged.get("target_date"), merged.get("mitigation_required"), merged.get("reasons"),
                merged.get("policy_version"), merged.get("policy_id"), merged.get("last_scored_at"),
                merged.get("source_conflict_count"), finding_id,
            ),
        )
        add_audit_event(
            db_path, finding_id=finding_id, event_type="source_conflict_resolution_retired",
            summary=f"다중 스캐너 충돌 조정 해제: {field}", details={"field_name": field}, actor=actor, conn=conn,
        )
        conn.commit()
    return get_source_reconciliation(db_path, finding_id)


def list_import_batches(db_path: str | Path, *, limit: int = 100) -> list[dict[str, Any]]:
    limit = max(1, min(int(limit), 1000))
    with connect(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM import_batches ORDER BY created_at DESC, batch_id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]


def update_scores(
    db_path: str | Path,
    rows: Iterable[dict[str, Any]],
    *,
    actor: str = "local-user",
    audit: bool = True,
) -> tuple[int, int]:
    """Update only changed scoring fields so unrelated records keep their row version."""
    prepared = [dict(row) for row in rows]
    if not prepared:
        return 0, 0
    changed = 0
    unchanged = 0
    with connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        for row in prepared:
            finding_id = str(row.get("finding_id") or "")
            current_row = conn.execute("SELECT * FROM findings WHERE finding_id=?", (finding_id,)).fetchone()
            if current_row is None:
                continue
            current = dict(current_row)
            differs = any(str(current.get(field) or "") != str(row.get(field) or "") for field in SCORE_FIELDS)
            if not differs:
                unchanged += 1
                continue
            assignments = ", ".join(f"{field}=?" for field in SCORE_FIELDS)
            conn.execute(
                f"""
                UPDATE findings
                   SET {assignments}, row_version=COALESCE(row_version,0)+1,
                       updated_at=CURRENT_TIMESTAMP
                 WHERE finding_id=?
                """,
                [row.get(field) for field in SCORE_FIELDS] + [finding_id],
            )
            changed += 1
        if audit:
            add_audit_event(
                db_path,
                finding_id=None,
                event_type="policy_rescore",
                summary=f"정책 재평가: 변경 {changed}건, 동일 {unchanged}건",
                details={"changed": changed, "unchanged": unchanged},
                actor=actor,
                conn=conn,
            )
        conn.commit()
    return changed, unchanged
