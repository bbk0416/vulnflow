from __future__ import annotations

"""Asset merge impact analysis, approval, and execution repository."""

import hashlib
import hmac
import json
import sqlite3
import uuid
from pathlib import Path
from typing import Any

from app.core.db import ConcurrencyError, connect, utc_now
from app.repositories.audit import add_audit_event
from app.repositories.reconciliation import (
    _aggregate_canonical_row,
    _apply_authoritative_asset_context,
    _create_asset_identity_candidate_conn,
    _score_canonical_from_active_policy,
    canonical_key_for,
)
from app.services.asset_identity import AUTHORITATIVE_IDENTIFIER_TYPES
from app.services.asset_merge_rollback import (
    collect_guard as _collect_asset_merge_rollback_guard,
    collect_snapshot as _collect_asset_merge_rollback_snapshot,
    digest as _asset_merge_rollback_digest,
)

ASSET_MERGE_REQUEST_STATUSES = {"PENDING", "APPROVED", "REJECTED", "CANCELLED"}

def list_asset_merge_history(db_path: str | Path, *, asset_ref_id: str = "", limit: int = 200) -> list[dict[str, Any]]:
    params: list[Any] = []
    where = ""
    if asset_ref_id:
        where = "WHERE h.source_asset_ref_id=? OR h.target_asset_ref_id=?"
        params.extend([asset_ref_id, asset_ref_id])
    params.append(max(1, min(int(limit), 2000)))
    with connect(db_path) as conn:
        rows = conn.execute(
            f"""SELECT h.*,s.asset_name AS source_asset_name,t.asset_name AS target_asset_name,
                       CASE WHEN j.merge_id IS NULL THEN 0 ELSE 1 END AS rollback_available,
                       (SELECT r.status FROM asset_merge_rollback_requests r
                         WHERE r.merge_id=h.merge_id ORDER BY r.requested_at DESC LIMIT 1) AS rollback_status
                  FROM asset_merge_history h
                  JOIN assets s ON s.asset_ref_id=h.source_asset_ref_id
                  JOIN assets t ON t.asset_ref_id=h.target_asset_ref_id
                  LEFT JOIN asset_merge_rollback_journals j ON j.merge_id=h.merge_id
                  {where} ORDER BY h.created_at DESC LIMIT ?""", params,
        ).fetchall()
    return [dict(row) for row in rows]


def _persist_canonical_aggregate_conn(conn: sqlite3.Connection, finding_id: str) -> None:
    managed_fields = [
        "product", "product_version", "asset_id", "asset_ref_id", "asset_name", "environment",
        "cve_id", "component", "component_version", "cvss", "epss", "epss_percentile", "kev",
        "internet_exposed", "asset_criticality", "data_sensitivity", "patch_available",
        "compensating_control", "intel_source", "intel_updated_at", "score", "threat_score",
        "asset_context_score", "remediation_urgency_score", "decision", "decision_label", "sla_days",
        "target_date", "mitigation_required", "reasons", "policy_version", "policy_id",
        "last_scored_at", "scanner_source", "source_last_seen_at", "record_state", "stale_since",
        "archived_at", "import_batch_id", "canonical_key", "source_count", "source_conflict_count",
    ]
    merged, _ = _aggregate_canonical_row(conn, finding_id)
    merged = _apply_authoritative_asset_context(conn, merged)
    merged = _score_canonical_from_active_policy(conn, merged)
    assignments = ",".join(f"{field}=?" for field in managed_fields)
    conn.execute(
        f"UPDATE findings SET {assignments},row_version=COALESCE(row_version,0)+1,updated_at=CURRENT_TIMESTAMP WHERE finding_id=?",
        [merged.get(field) for field in managed_fields] + [finding_id],
    )


def _asset_merge_impact_digest(impact: dict[str, Any]) -> str:
    payload = json.dumps(impact, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _asset_merge_impact_conn(
    conn: sqlite3.Connection,
    *,
    source_asset_ref_id: str,
    target_asset_ref_id: str,
    candidate_id: str = "",
) -> dict[str, Any]:
    source_id = str(source_asset_ref_id or "").strip()
    target_id = str(target_asset_ref_id or "").strip()
    if not source_id or not target_id or source_id == target_id:
        raise ValueError("서로 다른 원본 자산과 대표 자산이 필요합니다.")
    source_row = conn.execute("SELECT * FROM assets WHERE asset_ref_id=?", (source_id,)).fetchone()
    target_row = conn.execute("SELECT * FROM assets WHERE asset_ref_id=?", (target_id,)).fetchone()
    if source_row is None or target_row is None:
        raise KeyError(source_id if source_row is None else target_id)
    source = dict(source_row)
    target = dict(target_row)
    blockers: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []
    if str(source.get("status") or "") != "ACTIVE":
        blockers.append({"code": "SOURCE_NOT_ACTIVE", "message": "원본 자산이 ACTIVE 상태가 아닙니다."})
    if str(target.get("status") or "") != "ACTIVE":
        blockers.append({"code": "TARGET_NOT_ACTIVE", "message": "대표 자산이 ACTIVE 상태가 아닙니다."})

    candidate: dict[str, Any] | None = None
    if candidate_id:
        candidate_row = conn.execute(
            "SELECT * FROM asset_identity_candidates WHERE candidate_id=?", (candidate_id,)
        ).fetchone()
        if candidate_row is None:
            raise KeyError(candidate_id)
        candidate = dict(candidate_row)
        if str(candidate.get("status") or "") != "PENDING":
            blockers.append({"code": "CANDIDATE_NOT_PENDING", "message": "대기 중인 자산 식별 후보가 아닙니다."})
        pair = {str(candidate.get("asset_ref_id_a") or ""), str(candidate.get("asset_ref_id_b") or "")}
        if pair != {source_id, target_id}:
            blockers.append({"code": "CANDIDATE_PAIR_MISMATCH", "message": "후보의 자산 쌍과 병합 대상이 일치하지 않습니다."})

    source_findings = conn.execute(
        "SELECT * FROM findings WHERE asset_ref_id=? AND merged_into_finding_id IS NULL ORDER BY finding_id",
        (source_id,),
    ).fetchall()
    moved: list[dict[str, Any]] = []
    consolidated: list[dict[str, Any]] = []
    pending_risk = 0
    pending_verification = 0
    campaign_links = 0
    evidence_records = 0
    source_records = 0
    observations = 0
    for raw_finding in source_findings:
        finding = dict(raw_finding)
        finding_id = str(finding["finding_id"])
        new_key = canonical_key_for({**finding, "asset_ref_id": target_id})
        duplicate = conn.execute(
            """SELECT * FROM findings
                 WHERE asset_ref_id=? AND canonical_key=? AND record_state!='ARCHIVED' AND finding_id!=?
                 ORDER BY first_seen_at,finding_id LIMIT 1""",
            (target_id, new_key, finding_id),
        ).fetchone()
        campaign_links += int(conn.execute(
            "SELECT COUNT(*) FROM campaign_findings WHERE finding_id=?", (finding_id,)
        ).fetchone()[0])
        source_records += int(conn.execute(
            "SELECT COUNT(*) FROM source_finding_records WHERE finding_id=?", (finding_id,)
        ).fetchone()[0])
        observations += int(conn.execute(
            "SELECT COUNT(*) FROM finding_observations WHERE finding_id=?", (finding_id,)
        ).fetchone()[0])
        evidence_records += int(conn.execute(
            "SELECT COUNT(*) FROM verification_evidence_artifacts WHERE finding_id=?", (finding_id,)
        ).fetchone()[0])
        if duplicate is None:
            moved.append({
                "finding_id": finding_id,
                "cve_id": str(finding.get("cve_id") or ""),
                "component": str(finding.get("component") or ""),
                "new_canonical_key": new_key,
            })
            continue
        target_finding_id = str(duplicate["finding_id"])
        risk_count = int(conn.execute(
            "SELECT COUNT(*) FROM risk_approval_requests WHERE status='PENDING' AND finding_id IN (?,?)",
            (finding_id, target_finding_id),
        ).fetchone()[0])
        verification_count = int(conn.execute(
            "SELECT COUNT(*) FROM remediation_verification_requests WHERE status='PENDING' AND finding_id IN (?,?)",
            (finding_id, target_finding_id),
        ).fetchone()[0])
        pending_risk += risk_count
        pending_verification += verification_count
        consolidated.append({
            "source_finding_id": finding_id,
            "target_finding_id": target_finding_id,
            "cve_id": str(finding.get("cve_id") or ""),
            "component": str(finding.get("component") or ""),
            "pending_risk_requests": risk_count,
            "pending_verification_requests": verification_count,
        })
    if pending_risk:
        blockers.append({
            "code": "PENDING_RISK_APPROVALS",
            "message": f"중복 finding에 대기 중인 위험수용 요청이 {pending_risk}건 있습니다.",
            "count": pending_risk,
        })
    if pending_verification:
        blockers.append({
            "code": "PENDING_REMEDIATION_VERIFICATIONS",
            "message": f"중복 finding에 대기 중인 조치검증 요청이 {pending_verification}건 있습니다.",
            "count": pending_verification,
        })

    source_identifiers = [dict(row) for row in conn.execute(
        "SELECT * FROM asset_identifiers WHERE asset_ref_id=? AND status='ACTIVE' ORDER BY identifier_id",
        (source_id,),
    ).fetchall()]
    target_identifiers = [dict(row) for row in conn.execute(
        "SELECT * FROM asset_identifiers WHERE asset_ref_id=? AND status='ACTIVE' ORDER BY identifier_id",
        (target_id,),
    ).fetchall()]
    target_keys = {
        (str(item["identifier_type"]), str(item["scope"]), str(item["normalized_value"]))
        for item in target_identifiers
    }
    identifier_collisions = [
        item for item in source_identifiers
        if (str(item["identifier_type"]), str(item["scope"]), str(item["normalized_value"])) in target_keys
    ]
    strong_conflicts: list[dict[str, Any]] = []
    for kind in sorted(AUTHORITATIVE_IDENTIFIER_TYPES - {"SCANNER_ASSET_ID"}):
        scopes = {
            str(item["scope"]) for item in source_identifiers + target_identifiers
            if str(item["identifier_type"]) == kind
        }
        for scope in sorted(scopes):
            left = sorted({
                str(item["normalized_value"]) for item in source_identifiers
                if str(item["identifier_type"]) == kind and str(item["scope"]) == scope
            })
            right = sorted({
                str(item["normalized_value"]) for item in target_identifiers
                if str(item["identifier_type"]) == kind and str(item["scope"]) == scope
            })
            if left and right and not set(left).intersection(right):
                strong_conflicts.append({"identifier_type": kind, "scope": scope, "source_values": left, "target_values": right})
    if strong_conflicts:
        blockers.append({
            "code": "AUTHORITATIVE_IDENTIFIER_CONFLICT",
            "message": "CMDB·인벤토리·클라우드 권위 식별자가 서로 충돌합니다.",
            "conflicts": strong_conflicts,
        })

    weak_conflicts: list[dict[str, Any]] = []
    for kind in ("FQDN", "MAC_ADDRESS"):
        left = sorted({str(item["normalized_value"]) for item in source_identifiers if str(item["identifier_type"]) == kind})
        right = sorted({str(item["normalized_value"]) for item in target_identifiers if str(item["identifier_type"]) == kind})
        if left and right and not set(left).intersection(right):
            weak_conflicts.append({"identifier_type": kind, "source_values": left, "target_values": right})
    if weak_conflicts:
        warnings.append({
            "code": "SUPPORTING_IDENTIFIER_CONFLICT",
            "message": "보조 식별자가 서로 다릅니다. 병합 근거를 다시 확인하세요.",
            "conflicts": weak_conflicts,
        })

    remapped_candidates = int(conn.execute(
        """SELECT COUNT(*) FROM asset_identity_candidates
             WHERE status='PENDING' AND (asset_ref_id_a=? OR asset_ref_id_b=?)""",
        (source_id, source_id),
    ).fetchone()[0])
    impact = {
        "source_asset": {
            "asset_ref_id": source_id,
            "asset_name": source.get("asset_name"),
            "status": source.get("status"),
            "row_version": int(source.get("row_version") or 1),
        },
        "target_asset": {
            "asset_ref_id": target_id,
            "asset_name": target.get("asset_name"),
            "status": target.get("status"),
            "row_version": int(target.get("row_version") or 1),
        },
        "candidate_id": str(candidate_id or ""),
        "summary": {
            "source_finding_count": len(source_findings),
            "moved_finding_count": len(moved),
            "consolidated_finding_count": len(consolidated),
            "source_identifier_count": len(source_identifiers),
            "identifier_collision_count": len(identifier_collisions),
            "identifier_move_count": len(source_identifiers) - len(identifier_collisions),
            "pending_candidate_remap_count": remapped_candidates,
            "campaign_link_count": campaign_links,
            "source_record_count": source_records,
            "observation_count": observations,
            "evidence_record_count": evidence_records,
        },
        "moved_findings": moved,
        "consolidated_findings": consolidated,
        "identifiers": {
            "source": [
                {"identifier_type": item["identifier_type"], "scope": item["scope"],
                 "normalized_value": item["normalized_value"], "status": item["status"]}
                for item in source_identifiers
            ],
            "target": [
                {"identifier_type": item["identifier_type"], "scope": item["scope"],
                 "normalized_value": item["normalized_value"], "status": item["status"]}
                for item in target_identifiers
            ],
        },
        "identifier_collisions": [
            {
                "identifier_id": item["identifier_id"],
                "identifier_type": item["identifier_type"],
                "scope": item["scope"],
                "display_value": item["display_value"],
            }
            for item in identifier_collisions
        ],
        "blockers": blockers,
        "warnings": warnings,
        "can_request": not blockers,
    }
    impact["impact_sha256"] = _asset_merge_impact_digest({key: value for key, value in impact.items() if key != "impact_sha256"})
    return impact


def analyze_asset_merge(
    db_path: str | Path, *, source_asset_ref_id: str, target_asset_ref_id: str, candidate_id: str = ""
) -> dict[str, Any]:
    with connect(db_path) as conn:
        return _asset_merge_impact_conn(
            conn, source_asset_ref_id=source_asset_ref_id,
            target_asset_ref_id=target_asset_ref_id, candidate_id=candidate_id,
        )


def _decode_asset_merge_request(row: sqlite3.Row | dict[str, Any] | None) -> dict[str, Any] | None:
    if row is None:
        return None
    item = dict(row)
    try:
        item["impact"] = json.loads(item.pop("impact_json") or "{}")
    except json.JSONDecodeError:
        item["impact"] = {}
    return item


def get_asset_merge_request(db_path: str | Path, request_id: str) -> dict[str, Any] | None:
    with connect(db_path) as conn:
        row = conn.execute(
            """SELECT r.*,s.asset_name AS source_asset_name,t.asset_name AS target_asset_name
                 FROM asset_merge_requests r
                 JOIN assets s ON s.asset_ref_id=r.source_asset_ref_id
                 JOIN assets t ON t.asset_ref_id=r.target_asset_ref_id
                WHERE r.request_id=?""",
            (request_id,),
        ).fetchone()
    return _decode_asset_merge_request(row)


def list_asset_merge_requests(
    db_path: str | Path, *, status: str = "", limit: int = 500
) -> list[dict[str, Any]]:
    normalized = str(status or "").strip().upper()
    if normalized and normalized not in ASSET_MERGE_REQUEST_STATUSES:
        raise ValueError(f"허용되지 않은 자산 병합 요청 상태: {normalized}")
    where = "WHERE r.status=?" if normalized else ""
    params: list[Any] = [normalized] if normalized else []
    params.append(max(1, min(int(limit), 2000)))
    with connect(db_path) as conn:
        rows = conn.execute(
            f"""SELECT r.*,s.asset_name AS source_asset_name,t.asset_name AS target_asset_name
                  FROM asset_merge_requests r
                  JOIN assets s ON s.asset_ref_id=r.source_asset_ref_id
                  JOIN assets t ON t.asset_ref_id=r.target_asset_ref_id
                  {where}
                 ORDER BY CASE r.status WHEN 'PENDING' THEN 0 ELSE 1 END,r.requested_at DESC
                 LIMIT ?""",
            params,
        ).fetchall()
    return [_decode_asset_merge_request(row) or {} for row in rows]


def create_asset_merge_request(
    db_path: str | Path, *, source_asset_ref_id: str, target_asset_ref_id: str,
    reason: str, requested_by: str, candidate_id: str = "",
) -> dict[str, Any]:
    note = str(reason or "").strip()
    if len(note) < 3:
        raise ValueError("병합 사유는 3자 이상이어야 합니다.")
    now = utc_now()
    request_id = "AMR-" + uuid.uuid4().hex[:20].upper()
    with connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        impact = _asset_merge_impact_conn(
            conn, source_asset_ref_id=source_asset_ref_id,
            target_asset_ref_id=target_asset_ref_id, candidate_id=candidate_id,
        )
        if impact["blockers"]:
            raise ValueError("자산 병합 요청을 생성할 수 없습니다: " + "; ".join(
                str(item.get("message") or item.get("code")) for item in impact["blockers"]
            ))
        existing = conn.execute(
            """SELECT request_id FROM asset_merge_requests
                 WHERE status='PENDING' AND (
                    source_asset_ref_id IN (?,?) OR target_asset_ref_id IN (?,?)
                 ) LIMIT 1""",
            (source_asset_ref_id, target_asset_ref_id, source_asset_ref_id, target_asset_ref_id),
        ).fetchone()
        if existing:
            raise ValueError("두 자산 중 하나가 이미 다른 병합 승인 요청에 포함되어 있습니다.")
        source_version = int(impact["source_asset"]["row_version"])
        target_version = int(impact["target_asset"]["row_version"])
        impact_json = json.dumps(impact, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
        conn.execute(
            """INSERT INTO asset_merge_requests(
                   request_id,candidate_id,source_asset_ref_id,target_asset_ref_id,requested_by,reason,status,
                   source_row_version,target_row_version,impact_json,impact_sha256,requested_at
               ) VALUES(?,?,?,?,?,?,'PENDING',?,?,?,?,?)""",
            (request_id, candidate_id or None, source_asset_ref_id, target_asset_ref_id,
             requested_by, note, source_version, target_version, impact_json,
             impact["impact_sha256"], now),
        )
        add_audit_event(
            db_path, finding_id=None, event_type="asset_merge_requested",
            summary=f"자산 병합 승인 요청: {source_asset_ref_id} → {target_asset_ref_id}",
            details={"request_id": request_id, "candidate_id": candidate_id or None,
                     "impact_sha256": impact["impact_sha256"], "summary": impact["summary"], "reason": note},
            actor=requested_by, conn=conn,
        )
        conn.commit()
    return get_asset_merge_request(db_path, request_id) or {}


def reject_asset_merge_request(
    db_path: str | Path, request_id: str, *, decided_by: str, decision_note: str,
) -> dict[str, Any]:
    note = str(decision_note or "").strip()
    if len(note) < 3:
        raise ValueError("반려 사유는 3자 이상이어야 합니다.")
    now = utc_now()
    with connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM asset_merge_requests WHERE request_id=?", (request_id,)).fetchone()
        if row is None:
            raise KeyError(request_id)
        if str(row["status"]) != "PENDING":
            raise ValueError("대기 중인 자산 병합 요청만 반려할 수 있습니다.")
        conn.execute(
            """UPDATE asset_merge_requests
                  SET status='REJECTED',decided_by=?,decision_note=?,decided_at=?
                WHERE request_id=?""",
            (decided_by, note, now, request_id),
        )
        add_audit_event(
            db_path, finding_id=None, event_type="asset_merge_rejected",
            summary="자산 병합 요청 반려", details={"request_id": request_id, "decision_note": note},
            actor=decided_by, conn=conn,
        )
        conn.commit()
    return get_asset_merge_request(db_path, request_id) or {}


def _preflight_asset_merge_request_conn(
    conn: sqlite3.Connection, request_id: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    row = conn.execute("SELECT * FROM asset_merge_requests WHERE request_id=?", (request_id,)).fetchone()
    if row is None:
        raise KeyError(request_id)
    request_row = dict(row)
    if str(request_row.get("status") or "") != "PENDING":
        raise ValueError("대기 중인 자산 병합 요청만 승인할 수 있습니다.")
    current = _asset_merge_impact_conn(
        conn, source_asset_ref_id=str(request_row["source_asset_ref_id"]),
        target_asset_ref_id=str(request_row["target_asset_ref_id"]),
        candidate_id=str(request_row.get("candidate_id") or ""),
    )
    if current["blockers"]:
        raise ConcurrencyError("요청 이후 병합 차단 조건이 발생했습니다. 영향분석 후 다시 요청하세요.")
    if int(current["source_asset"]["row_version"]) != int(request_row["source_row_version"]):
        raise ConcurrencyError("요청 이후 원본 자산이 변경되었습니다. 영향분석 후 다시 요청하세요.")
    if int(current["target_asset"]["row_version"]) != int(request_row["target_row_version"]):
        raise ConcurrencyError("요청 이후 대표 자산이 변경되었습니다. 영향분석 후 다시 요청하세요.")
    if str(current["impact_sha256"]) != str(request_row["impact_sha256"]):
        raise ConcurrencyError("요청 이후 병합 영향 범위가 변경되었습니다. 영향분석 후 다시 요청하세요.")
    return request_row, current


def preflight_asset_merge_request(db_path: str | Path, request_id: str) -> dict[str, Any]:
    with connect(db_path) as conn:
        request_row, current = _preflight_asset_merge_request_conn(conn, request_id)
    item = get_asset_merge_request(db_path, request_id) or request_row
    item["current_impact"] = current
    return item


def approve_asset_merge_request(
    db_path: str | Path, request_id: str, *, decided_by: str, decision_note: str = "",
    recovery_bundle_path: str, recovery_bundle_sha256: str,
) -> dict[str, Any]:
    bundle_path = str(recovery_bundle_path or "").strip()
    bundle_sha = str(recovery_bundle_sha256 or "").strip().lower()
    if not bundle_path or len(bundle_sha) != 64 or any(ch not in "0123456789abcdef" for ch in bundle_sha):
        raise ValueError("병합 승인 전 생성된 복구 번들 경로와 SHA-256이 필요합니다.")
    recovery_file = Path(bundle_path)
    if not recovery_file.is_file():
        raise ValueError("병합 승인용 복구 번들 파일을 찾을 수 없습니다.")
    digest = hashlib.sha256()
    with recovery_file.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    if not hmac.compare_digest(digest.hexdigest(), bundle_sha):
        raise ValueError("병합 승인용 복구 번들의 SHA-256이 일치하지 않습니다.")
    now = utc_now()
    with connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        request_row, current = _preflight_asset_merge_request_conn(conn, request_id)
        result = _merge_assets_conn(
            conn, db_path,
            source_asset_ref_id=str(request_row["source_asset_ref_id"]),
            target_asset_ref_id=str(request_row["target_asset_ref_id"]),
            reason=str(request_row["reason"]), actor=decided_by,
            candidate_id=str(request_row.get("candidate_id") or ""),
        )
        conn.execute(
            """UPDATE asset_merge_requests
                  SET status='APPROVED',decided_by=?,decision_note=?,decided_at=?,
                      recovery_bundle_path=?,recovery_bundle_sha256=?,merge_id=?
                WHERE request_id=?""",
            (decided_by, str(decision_note or "").strip(), now, bundle_path, bundle_sha,
             result["merge_id"], request_id),
        )
        add_audit_event(
            db_path, finding_id=None, event_type="asset_merge_approved",
            summary="자산 병합 요청 승인 및 적용",
            details={"request_id": request_id, "merge_id": result["merge_id"],
                     "recovery_bundle_path": bundle_path, "recovery_bundle_sha256": bundle_sha,
                     "decision_note": str(decision_note or "").strip()},
            actor=decided_by, conn=conn,
        )
        conn.commit()
    item = get_asset_merge_request(db_path, request_id) or {}
    item["merge_result"] = result
    return item


def _merge_assets_conn(conn: sqlite3.Connection, db_path: str | Path, *, source_asset_ref_id: str, target_asset_ref_id: str,
                 reason: str, actor: str = "local-user", candidate_id: str = "") -> dict[str, Any]:
    source_id = str(source_asset_ref_id or "").strip()
    target_id = str(target_asset_ref_id or "").strip()
    note = str(reason or "").strip()
    if not source_id or not target_id or source_id == target_id:
        raise ValueError("서로 다른 원본 자산과 대표 자산이 필요합니다.")
    if len(note) < 3:
        raise ValueError("병합 사유는 3자 이상이어야 합니다.")
    now = utc_now()
    merge_id = "AMG-" + uuid.uuid4().hex[:20].upper()
    moved_findings = consolidated = moved_identifiers = 0
    source = conn.execute("SELECT * FROM assets WHERE asset_ref_id=?", (source_id,)).fetchone()
    target = conn.execute("SELECT * FROM assets WHERE asset_ref_id=?", (target_id,)).fetchone()
    if source is None or target is None:
        raise KeyError(source_id if source is None else target_id)
    if str(source["status"]) != "ACTIVE":
        raise ValueError("활성 원본 자산만 병합할 수 있습니다.")
    if str(target["status"]) != "ACTIVE":
        raise ValueError("활성 대표 자산으로만 병합할 수 있습니다.")
    if candidate_id:
        candidate = conn.execute("SELECT * FROM asset_identity_candidates WHERE candidate_id=?", (candidate_id,)).fetchone()
        if candidate is None:
            raise KeyError(candidate_id)
        if candidate["status"] != "PENDING":
            raise ValueError("대기 중인 후보만 병합할 수 있습니다.")
        if set([candidate["asset_ref_id_a"], candidate["asset_ref_id_b"]]) != set([source_id, target_id]):
            raise ValueError("후보의 자산 쌍과 병합 대상이 일치하지 않습니다.")

    rollback_snapshot = _collect_asset_merge_rollback_snapshot(
        conn, source_asset_ref_id=source_id, target_asset_ref_id=target_id,
    )
    rollback_snapshot_json = json.dumps(
        rollback_snapshot, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str,
    )
    rollback_snapshot_sha = _asset_merge_rollback_digest(rollback_snapshot)
    created_candidate_ids: list[str] = []

    source_findings = conn.execute(
        "SELECT * FROM findings WHERE asset_ref_id=? AND merged_into_finding_id IS NULL ORDER BY finding_id",
        (source_id,),
    ).fetchall()
    target_asset = dict(target)
    for raw_finding in source_findings:
        finding = dict(raw_finding)
        new_key = canonical_key_for({**finding, "asset_ref_id": target_id})
        duplicate = conn.execute(
            """SELECT * FROM findings
                 WHERE asset_ref_id=? AND canonical_key=? AND record_state!='ARCHIVED' AND finding_id!=?
                 ORDER BY first_seen_at,finding_id LIMIT 1""",
            (target_id, new_key, finding["finding_id"]),
        ).fetchone()
        if duplicate is None:
            conn.execute(
                """UPDATE findings SET asset_ref_id=?,asset_name=?,environment=?,asset_criticality=?,
                           data_sensitivity=?,internet_exposed=?,canonical_key=?,row_version=row_version+1,
                           updated_at=CURRENT_TIMESTAMP WHERE finding_id=?""",
                (target_id, target_asset["asset_name"], target_asset["environment"], target_asset["criticality"],
                 target_asset["data_sensitivity"], target_asset["internet_exposed"], new_key, finding["finding_id"]),
            )
            conn.execute("UPDATE source_finding_records SET canonical_key=? WHERE finding_id=?", (new_key, finding["finding_id"]))
            moved_findings += 1
            continue

        target_finding_id = str(duplicate["finding_id"])
        pending = int(conn.execute(
            """SELECT (SELECT COUNT(*) FROM risk_approval_requests WHERE status='PENDING' AND finding_id IN (?,?)) +
                      (SELECT COUNT(*) FROM remediation_verification_requests WHERE status='PENDING' AND finding_id IN (?,?))""",
            (finding["finding_id"], target_finding_id, finding["finding_id"], target_finding_id),
        ).fetchone()[0])
        if pending:
            raise ValueError("대기 중인 위험수용 또는 조치검증 요청이 있는 중복 finding은 자산 병합 전에 처리해야 합니다.")
        conn.execute("UPDATE source_finding_records SET finding_id=?,canonical_key=? WHERE finding_id=?",
                     (target_finding_id, new_key, finding["finding_id"]))
        conn.execute("UPDATE finding_observations SET finding_id=? WHERE finding_id=?",
                     (target_finding_id, finding["finding_id"]))
        conn.execute(
            """INSERT OR IGNORE INTO campaign_findings(campaign_id,finding_id,added_by,added_at)
               SELECT campaign_id,?,added_by,added_at FROM campaign_findings WHERE finding_id=?""",
            (target_finding_id, finding["finding_id"]),
        )
        conn.execute("DELETE FROM campaign_findings WHERE finding_id=?", (finding["finding_id"],))
        conn.execute(
            """UPDATE finding_reconciliation_decisions SET status='RETIRED',retired_by=?,retired_at=?
                 WHERE finding_id=? AND status='ACTIVE'""", (actor, now, finding["finding_id"]),
        )
        archived_key = f"{finding.get('canonical_key') or new_key}|merged|{merge_id}|{finding['finding_id']}"
        conn.execute(
            """UPDATE findings SET record_state='ARCHIVED',archived_at=?,source_count=0,source_conflict_count=0,
                       merged_into_finding_id=?,canonical_key=?,row_version=row_version+1,updated_at=CURRENT_TIMESTAMP
                 WHERE finding_id=?""",
            (now, target_finding_id, archived_key, finding["finding_id"]),
        )
        _persist_canonical_aggregate_conn(conn, target_finding_id)
        consolidated += 1

    identifiers = conn.execute(
        "SELECT * FROM asset_identifiers WHERE asset_ref_id=? AND status='ACTIVE' ORDER BY identifier_id",
        (source_id,),
    ).fetchall()
    for identifier in identifiers:
        collision = conn.execute(
            """SELECT identifier_id FROM asset_identifiers
                 WHERE asset_ref_id=? AND identifier_type=? AND scope=? AND normalized_value=? AND status='ACTIVE'""",
            (target_id, identifier["identifier_type"], identifier["scope"], identifier["normalized_value"]),
        ).fetchone()
        if collision:
            conn.execute(
                """UPDATE asset_identifiers SET status='RETIRED',retired_by=?,retired_at=?
                     WHERE identifier_id=?""", (actor, now, identifier["identifier_id"]),
            )
        else:
            conn.execute("UPDATE asset_identifiers SET asset_ref_id=?,last_seen_at=? WHERE identifier_id=?",
                         (target_id, now, identifier["identifier_id"]))
        moved_identifiers += 1

    conn.execute(
        """UPDATE assets SET status='RETIRED',merged_into_asset_ref_id=?,updated_at=?,row_version=row_version+1
             WHERE asset_ref_id=?""", (target_id, now, source_id),
    )
    pending_candidates = conn.execute(
        """SELECT * FROM asset_identity_candidates
             WHERE status='PENDING' AND (asset_ref_id_a=? OR asset_ref_id_b=?)
             ORDER BY created_at,candidate_id""", (source_id, source_id),
    ).fetchall()
    for pending_candidate in pending_candidates:
        other_asset = (str(pending_candidate["asset_ref_id_b"])
                       if str(pending_candidate["asset_ref_id_a"]) == source_id
                       else str(pending_candidate["asset_ref_id_a"]))
        remapped_ids: list[str] = []
        if other_asset != target_id:
            try:
                reasons = json.loads(pending_candidate["reasons_json"] or "[]")
            except json.JSONDecodeError:
                reasons = []
            for reason_item in reasons or [{
                "identifier_type": "HOSTNAME", "scope": "migration",
                "normalized_value": pending_candidate["fingerprint"],
                "display_value": "remapped identity candidate", "source": "asset-merge",
            }]:
                payload = dict(reason_item)
                payload["confidence"] = int(pending_candidate["score"] or 50)
                remapped = _create_asset_identity_candidate_conn(
                    conn, asset_ref_id_a=target_id, asset_ref_id_b=other_asset,
                    identifier=payload, actor=actor, now=now,
                )
                if remapped is not None:
                    remapped_id = str(remapped["candidate_id"])
                    remapped_ids.append(remapped_id)
                    created_candidate_ids.append(remapped_id)
        decision_text = note
        if remapped_ids:
            decision_text = f"{note} · 대표 자산 기준 후보 재연결: {', '.join(sorted(set(remapped_ids)))}"
        conn.execute(
            """UPDATE asset_identity_candidates SET status='MERGED',decided_by=?,decided_at=?,decision_reason=?
                 WHERE candidate_id=?""",
            (actor, now, decision_text, pending_candidate["candidate_id"]),
        )
    conn.execute(
        """INSERT INTO asset_merge_history(
               merge_id,source_asset_ref_id,target_asset_ref_id,moved_findings_count,
               consolidated_findings_count,moved_identifiers_count,source_snapshot_json,
               target_snapshot_json,reason,actor,created_at
           ) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
        (merge_id, source_id, target_id, moved_findings, consolidated, moved_identifiers,
         json.dumps(dict(source), ensure_ascii=False, sort_keys=True, default=str),
         json.dumps(dict(target), ensure_ascii=False, sort_keys=True, default=str), note, actor, now),
    )
    post_guard = _collect_asset_merge_rollback_guard(
        conn, snapshot=rollback_snapshot, created_candidate_ids=created_candidate_ids,
    )
    post_guard_json = json.dumps(
        post_guard, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str,
    )
    post_guard_sha = _asset_merge_rollback_digest(post_guard)
    conn.execute(
        """INSERT INTO asset_merge_rollback_journals(
               merge_id,source_asset_ref_id,target_asset_ref_id,snapshot_json,snapshot_sha256,
               post_guard_json,post_guard_sha256,created_by,created_at
           ) VALUES(?,?,?,?,?,?,?,?,?)""",
        (merge_id, source_id, target_id, rollback_snapshot_json, rollback_snapshot_sha,
         post_guard_json, post_guard_sha, actor, now),
    )
    add_audit_event(
        db_path, finding_id=None, event_type="asset_merged",
        summary=f"자산 병합: {source_id} → {target_id}",
        details={"merge_id": merge_id, "source_asset_ref_id": source_id,
                 "target_asset_ref_id": target_id, "moved_findings": moved_findings,
                 "consolidated_findings": consolidated, "moved_identifiers": moved_identifiers,
                 "reason": note}, actor=actor, conn=conn,
    )
    return {
        "merge_id": merge_id, "source_asset_ref_id": source_id, "target_asset_ref_id": target_id,
        "moved_findings": moved_findings, "consolidated_findings": consolidated,
        "moved_identifiers": moved_identifiers,
        "rollback_snapshot_sha256": rollback_snapshot_sha,
        "rollback_post_guard_sha256": post_guard_sha,
    }


def merge_assets(db_path: str | Path, *, source_asset_ref_id: str, target_asset_ref_id: str,
                 reason: str, actor: str = "local-user", candidate_id: str = "") -> dict[str, Any]:
    with connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        result = _merge_assets_conn(
            conn, db_path, source_asset_ref_id=source_asset_ref_id,
            target_asset_ref_id=target_asset_ref_id, reason=reason, actor=actor,
            candidate_id=candidate_id,
        )
        conn.commit()
    return result
