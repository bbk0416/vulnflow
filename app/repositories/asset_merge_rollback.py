from __future__ import annotations

"""Asset merge rollback impact analysis, approval, and restoration repository."""

import hmac
import json
import sqlite3
import uuid
from pathlib import Path
from typing import Any

from app.core.db import ConcurrencyError, connect, utc_now
from app.repositories.audit import add_audit_event
from app.services.asset_merge_rollback import (
    collect_guard as _collect_asset_merge_rollback_guard,
    digest as _asset_merge_rollback_digest,
    restore_snapshot as _restore_asset_merge_snapshot,
)

ASSET_MERGE_ROLLBACK_REQUEST_STATUSES = {"PENDING", "APPROVED", "REJECTED", "CANCELLED"}

def _decode_asset_merge_rollback_journal(row: sqlite3.Row | dict[str, Any] | None) -> dict[str, Any] | None:
    if row is None:
        return None
    item = dict(row)
    for field in ("snapshot_json", "post_guard_json"):
        try:
            item[field.removesuffix("_json")] = json.loads(item.get(field) or "{}")
        except json.JSONDecodeError:
            item[field.removesuffix("_json")] = {}
    return item


def _decode_asset_merge_rollback_request(row: sqlite3.Row | dict[str, Any] | None) -> dict[str, Any] | None:
    if row is None:
        return None
    item = dict(row)
    try:
        item["impact"] = json.loads(item.get("impact_json") or "{}")
    except json.JSONDecodeError:
        item["impact"] = {}
    return item


def get_asset_merge_rollback_request(db_path: str | Path, rollback_request_id: str) -> dict[str, Any] | None:
    with connect(db_path) as conn:
        row = conn.execute(
            """SELECT r.*,h.source_asset_ref_id,h.target_asset_ref_id,
                      s.asset_name AS source_asset_name,t.asset_name AS target_asset_name
                 FROM asset_merge_rollback_requests r
                 JOIN asset_merge_history h ON h.merge_id=r.merge_id
                 JOIN assets s ON s.asset_ref_id=h.source_asset_ref_id
                 JOIN assets t ON t.asset_ref_id=h.target_asset_ref_id
                WHERE r.rollback_request_id=?""",
            (rollback_request_id,),
        ).fetchone()
    return _decode_asset_merge_rollback_request(row)


def list_asset_merge_rollback_requests(
    db_path: str | Path, *, status: str = "", limit: int = 500,
) -> list[dict[str, Any]]:
    normalized = str(status or "").strip().upper()
    if normalized and normalized not in ASSET_MERGE_ROLLBACK_REQUEST_STATUSES:
        raise ValueError(f"허용되지 않은 자산 병합 롤백 상태: {normalized}")
    where = "WHERE r.status=?" if normalized else ""
    params: list[Any] = [normalized] if normalized else []
    params.append(max(1, min(int(limit), 5000)))
    with connect(db_path) as conn:
        rows = conn.execute(
            f"""SELECT r.*,h.source_asset_ref_id,h.target_asset_ref_id,
                       s.asset_name AS source_asset_name,t.asset_name AS target_asset_name
                  FROM asset_merge_rollback_requests r
                  JOIN asset_merge_history h ON h.merge_id=r.merge_id
                  JOIN assets s ON s.asset_ref_id=h.source_asset_ref_id
                  JOIN assets t ON t.asset_ref_id=h.target_asset_ref_id
                  {where}
                 ORDER BY CASE r.status WHEN 'PENDING' THEN 0 ELSE 1 END,r.requested_at DESC
                 LIMIT ?""",
            params,
        ).fetchall()
    return [_decode_asset_merge_rollback_request(row) or {} for row in rows]


def _asset_merge_rollback_impact_conn(conn: sqlite3.Connection, merge_id: str) -> dict[str, Any]:
    history_row = conn.execute("SELECT * FROM asset_merge_history WHERE merge_id=?", (merge_id,)).fetchone()
    if history_row is None:
        raise KeyError(merge_id)
    history = dict(history_row)
    journal_row = conn.execute(
        "SELECT * FROM asset_merge_rollback_journals WHERE merge_id=?", (merge_id,)
    ).fetchone()
    blockers: list[dict[str, Any]] = []
    if journal_row is None:
        blockers.append({
            "code": "ROLLBACK_JOURNAL_UNAVAILABLE",
            "message": "이 병합은 범위별 롤백 저널이 생성되기 전 버전에서 수행되었습니다.",
        })
        return {
            "merge_id": merge_id,
            "source_asset_ref_id": history["source_asset_ref_id"],
            "target_asset_ref_id": history["target_asset_ref_id"],
            "summary": {},
            "blockers": blockers,
            "warnings": [],
            "can_request": False,
            "impact_sha256": _asset_merge_rollback_digest({"merge_id": merge_id, "blockers": blockers}),
        }
    journal = _decode_asset_merge_rollback_journal(journal_row) or {}
    snapshot = dict(journal.get("snapshot") or {})
    pre_candidates = set(str(item) for item in (snapshot.get("scope") or {}).get("candidate_ids") or [])
    post_candidates = set(str(item) for item in (journal.get("post_guard") or {}).get("scope", {}).get("candidate_ids") or [])
    created_candidates = sorted(post_candidates - pre_candidates)
    current_guard = _collect_asset_merge_rollback_guard(
        conn, snapshot=snapshot, created_candidate_ids=created_candidates,
    )
    current_guard_sha = _asset_merge_rollback_digest(current_guard)
    if not hmac.compare_digest(str(journal.get("snapshot_sha256") or ""), _asset_merge_rollback_digest(snapshot)):
        blockers.append({"code": "ROLLBACK_JOURNAL_TAMPERED", "message": "롤백 저널 스냅샷 해시가 일치하지 않습니다."})
    if not hmac.compare_digest(str(journal.get("post_guard_sha256") or ""), current_guard_sha):
        blockers.append({
            "code": "POST_MERGE_STATE_CHANGED",
            "message": "병합 이후 관련 자산·finding·승인·증거·공급망 상태가 변경되었습니다.",
            "expected_sha256": journal.get("post_guard_sha256"),
            "current_sha256": current_guard_sha,
        })
    source = conn.execute("SELECT * FROM assets WHERE asset_ref_id=?", (history["source_asset_ref_id"],)).fetchone()
    target = conn.execute("SELECT * FROM assets WHERE asset_ref_id=?", (history["target_asset_ref_id"],)).fetchone()
    if source is None or target is None:
        blockers.append({"code": "ASSET_MISSING", "message": "병합 자산 레코드를 찾을 수 없습니다."})
    elif str(source["status"]) != "RETIRED" or str(source["merged_into_asset_ref_id"] or "") != str(target["asset_ref_id"]):
        blockers.append({"code": "MERGE_STATE_MISMATCH", "message": "원본 자산이 현재 해당 대표 자산으로 병합된 상태가 아닙니다."})
    approved = int(conn.execute(
        "SELECT COUNT(*) FROM asset_merge_rollback_requests WHERE merge_id=? AND status='APPROVED'",
        (merge_id,),
    ).fetchone()[0])
    if approved:
        blockers.append({"code": "ALREADY_ROLLED_BACK", "message": "이미 롤백이 승인·적용된 병합입니다."})
    pending = int(conn.execute(
        "SELECT COUNT(*) FROM asset_merge_rollback_requests WHERE merge_id=? AND status='PENDING'",
        (merge_id,),
    ).fetchone()[0])
    warnings: list[dict[str, Any]] = []
    if pending:
        warnings.append({"code": "ROLLBACK_ALREADY_PENDING", "message": "이미 대기 중인 롤백 승인 요청이 있습니다."})
    tables = dict(snapshot.get("tables") or {})
    summary = {
        "asset_count": len(tables.get("assets") or []),
        "finding_count": len(tables.get("findings") or []),
        "source_record_count": len(tables.get("source_finding_records") or []),
        "observation_count": len(tables.get("finding_observations") or []),
        "campaign_link_count": len(tables.get("campaign_findings") or []),
        "identifier_count": len(tables.get("asset_identifiers") or []),
        "candidate_count": len(tables.get("asset_identity_candidates") or []),
        "created_candidate_count": len(created_candidates),
    }
    base = {
        "merge_id": merge_id,
        "source_asset_ref_id": history["source_asset_ref_id"],
        "target_asset_ref_id": history["target_asset_ref_id"],
        "merge_created_at": history["created_at"],
        "journal_snapshot_sha256": journal.get("snapshot_sha256"),
        "expected_post_guard_sha256": journal.get("post_guard_sha256"),
        "current_post_guard_sha256": current_guard_sha,
        "created_candidate_ids": created_candidates,
        "summary": summary,
        "blockers": blockers,
        "warnings": warnings,
    }
    base["can_request"] = not blockers and not pending
    base["impact_sha256"] = _asset_merge_rollback_digest(base)
    return base


def analyze_asset_merge_rollback(db_path: str | Path, merge_id: str) -> dict[str, Any]:
    with connect(db_path) as conn:
        return _asset_merge_rollback_impact_conn(conn, str(merge_id or "").strip())


def create_asset_merge_rollback_request(
    db_path: str | Path, *, merge_id: str, reason: str, requested_by: str,
) -> dict[str, Any]:
    note = str(reason or "").strip()
    if len(note) < 3:
        raise ValueError("롤백 사유는 3자 이상이어야 합니다.")
    rollback_request_id = "AMRB-" + uuid.uuid4().hex[:20].upper()
    now = utc_now()
    with connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        impact = _asset_merge_rollback_impact_conn(conn, merge_id)
        if not impact.get("can_request"):
            messages = [str(item.get("message") or item.get("code")) for item in impact.get("blockers") or []]
            messages.extend(str(item.get("message") or item.get("code")) for item in impact.get("warnings") or [] if item.get("code") == "ROLLBACK_ALREADY_PENDING")
            raise ValueError("자산 병합 롤백 요청을 생성할 수 없습니다: " + "; ".join(messages))
        impact_json = json.dumps(impact, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
        conn.execute(
            """INSERT INTO asset_merge_rollback_requests(
                   rollback_request_id,merge_id,requested_by,reason,status,impact_json,impact_sha256,requested_at
               ) VALUES(?,?,?,?,'PENDING',?,?,?)""",
            (rollback_request_id, merge_id, requested_by, note, impact_json, impact["impact_sha256"], now),
        )
        add_audit_event(
            db_path, finding_id=None, event_type="asset_merge_rollback_requested",
            summary=f"자산 병합 롤백 승인 요청: {merge_id}",
            details={"rollback_request_id": rollback_request_id, "merge_id": merge_id,
                     "impact_sha256": impact["impact_sha256"], "summary": impact["summary"], "reason": note},
            actor=requested_by, conn=conn,
        )
        conn.commit()
    return get_asset_merge_rollback_request(db_path, rollback_request_id) or {}


def reject_asset_merge_rollback_request(
    db_path: str | Path, rollback_request_id: str, *, decided_by: str, decision_note: str,
) -> dict[str, Any]:
    note = str(decision_note or "").strip()
    if len(note) < 3:
        raise ValueError("반려 사유는 3자 이상이어야 합니다.")
    now = utc_now()
    with connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT * FROM asset_merge_rollback_requests WHERE rollback_request_id=?", (rollback_request_id,)
        ).fetchone()
        if row is None:
            raise KeyError(rollback_request_id)
        if str(row["status"]) != "PENDING":
            raise ValueError("대기 중인 롤백 요청만 반려할 수 있습니다.")
        conn.execute(
            """UPDATE asset_merge_rollback_requests
                  SET status='REJECTED',decided_by=?,decision_note=?,decided_at=?
                WHERE rollback_request_id=?""",
            (decided_by, note, now, rollback_request_id),
        )
        add_audit_event(
            db_path, finding_id=None, event_type="asset_merge_rollback_rejected",
            summary="자산 병합 롤백 요청 반려",
            details={"rollback_request_id": rollback_request_id, "merge_id": row["merge_id"], "decision_note": note},
            actor=decided_by, conn=conn,
        )
        conn.commit()
    return get_asset_merge_rollback_request(db_path, rollback_request_id) or {}


def _preflight_asset_merge_rollback_request_conn(
    conn: sqlite3.Connection, rollback_request_id: str,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    row = conn.execute(
        "SELECT * FROM asset_merge_rollback_requests WHERE rollback_request_id=?", (rollback_request_id,)
    ).fetchone()
    if row is None:
        raise KeyError(rollback_request_id)
    request_row = dict(row)
    if str(request_row.get("status") or "") != "PENDING":
        raise ValueError("대기 중인 자산 병합 롤백 요청만 승인할 수 있습니다.")
    current = _asset_merge_rollback_impact_conn(conn, str(request_row["merge_id"]))
    if not current.get("can_request") and not (
        not current.get("blockers") and any(item.get("code") == "ROLLBACK_ALREADY_PENDING" for item in current.get("warnings") or [])
    ):
        raise ConcurrencyError("요청 이후 병합 롤백 조건이 변경되었습니다. 다시 영향분석하세요.")
    requested_impact = json.loads(request_row.get("impact_json") or "{}")
    comparable = dict(current)
    comparable["can_request"] = True
    comparable["warnings"] = [item for item in comparable.get("warnings") or [] if item.get("code") != "ROLLBACK_ALREADY_PENDING"]
    comparable["impact_sha256"] = _asset_merge_rollback_digest({key: value for key, value in comparable.items() if key != "impact_sha256"})
    if str(request_row["impact_sha256"]) != str(requested_impact.get("impact_sha256") or ""):
        raise ConcurrencyError("저장된 롤백 요청 영향 해시가 일치하지 않습니다.")
    # The post-merge guard is the load-bearing concurrency control. Request metadata may differ only by the pending warning.
    if str(requested_impact.get("current_post_guard_sha256") or "") != str(current.get("current_post_guard_sha256") or ""):
        raise ConcurrencyError("요청 이후 병합 관련 레코드가 변경되었습니다. 다시 영향분석하세요.")
    journal_row = conn.execute(
        "SELECT * FROM asset_merge_rollback_journals WHERE merge_id=?", (request_row["merge_id"],)
    ).fetchone()
    journal = _decode_asset_merge_rollback_journal(journal_row)
    if journal is None:
        raise ValueError("자산 병합 롤백 저널을 찾을 수 없습니다.")
    return request_row, current, journal


def approve_asset_merge_rollback_request(
    db_path: str | Path, rollback_request_id: str, *, decided_by: str, decision_note: str = "",
) -> dict[str, Any]:
    now = utc_now()
    with connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        request_row, current, journal = _preflight_asset_merge_rollback_request_conn(conn, rollback_request_id)
        snapshot = dict(journal.get("snapshot") or {})
        pre_candidates = set(str(item) for item in (snapshot.get("scope") or {}).get("candidate_ids") or [])
        post_candidates = set(str(item) for item in (journal.get("post_guard") or {}).get("scope", {}).get("candidate_ids") or [])
        restored = _restore_asset_merge_snapshot(
            conn, snapshot=snapshot, created_candidate_ids=post_candidates - pre_candidates,
            actor=decided_by, now=now,
        )
        conn.execute(
            """UPDATE asset_merge_rollback_requests
                  SET status='APPROVED',decided_by=?,decision_note=?,decided_at=?
                WHERE rollback_request_id=?""",
            (decided_by, str(decision_note or "").strip(), now, rollback_request_id),
        )
        add_audit_event(
            db_path, finding_id=None, event_type="asset_merge_rollback_approved",
            summary=f"자산 병합 범위별 롤백 적용: {request_row['merge_id']}",
            details={"rollback_request_id": rollback_request_id, "merge_id": request_row["merge_id"],
                     "restored": restored, "decision_note": str(decision_note or "").strip(),
                     "journal_snapshot_sha256": journal.get("snapshot_sha256")},
            actor=decided_by, conn=conn,
        )
        conn.commit()
    item = get_asset_merge_rollback_request(db_path, rollback_request_id) or {}
    item["rollback_result"] = restored
    return item
