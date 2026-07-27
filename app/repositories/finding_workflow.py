from __future__ import annotations

"""Finding workflow, remediation verification and record-state writes."""

import json
import sqlite3
import uuid
from pathlib import Path
from typing import Any, Iterable

from app.core.db import ConcurrencyError, connect, utc_now
from app.repositories.audit import add_audit_event
from app.repositories.findings import get_finding

VERIFICATION_METHODS = {"SCAN_ABSENCE", "MANUAL_EVIDENCE", "RETEST"}
VERIFICATION_STATUSES = {"PENDING", "APPROVED", "REJECTED", "CANCELLED"}
RECORD_STATES = {"ACTIVE", "STALE", "ARCHIVED"}

def _cancel_pending_verifications_conn(
    conn: sqlite3.Connection, finding_id: str, *, actor: str, reason: str, db_path: str | Path
) -> int:
    now = utc_now()
    rows = conn.execute(
        "SELECT verification_id FROM remediation_verification_requests WHERE finding_id=? AND status='PENDING'",
        (finding_id,),
    ).fetchall()
    if not rows:
        return 0
    conn.execute(
        "UPDATE remediation_verification_requests SET status='CANCELLED',decided_by=?,decision_note=?,decided_at=? "
        "WHERE finding_id=? AND status='PENDING'",
        (actor, reason, now, finding_id),
    )
    add_audit_event(
        db_path, finding_id=finding_id, event_type="remediation_verification_cancelled",
        summary=f"조치 검증 요청 {len(rows)}건 자동 취소",
        details={"reason": reason, "verification_ids": [row["verification_id"] for row in rows]},
        actor=actor, conn=conn,
    )
    return len(rows)


def update_workflow(
    db_path: str | Path,
    finding_id: str,
    *,
    status: str,
    owner: str,
    due_date: str,
    exception_expiry: str,
    risk_acceptance_reason: str,
    risk_acceptance_approver: str,
    notes: str,
    actor: str = "local-user",
    expected_version: int | None = None,
) -> None:
    with connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        before_row = conn.execute("SELECT * FROM findings WHERE finding_id=?", (finding_id,)).fetchone()
        if before_row is None:
            raise KeyError(finding_id)
        before = dict(before_row)
        now = utc_now()
        resolved_at = before.get("resolved_at") or ""
        resolution_state = str(before.get("resolution_state") or "UNVERIFIED")
        resolution_requested_at = str(before.get("resolution_requested_at") or "")
        verified_at = str(before.get("verified_at") or "")
        verified_by = str(before.get("verified_by") or "")
        verification_method = str(before.get("verification_method") or "")
        verification_note = str(before.get("verification_note") or "")
        last_reopened_at = str(before.get("last_reopened_at") or "")
        reopen_count = int(before.get("reopen_count") or 0)

        if status == "MITIGATED":
            if before.get("status") != "MITIGATED":
                resolution_state = (
                    "READY_FOR_VERIFICATION"
                    if int(before.get("consecutive_absent_scans") or 0) >= 2
                    else "UNVERIFIED"
                )
                resolution_requested_at = ""
                verified_at = verified_by = verification_method = verification_note = ""
                resolved_at = ""
        elif status in {"OPEN", "IN_PROGRESS"}:
            was_resolved = before.get("status") in {"CLOSED", "MITIGATED"} or resolution_state == "VERIFIED"
            if was_resolved and before.get("status") != status:
                resolution_state = "REOPENED"
                last_reopened_at = now
                reopen_count += 1
            else:
                resolution_state = "UNVERIFIED"
            resolution_requested_at = ""
            verified_at = verified_by = verification_method = verification_note = ""
            resolved_at = ""
            _cancel_pending_verifications_conn(
                conn, finding_id, actor=actor, reason=f"워크플로 상태가 {status}로 변경됨", db_path=db_path
            )
        elif status == "RISK_ACCEPTED":
            resolution_state = "NOT_REQUIRED"
            resolution_requested_at = ""
            verified_at = verified_by = verification_method = verification_note = ""
            if before.get("status") != status:
                resolved_at = now
        elif status == "CLOSED":
            # Storage-level backward compatibility: direct close is recorded as unverified.
            # UI/API users must use the remediation verification approval flow.
            if resolution_state != "VERIFIED":
                resolution_state = "UNVERIFIED"
                verified_at = verified_by = verification_method = verification_note = ""
            if before.get("status") != status:
                resolved_at = now

        params: list[Any] = [
            status, owner, due_date, exception_expiry,
            risk_acceptance_reason, risk_acceptance_approver, notes, resolved_at,
            resolution_state, resolution_requested_at, verified_at, verified_by,
            verification_method, verification_note, last_reopened_at, reopen_count, finding_id,
        ]
        version_clause = ""
        if expected_version is not None:
            version_clause = " AND row_version=?"
            params.append(int(expected_version))
        cursor = conn.execute(
            f"""
            UPDATE findings
               SET status=?, owner=?, due_date=?, exception_expiry=?,
                   risk_acceptance_reason=?, risk_acceptance_approver=?, notes=?,
                   resolved_at=?, resolution_state=?, resolution_requested_at=?,
                   verified_at=?, verified_by=?, verification_method=?, verification_note=?,
                   last_reopened_at=?, reopen_count=?,
                   row_version=COALESCE(row_version,0)+1, updated_at=CURRENT_TIMESTAMP
             WHERE finding_id=?{version_clause}
            """,
            params,
        )
        if cursor.rowcount != 1:
            conn.rollback()
            raise ConcurrencyError("다른 화면이나 작업에서 항목이 먼저 변경되었습니다. 새로고침 후 다시 시도하세요.")
        changes = {}
        tracked = {
            "status": status, "owner": owner, "due_date": due_date,
            "exception_expiry": exception_expiry, "risk_acceptance_reason": risk_acceptance_reason,
            "risk_acceptance_approver": risk_acceptance_approver, "notes": notes,
            "resolution_state": resolution_state,
        }
        for field, new_value in tracked.items():
            old_value = before.get(field) or ""
            if str(old_value) != str(new_value or ""):
                changes[field] = {"old": old_value, "new": new_value}
        add_audit_event(
            db_path, finding_id=finding_id, event_type="workflow_update",
            summary=f"워크플로 변경: {before.get('status')} → {status}",
            details=changes, actor=actor, conn=conn,
        )
        conn.commit()


def list_finding_observations(db_path: str | Path, finding_id: str, *, limit: int = 100) -> list[dict[str, Any]]:
    with connect(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM finding_observations WHERE finding_id=? ORDER BY observed_at DESC,rowid DESC LIMIT ?",
            (finding_id, max(1, min(int(limit), 1000))),
        ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            try:
                item["details"] = json.loads(item.get("details_json") or "{}")
            except json.JSONDecodeError:
                item["details"] = {}
            result.append(item)
        return result


def list_remediation_verification_requests(
    db_path: str | Path, *, finding_id: str = "", status: str = "", limit: int = 200
) -> list[dict[str, Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    if finding_id:
        clauses.append("v.finding_id=?")
        params.append(finding_id)
    if status:
        clauses.append("v.status=?")
        params.append(str(status).upper())
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    params.append(max(1, min(int(limit), 1000)))
    with connect(db_path) as conn:
        rows = conn.execute(
            f"""SELECT v.*,f.cve_id,f.asset_name,f.product,f.status AS finding_status,
                       f.resolution_state,f.row_version AS current_finding_row_version,
                       (SELECT COUNT(*) FROM verification_evidence_artifacts e
                         WHERE e.verification_id=v.verification_id AND e.status!='PURGED') AS evidence_count
                  FROM remediation_verification_requests v
                  JOIN findings f ON f.finding_id=v.finding_id
                  {where}
                 ORDER BY CASE v.status WHEN 'PENDING' THEN 0 ELSE 1 END,v.requested_at DESC
                 LIMIT ?""",
            params,
        ).fetchall()
        return [dict(row) for row in rows]


def create_remediation_verification_request(
    db_path: str | Path, finding_id: str, *, method: str, evidence_note: str,
    actor: str, expected_version: int | None = None, absence_threshold: int = 2
) -> dict[str, Any]:
    method = str(method or "").strip().upper()
    if method not in VERIFICATION_METHODS:
        raise ValueError("지원하지 않는 조치 검증 방식입니다.")
    evidence_note = str(evidence_note or "").strip()
    threshold = max(1, int(absence_threshold))
    with connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM findings WHERE finding_id=?", (finding_id,)).fetchone()
        if row is None:
            raise KeyError(finding_id)
        finding = dict(row)
        if str(finding.get("record_state") or "ACTIVE") == "ARCHIVED":
            raise ValueError("ARCHIVED 항목은 검증 요청을 만들 수 없습니다.")
        if str(finding.get("status") or "OPEN") != "MITIGATED":
            raise ValueError("MITIGATED 상태에서만 조치 검증을 요청할 수 있습니다.")
        if expected_version is not None and int(finding.get("row_version") or 0) != int(expected_version):
            raise ConcurrencyError("항목이 먼저 변경되었습니다. 새로고침 후 다시 시도하세요.")
        if conn.execute(
            "SELECT 1 FROM remediation_verification_requests WHERE finding_id=? AND status='PENDING'",
            (finding_id,),
        ).fetchone():
            raise ValueError("이미 대기 중인 조치 검증 요청이 있습니다.")
        absence_count = int(finding.get("consecutive_absent_scans") or 0)
        if method == "SCAN_ABSENCE":
            if str(finding.get("record_state") or "ACTIVE") != "STALE" or absence_count < threshold:
                raise ValueError(f"SCAN_ABSENCE 검증에는 연속 전체 스냅샷 미탐지 {threshold}회 이상이 필요합니다.")
        elif not evidence_note:
            raise ValueError("수동 증거·재시험 검증에는 근거 메모가 필요합니다.")
        source_batch = conn.execute(
            "SELECT batch_id FROM finding_observations WHERE finding_id=? AND observation='ABSENT' ORDER BY observed_at DESC LIMIT 1",
            (finding_id,),
        ).fetchone()
        verification_id = f"VRF-{uuid.uuid4().hex[:16].upper()}"
        now = utc_now()
        next_version = int(finding.get("row_version") or 0) + 1
        conn.execute(
            """INSERT INTO remediation_verification_requests(
                   verification_id,finding_id,method,evidence_note,source_batch_id,observed_absence_count,
                   status,requested_by,requested_at,finding_row_version
               ) VALUES(?,?,?,?,?,?,'PENDING',?,?,?)""",
            (verification_id, finding_id, method, evidence_note, source_batch["batch_id"] if source_batch else None,
             absence_count, actor, now, next_version),
        )
        conn.execute(
            """UPDATE findings SET resolution_state='PENDING',resolution_requested_at=?,
                       verification_method=?,verification_note=?,row_version=?,updated_at=CURRENT_TIMESTAMP
                 WHERE finding_id=?""",
            (now, method, evidence_note, next_version, finding_id),
        )
        add_audit_event(
            db_path, finding_id=finding_id, event_type="remediation_verification_requested",
            summary=f"조치 검증 요청: {method}",
            details={"verification_id": verification_id, "method": method, "absence_count": absence_count,
                     "source_batch_id": source_batch["batch_id"] if source_batch else None},
            actor=actor, conn=conn,
        )
        conn.commit()
    return list_remediation_verification_requests(db_path, finding_id=finding_id, limit=1)[0]


def decide_remediation_verification_request(
    db_path: str | Path, verification_id: str, *, decision: str, decision_note: str, actor: str
) -> dict[str, Any]:
    normalized = str(decision or "").strip().upper()
    if normalized not in {"APPROVE", "REJECT"}:
        raise ValueError("decision은 APPROVE 또는 REJECT여야 합니다.")
    decision_note = str(decision_note or "").strip()
    with connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        request = conn.execute(
            "SELECT * FROM remediation_verification_requests WHERE verification_id=?", (verification_id,)
        ).fetchone()
        if request is None:
            raise KeyError(verification_id)
        request = dict(request)
        if request["status"] != "PENDING":
            raise ValueError("이미 처리된 조치 검증 요청입니다.")
        finding_row = conn.execute("SELECT * FROM findings WHERE finding_id=?", (request["finding_id"],)).fetchone()
        if finding_row is None:
            raise KeyError(request["finding_id"])
        finding = dict(finding_row)
        if int(finding.get("row_version") or 0) != int(request["finding_row_version"]):
            raise ConcurrencyError("검증 요청 이후 취약점이 변경되었습니다. 기존 요청을 취소하고 다시 요청하세요.")
        if normalized == "APPROVE":
            unsafe = conn.execute(
                """SELECT evidence_id,original_filename,scan_status FROM verification_evidence_artifacts
                     WHERE verification_id=? AND status='ACTIVE'
                       AND scan_status NOT IN ('CLEAN','WAIVED')
                     ORDER BY uploaded_at""",
                (verification_id,),
            ).fetchall()
            if unsafe:
                summary = ", ".join(f"{row['original_filename']}({row['scan_status']})" for row in unsafe[:5])
                raise ValueError("악성코드 검사 또는 관리자 면제가 완료되지 않은 증거가 있습니다: " + summary)
        now = utc_now()
        if normalized == "APPROVE":
            request_status = "APPROVED"
            finding_status = "CLOSED"
            resolution_state = "VERIFIED"
            verified_at = now
            verified_by = actor
            resolved_at = now
            summary = "조치 검증 승인 및 취약점 종료"
        else:
            request_status = "REJECTED"
            finding_status = "IN_PROGRESS"
            resolution_state = "REJECTED"
            verified_at = verified_by = resolved_at = ""
            summary = "조치 검증 반려 및 재조치 전환"
        conn.execute(
            """UPDATE remediation_verification_requests
                   SET status=?,decided_by=?,decision_note=?,decided_at=?
                 WHERE verification_id=?""",
            (request_status, actor, decision_note, now, verification_id),
        )
        conn.execute(
            """UPDATE findings SET status=?,resolution_state=?,verified_at=?,verified_by=?,
                       verification_method=?,verification_note=?,resolved_at=?,resolution_requested_at='',
                       row_version=COALESCE(row_version,0)+1,updated_at=CURRENT_TIMESTAMP
                 WHERE finding_id=?""",
            (finding_status, resolution_state, verified_at, verified_by, request["method"],
             decision_note or request["evidence_note"], resolved_at, request["finding_id"]),
        )
        add_audit_event(
            db_path, finding_id=request["finding_id"], event_type="remediation_verification_decided",
            summary=summary,
            details={"verification_id": verification_id, "decision": normalized, "method": request["method"],
                     "decision_note": decision_note},
            actor=actor, conn=conn,
        )
        conn.commit()
    return list_remediation_verification_requests(db_path, finding_id=request["finding_id"], limit=1)[0]


def bulk_update_intel(
    db_path: str | Path,
    updates: dict[str, dict[str, Any]],
    *,
    intel_source: str,
    actor: str = "local-user",
) -> int:
    now = utc_now()
    changed = 0
    with connect(db_path) as conn:
        for cve_id, values in updates.items():
            assignments = ["intel_source=?", "intel_updated_at=?", "row_version=COALESCE(row_version,0)+1", "updated_at=CURRENT_TIMESTAMP"]
            params: list[Any] = [intel_source, now]
            for field in ("epss", "epss_percentile", "kev"):
                if field in values and values[field] is not None:
                    assignments.append(f"{field}=?")
                    params.append(int(bool(values[field])) if field == "kev" else float(values[field]))
            params.append(cve_id)
            cursor = conn.execute(f"UPDATE findings SET {', '.join(assignments)} WHERE cve_id=?", params)
            changed += cursor.rowcount
        add_audit_event(
            db_path,
            finding_id=None,
            event_type="intel_refresh",
            summary=f"위협정보 {changed}개 항목 갱신",
            details={"cves": len(updates), "rows": changed, "source": intel_source},
            actor=actor,
            conn=conn,
        )
        conn.commit()
    return changed


def delete_all_findings(db_path: str | Path, *, actor: str = "local-user") -> int:
    with connect(db_path) as conn:
        merge_records = int(conn.execute(
            "SELECT (SELECT COUNT(*) FROM asset_merge_history) + (SELECT COUNT(*) FROM asset_merge_requests)"
        ).fetchone()[0])
        if merge_records:
            raise ValueError(
                "자산 병합 요청·이력이 있는 데이터베이스는 데모 부분 초기화를 지원하지 않습니다. "
                "복구 번들을 보관한 뒤 새 데이터베이스로 초기화하세요."
            )
        count = int(conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0])
        approval_count = int(conn.execute("SELECT COUNT(*) FROM risk_approval_requests").fetchone()[0])
        campaign_count = int(conn.execute("SELECT COUNT(*) FROM remediation_campaigns").fetchone()[0])
        asset_count = int(conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0])
        conn.execute("DELETE FROM risk_approval_requests")
        conn.execute("DELETE FROM remediation_campaigns")
        conn.execute("DELETE FROM findings")
        conn.execute("DELETE FROM assets")
        add_audit_event(
            db_path,
            finding_id=None,
            event_type="reset",
            summary=f"취약점 데이터 {count}건 삭제",
            details={"deleted": count, "approval_requests_deleted": approval_count, "campaigns_deleted": campaign_count, "assets_deleted": asset_count},
            actor=actor,
            conn=conn,
        )
        conn.commit()
        return count


def _bulk_update_workflow_conn(
    db_path: str | Path,
    conn: sqlite3.Connection,
    finding_ids: Iterable[str],
    *,
    status: str | None = None,
    owner_mode: str = "keep",
    owner: str = "",
    due_date_mode: str = "keep",
    due_date: str = "",
    notes_append: str = "",
    actor: str = "local-user",
) -> int:
    """Apply an all-or-nothing workflow update using an existing transaction."""
    ids = list(dict.fromkeys(str(fid).strip() for fid in finding_ids if str(fid).strip()))
    if not ids:
        raise ValueError("선택된 취약점이 없습니다.")
    if owner_mode not in {"keep", "set", "clear"}:
        raise ValueError("담당자 처리 방식이 올바르지 않습니다.")
    if due_date_mode not in {"keep", "set", "clear"}:
        raise ValueError("목표일 처리 방식이 올바르지 않습니다.")

    placeholders = ",".join("?" for _ in ids)
    rows = conn.execute(
        f"SELECT * FROM findings WHERE finding_id IN ({placeholders})", ids
    ).fetchall()
    if len(rows) != len(ids):
        found = {row["finding_id"] for row in rows}
        missing = [fid for fid in ids if fid not in found]
        raise ValueError("존재하지 않는 finding_id: " + ", ".join(missing))

    prepared: list[tuple[dict[str, Any], dict[str, Any]]] = []
    now = utc_now()
    for row in rows:
        before = dict(row)
        after = dict(before)
        if status:
            after["status"] = status
        if owner_mode == "set":
            after["owner"] = owner
        elif owner_mode == "clear":
            after["owner"] = ""
        if due_date_mode == "set":
            after["due_date"] = due_date
        elif due_date_mode == "clear":
            after["due_date"] = ""
        if notes_append:
            prefix = str(before.get("notes") or "").rstrip()
            entry = f"[일괄처리 {now} · {actor}] {notes_append}"
            after["notes"] = f"{prefix}\n\n{entry}" if prefix else entry
        if before.get("status") == "RISK_ACCEPTED" and after["status"] != "RISK_ACCEPTED":
            after["exception_expiry"] = ""
            after["risk_acceptance_reason"] = ""
            after["risk_acceptance_approver"] = ""
        if after["status"] in {"MITIGATED", "CLOSED"} and before.get("status") != after["status"]:
            after["resolved_at"] = now
        elif after["status"] in {"OPEN", "IN_PROGRESS"}:
            after["resolved_at"] = ""
        prepared.append((before, after))

    for before, after in prepared:
        conn.execute(
            """
            UPDATE findings
               SET status=?, owner=?, due_date=?, notes=?, resolved_at=?,
                   exception_expiry=?, risk_acceptance_reason=?, risk_acceptance_approver=?,
                   row_version=COALESCE(row_version,0)+1, updated_at=CURRENT_TIMESTAMP
             WHERE finding_id=?
            """,
            (
                after["status"], after.get("owner") or "", after.get("due_date") or "",
                after.get("notes") or "", after.get("resolved_at") or "",
                after.get("exception_expiry") or "", after.get("risk_acceptance_reason") or "",
                after.get("risk_acceptance_approver") or "", after["finding_id"],
            ),
        )
        changes: dict[str, Any] = {}
        for field in ("status", "owner", "due_date", "notes", "exception_expiry", "risk_acceptance_reason", "risk_acceptance_approver"):
            if str(before.get(field) or "") != str(after.get(field) or ""):
                changes[field] = {"old": before.get(field) or "", "new": after.get(field) or ""}
        add_audit_event(
            db_path, finding_id=after["finding_id"], event_type="bulk_workflow_update",
            summary=f"일괄 워크플로 변경: {before.get('status')} → {after.get('status')}",
            details=changes, actor=actor, conn=conn,
        )
    add_audit_event(
        db_path, finding_id=None, event_type="bulk_workflow_update",
        summary=f"취약점 {len(prepared)}건 일괄 변경",
        details={
            "finding_ids": ids, "status": status or "keep", "owner_mode": owner_mode,
            "due_date_mode": due_date_mode, "notes_appended": bool(notes_append),
        },
        actor=actor, conn=conn,
    )
    return len(prepared)


def bulk_update_workflow(
    db_path: str | Path,
    finding_ids: Iterable[str],
    *,
    status: str | None = None,
    owner_mode: str = "keep",
    owner: str = "",
    due_date_mode: str = "keep",
    due_date: str = "",
    notes_append: str = "",
    actor: str = "local-user",
) -> int:
    """Apply a single, all-or-nothing workflow update to multiple findings."""
    with connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        count = _bulk_update_workflow_conn(
            db_path, conn, finding_ids, status=status, owner_mode=owner_mode, owner=owner,
            due_date_mode=due_date_mode, due_date=due_date, notes_append=notes_append, actor=actor,
        )
        conn.commit()
    return count


def update_record_state(
    db_path: str | Path,
    finding_id: str,
    *,
    record_state: str,
    actor: str = "local-user",
    expected_version: int | None = None,
) -> dict[str, Any]:
    state = str(record_state or "").strip().upper()
    if state not in RECORD_STATES:
        raise ValueError("허용되지 않은 레코드 상태입니다.")
    now = utc_now()
    with connect(db_path) as conn:
        before_row = conn.execute("SELECT * FROM findings WHERE finding_id=?", (finding_id,)).fetchone()
        if before_row is None:
            raise KeyError(finding_id)
        before = dict(before_row)
        stale_since = before.get("stale_since") or ""
        archived_at = before.get("archived_at") or ""
        if state == "ACTIVE":
            stale_since = ""
            archived_at = ""
        elif state == "STALE":
            stale_since = stale_since or now
            archived_at = ""
        elif state == "ARCHIVED":
            archived_at = archived_at or now

        params: list[Any] = [state, stale_since, archived_at, finding_id]
        version_clause = ""
        if expected_version is not None:
            version_clause = " AND row_version=?"
            params.append(int(expected_version))
        cursor = conn.execute(
            f"""
            UPDATE findings
               SET record_state=?, stale_since=?, archived_at=?,
                   row_version=COALESCE(row_version,0)+1, updated_at=CURRENT_TIMESTAMP
             WHERE finding_id=?{version_clause}
            """,
            params,
        )
        if cursor.rowcount != 1:
            raise ConcurrencyError("다른 화면이나 작업에서 항목이 먼저 변경되었습니다. 새로고침 후 다시 시도하세요.")
        add_audit_event(
            db_path,
            finding_id=finding_id,
            event_type="record_state_update",
            summary=f"레코드 상태 변경: {before.get('record_state') or 'ACTIVE'} → {state}",
            details={"old": before.get("record_state") or "ACTIVE", "new": state},
            actor=actor,
            conn=conn,
        )
        conn.commit()
    return get_finding(db_path, finding_id) or {}
