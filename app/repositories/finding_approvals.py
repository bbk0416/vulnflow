from __future__ import annotations

"""Risk-acceptance approval request persistence for findings."""

import uuid
from datetime import date
from pathlib import Path
from typing import Any

from app.core.db import ConcurrencyError, connect, utc_now
from app.repositories.audit import add_audit_event

APPROVAL_STATUSES = {"PENDING", "APPROVED", "REJECTED", "CANCELLED"}

def create_risk_approval_request(
    db_path: str | Path,
    finding_id: str,
    *,
    requested_by: str,
    reason: str,
    exception_expiry: str,
    notes: str = "",
    expected_version: int | None = None,
) -> dict[str, Any]:
    request_id = f"APR-{uuid.uuid4().hex[:16].upper()}"
    now = utc_now()
    with connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM findings WHERE finding_id=?", (finding_id,)).fetchone()
        if row is None:
            raise KeyError(finding_id)
        finding = dict(row)
        if str(finding.get("record_state") or "ACTIVE").upper() == "ARCHIVED":
            raise ValueError("ARCHIVED 항목은 위험수용을 요청할 수 없습니다.")
        version = int(finding.get("row_version") or 1)
        if expected_version is not None and version != int(expected_version):
            raise ConcurrencyError("항목이 먼저 변경되었습니다. 새로고침 후 위험수용을 다시 요청하세요.")
        pending = conn.execute(
            "SELECT request_id FROM risk_approval_requests WHERE finding_id=? AND status='PENDING'",
            (finding_id,),
        ).fetchone()
        if pending:
            raise ValueError("이미 대기 중인 위험수용 요청이 있습니다.")
        conn.execute(
            """
            INSERT INTO risk_approval_requests(
                request_id,finding_id,requested_by,reason,exception_expiry,notes,status,
                finding_row_version,requested_at
            ) VALUES(?,?,?,?,?,?, 'PENDING', ?, ?)
            """,
            (request_id, finding_id, requested_by, reason, exception_expiry, notes, version, now),
        )
        add_audit_event(
            db_path, finding_id=finding_id, event_type="risk_acceptance_requested",
            summary="위험수용 승인 요청 생성",
            details={"request_id": request_id, "exception_expiry": exception_expiry, "reason": reason},
            actor=requested_by, conn=conn,
        )
        conn.commit()
    return get_risk_approval_request(db_path, request_id) or {}


def get_risk_approval_request(db_path: str | Path, request_id: str) -> dict[str, Any] | None:
    with connect(db_path) as conn:
        row = conn.execute(
            """
            SELECT r.*, f.product, f.cve_id, f.asset_name, f.status AS finding_status,
                   f.row_version AS current_row_version, f.record_state
              FROM risk_approval_requests r
              JOIN findings f ON f.finding_id=r.finding_id
             WHERE r.request_id=?
            """,
            (request_id,),
        ).fetchone()
        return dict(row) if row else None


def list_risk_approval_requests(
    db_path: str | Path, *, status: str = "", limit: int = 200
) -> list[dict[str, Any]]:
    limit = max(1, min(int(limit), 1000))
    with connect(db_path) as conn:
        if status:
            rows = conn.execute(
                """
                SELECT r.*, f.product, f.cve_id, f.asset_name, f.status AS finding_status,
                       f.row_version AS current_row_version, f.record_state
                  FROM risk_approval_requests r JOIN findings f ON f.finding_id=r.finding_id
                 WHERE r.status=? ORDER BY r.requested_at DESC LIMIT ?
                """,
                (status.upper(), limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT r.*, f.product, f.cve_id, f.asset_name, f.status AS finding_status,
                       f.row_version AS current_row_version, f.record_state
                  FROM risk_approval_requests r JOIN findings f ON f.finding_id=r.finding_id
                 ORDER BY CASE r.status WHEN 'PENDING' THEN 0 ELSE 1 END, r.requested_at DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]


def decide_risk_approval_request(
    db_path: str | Path, request_id: str, *, decision: str, decided_by: str, decision_note: str = ""
) -> dict[str, Any]:
    action = str(decision or "").strip().upper()
    if action not in {"APPROVED", "REJECTED"}:
        raise ValueError("승인 또는 반려만 가능합니다.")
    now = utc_now()
    with connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT * FROM risk_approval_requests WHERE request_id=?", (request_id,)
        ).fetchone()
        if row is None:
            raise KeyError(request_id)
        request_row = dict(row)
        if request_row.get("status") != "PENDING":
            raise ValueError("이미 처리된 승인 요청입니다.")
        if date.fromisoformat(str(request_row.get("exception_expiry"))) < date.today():
            raise ValueError("만료일이 지난 위험수용 요청은 승인할 수 없습니다.")
        finding_row = conn.execute("SELECT * FROM findings WHERE finding_id=?", (request_row["finding_id"],)).fetchone()
        if finding_row is None:
            raise KeyError(request_row["finding_id"])
        finding = dict(finding_row)
        if str(finding.get("record_state") or "ACTIVE").upper() == "ARCHIVED":
            raise ValueError("ARCHIVED 항목은 승인할 수 없습니다.")
        if action == "APPROVED":
            if int(finding.get("row_version") or 1) != int(request_row.get("finding_row_version") or 1):
                raise ConcurrencyError("요청 이후 취약점이 변경되었습니다. 기존 요청을 반려하고 다시 요청하세요.")
            existing_notes = str(finding.get("notes") or "").strip()
            request_notes = str(request_row.get("notes") or "").strip()
            merged_notes = existing_notes
            if request_notes:
                merged_notes = (existing_notes + "\n[위험수용 요청] " + request_notes).strip()
            conn.execute(
                """
                UPDATE findings SET status='RISK_ACCEPTED', exception_expiry=?,
                    risk_acceptance_reason=?, risk_acceptance_approver=?, notes=?, resolved_at=?,
                    row_version=COALESCE(row_version,0)+1, updated_at=CURRENT_TIMESTAMP
                WHERE finding_id=?
                """,
                (request_row["exception_expiry"], request_row["reason"], decided_by,
                 merged_notes, now, request_row["finding_id"]),
            )
        conn.execute(
            """
            UPDATE risk_approval_requests SET status=?, decided_by=?, decision_note=?, decided_at=?
             WHERE request_id=?
            """,
            (action, decided_by, decision_note, now, request_id),
        )
        add_audit_event(
            db_path, finding_id=request_row["finding_id"],
            event_type="risk_acceptance_approved" if action == "APPROVED" else "risk_acceptance_rejected",
            summary="위험수용 요청 승인" if action == "APPROVED" else "위험수용 요청 반려",
            details={"request_id": request_id, "decision_note": decision_note},
            actor=decided_by, conn=conn,
        )
        conn.commit()
    return get_risk_approval_request(db_path, request_id) or {}
