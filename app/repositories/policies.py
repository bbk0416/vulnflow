from __future__ import annotations

import json
import sqlite3
import uuid
from pathlib import Path
from typing import Any, Iterable

from app.core.db import ConcurrencyError, connect, utc_now
from app.core.fields import SCORE_FIELDS
from app.repositories.audit import add_audit_event

POLICY_STATUSES = {"DRAFT", "ACTIVE", "RETIRED"}


POLICY_REQUEST_STATUSES = {"PENDING", "APPROVED", "REJECTED", "CANCELLED"}


def create_policy_version(
    db_path: str | Path, *, version: str, name: str, content_yaml: str,
    content_sha256: str, created_by: str, notes: str = "",
    status: str = "DRAFT", supersedes_policy_id: str | None = None,
) -> dict[str, Any]:
    status = str(status).upper()
    if status not in POLICY_STATUSES:
        raise ValueError("정책 상태가 올바르지 않습니다.")
    policy_id = f"POL-{uuid.uuid4().hex[:16].upper()}"
    now = utc_now()
    with connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        if status == "ACTIVE":
            active = conn.execute("SELECT policy_id FROM policy_versions WHERE status='ACTIVE'").fetchone()
            if active:
                raise ValueError("이미 활성 정책이 있습니다.")
        try:
            conn.execute(
                """
                INSERT INTO policy_versions(
                    policy_id,version,name,content_yaml,content_sha256,status,notes,
                    created_by,created_at,activated_by,activated_at,supersedes_policy_id
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    policy_id, version, name, content_yaml, content_sha256, status, notes,
                    created_by, now, created_by if status == "ACTIVE" else None,
                    now if status == "ACTIVE" else None, supersedes_policy_id,
                ),
            )
        except sqlite3.IntegrityError as exc:
            message = str(exc).lower()
            if "version" in message:
                raise ValueError(f"이미 등록된 정책 version입니다: {version}") from exc
            if "content_sha256" in message:
                raise ValueError("동일한 내용의 정책이 이미 등록되어 있습니다.") from exc
            raise
        add_audit_event(
            db_path, finding_id=None, event_type="policy_created",
            summary=f"정책 등록: {version} ({status})",
            details={"policy_id": policy_id, "version": version, "status": status, "sha256": content_sha256},
            actor=created_by, conn=conn,
        )
        conn.commit()
    return get_policy_version(db_path, policy_id) or {}


def get_policy_version(db_path: str | Path, policy_id: str) -> dict[str, Any] | None:
    with connect(db_path) as conn:
        row = conn.execute("SELECT * FROM policy_versions WHERE policy_id=?", (policy_id,)).fetchone()
        return dict(row) if row else None


def get_active_policy_version(db_path: str | Path) -> dict[str, Any] | None:
    with connect(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM policy_versions WHERE status='ACTIVE' ORDER BY activated_at DESC LIMIT 1"
        ).fetchone()
        return dict(row) if row else None


def list_policy_versions(db_path: str | Path, *, limit: int = 200) -> list[dict[str, Any]]:
    limit = max(1, min(int(limit), 1000))
    with connect(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM policy_versions ORDER BY CASE status WHEN 'ACTIVE' THEN 0 WHEN 'DRAFT' THEN 1 ELSE 2 END, created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]


def create_policy_activation_request(
    db_path: str | Path, *, policy_id: str, requested_by: str, reason: str,
    impact: dict[str, Any],
) -> dict[str, Any]:
    request_id = f"PAC-{uuid.uuid4().hex[:16].upper()}"
    now = utc_now()
    with connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        target = conn.execute("SELECT * FROM policy_versions WHERE policy_id=?", (policy_id,)).fetchone()
        if target is None:
            raise KeyError(policy_id)
        if str(target["status"]) == "ACTIVE":
            raise ValueError("이미 활성 상태인 정책입니다.")
        pending = conn.execute(
            "SELECT request_id FROM policy_activation_requests WHERE policy_id=? AND status='PENDING'",
            (policy_id,),
        ).fetchone()
        if pending:
            raise ValueError("이미 대기 중인 정책 활성화 요청이 있습니다.")
        active = conn.execute("SELECT policy_id FROM policy_versions WHERE status='ACTIVE' LIMIT 1").fetchone()
        active_id = str(active["policy_id"]) if active else None
        conn.execute(
            """
            INSERT INTO policy_activation_requests(
                request_id,policy_id,requested_by,reason,status,active_policy_id_at_request,
                impact_json,requested_at
            ) VALUES(?,?,?,?, 'PENDING', ?, ?, ?)
            """,
            (request_id, policy_id, requested_by, reason, active_id, json.dumps(impact, ensure_ascii=False), now),
        )
        add_audit_event(
            db_path, finding_id=None, event_type="policy_activation_requested",
            summary=f"정책 활성화 요청: {target['version']}",
            details={"request_id": request_id, "policy_id": policy_id, "active_policy_id": active_id, "impact": impact},
            actor=requested_by, conn=conn,
        )
        conn.commit()
    return get_policy_activation_request(db_path, request_id) or {}


def get_policy_activation_request(db_path: str | Path, request_id: str) -> dict[str, Any] | None:
    with connect(db_path) as conn:
        row = conn.execute(
            """
            SELECT r.*, p.version, p.name, p.status AS policy_status
              FROM policy_activation_requests r
              JOIN policy_versions p ON p.policy_id=r.policy_id
             WHERE r.request_id=?
            """,
            (request_id,),
        ).fetchone()
    if not row:
        return None
    item = dict(row)
    try:
        item["impact"] = json.loads(item.pop("impact_json") or "{}")
    except json.JSONDecodeError:
        item["impact"] = {}
    return item


def list_policy_activation_requests(
    db_path: str | Path, *, status: str = "", limit: int = 200,
) -> list[dict[str, Any]]:
    limit = max(1, min(int(limit), 1000))
    with connect(db_path) as conn:
        if status:
            rows = conn.execute(
                """
                SELECT r.*, p.version, p.name, p.status AS policy_status
                  FROM policy_activation_requests r JOIN policy_versions p ON p.policy_id=r.policy_id
                 WHERE r.status=? ORDER BY r.requested_at DESC LIMIT ?
                """,
                (str(status).upper(), limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT r.*, p.version, p.name, p.status AS policy_status
                  FROM policy_activation_requests r JOIN policy_versions p ON p.policy_id=r.policy_id
                 ORDER BY r.requested_at DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
    output: list[dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        try:
            item["impact"] = json.loads(item.pop("impact_json") or "{}")
        except json.JSONDecodeError:
            item["impact"] = {}
        output.append(item)
    return output


def reject_policy_activation_request(
    db_path: str | Path, request_id: str, *, decided_by: str, decision_note: str,
) -> dict[str, Any]:
    now = utc_now()
    with connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM policy_activation_requests WHERE request_id=?", (request_id,)).fetchone()
        if row is None:
            raise KeyError(request_id)
        if str(row["status"]) != "PENDING":
            raise ValueError("대기 중인 요청만 반려할 수 있습니다.")
        conn.execute(
            "UPDATE policy_activation_requests SET status='REJECTED',decided_by=?,decision_note=?,decided_at=? WHERE request_id=?",
            (decided_by, decision_note, now, request_id),
        )
        add_audit_event(
            db_path, finding_id=None, event_type="policy_activation_rejected",
            summary="정책 활성화 요청 반려", details={"request_id": request_id, "decision_note": decision_note},
            actor=decided_by, conn=conn,
        )
        conn.commit()
    return get_policy_activation_request(db_path, request_id) or {}


def approve_policy_activation_request(
    db_path: str | Path, request_id: str, *, scored_rows: Iterable[dict[str, Any]],
    decided_by: str, decision_note: str,
) -> dict[str, Any]:
    now = utc_now()
    rows = [dict(row) for row in scored_rows]
    with connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        request_row = conn.execute(
            "SELECT * FROM policy_activation_requests WHERE request_id=?", (request_id,)
        ).fetchone()
        if request_row is None:
            raise KeyError(request_id)
        if str(request_row["status"]) != "PENDING":
            raise ValueError("대기 중인 요청만 승인할 수 있습니다.")
        target = conn.execute(
            "SELECT * FROM policy_versions WHERE policy_id=?", (request_row["policy_id"],)
        ).fetchone()
        if target is None:
            raise KeyError(str(request_row["policy_id"]))
        if str(target["status"]) == "ACTIVE":
            raise ValueError("대상 정책은 이미 활성 상태입니다.")
        active = conn.execute("SELECT policy_id FROM policy_versions WHERE status='ACTIVE' LIMIT 1").fetchone()
        current_active_id = str(active["policy_id"]) if active else None
        requested_active_id = request_row["active_policy_id_at_request"]
        if (current_active_id or None) != (requested_active_id or None):
            raise ConcurrencyError("요청 이후 활성 정책이 변경되었습니다. 영향분석 후 다시 요청하세요.")
        for row in rows:
            finding_id = str(row.get("finding_id") or "")
            current_finding = conn.execute(
                "SELECT row_version FROM findings WHERE finding_id=?", (finding_id,)
            ).fetchone()
            if current_finding is None:
                continue
            expected_version = int(row.get("row_version") or 0)
            if expected_version and int(current_finding["row_version"] or 0) != expected_version:
                raise ConcurrencyError(
                    f"정책 영향분석 이후 취약점이 변경되었습니다: {finding_id}. 다시 영향분석 후 요청하세요."
                )
        conn.execute(
            "UPDATE policy_versions SET status='RETIRED',retired_at=? WHERE status='ACTIVE'", (now,)
        )
        conn.execute(
            """
            UPDATE policy_versions SET status='ACTIVE',activated_by=?,activated_at=?,retired_at=NULL
             WHERE policy_id=?
            """,
            (decided_by, now, target["policy_id"]),
        )
        for row in rows:
            finding_id = str(row.get("finding_id") or "")
            current = conn.execute("SELECT finding_id FROM findings WHERE finding_id=?", (finding_id,)).fetchone()
            if current is None:
                continue
            assignments = ", ".join(f"{field}=?" for field in SCORE_FIELDS)
            conn.execute(
                f"UPDATE findings SET {assignments}, row_version=COALESCE(row_version,0)+1, updated_at=CURRENT_TIMESTAMP WHERE finding_id=?",
                [row.get(field) for field in SCORE_FIELDS] + [finding_id],
            )
        conn.execute(
            """
            UPDATE policy_activation_requests SET status='APPROVED',decided_by=?,decision_note=?,decided_at=?
             WHERE request_id=?
            """,
            (decided_by, decision_note, now, request_id),
        )
        conn.execute(
            """
            UPDATE policy_activation_requests SET status='CANCELLED',decided_by='system',
                decision_note='다른 정책이 활성화되어 자동 취소됨',decided_at=?
             WHERE status='PENDING' AND request_id<>?
            """,
            (now, request_id),
        )
        add_audit_event(
            db_path, finding_id=None, event_type="policy_activated",
            summary=f"정책 활성화: {target['version']}",
            details={"request_id": request_id, "policy_id": target["policy_id"], "version": target["version"], "rescored": len(rows)},
            actor=decided_by, conn=conn,
        )
        conn.commit()
    return get_policy_activation_request(db_path, request_id) or {}
