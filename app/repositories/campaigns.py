from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any, Iterable

from app.core.db import ConcurrencyError, connect, utc_now
from app.repositories.audit import add_audit_event
from app.repositories.finding_workflow import _bulk_update_workflow_conn

CAMPAIGN_STATUSES = {"PLANNED", "ACTIVE", "COMPLETED", "CANCELLED"}

def create_campaign(
    db_path: str | Path, *, title: str, finding_ids: Iterable[str], description: str = "",
    owner: str = "", due_date: str = "", actor: str = "local-user", status: str = "PLANNED",
    apply_workflow: bool = False,
) -> dict[str, Any]:
    ids = list(dict.fromkeys(str(fid).strip() for fid in finding_ids if str(fid).strip()))
    if not ids:
        raise ValueError("캠페인에 포함할 취약점이 없습니다.")
    normalized_status = "ACTIVE" if apply_workflow else str(status or "PLANNED").upper()
    if normalized_status not in CAMPAIGN_STATUSES:
        raise ValueError("허용되지 않은 캠페인 상태입니다.")
    campaign_id = "CMP-" + uuid.uuid4().hex[:16].upper()
    now = utc_now()
    with connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        placeholders = ",".join("?" for _ in ids)
        found = {r[0] for r in conn.execute(f"SELECT finding_id FROM findings WHERE finding_id IN ({placeholders})", ids).fetchall()}
        missing = [fid for fid in ids if fid not in found]
        if missing:
            raise ValueError("존재하지 않는 finding_id: " + ", ".join(missing))
        conn.execute(
            """INSERT INTO remediation_campaigns(
                campaign_id,title,description,owner,due_date,status,created_by,created_at,updated_at,row_version
            ) VALUES(?,?,?,?,?,?,?,?,?,1)""",
            (campaign_id, title.strip(), description.strip(), owner.strip(), due_date.strip(), normalized_status, actor, now, now),
        )
        conn.executemany(
            "INSERT INTO campaign_findings(campaign_id,finding_id,added_by,added_at) VALUES(?,?,?,?)",
            [(campaign_id, fid, actor, now) for fid in ids],
        )
        if apply_workflow:
            _bulk_update_workflow_conn(
                db_path, conn, ids, status="IN_PROGRESS",
                owner_mode="set" if owner.strip() else "keep", owner=owner.strip(),
                due_date_mode="set" if due_date.strip() else "keep", due_date=due_date.strip(),
                notes_append=f"캠페인 {campaign_id} 시작", actor=actor,
            )
        add_audit_event(
            db_path, finding_id=None, event_type="campaign_created",
            summary=f"조치 캠페인 생성: {title.strip()} ({len(ids)}건)",
            details={"campaign_id": campaign_id, "finding_ids": ids, "owner": owner, "due_date": due_date},
            actor=actor, conn=conn,
        )
        conn.commit()
    return get_campaign(db_path, campaign_id) or {"campaign_id": campaign_id}

def list_campaigns(db_path: str | Path, *, status: str = "", limit: int = 500) -> list[dict[str, Any]]:
    params: list[Any] = []
    where = ""
    if status:
        where = "WHERE c.status=?"
        params.append(str(status).upper())
    params.append(max(1, min(int(limit), 5000)))
    with connect(db_path) as conn:
        rows = conn.execute(
            f"""
            SELECT c.*,COUNT(cf.finding_id) AS finding_count,
                   SUM(CASE WHEN f.status IN ('OPEN','IN_PROGRESS') AND f.record_state!='ARCHIVED' THEN 1 ELSE 0 END) AS active_count,
                   SUM(CASE WHEN f.status IN ('MITIGATED','RISK_ACCEPTED','CLOSED') OR f.record_state='ARCHIVED' THEN 1 ELSE 0 END) AS completed_count,
                   MAX(f.score) AS max_score
              FROM remediation_campaigns c
              LEFT JOIN campaign_findings cf ON cf.campaign_id=c.campaign_id
              LEFT JOIN findings f ON f.finding_id=cf.finding_id
              {where}
             GROUP BY c.campaign_id
             ORDER BY CASE c.status WHEN 'ACTIVE' THEN 0 WHEN 'PLANNED' THEN 1 ELSE 2 END,c.due_date,c.created_at DESC
             LIMIT ?
            """, params,
        ).fetchall()
    return [dict(row) for row in rows]

def get_campaign(db_path: str | Path, campaign_id: str) -> dict[str, Any] | None:
    with connect(db_path) as conn:
        row = conn.execute("SELECT * FROM remediation_campaigns WHERE campaign_id=?", (campaign_id,)).fetchone()
        if row is None:
            return None
        item = dict(row)
        members = conn.execute(
            """SELECT f.* FROM campaign_findings cf JOIN findings f ON f.finding_id=cf.finding_id
                 WHERE cf.campaign_id=? ORDER BY f.score DESC,f.kev DESC,f.cve_id""", (campaign_id,),
        ).fetchall()
        item["findings"] = [dict(r) for r in members]
        item["finding_count"] = len(members)
        item["active_count"] = sum(str(r["status"]).upper() in {"OPEN","IN_PROGRESS"} and str(r["record_state"]).upper() != "ARCHIVED" for r in members)
        return item

def update_campaign_status(db_path: str | Path, campaign_id: str, *, status: str, actor: str = "local-user", expected_version: int | None = None) -> dict[str, Any]:
    normalized = str(status or "").upper()
    if normalized not in CAMPAIGN_STATUSES:
        raise ValueError("허용되지 않은 캠페인 상태입니다.")
    now = utc_now()
    with connect(db_path) as conn:
        before = conn.execute("SELECT * FROM remediation_campaigns WHERE campaign_id=?", (campaign_id,)).fetchone()
        if before is None:
            raise KeyError(campaign_id)
        if normalized == "COMPLETED":
            active_members = int(conn.execute(
                """SELECT COUNT(*) FROM campaign_findings cf JOIN findings f ON f.finding_id=cf.finding_id
                     WHERE cf.campaign_id=? AND f.record_state!='ARCHIVED' AND f.status IN ('OPEN','IN_PROGRESS')""",
                (campaign_id,),
            ).fetchone()[0])
            if active_members:
                raise ValueError(f"활성 취약점 {active_members}건이 남아 있어 캠페인을 완료할 수 없습니다.")
        params: list[Any] = [normalized, now if normalized == "COMPLETED" else "", now, campaign_id]
        clause = ""
        if expected_version is not None:
            clause = " AND row_version=?"
            params.append(int(expected_version))
        cur = conn.execute(
            f"UPDATE remediation_campaigns SET status=?,completed_at=?,updated_at=?,row_version=row_version+1 WHERE campaign_id=?{clause}",
            params,
        )
        if cur.rowcount != 1:
            raise ConcurrencyError("캠페인이 다른 요청에서 변경되었습니다.")
        add_audit_event(
            db_path, finding_id=None, event_type="campaign_status_changed",
            summary=f"조치 캠페인 상태 변경: {before['status']} → {normalized}",
            details={"campaign_id": campaign_id, "old": before["status"], "new": normalized}, actor=actor, conn=conn,
        )
        conn.commit()
    return get_campaign(db_path, campaign_id) or {}

def add_campaign_findings(db_path: str | Path, campaign_id: str, finding_ids: Iterable[str], *, actor: str = "local-user") -> int:
    ids = list(dict.fromkeys(str(fid).strip() for fid in finding_ids if str(fid).strip()))
    if not ids:
        raise ValueError("추가할 취약점이 없습니다.")
    now = utc_now()
    with connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        campaign = conn.execute("SELECT status FROM remediation_campaigns WHERE campaign_id=?", (campaign_id,)).fetchone()
        if campaign is None:
            raise KeyError(campaign_id)
        if str(campaign["status"]) in {"COMPLETED", "CANCELLED"}:
            raise ValueError("완료·취소된 캠페인에는 취약점을 추가할 수 없습니다.")
        placeholders = ",".join("?" for _ in ids)
        found = {r[0] for r in conn.execute(f"SELECT finding_id FROM findings WHERE finding_id IN ({placeholders})", ids).fetchall()}
        missing = [fid for fid in ids if fid not in found]
        if missing:
            raise ValueError("존재하지 않는 finding_id: " + ", ".join(missing))
        before = int(conn.execute("SELECT COUNT(*) FROM campaign_findings WHERE campaign_id=?", (campaign_id,)).fetchone()[0])
        conn.executemany(
            "INSERT OR IGNORE INTO campaign_findings(campaign_id,finding_id,added_by,added_at) VALUES(?,?,?,?)",
            [(campaign_id, fid, actor, now) for fid in ids],
        )
        after = int(conn.execute("SELECT COUNT(*) FROM campaign_findings WHERE campaign_id=?", (campaign_id,)).fetchone()[0])
        added = after - before
        if added:
            conn.execute("UPDATE remediation_campaigns SET updated_at=?,row_version=row_version+1 WHERE campaign_id=?", (now, campaign_id))
            add_audit_event(
                db_path, finding_id=None, event_type="campaign_members_added",
                summary=f"조치 캠페인에 취약점 {added}건 추가",
                details={"campaign_id": campaign_id, "finding_ids": ids, "added": added}, actor=actor, conn=conn,
            )
        conn.commit()
    return added

def remove_campaign_finding(db_path: str | Path, campaign_id: str, finding_id: str, *, actor: str = "local-user") -> bool:
    now = utc_now()
    with connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        campaign = conn.execute("SELECT status FROM remediation_campaigns WHERE campaign_id=?", (campaign_id,)).fetchone()
        if campaign is None:
            raise KeyError(campaign_id)
        if str(campaign["status"]) in {"COMPLETED", "CANCELLED"}:
            raise ValueError("완료·취소된 캠페인의 구성은 변경할 수 없습니다.")
        cur = conn.execute("DELETE FROM campaign_findings WHERE campaign_id=? AND finding_id=?", (campaign_id, finding_id))
        removed = cur.rowcount == 1
        if removed:
            conn.execute("UPDATE remediation_campaigns SET updated_at=?,row_version=row_version+1 WHERE campaign_id=?", (now, campaign_id))
            add_audit_event(
                db_path, finding_id=finding_id, event_type="campaign_member_removed",
                summary="조치 캠페인에서 취약점 제거", details={"campaign_id": campaign_id}, actor=actor, conn=conn,
            )
        conn.commit()
    return removed
