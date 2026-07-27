from __future__ import annotations

"""Asset identifier and identity-candidate write repository."""

import json
from pathlib import Path
from typing import Any

from app.core.db import connect, utc_now
from app.repositories.audit import add_audit_event
from app.repositories.reconciliation import (
    _create_asset_identity_candidate_conn,
    _register_asset_identifiers_conn,
)
from app.services.asset_identity import (
    ASSET_IDENTITY_CANDIDATE_STATUSES,
    IDENTIFIER_CONFIDENCE,
    identifier_scope as _identifier_scope,
    normalize_asset_identifier,
)

def list_asset_identifiers(db_path: str | Path, asset_ref_id: str, *, include_retired: bool = False) -> list[dict[str, Any]]:
    sql = "SELECT * FROM asset_identifiers WHERE asset_ref_id=?"
    params: list[Any] = [asset_ref_id]
    if not include_retired:
        sql += " AND status='ACTIVE'"
    sql += " ORDER BY status,confidence DESC,identifier_type,display_value"
    with connect(db_path) as conn:
        return [dict(row) for row in conn.execute(sql, params).fetchall()]


def get_asset_identity_candidate(db_path: str | Path, candidate_id: str) -> dict[str, Any] | None:
    with connect(db_path) as conn:
        row = conn.execute(
            """SELECT c.*,a.asset_name AS asset_name_a,a.status AS asset_status_a,
                       b.asset_name AS asset_name_b,b.status AS asset_status_b
                  FROM asset_identity_candidates c
                  JOIN assets a ON a.asset_ref_id=c.asset_ref_id_a
                  JOIN assets b ON b.asset_ref_id=c.asset_ref_id_b
                 WHERE c.candidate_id=?""", (candidate_id,),
        ).fetchone()
    if row is None:
        return None
    item = dict(row)
    try:
        item["reasons"] = json.loads(item.get("reasons_json") or "[]")
    except json.JSONDecodeError:
        item["reasons"] = []
    return item


def list_asset_identity_candidates(db_path: str | Path, *, status: str = "PENDING", limit: int = 500) -> list[dict[str, Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    normalized_status = str(status or "").strip().upper()
    if normalized_status:
        if normalized_status not in ASSET_IDENTITY_CANDIDATE_STATUSES:
            raise ValueError(f"허용되지 않은 후보 상태: {normalized_status}")
        clauses.append("c.status=?")
        params.append(normalized_status)
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    params.append(max(1, min(int(limit), 5000)))
    with connect(db_path) as conn:
        rows = conn.execute(
            f"""SELECT c.*,a.asset_name AS asset_name_a,a.status AS asset_status_a,
                       b.asset_name AS asset_name_b,b.status AS asset_status_b
                  FROM asset_identity_candidates c
                  JOIN assets a ON a.asset_ref_id=c.asset_ref_id_a
                  JOIN assets b ON b.asset_ref_id=c.asset_ref_id_b
                  {where}
                 ORDER BY CASE c.status WHEN 'PENDING' THEN 0 ELSE 1 END,c.score DESC,c.created_at DESC
                 LIMIT ?""", params,
        ).fetchall()
    items: list[dict[str, Any]] = []
    for raw in rows:
        item = dict(raw)
        try:
            item["reasons"] = json.loads(item.get("reasons_json") or "[]")
        except json.JSONDecodeError:
            item["reasons"] = []
        items.append(item)
    return items


def add_asset_identifier(db_path: str | Path, asset_ref_id: str, *, identifier_type: str,
                         value: str, scope: str = "", source: str = "manual",
                         confidence: int | None = None, actor: str = "local-user") -> dict[str, Any]:
    kind = str(identifier_type or "").strip().upper()
    normalized = normalize_asset_identifier(kind, value)
    normalized_scope = str(scope or "").strip().casefold() or _identifier_scope(kind)
    if len(normalized_scope) > 200:
        raise ValueError("자산 식별자 scope는 200자 이하여야 합니다.")
    now = utc_now()
    item = {
        "identifier_type": kind, "scope": normalized_scope, "normalized_value": normalized,
        "display_value": str(value).strip(), "source": str(source or "manual").strip()[:200],
        "confidence": max(1, min(100, int(confidence or IDENTIFIER_CONFIDENCE.get(kind, 50)))),
    }
    with connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        asset = conn.execute("SELECT * FROM assets WHERE asset_ref_id=?", (asset_ref_id,)).fetchone()
        if asset is None:
            raise KeyError(asset_ref_id)
        existing = conn.execute(
            """SELECT * FROM asset_identifiers
                 WHERE identifier_type=? AND scope=? AND normalized_value=? AND status='ACTIVE'""",
            (kind, normalized_scope, normalized),
        ).fetchone()
        if existing is not None and str(existing["asset_ref_id"]) != asset_ref_id:
            candidate = _create_asset_identity_candidate_conn(
                conn, asset_ref_id_a=str(existing["asset_ref_id"]), asset_ref_id_b=asset_ref_id,
                identifier=item, actor=actor, now=now,
            )
            add_audit_event(
                db_path, finding_id=None, event_type="asset_identity_candidate_created",
                summary="자산 식별자 충돌로 병합 후보 생성",
                details={"candidate_id": candidate["candidate_id"] if candidate else "", "asset_ref_id": asset_ref_id,
                         "conflicting_asset_ref_id": existing["asset_ref_id"], "identifier_type": kind,
                         "scope": normalized_scope, "normalized_value": normalized}, actor=actor, conn=conn,
            )
            conn.commit()
            return {"status": "CANDIDATE", "candidate": candidate}
        _register_asset_identifiers_conn(conn, asset_ref_id=asset_ref_id, identifiers=[item], actor=actor, now=now)
        row = conn.execute(
            """SELECT * FROM asset_identifiers
                 WHERE asset_ref_id=? AND identifier_type=? AND scope=? AND normalized_value=? AND status='ACTIVE'""",
            (asset_ref_id, kind, normalized_scope, normalized),
        ).fetchone()
        add_audit_event(
            db_path, finding_id=None, event_type="asset_identifier_added",
            summary=f"자산 식별자 추가: {kind}",
            details={"asset_ref_id": asset_ref_id, "identifier_id": row["identifier_id"], "scope": normalized_scope},
            actor=actor, conn=conn,
        )
        conn.commit()
    return {"status": "ACTIVE", "identifier": dict(row)}


def reject_asset_identity_candidate(db_path: str | Path, candidate_id: str, *, reason: str,
                                    actor: str = "local-user") -> dict[str, Any]:
    note = str(reason or "").strip()
    if len(note) < 3:
        raise ValueError("거절 사유는 3자 이상이어야 합니다.")
    now = utc_now()
    with connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM asset_identity_candidates WHERE candidate_id=?", (candidate_id,)).fetchone()
        if row is None:
            raise KeyError(candidate_id)
        if row["status"] != "PENDING":
            raise ValueError("대기 중인 자산 식별 후보만 거절할 수 있습니다.")
        conn.execute(
            """UPDATE asset_identity_candidates SET status='REJECTED',decided_by=?,decided_at=?,decision_reason=?
                 WHERE candidate_id=?""", (actor, now, note, candidate_id),
        )
        conn.execute(
            """UPDATE asset_merge_requests SET status='CANCELLED',decided_by='system',
                       decision_note='자산 식별 후보가 거절되어 자동 취소됨',decided_at=?
                 WHERE candidate_id=? AND status='PENDING'""",
            (now, candidate_id),
        )
        add_audit_event(
            db_path, finding_id=None, event_type="asset_identity_candidate_rejected",
            summary="자산 병합 후보 거절",
            details={"candidate_id": candidate_id, "asset_ref_id_a": row["asset_ref_id_a"],
                     "asset_ref_id_b": row["asset_ref_id_b"], "reason": note}, actor=actor, conn=conn,
        )
        conn.commit()
        return dict(conn.execute("SELECT * FROM asset_identity_candidates WHERE candidate_id=?", (candidate_id,)).fetchone())
