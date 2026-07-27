from __future__ import annotations

from pathlib import Path
from typing import Any

from app.core.db import connect

def list_assets(db_path: str | Path, *, status: str = "", owner: str = "", query: str = "", limit: int = 500) -> list[dict[str, Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    if status:
        clauses.append("a.status=?")
        params.append(str(status).upper())
    if owner:
        clauses.append("a.owner=?")
        params.append(str(owner))
    if query:
        clauses.append("LOWER(COALESCE(a.asset_name,'')||' '||COALESCE(a.external_asset_id,'')||' '||COALESCE(a.service_name,'')||' '||COALESCE(a.business_unit,'')||' '||COALESCE(a.owner,'')) LIKE ?")
        params.append("%" + str(query).casefold() + "%")
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    params.append(max(1, min(int(limit), 5000)))
    with connect(db_path) as conn:
        rows = conn.execute(
            f"""
            SELECT a.*,
                   COUNT(f.finding_id) AS finding_count,
                   COUNT(DISTINCT CASE WHEN f.record_state!='ARCHIVED' THEN f.cve_id END) AS cve_count,
                   SUM(CASE WHEN f.record_state!='ARCHIVED' AND f.status IN ('OPEN','IN_PROGRESS') THEN 1 ELSE 0 END) AS active_finding_count,
                   SUM(CASE WHEN f.record_state!='ARCHIVED' AND f.kev=1 THEN 1 ELSE 0 END) AS kev_count,
                   MAX(CASE WHEN f.record_state!='ARCHIVED' THEN f.score ELSE 0 END) AS max_score
              FROM assets a
              LEFT JOIN findings f ON f.asset_ref_id=a.asset_ref_id
              {where}
             GROUP BY a.asset_ref_id
             ORDER BY active_finding_count DESC, max_score DESC, a.asset_name
             LIMIT ?
            """, params,
        ).fetchall()
    return [dict(row) for row in rows]


def get_asset(db_path: str | Path, asset_ref_id: str) -> dict[str, Any] | None:
    with connect(db_path) as conn:
        row = conn.execute("SELECT * FROM assets WHERE asset_ref_id=?", (asset_ref_id,)).fetchone()
        if row is None:
            return None
        item = dict(row)
        findings = conn.execute(
            "SELECT * FROM findings WHERE asset_ref_id=? ORDER BY score DESC,kev DESC,epss DESC",
            (asset_ref_id,),
        ).fetchall()
        item["findings"] = [dict(f) for f in findings]
        item["identifiers"] = [dict(r) for r in conn.execute(
            "SELECT * FROM asset_identifiers WHERE asset_ref_id=? ORDER BY status,confidence DESC,identifier_type",
            (asset_ref_id,),
        ).fetchall()]
        item["merge_history"] = [dict(r) for r in conn.execute(
            """SELECT * FROM asset_merge_history
                 WHERE source_asset_ref_id=? OR target_asset_ref_id=? ORDER BY created_at DESC""",
            (asset_ref_id, asset_ref_id),
        ).fetchall()]
        if item.get("merged_into_asset_ref_id"):
            merged = conn.execute("SELECT asset_ref_id,asset_name,status FROM assets WHERE asset_ref_id=?",
                                  (item["merged_into_asset_ref_id"],)).fetchone()
            item["merged_into_asset"] = dict(merged) if merged else None
        return item


def list_exposure_groups(db_path: str | Path, *, limit: int = 500) -> list[dict[str, Any]]:
    with connect(db_path) as conn:
        rows = conn.execute(
            """
            SELECT cve_id,component,component_version,
                   COUNT(*) AS finding_count,COUNT(DISTINCT asset_ref_id) AS asset_count,
                   SUM(CASE WHEN status IN ('OPEN','IN_PROGRESS') AND record_state!='ARCHIVED' THEN 1 ELSE 0 END) AS active_count,
                   SUM(CASE WHEN kev=1 AND record_state!='ARCHIVED' THEN 1 ELSE 0 END) AS kev_count,
                   SUM(CASE WHEN internet_exposed=1 AND record_state!='ARCHIVED' THEN 1 ELSE 0 END) AS exposed_count,
                   MAX(score) AS max_score,MAX(epss) AS max_epss,MIN(COALESCE(NULLIF(due_date,''),target_date)) AS earliest_due,
                   COUNT(DISTINCT NULLIF(owner,'')) AS owner_count
              FROM findings
             WHERE record_state!='ARCHIVED'
             GROUP BY cve_id,component,component_version
             ORDER BY active_count DESC,kev_count DESC,max_score DESC,cve_id
             LIMIT ?
            """, (max(1, min(int(limit), 5000)),),
        ).fetchall()
    return [dict(row) for row in rows]
