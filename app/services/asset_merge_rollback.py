from __future__ import annotations

import hashlib
import json
import sqlite3
from typing import Any, Iterable


PRIMARY_KEYS: dict[str, tuple[str, ...]] = {
    "assets": ("asset_ref_id",),
    "findings": ("finding_id",),
    "source_finding_records": ("source_record_id",),
    "finding_observations": ("observation_id",),
    "campaign_findings": ("campaign_id", "finding_id"),
    "finding_reconciliation_decisions": ("decision_id",),
    "asset_identifiers": ("identifier_id",),
    "asset_identity_candidates": ("candidate_id",),
    "risk_approval_requests": ("request_id",),
    "remediation_verification_requests": ("verification_id",),
    "verification_evidence_artifacts": ("evidence_id",),
    "evidence_custody_events": ("id",),
    "sbom_finding_links": ("link_id",),
    "vex_statements": ("vex_id",),
}

RESTORABLE_TABLES = (
    "assets",
    "findings",
    "source_finding_records",
    "finding_observations",
    "campaign_findings",
    "finding_reconciliation_decisions",
    "asset_identifiers",
    "asset_identity_candidates",
)

GUARD_ONLY_TABLES = (
    "risk_approval_requests",
    "remediation_verification_requests",
    "verification_evidence_artifacts",
    "evidence_custody_events",
    "sbom_finding_links",
    "vex_statements",
)


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _rows(conn: sqlite3.Connection, sql: str, params: Iterable[Any] = ()) -> list[dict[str, Any]]:
    return [dict(row) for row in conn.execute(sql, tuple(params)).fetchall()]


def _ordered(table: str, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    keys = PRIMARY_KEYS[table]
    return sorted(rows, key=lambda row: tuple(str(row.get(key, "")) for key in keys))


def _in_clause(values: list[str]) -> tuple[str, list[str]]:
    if not values:
        return "NULL", []
    return ",".join("?" for _ in values), values


def collect_snapshot(
    conn: sqlite3.Connection,
    *,
    source_asset_ref_id: str,
    target_asset_ref_id: str,
) -> dict[str, Any]:
    asset_ids = [str(source_asset_ref_id), str(target_asset_ref_id)]
    placeholders, params = _in_clause(asset_ids)
    assets = _rows(conn, f"SELECT * FROM assets WHERE asset_ref_id IN ({placeholders})", params)
    findings = _rows(conn, f"SELECT * FROM findings WHERE asset_ref_id IN ({placeholders})", params)
    finding_ids = sorted({str(row["finding_id"]) for row in findings})
    finding_clause, finding_params = _in_clause(finding_ids)

    tables: dict[str, list[dict[str, Any]]] = {
        "assets": _ordered("assets", assets),
        "findings": _ordered("findings", findings),
        "source_finding_records": _ordered(
            "source_finding_records",
            _rows(conn, f"SELECT * FROM source_finding_records WHERE finding_id IN ({finding_clause})", finding_params),
        ),
        "finding_observations": _ordered(
            "finding_observations",
            _rows(conn, f"SELECT * FROM finding_observations WHERE finding_id IN ({finding_clause})", finding_params),
        ),
        "campaign_findings": _ordered(
            "campaign_findings",
            _rows(conn, f"SELECT * FROM campaign_findings WHERE finding_id IN ({finding_clause})", finding_params),
        ),
        "finding_reconciliation_decisions": _ordered(
            "finding_reconciliation_decisions",
            _rows(conn, f"SELECT * FROM finding_reconciliation_decisions WHERE finding_id IN ({finding_clause})", finding_params),
        ),
        "asset_identifiers": _ordered(
            "asset_identifiers",
            _rows(conn, f"SELECT * FROM asset_identifiers WHERE asset_ref_id IN ({placeholders})", params),
        ),
        "asset_identity_candidates": _ordered(
            "asset_identity_candidates",
            _rows(
                conn,
                f"SELECT * FROM asset_identity_candidates WHERE asset_ref_id_a IN ({placeholders}) OR asset_ref_id_b IN ({placeholders})",
                params + params,
            ),
        ),
    }
    candidate_ids = [str(row["candidate_id"]) for row in tables["asset_identity_candidates"]]
    evidence = _rows(
        conn,
        f"SELECT * FROM verification_evidence_artifacts WHERE finding_id IN ({finding_clause})",
        finding_params,
    )
    evidence_ids = sorted({str(row["evidence_id"]) for row in evidence})
    evidence_clause, evidence_params = _in_clause(evidence_ids)
    guard_only: dict[str, list[dict[str, Any]]] = {
        "risk_approval_requests": _ordered(
            "risk_approval_requests",
            _rows(conn, f"SELECT * FROM risk_approval_requests WHERE finding_id IN ({finding_clause})", finding_params),
        ),
        "remediation_verification_requests": _ordered(
            "remediation_verification_requests",
            _rows(conn, f"SELECT * FROM remediation_verification_requests WHERE finding_id IN ({finding_clause})", finding_params),
        ),
        "verification_evidence_artifacts": _ordered("verification_evidence_artifacts", evidence),
        "evidence_custody_events": _ordered(
            "evidence_custody_events",
            _rows(conn, f"SELECT * FROM evidence_custody_events WHERE evidence_id IN ({evidence_clause})", evidence_params),
        ),
        "sbom_finding_links": _ordered(
            "sbom_finding_links",
            _rows(conn, f"SELECT * FROM sbom_finding_links WHERE finding_id IN ({finding_clause})", finding_params),
        ),
        "vex_statements": _ordered(
            "vex_statements",
            _rows(conn, f"SELECT * FROM vex_statements WHERE finding_id IN ({finding_clause})", finding_params),
        ),
    }
    return {
        "scope": {
            "source_asset_ref_id": str(source_asset_ref_id),
            "target_asset_ref_id": str(target_asset_ref_id),
            "finding_ids": finding_ids,
            "candidate_ids": sorted(candidate_ids),
            "evidence_ids": evidence_ids,
        },
        "tables": tables,
        "guard_only": guard_only,
    }


def collect_guard(
    conn: sqlite3.Connection,
    *,
    snapshot: dict[str, Any],
    created_candidate_ids: Iterable[str] = (),
) -> dict[str, Any]:
    scope = dict(snapshot.get("scope") or {})
    asset_ids = [str(scope["source_asset_ref_id"]), str(scope["target_asset_ref_id"])]
    finding_ids = [str(item) for item in scope.get("finding_ids") or []]
    candidate_ids = sorted({*(str(item) for item in scope.get("candidate_ids") or []), *(str(item) for item in created_candidate_ids)})
    evidence_ids = [str(item) for item in scope.get("evidence_ids") or []]
    asset_clause, asset_params = _in_clause(asset_ids)
    finding_clause, finding_params = _in_clause(finding_ids)
    candidate_clause, candidate_params = _in_clause(candidate_ids)
    evidence_clause, evidence_params = _in_clause(evidence_ids)

    tables: dict[str, list[dict[str, Any]]] = {
        "assets": _ordered("assets", _rows(conn, f"SELECT * FROM assets WHERE asset_ref_id IN ({asset_clause})", asset_params)),
        "findings": _ordered("findings", _rows(conn, f"SELECT * FROM findings WHERE finding_id IN ({finding_clause})", finding_params)),
        "source_finding_records": _ordered("source_finding_records", _rows(conn, f"SELECT * FROM source_finding_records WHERE finding_id IN ({finding_clause})", finding_params)),
        "finding_observations": _ordered("finding_observations", _rows(conn, f"SELECT * FROM finding_observations WHERE finding_id IN ({finding_clause})", finding_params)),
        "campaign_findings": _ordered("campaign_findings", _rows(conn, f"SELECT * FROM campaign_findings WHERE finding_id IN ({finding_clause})", finding_params)),
        "finding_reconciliation_decisions": _ordered("finding_reconciliation_decisions", _rows(conn, f"SELECT * FROM finding_reconciliation_decisions WHERE finding_id IN ({finding_clause})", finding_params)),
        "asset_identifiers": _ordered("asset_identifiers", _rows(conn, f"SELECT * FROM asset_identifiers WHERE asset_ref_id IN ({asset_clause})", asset_params)),
        "asset_identity_candidates": _ordered("asset_identity_candidates", _rows(conn, f"SELECT * FROM asset_identity_candidates WHERE candidate_id IN ({candidate_clause})", candidate_params)),
        "risk_approval_requests": _ordered("risk_approval_requests", _rows(conn, f"SELECT * FROM risk_approval_requests WHERE finding_id IN ({finding_clause})", finding_params)),
        "remediation_verification_requests": _ordered("remediation_verification_requests", _rows(conn, f"SELECT * FROM remediation_verification_requests WHERE finding_id IN ({finding_clause})", finding_params)),
        "verification_evidence_artifacts": _ordered("verification_evidence_artifacts", _rows(conn, f"SELECT * FROM verification_evidence_artifacts WHERE finding_id IN ({finding_clause})", finding_params)),
        "evidence_custody_events": _ordered("evidence_custody_events", _rows(conn, f"SELECT * FROM evidence_custody_events WHERE evidence_id IN ({evidence_clause})", evidence_params)),
        "sbom_finding_links": _ordered("sbom_finding_links", _rows(conn, f"SELECT * FROM sbom_finding_links WHERE finding_id IN ({finding_clause})", finding_params)),
        "vex_statements": _ordered("vex_statements", _rows(conn, f"SELECT * FROM vex_statements WHERE finding_id IN ({finding_clause})", finding_params)),
    }
    return {"scope": {**scope, "candidate_ids": candidate_ids}, "tables": tables}


def _update_row(conn: sqlite3.Connection, table: str, row: dict[str, Any]) -> None:
    keys = PRIMARY_KEYS[table]
    columns = [key for key in row if key not in keys]
    set_sql = ",".join(f"{column}=?" for column in columns)
    where_sql = " AND ".join(f"{key}=?" for key in keys)
    params = [row[column] for column in columns] + [row[key] for key in keys]
    cursor = conn.execute(f"UPDATE {table} SET {set_sql} WHERE {where_sql}", params)
    if cursor.rowcount != 1:
        raise ValueError(f"롤백 대상 레코드를 찾을 수 없습니다: {table} {tuple(row[key] for key in keys)}")


def restore_snapshot(
    conn: sqlite3.Connection,
    *,
    snapshot: dict[str, Any],
    created_candidate_ids: Iterable[str],
    actor: str,
    now: str,
) -> dict[str, int]:
    tables = dict(snapshot.get("tables") or {})
    finding_ids = [str(item) for item in (snapshot.get("scope") or {}).get("finding_ids") or []]
    finding_clause, finding_params = _in_clause(finding_ids)

    # Junction rows are the only merge-mutated rows that are safely replaceable.
    conn.execute(f"DELETE FROM campaign_findings WHERE finding_id IN ({finding_clause})", finding_params)

    for table in (
        "assets",
        "findings",
        "source_finding_records",
        "finding_observations",
        "finding_reconciliation_decisions",
        "asset_identifiers",
        "asset_identity_candidates",
    ):
        for row in tables.get(table) or []:
            _update_row(conn, table, dict(row))

    for row in tables.get("campaign_findings") or []:
        columns = list(row)
        conn.execute(
            f"INSERT INTO campaign_findings({','.join(columns)}) VALUES({','.join('?' for _ in columns)})",
            [row[column] for column in columns],
        )

    pre_candidate_ids = {str(row["candidate_id"]) for row in tables.get("asset_identity_candidates") or []}
    retired_created = 0
    for candidate_id in sorted({str(item) for item in created_candidate_ids} - pre_candidate_ids):
        cursor = conn.execute(
            """UPDATE asset_identity_candidates
                  SET status='REJECTED',decided_by=?,decided_at=?,decision_reason=?
                WHERE candidate_id=? AND status='PENDING'""",
            (actor, now, "자산 병합 롤백으로 생성 후보 비활성화", candidate_id),
        )
        retired_created += max(0, int(cursor.rowcount))

    return {
        "restored_assets": len(tables.get("assets") or []),
        "restored_findings": len(tables.get("findings") or []),
        "restored_identifiers": len(tables.get("asset_identifiers") or []),
        "restored_candidates": len(tables.get("asset_identity_candidates") or []),
        "retired_created_candidates": retired_created,
    }
