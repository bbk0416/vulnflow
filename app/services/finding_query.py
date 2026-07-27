from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import date
import hashlib
import hmac
import json
from pathlib import Path
import re
from time import perf_counter
from typing import Any

from app.core.db import connect

ACTIVE_STATUSES = ("OPEN", "IN_PROGRESS")
VISIBLE_RECORD_STATES = ("ACTIVE", "STALE")
_CURSOR_VERSION = 1
_SORT_SQL = "COALESCE(f.score,0) DESC,COALESCE(f.kev,0) DESC,COALESCE(f.epss,0) DESC,COALESCE(f.cve_id,'') ASC,f.finding_id ASC"


@dataclass(frozen=True)
class FindingQuery:
    decision: str = ""
    status: str = ""
    query: str = ""
    overdue: bool = False
    exception: str = ""
    record_state: str = "CURRENT"
    scanner_source: str = ""
    page: int = 1
    page_size: int = 50
    pagination_mode: str = "offset"

    def normalized(self) -> "FindingQuery":
        page = max(1, int(self.page or 1))
        page_size = max(1, min(int(self.page_size or 50), 1000))
        mode = str(self.pagination_mode or "offset").strip().lower()
        if mode not in {"offset", "cursor"}:
            raise ValueError("pagination은 offset 또는 cursor여야 합니다.")
        return FindingQuery(
            decision=str(self.decision or "").strip(),
            status=str(self.status or "").strip().upper(),
            query=str(self.query or "").strip(),
            overdue=bool(self.overdue),
            exception=str(self.exception or "").strip().lower(),
            record_state=str(self.record_state or "CURRENT").strip().upper(),
            scanner_source=str(self.scanner_source or "").strip(),
            page=page,
            page_size=page_size,
            pagination_mode=mode,
        )


def _fts_query(text: str) -> str:
    """Convert user text to a bounded FTS5 AND-prefix expression."""
    if len(text) > 500:
        raise ValueError("검색어는 500자를 초과할 수 없습니다.")
    tokens = re.findall(r"\w+", text.casefold(), flags=re.UNICODE)
    if not tokens:
        raise ValueError("검색 가능한 문자 또는 숫자를 입력하세요.")
    if len(tokens) > 20:
        raise ValueError("검색 토큰은 20개를 초과할 수 없습니다.")
    return " ".join('"' + token.replace('"', '""') + '"*' for token in tokens)


def _filter_fingerprint(filters: FindingQuery) -> str:
    payload = {
        "decision": filters.decision,
        "status": filters.status,
        "query": filters.query.casefold(),
        "overdue": filters.overdue,
        "exception": filters.exception,
        "record_state": filters.record_state,
        "scanner_source": filters.scanner_source,
        "page_size": filters.page_size,
    }
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _cursor_secret(secret: str) -> bytes:
    value = str(secret or "")
    if len(value) < 16:
        raise ValueError("커서 서명 키는 16자 이상이어야 합니다.")
    return value.encode("utf-8")


def _encode_cursor(item: dict[str, Any], filters: FindingQuery, *, secret: str) -> str:
    payload = {
        "v": _CURSOR_VERSION,
        "f": _filter_fingerprint(filters),
        "s": [
            int(item.get("score") or 0),
            int(item.get("kev") or 0),
            float(item.get("epss") or 0),
            str(item.get("cve_id") or ""),
            str(item.get("finding_id") or ""),
        ],
    }
    body = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    signature = hmac.new(_cursor_secret(secret), body, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(body + signature).decode("ascii").rstrip("=")


def _decode_cursor(cursor: str, filters: FindingQuery, *, secret: str) -> tuple[int, int, float, str, str]:
    value = str(cursor or "").strip()
    if not value or len(value) > 2048:
        raise ValueError("유효하지 않은 페이지 커서입니다.")
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        if len(raw) <= 32:
            raise ValueError
        body, signature = raw[:-32], raw[-32:]
        expected = hmac.new(_cursor_secret(secret), body, hashlib.sha256).digest()
        if not hmac.compare_digest(signature, expected):
            raise ValueError
        payload = json.loads(body.decode("utf-8"))
        if payload.get("v") != _CURSOR_VERSION or payload.get("f") != _filter_fingerprint(filters):
            raise ValueError
        values = payload.get("s")
        if not isinstance(values, list) or len(values) != 5:
            raise ValueError
        score, kev, epss, cve_id, finding_id = values
        return int(score), int(kev), float(epss), str(cve_id), str(finding_id)
    except (ValueError, TypeError, json.JSONDecodeError, UnicodeDecodeError, base64.binascii.Error) as exc:
        raise ValueError("페이지 커서가 손상되었거나 현재 필터와 일치하지 않습니다.") from exc


def _where_clause(filters: FindingQuery, *, today: date) -> tuple[str, list[Any], str]:
    filters = filters.normalized()
    clauses: list[str] = []
    params: list[Any] = []
    join = ""

    if filters.record_state == "CURRENT":
        clauses.append("f.record_state!='ARCHIVED'")
    elif filters.record_state and filters.record_state != "ALL":
        clauses.append("f.record_state=?")
        params.append(filters.record_state)

    if filters.scanner_source:
        clauses.append("f.scanner_source=?")
        params.append(filters.scanner_source)
    if filters.decision:
        clauses.append("f.decision=?")
        params.append(filters.decision)
    if filters.status:
        clauses.append("f.status=?")
        params.append(filters.status)

    today_text = today.isoformat()
    if filters.overdue:
        clauses.append("f.status IN ('OPEN','IN_PROGRESS')")
        clauses.append("DATE(COALESCE(NULLIF(f.due_date,''),NULLIF(f.target_date,''))) < DATE(?)")
        params.append(today_text)

    if filters.exception:
        clauses.append("f.status='RISK_ACCEPTED'")
        if filters.exception == "expired":
            clauses.append("(NULLIF(f.exception_expiry,'') IS NULL OR DATE(f.exception_expiry) IS NULL OR DATE(f.exception_expiry) < DATE(?))")
            params.append(today_text)
        elif filters.exception == "expiring":
            clauses.append("DATE(f.exception_expiry) BETWEEN DATE(?) AND DATE(?, '+14 day')")
            params.extend([today_text, today_text])
        elif filters.exception == "active":
            clauses.append("DATE(f.exception_expiry) > DATE(?, '+14 day')")
            params.append(today_text)
        else:
            raise ValueError("허용되지 않은 예외 필터입니다.")

    if filters.query:
        join = " JOIN findings_fts ON findings_fts.rowid=f.rowid"
        clauses.append("findings_fts MATCH ?")
        params.append(_fts_query(filters.query))

    return (" WHERE " + " AND ".join(clauses)) if clauses else "", params, join


def _cursor_clause(values: tuple[int, int, float, str, str]) -> tuple[str, list[Any]]:
    score, kev, epss, cve_id, finding_id = values
    clause = """
    (
       COALESCE(f.score,0) < ?
       OR (COALESCE(f.score,0)=? AND COALESCE(f.kev,0) < ?)
       OR (COALESCE(f.score,0)=? AND COALESCE(f.kev,0)=? AND COALESCE(f.epss,0) < ?)
       OR (COALESCE(f.score,0)=? AND COALESCE(f.kev,0)=? AND COALESCE(f.epss,0)=? AND COALESCE(f.cve_id,'') > ?)
       OR (COALESCE(f.score,0)=? AND COALESCE(f.kev,0)=? AND COALESCE(f.epss,0)=? AND COALESCE(f.cve_id,'')=? AND f.finding_id > ?)
    )
    """
    params = [score, score, kev, score, kev, epss, score, kev, epss, cve_id, score, kev, epss, cve_id, finding_id]
    return clause, params


def query_findings(
    db_path: str | Path,
    *,
    decision: str = "",
    status: str = "",
    query: str = "",
    overdue: bool = False,
    exception: str = "",
    record_state: str = "CURRENT",
    scanner_source: str = "",
    page: int = 1,
    page_size: int = 50,
    today: date | None = None,
    pagination_mode: str = "offset",
    cursor: str = "",
    cursor_secret: str = "",
    include_count: bool = True,
) -> dict[str, Any]:
    """Return FTS-indexed results using stable offset or signed keyset pagination."""
    started = perf_counter()
    filters = FindingQuery(
        decision=decision, status=status, query=query, overdue=overdue, exception=exception,
        record_state=record_state, scanner_source=scanner_source, page=page, page_size=page_size,
        pagination_mode="cursor" if cursor else pagination_mode,
    ).normalized()
    where, params, join = _where_clause(filters, today=today or date.today())
    count_value: int | None = None
    total_pages: int | None = None
    current_page: int | None = filters.page if filters.pagination_mode == "offset" else None

    with connect(db_path) as conn:
        if include_count:
            count_value = int(conn.execute(f"SELECT COUNT(*) FROM findings AS f{join}{where}", params).fetchone()[0])
        row_params = list(params)
        row_where = where
        if filters.pagination_mode == "cursor" and cursor:
            cursor_values = _decode_cursor(cursor, filters, secret=cursor_secret)
            cursor_sql, cursor_params = _cursor_clause(cursor_values)
            row_where += (" AND " if row_where else " WHERE ") + cursor_sql
            row_params.extend(cursor_params)

        if filters.pagination_mode == "offset":
            total_pages = max(1, ((count_value or 0) + filters.page_size - 1) // filters.page_size) if include_count else None
            if total_pages is not None:
                current_page = min(filters.page, total_pages)
            offset = ((current_page or 1) - 1) * filters.page_size
            rows = conn.execute(
                f"SELECT f.* FROM findings AS f{join}{row_where} ORDER BY {_SORT_SQL} LIMIT ? OFFSET ?",
                [*row_params, filters.page_size, offset],
            ).fetchall()
            has_more = bool(total_pages is not None and (current_page or 1) < total_pages)
        else:
            rows = conn.execute(
                f"SELECT f.* FROM findings AS f{join}{row_where} ORDER BY {_SORT_SQL} LIMIT ?",
                [*row_params, filters.page_size + 1],
            ).fetchall()
            has_more = len(rows) > filters.page_size
            rows = rows[:filters.page_size]

    items = [dict(row) for row in rows]
    next_cursor = _encode_cursor(items[-1], filters, secret=cursor_secret) if filters.pagination_mode == "cursor" and has_more and items else None
    elapsed_ms = round((perf_counter() - started) * 1000, 3)
    return {
        "count": count_value,
        "items": items,
        "page": current_page,
        "page_size": filters.page_size,
        "total_pages": total_pages,
        "pagination_mode": filters.pagination_mode,
        "next_cursor": next_cursor,
        "has_more": has_more,
        "query_ms": elapsed_ms,
        "search_backend": "fts5" if filters.query else "indexed_sql",
    }


def list_scanner_sources(db_path: str | Path) -> list[str]:
    with connect(db_path) as conn:
        rows = conn.execute(
            "SELECT DISTINCT scanner_source FROM findings WHERE NULLIF(scanner_source,'') IS NOT NULL ORDER BY scanner_source"
        ).fetchall()
    return [str(row[0]) for row in rows]


def finding_summary(db_path: str | Path, *, today: date | None = None) -> dict[str, Any]:
    """Compute dashboard KPI values without loading all findings into Python."""
    today_text = (today or date.today()).isoformat()
    visible = "record_state!='ARCHIVED'"
    active = f"{visible} AND status IN ('OPEN','IN_PROGRESS')"

    with connect(db_path) as conn:
        totals = conn.execute(
            f"""
            SELECT
                COUNT(*) AS all_records,
                SUM(CASE WHEN {visible} THEN 1 ELSE 0 END) AS total,
                SUM(CASE WHEN {active} THEN 1 ELSE 0 END) AS active,
                SUM(CASE WHEN {visible} AND kev=1 THEN 1 ELSE 0 END) AS kev,
                SUM(CASE WHEN {visible} AND internet_exposed=1 THEN 1 ELSE 0 END) AS internet_exposed,
                SUM(CASE WHEN {active} AND mitigation_required=1 THEN 1 ELSE 0 END) AS mitigation_required,
                SUM(CASE WHEN {active} AND DATE(COALESCE(NULLIF(due_date,''),NULLIF(target_date,''))) < DATE(?) THEN 1 ELSE 0 END) AS overdue,
                SUM(CASE WHEN {visible} AND status='RISK_ACCEPTED' AND (NULLIF(exception_expiry,'') IS NULL OR DATE(exception_expiry) IS NULL OR DATE(exception_expiry) < DATE(?)) THEN 1 ELSE 0 END) AS exception_expired,
                SUM(CASE WHEN {visible} AND status='RISK_ACCEPTED' AND DATE(exception_expiry) BETWEEN DATE(?) AND DATE(?, '+14 day') THEN 1 ELSE 0 END) AS exception_expiring,
                SUM(CASE WHEN {visible} THEN COALESCE(reopen_count,0) ELSE 0 END) AS reopened
            FROM findings
            """,
            (today_text, today_text, today_text, today_text),
        ).fetchone()

        decisions = {str(row["label"]): int(row["count"]) for row in conn.execute(
            f"SELECT COALESCE(NULLIF(decision_label,''),'미분류') AS label,COUNT(*) AS count FROM findings WHERE {active} GROUP BY COALESCE(NULLIF(decision_label,''),'미분류')"
        ).fetchall()}
        record_states = {str(row["state"]): int(row["count"]) for row in conn.execute(
            "SELECT COALESCE(NULLIF(record_state,''),'ACTIVE') AS state,COUNT(*) AS count FROM findings GROUP BY COALESCE(NULLIF(record_state,''),'ACTIVE')"
        ).fetchall()}
        resolution_states = {str(row["state"]): int(row["count"]) for row in conn.execute(
            f"SELECT COALESCE(NULLIF(resolution_state,''),'UNVERIFIED') AS state,COUNT(*) AS count FROM findings WHERE {visible} GROUP BY COALESCE(NULLIF(resolution_state,''),'UNVERIFIED')"
        ).fetchall()}

    total = int(totals["total"] or 0)
    active_count = int(totals["active"] or 0)
    return {
        "total": total, "all_records": int(totals["all_records"] or 0), "active": active_count,
        "resolved": total - active_count, "kev": int(totals["kev"] or 0),
        "internet_exposed": int(totals["internet_exposed"] or 0),
        "mitigation_required": int(totals["mitigation_required"] or 0),
        "overdue": int(totals["overdue"] or 0),
        "exception_expired": int(totals["exception_expired"] or 0),
        "exception_expiring": int(totals["exception_expiring"] or 0),
        "decisions": decisions, "record_states": record_states, "resolution_states": resolution_states,
        "verified_closed": int(resolution_states.get("VERIFIED", 0)),
        "verification_pending": int(resolution_states.get("PENDING", 0)),
        "verification_ready": int(resolution_states.get("READY_FOR_VERIFICATION", 0)),
        "reopened": int(totals["reopened"] or 0),
    }


def operational_counts(db_path: str | Path) -> dict[str, int]:
    with connect(db_path) as conn:
        asset_count = int(conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0])
        exposure_group_count = int(conn.execute("SELECT COUNT(*) FROM (SELECT 1 FROM findings WHERE record_state!='ARCHIVED' GROUP BY cve_id,component,component_version)").fetchone()[0])
        active_campaign_count = int(conn.execute("SELECT COUNT(*) FROM remediation_campaigns WHERE status='ACTIVE'").fetchone()[0])
    return {"asset_count": asset_count, "exposure_group_count": exposure_group_count, "active_campaign_count": active_campaign_count}


def finding_query_plan(db_path: str | Path, *, decision: str = "", status: str = "", record_state: str = "CURRENT", scanner_source: str = "", query: str = "") -> list[str]:
    filters = FindingQuery(decision=decision, status=status, record_state=record_state, scanner_source=scanner_source, query=query, page=1, page_size=50).normalized()
    where, params, join = _where_clause(filters, today=date.today())
    with connect(db_path) as conn:
        rows = conn.execute(
            f"EXPLAIN QUERY PLAN SELECT f.* FROM findings AS f{join}{where} ORDER BY {_SORT_SQL} LIMIT 50", params
        ).fetchall()
    return [str(row[3]) for row in rows]
