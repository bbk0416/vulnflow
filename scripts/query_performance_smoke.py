from __future__ import annotations

import json
import sqlite3
import statistics
import sys
import tempfile
from pathlib import Path
from time import perf_counter

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.core.storage import init_db, list_findings
from app.services.finding_query import _encode_cursor, FindingQuery, finding_query_plan, finding_summary, query_findings

N = 50_000
CURSOR_SECRET = "release-query-cursor-signing-key-25"


def _rows():
    statuses = ("OPEN", "IN_PROGRESS", "CLOSED", "RISK_ACCEPTED")
    decisions = (
        ("immediate", "즉시 조치"),
        ("urgent_review", "긴급 검토"),
        ("scheduled", "예정 조치"),
        ("monitor", "관찰"),
    )
    scanners = ("scanner-a", "scanner-b", "scanner-c", "scanner-d")
    for i in range(N):
        status = statuses[i % len(statuses)]
        decision, label = decisions[(i // 3) % len(decisions)]
        scanner = scanners[(i // 5) % len(scanners)]
        record_state = "ARCHIVED" if i % 29 == 0 else ("STALE" if i % 11 == 0 else "ACTIVE")
        score = 100 - (i % 101)
        yield (
            f"PERF-{i:06d}", f"Product-{i % 50}", f"asset-{i % 5000:05d}",
            f"CVE-2026-{10000 + (i % 30000)}", f"component-{i % 200}", status,
            decision, label, record_state, scanner, score, int(i % 17 == 0),
            round((i % 1000) / 1000, 3), int(i % 7 == 0), int(i % 13 == 0),
            f"owner-{i % 30}", "2026-07-01" if status in {"OPEN", "IN_PROGRESS"} and i % 5 == 0 else "2026-12-31",
            "2026-07-25" if status == "RISK_ACCEPTED" else "", "UNVERIFIED", i % 4,
        )


def _seed(db: Path) -> float:
    init_db(db)
    started = perf_counter()
    with sqlite3.connect(db) as conn:
        # Bulk-load the synthetic fixture without paying per-row FTS trigger cost;
        # trigger synchronization is covered independently by the v25 regression tests.
        conn.executescript(
            "DROP TRIGGER IF EXISTS findings_fts_after_insert;"
            "DROP TRIGGER IF EXISTS findings_fts_after_delete;"
            "DROP TRIGGER IF EXISTS findings_fts_after_update;"
        )
        conn.executemany(
            """
            INSERT INTO findings(
                finding_id,product,asset_name,cve_id,component,status,decision,decision_label,
                record_state,scanner_source,score,kev,epss,internet_exposed,mitigation_required,
                owner,due_date,exception_expiry,resolution_state,reopen_count
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            _rows(),
        )
        conn.execute("INSERT INTO findings_fts(findings_fts) VALUES('rebuild')")
        conn.commit()
    return (perf_counter() - started) * 1000


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="vulnflow-query-perf-") as td:
        db = Path(td) / "performance.sqlite3"
        seed_ms = _seed(db)

        indexed_runs = []
        result = None
        for _ in range(3):
            result = query_findings(
                db, record_state="CURRENT", status="OPEN", decision="immediate",
                scanner_source="scanner-a", page=2, page_size=100,
            )
            indexed_runs.append(float(result["query_ms"]))
        assert result is not None

        summary_runs = []
        summary = None
        for _ in range(3):
            started = perf_counter()
            summary = finding_summary(db)
            summary_runs.append((perf_counter() - started) * 1000)
        assert summary is not None

        started = perf_counter()
        all_rows = list_findings(db)
        legacy_filtered = [
            row for row in all_rows
            if str(row.get("record_state") or "ACTIVE") != "ARCHIVED"
            and row.get("status") == "OPEN"
            and row.get("decision") == "immediate"
            and row.get("scanner_source") == "scanner-a"
        ]
        legacy_ms = (perf_counter() - started) * 1000


        # FTS5 prefix search is compared with the legacy concatenated LIKE path.
        fts_runs = []
        fts_result = None
        for _ in range(3):
            fts_result = query_findings(db, query="component 199", record_state="ALL", page_size=100)
            fts_runs.append(float(fts_result["query_ms"]))
        assert fts_result is not None and fts_result["count"] > 0
        with sqlite3.connect(db) as conn:
            started = perf_counter()
            legacy_search_count = int(conn.execute(
                "SELECT COUNT(*) FROM findings WHERE LOWER(COALESCE(finding_id,'')||' '||COALESCE(product,'')||' '||COALESCE(asset_name,'')||' '||COALESCE(cve_id,'')||' '||COALESCE(component,'')||' '||COALESCE(owner,'')) LIKE ?",
                ("%component-199%",),
            ).fetchone()[0])
            legacy_search_ms = (perf_counter() - started) * 1000

        # Build a signed keyset cursor at a deep offset once, then measure the seek query itself.
        previous = query_findings(db, record_state="ALL", page=399, page_size=100)
        cursor_filters = FindingQuery(record_state="ALL", page_size=100, pagination_mode="cursor").normalized()
        deep_cursor = _encode_cursor(previous["items"][-1], cursor_filters, secret=CURSOR_SECRET)
        cursor_runs = []
        cursor_result = None
        for _ in range(3):
            cursor_result = query_findings(
                db, record_state="ALL", pagination_mode="cursor", cursor=deep_cursor, page_size=100,
                cursor_secret=CURSOR_SECRET, include_count=False,
            )
            cursor_runs.append(float(cursor_result["query_ms"]))
        offset_runs = []
        for _ in range(3):
            offset_runs.append(float(query_findings(db, record_state="ALL", page=400, page_size=100)["query_ms"]))
        assert cursor_result is not None and len(cursor_result["items"]) == 100

        plan = finding_query_plan(
            db, status="OPEN", decision="immediate", scanner_source="scanner-a"
        )
        used_index = any("idx_findings_list_filters" in line for line in plan)
        page_ids = [str(row["finding_id"]) for row in result["items"]]

        assert result["count"] == len(legacy_filtered)
        assert len(result["items"]) == 100
        assert len(page_ids) == len(set(page_ids))
        assert used_index
        assert summary["all_records"] == N
        assert statistics.median(indexed_runs) < legacy_ms

        payload = {
            "dataset_rows": N,
            "seed_ms": round(seed_ms, 3),
            "filtered_count": int(result["count"]),
            "page_size": int(result["page_size"]),
            "page": int(result["page"]),
            "indexed_query_ms_median": round(statistics.median(indexed_runs), 3),
            "indexed_query_ms_min": round(min(indexed_runs), 3),
            "indexed_query_ms_max": round(max(indexed_runs), 3),
            "summary_query_ms_median": round(statistics.median(summary_runs), 3),
            "legacy_materialize_filter_ms": round(legacy_ms, 3),
            "index_plan_verified": used_index,
            "fts_query_ms_median": round(statistics.median(fts_runs), 3),
            "legacy_like_search_ms": round(legacy_search_ms, 3),
            "fts_match_count": int(fts_result["count"]),
            "legacy_like_match_count": legacy_search_count,
            "deep_cursor_query_ms_median": round(statistics.median(cursor_runs), 3),
            "deep_offset_query_ms_median": round(statistics.median(offset_runs), 3),
            "query_plan": plan,
            "scope": "synthetic local SQLite query-path verification; not production capacity evidence",
        }

    reports = ROOT / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    (reports / "query_performance_verification.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    lines = [
        "VulnFlow 72.0.95 FTS5 search and cursor pagination verification",
        f"Synthetic findings: {payload['dataset_rows']}",
        f"Filtered findings: {payload['filtered_count']}",
        f"Indexed page query median: {payload['indexed_query_ms_median']:.3f} ms",
        f"SQL summary median: {payload['summary_query_ms_median']:.3f} ms",
        f"Legacy full materialize + Python filter: {payload['legacy_materialize_filter_ms']:.3f} ms",
        f"Composite index plan: {'PASS' if payload['index_plan_verified'] else 'FAIL'}",
        f"FTS5 prefix search median: {payload['fts_query_ms_median']:.3f} ms",
        f"Legacy concatenated LIKE: {payload['legacy_like_search_ms']:.3f} ms",
        f"Deep cursor query median: {payload['deep_cursor_query_ms_median']:.3f} ms",
        f"Deep OFFSET query median: {payload['deep_offset_query_ms_median']:.3f} ms",
        "Limit: synthetic local SQLite measurement; not a production SLA or multi-server benchmark.",
    ]
    (reports / "query_performance_verification.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
