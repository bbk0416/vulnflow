from __future__ import annotations

from collections import Counter
from datetime import date, datetime
from html import escape
from typing import Any

from app.core.scoring import ACTIVE_STATUSES, as_bool, exception_state, is_overdue


def report_summary(findings: list[dict[str, Any]]) -> dict[str, Any]:
    visible = [r for r in findings if str(r.get("record_state") or "ACTIVE").upper() != "ARCHIVED"]
    active = [r for r in visible if str(r.get("status", "OPEN")).upper() in ACTIVE_STATUSES]
    decisions = Counter(row.get("decision_label") or "미분류" for row in active)
    exception_states = Counter(exception_state(row) for row in visible)
    record_states = Counter(str(row.get("record_state") or "ACTIVE").upper() for row in findings)
    resolution_states = Counter(str(row.get("resolution_state") or "UNVERIFIED").upper() for row in visible)
    return {
        "total": len(visible),
        "all_records": len(findings),
        "active": len(active),
        "resolved": len(visible) - len(active),
        "kev": sum(as_bool(row.get("kev")) for row in visible),
        "internet_exposed": sum(as_bool(row.get("internet_exposed")) for row in visible),
        "mitigation_required": sum(as_bool(row.get("mitigation_required")) for row in active),
        "overdue": sum(is_overdue(row) for row in active),
        "exception_expired": exception_states["expired"],
        "exception_expiring": exception_states["expiring"],
        "decisions": dict(decisions),
        "record_states": dict(record_states),
        "resolution_states": dict(resolution_states),
        "verified_closed": resolution_states["VERIFIED"],
        "verification_pending": resolution_states["PENDING"],
        "verification_ready": resolution_states["READY_FOR_VERIFICATION"],
        "reopened": sum(int(row.get("reopen_count") or 0) for row in visible),
    }


def generate_html_report(findings: list[dict[str, Any]]) -> str:
    report_rows = [row for row in findings if str(row.get("record_state") or "ACTIVE").upper() != "ARCHIVED"]
    summary = report_summary(report_rows)
    rows_html = "".join(
        "<tr>"
        f"<td>{escape(str(row.get('finding_id', '')))}</td>"
        f"<td>{escape(str(row.get('product', '')))}</td>"
        f"<td>{escape(str(row.get('asset_name', '')))}</td>"
        f"<td>{escape(str(row.get('cve_id', '')))}</td>"
        f"<td>{int(row.get('score') or 0)}</td>"
        f"<td>{escape(str(row.get('decision_label', '')))}</td>"
        f"<td>{escape(str(row.get('owner', '')))}</td>"
        f"<td>{escape(str(row.get('status', '')))}</td>"
        f"<td>{escape(str(row.get('resolution_state') or 'UNVERIFIED'))}</td>"
        f"<td>{escape(str(row.get('record_state') or 'ACTIVE'))}</td>"
        f"<td>{escape(str(row.get('scanner_source') or 'manual'))}</td>"
        f"<td>{escape(str(row.get('due_date') or row.get('target_date') or ''))}</td>"
        "</tr>"
        for row in report_rows
    )
    decision_html = "".join(
        f"<li><strong>{escape(str(label))}</strong>: {count}</li>"
        for label, count in sorted(summary["decisions"].items())
    )
    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    policy_versions = sorted({str(row.get("policy_version") or "unknown") for row in report_rows})
    return f"""<!doctype html>
<html lang="ko"><head><meta charset="utf-8"><title>VulnFlow 조치 우선순위·이행 현황 보고서</title>
<style>
body{{font-family:Arial,'Malgun Gothic',sans-serif;margin:40px;color:#1f2937}}
h1,h2{{color:#111827}} .kpi{{display:inline-block;border:1px solid #d1d5db;border-radius:10px;padding:14px;margin:4px;min-width:140px}}
table{{border-collapse:collapse;width:100%;font-size:13px}}th,td{{border:1px solid #d1d5db;padding:8px;text-align:left}}th{{background:#f3f4f6}}
.notice{{background:#fff7ed;border-left:4px solid #f97316;padding:12px}} .meta{{color:#667085;font-size:12px}}
</style></head><body>
<h1>VulnFlow 조치 우선순위·이행 현황 보고서</h1>
<p class="meta">생성 시각: {generated} · 정책 버전: {escape(', '.join(policy_versions))}</p>
<div class="notice">본 보고서는 조치 검토 순서를 지원하는 로컬 취약점 운영 도구의 출력물입니다. 점수는 공격 예측 확률이 아니며 실제 운영 적용 전 조직 정책과 담당자 검토가 필요합니다.</div>
<h2>요약</h2>
<div class="kpi">전체<br><strong>{summary['total']}</strong></div>
<div class="kpi">활성 조치 대상<br><strong>{summary['active']}</strong></div>
<div class="kpi">기한 초과<br><strong>{summary['overdue']}</strong></div>
<div class="kpi">KEV<br><strong>{summary['kev']}</strong></div>
<div class="kpi">인터넷 노출<br><strong>{summary['internet_exposed']}</strong></div>
<div class="kpi">완화조치 필요<br><strong>{summary['mitigation_required']}</strong></div>
<div class="kpi">예외 만료/임박<br><strong>{summary['exception_expired']} / {summary['exception_expiring']}</strong></div>
<div class="kpi">검증 완료<br><strong>{summary['verified_closed']}</strong></div>
<div class="kpi">검증 대기/가능<br><strong>{summary['verification_pending']} / {summary['verification_ready']}</strong></div>
<div class="kpi">재발 누계<br><strong>{summary['reopened']}</strong></div>
<ul>{decision_html}</ul>
<h2>상세 목록</h2>
<table><thead><tr><th>ID</th><th>제품</th><th>자산</th><th>CVE</th><th>조치 우선순위</th><th>판정</th><th>담당자</th><th>상태</th><th>검증</th><th>레코드</th><th>원천</th><th>목표일</th></tr></thead>
<tbody>{rows_html}</tbody></table>
</body></html>"""
