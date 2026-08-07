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


def generate_executive_html_report(
    findings: list[dict[str, Any]],
    *,
    profile: dict[str, Any] | None = None,
    project_name: str = "",
) -> str:
    """Generate a printable customer-facing remediation status report."""
    profile = dict(profile or {})
    visible = [row for row in findings if str(row.get("record_state") or "ACTIVE").upper() != "ARCHIVED"]
    active = [row for row in visible if str(row.get("status") or "OPEN").upper() in ACTIVE_STATUSES]
    summary = report_summary(visible)
    status_labels = {
        "OPEN": "처리 전",
        "IN_PROGRESS": "조치 중",
        "MITIGATED": "확인 요청",
        "RISK_ACCEPTED": "예외 승인",
        "CLOSED": "완료",
    }
    statuses = Counter(str(row.get("status") or "OPEN").upper() for row in visible)
    top_rows = sorted(
        active,
        key=lambda row: (
            int(bool(as_bool(row.get("kev")))),
            int(row.get("score") or 0),
            float(row.get("epss") or 0),
        ),
        reverse=True,
    )[:25]
    top_html = "".join(
        "<tr>"
        f"<td>{escape(str(row.get('product') or ''))}</td>"
        f"<td>{escape(str(row.get('asset_name') or ''))}</td>"
        f"<td>{escape(str(row.get('cve_id') or ''))}</td>"
        f"<td>{escape(str(row.get('decision_label') or '미분류'))}</td>"
        f"<td>{escape(status_labels.get(str(row.get('status') or 'OPEN').upper(), str(row.get('status') or '')))}</td>"
        f"<td>{escape(str(row.get('owner') or '미배정'))}</td>"
        f"<td>{escape(str(row.get('due_date') or row.get('target_date') or ''))}</td>"
        "</tr>"
        for row in top_rows
    ) or '<tr><td colspan="7">활성 취약점이 없습니다.</td></tr>'
    status_html = "".join(
        f'<div class="metric"><span>{escape(status_labels[key])}</span><strong>{statuses.get(key, 0)}</strong></div>'
        for key in ("OPEN", "IN_PROGRESS", "MITIGATED", "RISK_ACCEPTED", "CLOSED")
    )
    decision_html = "".join(
        f"<li><span>{escape(str(label))}</span><strong>{int(count)}</strong></li>"
        for label, count in sorted(summary["decisions"].items(), key=lambda item: (-item[1], item[0]))
    ) or "<li><span>활성 판정 없음</span><strong>0</strong></li>"
    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    customer = str(profile.get("customer_name") or "고객사 미설정")
    engagement = str(profile.get("engagement_name") or project_name or "취약점 조치 프로젝트")
    contact = " · ".join(
        part for part in (
            str(profile.get("contact_name") or "").strip(),
            str(profile.get("contact_email") or "").strip(),
        ) if part
    ) or "담당자 미설정"
    scope = escape(str(profile.get("scope_notes") or "등록된 스캐너 결과와 자산을 기준으로 조치 현황을 집계했습니다."))
    footer = escape(str(profile.get("report_footer") or "본 보고서는 취약점 조치 우선순위와 이행 현황을 지원하기 위한 운영 자료입니다."))
    return f"""<!doctype html>
<html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{escape(customer)} · {escape(engagement)} 취약점 조치현황</title>
<style>
:root{{--ink:#172033;--muted:#667085;--line:#d8dee9;--soft:#f5f7fb;--accent:#2456d6;--danger:#b42318}}
*{{box-sizing:border-box}}body{{font-family:Arial,'Malgun Gothic',sans-serif;margin:0;color:var(--ink);background:#fff}}
main{{max-width:1120px;margin:0 auto;padding:44px}}header{{border-bottom:3px solid var(--accent);padding-bottom:22px;margin-bottom:28px}}
h1{{margin:6px 0 10px;font-size:30px}}h2{{margin-top:34px;font-size:20px}}p{{line-height:1.65}}.eyebrow{{color:var(--accent);font-weight:700;letter-spacing:.08em;font-size:12px}}
.meta{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px 24px;color:var(--muted);font-size:13px}}
.metrics{{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:10px}}.metric{{border:1px solid var(--line);border-radius:10px;padding:14px;background:var(--soft)}}
.metric span{{display:block;color:var(--muted);font-size:12px}}.metric strong{{display:block;font-size:25px;margin-top:7px}}
.alert{{border-left:4px solid var(--danger);background:#fff4f2;padding:14px 16px;margin:18px 0}}.split{{display:grid;grid-template-columns:1.4fr 1fr;gap:24px}}
ul.summary{{list-style:none;padding:0;margin:0;border:1px solid var(--line);border-radius:10px;overflow:hidden}}ul.summary li{{display:flex;justify-content:space-between;padding:11px 14px;border-bottom:1px solid var(--line)}}ul.summary li:last-child{{border-bottom:0}}
table{{border-collapse:collapse;width:100%;font-size:12px}}th,td{{border:1px solid var(--line);padding:8px;text-align:left;vertical-align:top}}th{{background:var(--soft)}}footer{{margin-top:36px;padding-top:16px;border-top:1px solid var(--line);color:var(--muted);font-size:12px}}
@media print{{main{{max-width:none;padding:20px}}.no-print{{display:none}}}}@media(max-width:760px){{main{{padding:24px}}.metrics{{grid-template-columns:repeat(2,1fr)}}.split,.meta{{grid-template-columns:1fr}}}}
</style></head><body><main>
<header><div class="eyebrow">VULNERABILITY REMEDIATION STATUS</div><h1>{escape(customer)}</h1><p><strong>{escape(engagement)}</strong></p>
<div class="meta"><span>프로젝트: {escape(project_name or engagement)}</span><span>담당자: {escape(contact)}</span><span>생성 시각: {generated}</span><span>기본 조치기한: {int(profile.get('default_due_days') or 30)}일</span></div></header>
<section><h2>경영진 요약</h2><div class="metrics">{status_html}</div>
<div class="alert">활성 조치 대상 <strong>{summary['active']}건</strong> 중 기한 초과 <strong>{summary['overdue']}건</strong>, KEV 등재 <strong>{summary['kev']}건</strong>, 인터넷 노출 <strong>{summary['internet_exposed']}건</strong>입니다.</div></section>
<section class="split"><div><h2>진단 범위</h2><p>{scope}</p><p>전체 관리 항목 {summary['total']}건 · 검증 완료 {summary['verified_closed']}건 · 검증 대기 {summary['verification_pending']}건</p></div><div><h2>조치 우선순위</h2><ul class="summary">{decision_html}</ul></div></section>
<section><h2>우선 확인 대상</h2><table><thead><tr><th>제품</th><th>자산</th><th>CVE</th><th>우선순위</th><th>상태</th><th>담당자</th><th>목표일</th></tr></thead><tbody>{top_html}</tbody></table></section>
<footer>{footer}<br>VulnFlow가 생성한 시점 기준 스냅샷이며, 최종 위험 판단과 예외 승인은 조직 책임자의 검토가 필요합니다.</footer>
</main></body></html>"""
