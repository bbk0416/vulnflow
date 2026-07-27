from __future__ import annotations

"""Domain routes extracted from :mod:`app.main`.

The route module is intentionally dependency-injected by ``app.routers`` so the
historical compatibility surface in ``app.main`` remains available without creating
internal import cycles.
"""

from datetime import date
from pathlib import Path
from typing import Any

from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response, StreamingResponse
from starlette.background import BackgroundTask

from app.api.models import *  # noqa: F403 - route request models

router = APIRouter()


def install_dependencies(namespace: dict[str, Any]) -> None:
    protected = {"router", "install_dependencies", "route_exports", "ROUTE_NAMES"}
    for name, value in namespace.items():
        if not name.startswith("__") and name not in protected:
            globals()[name] = value


def route_exports() -> dict[str, Any]:
    return {name: globals()[name] for name in ROUTE_NAMES}


ROUTE_NAMES = ('dashboard', 'upload_page', 'upload_findings', 'bulk_update', 'reconciliation_page', 'finding_detail', 'finding_source_resolution', 'finding_source_resolution_retire', 'finding_update', 'policies_page', 'system_page', 'finding_record_state', 'api_import_csv', 'api_update_workflow', 'api_policies', 'api_summary', 'api_findings', 'api_reconciliation', 'api_finding_sources', 'api_finding_source_resolution', 'api_finding_source_resolution_retire', 'api_finding_detail')

@router.get("/", response_class=HTMLResponse)
def dashboard(
    request: Request,
    decision: str = "",
    status: str = "",
    query: str = "",
    overdue: bool = False,
    exception: str = "",
    record_state: str = "CURRENT",
    scanner_source: str = "",
    page: int = 1,
    page_size: int = 50,
    notice: str = "",
):
    page = max(1, page)
    page_size = max(10, min(page_size, 200))
    result = query_findings(
        DB_PATH, decision=decision, status=status, query=query, overdue=overdue, exception=exception,
        record_state=record_state, scanner_source=scanner_source, page=page, page_size=page_size,
    )
    page = int(result["page"])
    total_pages = int(result["total_pages"])
    total_filtered = int(result["count"])
    paged = result["items"]
    summary = finding_summary(DB_PATH)
    counts = operational_counts(DB_PATH)
    kpis = {
        "total": summary["total"],
        "active": summary["active"],
        "immediate": summary["decisions"].get("즉시 조치", 0),
        "closed": summary["resolved"],
        "overdue": summary["overdue"],
        "exception_expired": summary["exception_expired"],
        "exception_expiring": summary["exception_expiring"],
        "stale": summary.get("record_states", {}).get("STALE", 0),
        "archived": summary.get("record_states", {}).get("ARCHIVED", 0),
        "verified_closed": summary.get("verified_closed", 0),
        "verification_pending": summary.get("verification_pending", 0),
        "verification_ready": summary.get("verification_ready", 0),
        "reopened": summary.get("reopened", 0),
        "assets": counts["asset_count"],
        "exposure_groups": counts["exposure_group_count"],
        "campaigns_active": counts["active_campaign_count"],
    }
    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "findings": paged,
            "kpis": kpis,
            "decision": decision,
            "status": status,
            "query": query,
            "overdue": overdue,
            "exception": exception,
            "record_state": record_state,
            "scanner_source": scanner_source,
            "scanner_sources": list_scanner_sources(DB_PATH),
            "query_ms": result["query_ms"],
            "page": page,
            "page_size": page_size,
            "total_pages": total_pages,
            "total_filtered": total_filtered,
            "notice_message": NOTICE_MESSAGES.get(notice, ""),
            "policy_version": _policy().get("version", "unknown"),
            "policy_id": (_active_policy_record() or {}).get("policy_id", ""),
        },
    )

@router.get("/upload", response_class=HTMLResponse)
def upload_page(request: Request):
    _require_role(request, "operator")
    return templates.TemplateResponse(request=request, name="upload.html", context={})

@router.post("/upload/findings")
async def upload_findings(
    request: Request,
    file: UploadFile = File(...),
    scanner_source: str = Form("manual"),
    import_mode: str = Form("incremental"),
    csrf_token: str = Form(...),
):
    _require_role(request, "operator")
    _verify_csrf(request, csrf_token)
    filename = file.filename or ""
    try:
        scanner_source = _bounded_text(scanner_source, "scanner_source", 120) or "manual"
        import_mode = str(import_mode or "incremental").strip().lower()
        if import_mode not in {"incremental", "snapshot"}:
            raise ValueError("가져오기 방식은 incremental 또는 snapshot이어야 합니다.")
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    if not filename.lower().endswith(".csv"):
        raise HTTPException(400, "CSV 파일만 지원합니다.")
    content = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, "파일 크기는 최대 5MB입니다.")
    try:
        rows = _parse_findings_csv(content, scanner_source=scanner_source, allow_empty=(import_mode == "snapshot"))
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    result = apply_import_batch(
        DB_PATH, rows, scanner_source=scanner_source, filename=filename,
        reconcile_missing=(import_mode == "snapshot"), actor=_actor(request),
        verification_absence_threshold=VERIFICATION_ABSENCE_SCANS,
    )
    _queue_webhook("import.completed", result, _actor(request))
    return RedirectResponse(url="/?notice=upload_ok", status_code=303)

@router.post("/bulk-update")
def bulk_update(
    request: Request,
    finding_ids: list[str] = Form(default=[]),
    bulk_status: str = Form(""),
    owner_mode: str = Form("keep"),
    bulk_owner: str = Form(""),
    due_date_mode: str = Form("keep"),
    bulk_due_date: str = Form(""),
    bulk_notes: str = Form(""),
    csrf_token: str = Form(...),
):
    _require_role(request, "operator")
    _verify_csrf(request, csrf_token)
    try:
        ids = list(dict.fromkeys(fid.strip() for fid in finding_ids if fid.strip()))
        if not ids:
            raise ValueError("선택된 취약점이 없습니다.")
        if len(ids) > MAX_BULK_ITEMS:
            raise ValueError(f"일괄 변경은 최대 {MAX_BULK_ITEMS}건까지 지원합니다.")
        status = bulk_status.strip().upper()
        if status:
            if status not in ALLOWED_STATUSES:
                raise ValueError("허용되지 않은 상태값입니다.")
            if status == "RISK_ACCEPTED":
                raise ValueError("위험수용은 사유·승인자·만료일이 필요하므로 상세화면에서 개별 처리해야 합니다.")
            if status == "CLOSED":
                raise ValueError("CLOSED 일괄 변경은 지원하지 않습니다. 조치 검증 승인 흐름을 사용하세요.")
        owner = _bounded_text(bulk_owner, "bulk_owner")
        due_date = _date_text(bulk_due_date, "bulk_due_date")
        notes = _bounded_text(bulk_notes, "bulk_notes", 1000)
        if owner_mode == "set" and not owner:
            raise ValueError("담당자 설정을 선택했으면 담당자 값을 입력해야 합니다.")
        if due_date_mode == "set" and not due_date:
            raise ValueError("목표일 설정을 선택했으면 날짜를 입력해야 합니다.")
        if status in {"MITIGATED", "CLOSED"} and not notes:
            raise ValueError(f"{status} 일괄 변경에는 처리 근거 메모가 필요합니다.")
        if not status and owner_mode == "keep" and due_date_mode == "keep" and not notes:
            raise ValueError("변경할 항목을 하나 이상 지정해야 합니다.")
        for finding_id in ids:
            finding = get_finding(DB_PATH, finding_id)
            if not finding:
                raise ValueError(f"존재하지 않는 finding_id: {finding_id}")
            if str(finding.get("record_state") or "ACTIVE").upper() == "ARCHIVED":
                raise ValueError(f"{finding_id}: ARCHIVED 항목은 ACTIVE로 복원한 뒤 변경하세요.")
            if status:
                current = str(finding.get("status", "OPEN")).upper()
                if status not in STATUS_TRANSITIONS.get(current, ALLOWED_STATUSES):
                    raise ValueError(f"{finding_id}: 허용되지 않은 상태 전환 {current} → {status}")
        bulk_update_workflow(
            DB_PATH,
            ids,
            status=status or None,
            owner_mode=owner_mode,
            owner=owner,
            due_date_mode=due_date_mode,
            due_date=due_date,
            notes_append=notes,
            actor=_actor(request),
        )
        rescore_all(audit=False, actor=_actor(request))
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return RedirectResponse(url="/?notice=bulk_ok", status_code=303)

@router.get("/reconciliation", response_class=HTMLResponse)
def reconciliation_page(request: Request, unresolved_only: bool = False):
    return templates.TemplateResponse(
        request=request,
        name="reconciliation.html",
        context={
            "items": list_reconciliation_findings(DB_PATH, unresolved_only=unresolved_only, limit=1000),
            "unresolved_only": unresolved_only,
        },
    )

@router.get("/finding/{finding_id}", response_class=HTMLResponse)
def finding_detail(request: Request, finding_id: str, notice: str = ""):
    finding = get_finding(DB_PATH, finding_id)
    if not finding:
        raise HTTPException(404, "해당 항목을 찾을 수 없습니다.")
    return templates.TemplateResponse(
        request=request,
        name="finding.html",
        context={
            "finding": finding,
            "audit_events": list_audit_events(DB_PATH, finding_id, limit=50),
            "overdue": is_overdue(finding),
            "exception_state": exception_state(finding),
            "approval_requests": [r for r in list_risk_approval_requests(DB_PATH, limit=200) if r.get("finding_id") == finding_id],
            "verification_requests": list_remediation_verification_requests(DB_PATH, finding_id=finding_id, limit=100),
            "observations": list_finding_observations(DB_PATH, finding_id, limit=50),
            "evidence_artifacts": _evidence_with_custody(finding_id=finding_id),
            "source_reconciliation": get_source_reconciliation(DB_PATH, finding_id),
            "verification_absence_scans": VERIFICATION_ABSENCE_SCANS,
            "notice_message": NOTICE_MESSAGES.get(notice, ""),
        },
    )

@router.post("/finding/{finding_id}/source-resolution")
def finding_source_resolution(
    request: Request, finding_id: str, field_name: str = Form(...),
    chosen_source_record_id: str = Form(...), reason: str = Form(...), csrf_token: str = Form(...),
):
    _require_role(request, "operator")
    _verify_csrf(request, csrf_token)
    try:
        resolve_source_conflict(
            DB_PATH, finding_id, field_name=field_name,
            chosen_source_record_id=chosen_source_record_id, reason=reason, actor=_actor(request),
        )
    except KeyError as exc:
        raise HTTPException(404, "해당 항목을 찾을 수 없습니다.") from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    _queue_webhook("finding.source_conflict_resolved", {"finding_id": finding_id, "field_name": field_name}, _actor(request))
    return RedirectResponse(url=f"/finding/{finding_id}?notice=source_resolution_ok", status_code=303)

@router.post("/finding/{finding_id}/source-resolution/{field_name}/retire")
def finding_source_resolution_retire(
    request: Request, finding_id: str, field_name: str, csrf_token: str = Form(...),
):
    _require_role(request, "operator")
    _verify_csrf(request, csrf_token)
    try:
        retire_source_conflict_resolution(DB_PATH, finding_id, field_name=field_name, actor=_actor(request))
    except KeyError as exc:
        raise HTTPException(404, "해당 항목을 찾을 수 없습니다.") from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return RedirectResponse(url=f"/finding/{finding_id}", status_code=303)

@router.post("/finding/{finding_id}")
def finding_update(
    request: Request,
    finding_id: str,
    status: str = Form(...),
    owner: str = Form(""),
    due_date: str = Form(""),
    exception_expiry: str = Form(""),
    risk_acceptance_reason: str = Form(""),
    risk_acceptance_approver: str = Form(""),
    notes: str = Form(""),
    row_version: int = Form(0),
    csrf_token: str = Form(...),
):
    _require_role(request, "operator")
    _verify_csrf(request, csrf_token)
    finding = get_finding(DB_PATH, finding_id)
    if not finding:
        raise HTTPException(404, "해당 항목을 찾을 수 없습니다.")
    if str(finding.get("record_state") or "ACTIVE").upper() == "ARCHIVED":
        raise HTTPException(400, "ARCHIVED 항목은 ACTIVE로 복원한 뒤 워크플로를 변경하세요.")
    try:
        status = status.strip().upper()
        if status not in ALLOWED_STATUSES:
            raise ValueError("허용되지 않은 상태값입니다.")
        if status == "CLOSED":
            raise ValueError("CLOSED는 조치 검증 승인으로만 전환할 수 있습니다.")
        current = str(finding.get("status", "OPEN")).upper()
        if status not in STATUS_TRANSITIONS.get(current, ALLOWED_STATUSES):
            raise ValueError(f"허용되지 않은 상태 전환입니다: {current} → {status}")
        owner = _bounded_text(owner, "owner")
        notes = _bounded_text(notes, "notes", MAX_NOTES)
        due_date = _date_text(due_date, "due_date")
        exception_expiry = _date_text(exception_expiry, "exception_expiry")
        risk_acceptance_reason = _bounded_text(risk_acceptance_reason, "risk_acceptance_reason", MAX_REASON)
        risk_acceptance_approver = _bounded_text(risk_acceptance_approver, "risk_acceptance_approver")
        if status == "RISK_ACCEPTED":
            if not exception_expiry or not risk_acceptance_reason:
                raise ValueError("RISK_ACCEPTED에는 예외 만료일과 수용 사유가 필요합니다.")
            if parse_date(exception_expiry) < date.today():
                raise ValueError("예외 만료일은 오늘 이후여야 합니다.")
            if not has_role(getattr(request.state, "role", "viewer"), "approver"):
                approval = create_risk_approval_request(
                    DB_PATH, finding_id, requested_by=_actor(request),
                    reason=risk_acceptance_reason, exception_expiry=exception_expiry,
                    notes=notes, expected_version=row_version or None,
                )
                _queue_webhook(
                    "risk_acceptance.requested",
                    {"request_id": approval.get("request_id"), "finding_id": finding_id, "exception_expiry": exception_expiry},
                    _actor(request),
                )
                return RedirectResponse(url=f"/finding/{finding_id}?notice=approval_requested", status_code=303)
            risk_acceptance_approver = _actor(request)
        else:
            exception_expiry = ""
            risk_acceptance_reason = ""
            risk_acceptance_approver = ""
        if status in {"MITIGATED", "CLOSED"} and not notes:
            raise ValueError(f"{status} 상태에는 처리 근거 메모가 필요합니다.")
    except ConcurrencyError as exc:
        raise HTTPException(409, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    try:
        update_workflow(
            DB_PATH,
            finding_id,
            status=status,
            owner=owner,
            due_date=due_date,
            exception_expiry=exception_expiry,
            risk_acceptance_reason=risk_acceptance_reason,
            risk_acceptance_approver=risk_acceptance_approver,
            notes=notes,
            actor=_actor(request),
            expected_version=row_version or None,
        )
    except ConcurrencyError as exc:
        raise HTTPException(409, str(exc)) from exc
    rescore_all(audit=False, actor=_actor(request))
    updated_finding = get_finding(DB_PATH, finding_id) or {}
    _queue_webhook(
        "finding.workflow_changed",
        {"finding_id": finding_id, "status": updated_finding.get("status"), "owner": updated_finding.get("owner"), "row_version": updated_finding.get("row_version")},
        _actor(request),
    )
    return RedirectResponse(url=f"/finding/{finding_id}?notice=workflow_ok", status_code=303)

@router.get("/policies", response_class=HTMLResponse)
def policies_page(
    request: Request, policy_id: str = "", request_status: str = "", notice: str = "",
):
    active = _ensure_policy_registry()
    policies = list_policy_versions(DB_PATH, limit=500)
    selected = get_policy_version(DB_PATH, policy_id) if policy_id else active
    if policy_id and not selected:
        raise HTTPException(404, "정책을 찾을 수 없습니다.")
    impact: dict[str, Any] | None = None
    if selected and str(selected["policy_id"]) != str(active["policy_id"]):
        impact = compare_policy_impact(
            list_findings(DB_PATH),
            parse_policy_text(str(active["content_yaml"])),
            parse_policy_text(str(selected["content_yaml"])),
        )
    return templates.TemplateResponse(
        request=request,
        name="policies.html",
        context={
            "active_policy": active,
            "policies": policies,
            "selected_policy": selected,
            "impact": impact,
            "activation_requests": list_policy_activation_requests(
                DB_PATH, status=request_status, limit=300
            ),
            "request_status": request_status,
            "notice_message": NOTICE_MESSAGES.get(notice, ""),
        },
    )

@router.get("/system", response_class=HTMLResponse)
def system_page(request: Request, notice: str = ""):
    _require_role(request, "admin")
    audit = build_config_audit(db_path=DB_PATH, base_dir=BASE_DIR)
    return templates.TemplateResponse(
        request=request,
        name="system.html",
        context={
            "audit": audit,
            "config_drift": evaluate_change_control(DB_PATH, audit, evaluate_drift(DB_PATH, audit)),
            "config_baselines": list_baselines(DB_PATH, limit=20),
            "config_drift_checks": list_drift_checks(DB_PATH, limit=20),
            "schema": get_schema_info(DB_PATH),
            "bundles": list_recovery_bundles(RECOVERY_DIR, limit=50),
            "notice_message": NOTICE_MESSAGES.get(notice, ""),
            "signature_required": BACKUP_REQUIRE_SIGNATURE,
            "signing": _signing_config().public_summary(),
            "evidence_integrity": verify_evidence_store(DB_PATH, EVIDENCE_DIR),
            "signing_usage": collect_signing_key_usage(
                db_path=str(DB_PATH), recovery_dir=str(RECOVERY_DIR), export_dir=str(EXPORT_DIR),
                configured_key_ids=sorted(_signing_config().keys),
            ),
        },
    )

@router.post("/finding/{finding_id}/record-state")
def finding_record_state(
    request: Request,
    finding_id: str,
    record_state: str = Form(...),
    row_version: int = Form(0),
    csrf_token: str = Form(...),
):
    _require_role(request, "operator")
    _verify_csrf(request, csrf_token)
    try:
        update_record_state(
            DB_PATH, finding_id, record_state=record_state, actor=_actor(request),
            expected_version=row_version or None,
        )
    except KeyError as exc:
        raise HTTPException(404, "해당 항목을 찾을 수 없습니다.") from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except ConcurrencyError as exc:
        raise HTTPException(409, str(exc)) from exc
    return RedirectResponse(url=f"/finding/{finding_id}?notice=record_state_ok", status_code=303)

@router.post("/api/v1/imports/csv")
async def api_import_csv(
    request: Request, file: UploadFile = File(...), scanner_source: str = "api", import_mode: str = "incremental"
):
    _require_role(request, "operator")
    _require_api_token(request)
    source = _bounded_text(scanner_source, "scanner_source", 120) or "api"
    mode = str(import_mode or "incremental").strip().lower()
    if mode not in {"incremental", "snapshot"}:
        raise HTTPException(400, "import_mode는 incremental 또는 snapshot이어야 합니다.")
    if not (file.filename or "").lower().endswith(".csv"):
        raise HTTPException(400, "CSV 파일만 지원합니다.")
    content = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, "파일 크기는 최대 5MB입니다.")
    try:
        rows = _parse_findings_csv(content, scanner_source=source)
        result = apply_import_batch(
            DB_PATH, rows, scanner_source=source, filename=file.filename or "api.csv",
            reconcile_missing=(mode == "snapshot"), actor=_actor(request),
            verification_absence_threshold=VERIFICATION_ABSENCE_SCANS,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    _queue_webhook("import.completed", result, _actor(request))
    return result

@router.post("/api/v1/findings/{finding_id}/workflow")
def api_update_workflow(request: Request, finding_id: str, payload: ApiWorkflowUpdate):
    _require_role(request, "operator")
    _require_api_token(request)
    finding = get_finding(DB_PATH, finding_id)
    if not finding:
        raise HTTPException(404, "해당 항목을 찾을 수 없습니다.")
    if str(finding.get("record_state") or "ACTIVE").upper() == "ARCHIVED":
        raise HTTPException(400, "ARCHIVED 항목은 ACTIVE로 복원한 뒤 변경하세요.")
    try:
        status = str(payload.status or "").strip().upper()
        if status not in ALLOWED_STATUSES or status in {"RISK_ACCEPTED", "CLOSED"}:
            raise ValueError("API workflow에서는 RISK_ACCEPTED·CLOSED를 직접 지정할 수 없습니다. 승인 API를 사용하세요.")
        current = str(finding.get("status") or "OPEN").upper()
        if status not in STATUS_TRANSITIONS.get(current, ALLOWED_STATUSES):
            raise ValueError(f"허용되지 않은 상태 전환입니다: {current} → {status}")
        owner = _bounded_text(payload.owner, "owner")
        due_date = _date_text(payload.due_date, "due_date")
        notes = _bounded_text(payload.notes, "notes", MAX_NOTES)
        if status in {"MITIGATED", "CLOSED"} and not notes:
            raise ValueError(f"{status} 상태에는 처리 근거 메모가 필요합니다.")
        update_workflow(
            DB_PATH, finding_id, status=status, owner=owner, due_date=due_date,
            exception_expiry="", risk_acceptance_reason="", risk_acceptance_approver="",
            notes=notes, actor=_actor(request), expected_version=payload.expected_row_version,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except ConcurrencyError as exc:
        raise HTTPException(409, str(exc)) from exc
    rescore_all(audit=False, actor=_actor(request))
    updated = get_finding(DB_PATH, finding_id) or {}
    _queue_webhook(
        "finding.workflow_changed",
        {"finding_id": finding_id, "status": updated.get("status"), "owner": updated.get("owner"), "row_version": updated.get("row_version")},
        _actor(request),
    )
    return updated

@router.get("/api/v1/policies")
def api_policies(request: Request, limit: int = 200):
    _require_role(request, "viewer")
    return {
        "active": get_active_policy_version(DB_PATH),
        "items": list_policy_versions(DB_PATH, limit=limit),
        "activation_requests": list_policy_activation_requests(DB_PATH, limit=limit),
    }

@router.get("/api/v1/summary")
def api_summary():
    return finding_summary(DB_PATH) | operational_counts(DB_PATH) | {
        "policy_version": _policy().get("version", "unknown"),
        "policy_id": (_active_policy_record() or {}).get("policy_id", ""),
    }

@router.get("/api/v1/findings")
def api_findings(
    decision: str = "",
    status: str = "",
    query: str = "",
    overdue: bool = False,
    exception: str = "",
    record_state: str = "",
    scanner_source: str = "",
    limit: int = 200,
    page: int = 1,
    pagination: str = "offset",
    cursor: str = "",
    include_count: bool = True,
):
    try:
        return query_findings(
            DB_PATH, decision=decision, status=status, query=query, overdue=overdue, exception=exception,
            record_state=record_state or "ALL", scanner_source=scanner_source, page=page,
            page_size=max(1, min(limit, 1000)), pagination_mode=pagination, cursor=cursor,
            cursor_secret=CURSOR_SIGNING_KEY, include_count=include_count,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc

@router.get("/api/v1/reconciliation")
def api_reconciliation(request: Request, unresolved_only: bool = False, limit: int = 500):
    _require_role(request, "viewer")
    items = list_reconciliation_findings(DB_PATH, unresolved_only=unresolved_only, limit=limit)
    return {"count": len(items), "items": items}

@router.get("/api/v1/findings/{finding_id}/sources")
def api_finding_sources(request: Request, finding_id: str):
    _require_role(request, "viewer")
    try:
        return get_source_reconciliation(DB_PATH, finding_id)
    except KeyError as exc:
        raise HTTPException(404, "해당 항목을 찾을 수 없습니다.") from exc

@router.post("/api/v1/findings/{finding_id}/source-resolution")
def api_finding_source_resolution(request: Request, finding_id: str, payload: ApiSourceConflictDecision):
    _require_role(request, "operator")
    _require_api_token(request)
    try:
        result = resolve_source_conflict(
            DB_PATH, finding_id, field_name=payload.field_name,
            chosen_source_record_id=payload.chosen_source_record_id, reason=payload.reason, actor=_actor(request),
        )
    except KeyError as exc:
        raise HTTPException(404, "해당 항목을 찾을 수 없습니다.") from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    _queue_webhook("finding.source_conflict_resolved", {"finding_id": finding_id, "field_name": payload.field_name}, _actor(request))
    return result

@router.post("/api/v1/findings/{finding_id}/source-resolution/{field_name}/retire")
def api_finding_source_resolution_retire(request: Request, finding_id: str, field_name: str):
    _require_role(request, "operator")
    _require_api_token(request)
    try:
        return retire_source_conflict_resolution(DB_PATH, finding_id, field_name=field_name, actor=_actor(request))
    except KeyError as exc:
        raise HTTPException(404, "해당 항목을 찾을 수 없습니다.") from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc

@router.get("/api/v1/findings/{finding_id}")
def api_finding_detail(finding_id: str):
    finding = get_finding(DB_PATH, finding_id)
    if not finding:
        raise HTTPException(404, "해당 항목을 찾을 수 없습니다.")
    return finding | {
        "overdue": is_overdue(finding),
        "exception_state": exception_state(finding),
        "audit_events": list_audit_events(DB_PATH, finding_id, limit=100),
        "source_reconciliation": get_source_reconciliation(DB_PATH, finding_id),
    }
