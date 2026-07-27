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


ROUTE_NAMES = ('verifications_page', 'remediation_verification_request', 'remediation_evidence_upload', 'remediation_evidence_download', 'remediation_evidence_scan_ui', 'remediation_evidence_scan_waiver_ui', 'remediation_evidence_custody_transfer_ui', 'remediation_evidence_retire_ui', 'remediation_verification_decision', 'approvals_page', 'approval_decision', 'api_list_remediation_verifications', 'api_create_remediation_verification', 'api_list_remediation_evidence', 'api_upload_remediation_evidence', 'api_download_remediation_evidence', 'api_evidence_custody', 'api_evidence_custody_transfer', 'api_scan_remediation_evidence', 'api_waive_remediation_evidence_scan', 'api_retire_remediation_evidence', 'api_evidence_integrity', 'api_decide_remediation_verification', 'api_request_risk_acceptance', 'api_decide_approval', 'api_approvals')

@router.get("/verifications", response_class=HTMLResponse)
def verifications_page(request: Request, status: str = "", notice: str = ""):
    _require_role(request, "operator")
    normalized = str(status or "").strip().upper()
    if normalized and normalized not in {"PENDING", "APPROVED", "REJECTED", "CANCELLED"}:
        raise HTTPException(400, "허용되지 않은 검증 상태입니다.")
    return templates.TemplateResponse(
        request=request, name="verifications.html",
        context={
            "requests": list_remediation_verification_requests(DB_PATH, status=normalized, limit=500),
            "status_filter": normalized,
            "notice_message": NOTICE_MESSAGES.get(notice, ""),
        },
    )

@router.post("/finding/{finding_id}/verification-requests")
def remediation_verification_request(
    request: Request, finding_id: str, method: str = Form(...), evidence_note: str = Form(""),
    row_version: int = Form(...), csrf_token: str = Form(...),
):
    _require_role(request, "operator")
    _verify_csrf(request, csrf_token)
    try:
        created = create_remediation_verification_request(
            DB_PATH, finding_id, method=method, evidence_note=_bounded_text(evidence_note, "evidence_note", 4000),
            actor=_actor(request), expected_version=row_version, absence_threshold=VERIFICATION_ABSENCE_SCANS,
        )
        _queue_webhook(
            "remediation.verification_requested",
            {"verification_id": created.get("verification_id"), "finding_id": finding_id, "method": created.get("method")},
            _actor(request),
        )
    except KeyError as exc:
        raise HTTPException(404, "해당 취약점을 찾을 수 없습니다.") from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except ConcurrencyError as exc:
        raise HTTPException(409, str(exc)) from exc
    return RedirectResponse(f"/finding/{finding_id}?notice=verification_requested", status_code=303)

@router.post("/verifications/{verification_id}/evidence")
async def remediation_evidence_upload(
    request: Request, verification_id: str, file: UploadFile = File(...),
    notes: str = Form(""), source_type: str = Form("USER_UPLOAD"),
    source_reference: str = Form(""), acquisition_method: str = Form("UPLOAD"),
    collected_at: str = Form(""), csrf_token: str = Form(...),
):
    _require_role(request, "operator")
    _verify_csrf(request, csrf_token)
    content = await file.read(MAX_EVIDENCE_BYTES + 1)
    if len(content) > MAX_EVIDENCE_BYTES:
        raise HTTPException(413, f"증거 파일은 최대 {MAX_EVIDENCE_BYTES // (1024 * 1024)}MB입니다.")
    try:
        created = store_verification_evidence(
            DB_PATH, EVIDENCE_DIR, verification_id=verification_id, filename=file.filename or "evidence.bin",
            content=content, notes=_bounded_text(notes, "notes", 1500), actor=_actor(request),
            max_bytes=MAX_EVIDENCE_BYTES,
            source_type=_bounded_text(source_type, "source_type", 80),
            source_reference=_bounded_text(source_reference, "source_reference", 1000),
            acquisition_method=_bounded_text(acquisition_method, "acquisition_method", 80),
            collected_at=_bounded_text(collected_at, "collected_at", 64),
        )
        if EVIDENCE_SCANNER_MODE == "clamscan":
            create_background_job(
                DB_PATH, job_type="EVIDENCE_SCAN", payload={"evidence_id": created.get("evidence_id")},
                requested_by=_actor(request), priority=20, max_attempts=3,
                dedupe_key=f"evidence-scan:{created.get('evidence_id')}",
            )
        else:
            created = scan_evidence_artifact(
                DB_PATH, EVIDENCE_DIR, str(created.get("evidence_id")), mode=EVIDENCE_SCANNER_MODE,
                clamscan_path=EVIDENCE_CLAMSCAN_PATH, timeout_seconds=EVIDENCE_SCAN_TIMEOUT_SECONDS,
                actor=_actor(request),
            )
        _queue_webhook(
            "remediation.evidence_uploaded",
            {"evidence_id": created.get("evidence_id"), "verification_id": verification_id,
             "finding_id": created.get("finding_id"), "sha256": created.get("sha256"),
             "scan_status": created.get("scan_status")},
            _actor(request),
        )
    except KeyError as exc:
        raise HTTPException(404, "조치 검증 요청을 찾을 수 없습니다.") from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return RedirectResponse(f"/finding/{created['finding_id']}?notice=evidence_uploaded", status_code=303)

@router.get("/evidence/{evidence_id}/download")
def remediation_evidence_download(request: Request, evidence_id: str):
    _require_role(request, "operator")
    artifact = get_evidence_artifact(DB_PATH, evidence_id)
    if not artifact:
        raise HTTPException(404, "증거 파일을 찾을 수 없습니다.")
    integrity = verify_evidence_artifact(EVIDENCE_DIR, artifact)
    if not integrity.get("valid"):
        raise HTTPException(409, "증거 파일 무결성 검증에 실패했습니다.")
    if not evidence_download_allowed(artifact, require_clean=EVIDENCE_REQUIRE_CLEAN):
        raise HTTPException(423, f"증거 파일은 검사 완료 또는 관리자 면제 후 다운로드할 수 있습니다. 현재 상태: {artifact.get('scan_status') or 'PENDING'}")
    path = resolve_evidence_path(EVIDENCE_DIR, artifact)
    record_evidence_access(DB_PATH, evidence_id, actor=_actor(request), purpose="UI download")
    return FileResponse(
        path, filename=str(artifact.get("original_filename") or evidence_id),
        media_type="application/octet-stream",
        headers={"X-Content-Type-Options": "nosniff", "Cache-Control": "no-store"},
    )

@router.post("/evidence/{evidence_id}/scan")
def remediation_evidence_scan_ui(request: Request, evidence_id: str, csrf_token: str = Form(...)):
    _require_role(request, "admin")
    _verify_csrf(request, csrf_token)
    try:
        item = scan_evidence_artifact(
            DB_PATH, EVIDENCE_DIR, evidence_id, mode=EVIDENCE_SCANNER_MODE,
            clamscan_path=EVIDENCE_CLAMSCAN_PATH, timeout_seconds=EVIDENCE_SCAN_TIMEOUT_SECONDS,
            actor=_actor(request),
        )
    except KeyError as exc:
        raise HTTPException(404, "증거 파일을 찾을 수 없습니다.") from exc
    return RedirectResponse(f"/finding/{item['finding_id']}?notice=evidence_scanned", status_code=303)

@router.post("/evidence/{evidence_id}/scan-waiver")
def remediation_evidence_scan_waiver_ui(
    request: Request, evidence_id: str, reason: str = Form(...), csrf_token: str = Form(...)
):
    _require_role(request, "admin")
    _verify_csrf(request, csrf_token)
    try:
        item = waive_evidence_scan(DB_PATH, evidence_id, actor=_actor(request), reason=_bounded_text(reason, "reason", 1500))
    except KeyError as exc:
        raise HTTPException(404, "증거 파일을 찾을 수 없습니다.") from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return RedirectResponse(f"/finding/{item['finding_id']}?notice=evidence_scan_waived", status_code=303)

@router.post("/evidence/{evidence_id}/custody-transfer")
def remediation_evidence_custody_transfer_ui(
    request: Request, evidence_id: str, to_custodian: str = Form(...),
    purpose: str = Form(...), csrf_token: str = Form(...),
):
    _require_role(request, "operator")
    _verify_csrf(request, csrf_token)
    try:
        item = transfer_evidence_custody(
            DB_PATH, evidence_id, actor=_actor(request),
            to_custodian=_bounded_text(to_custodian, "to_custodian", 200),
            purpose=_bounded_text(purpose, "purpose", 1500),
        )
    except KeyError as exc:
        raise HTTPException(404, "증거 파일을 찾을 수 없습니다.") from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return RedirectResponse(f"/finding/{item['finding_id']}?notice=evidence_transferred", status_code=303)

@router.post("/evidence/{evidence_id}/retire")
def remediation_evidence_retire_ui(
    request: Request, evidence_id: str, reason: str = Form(...), csrf_token: str = Form(...),
):
    _require_role(request, "operator")
    _verify_csrf(request, csrf_token)
    try:
        item = retire_evidence_artifact(
            DB_PATH, evidence_id, actor=_actor(request), reason=_bounded_text(reason, "reason", 1500)
        )
    except KeyError as exc:
        raise HTTPException(404, "증거 파일을 찾을 수 없습니다.") from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    _queue_webhook(
        "remediation.evidence_retired",
        {"evidence_id": evidence_id, "verification_id": item.get("verification_id"),
         "finding_id": item.get("finding_id")},
        _actor(request),
    )
    return RedirectResponse(f"/finding/{item['finding_id']}?notice=evidence_retired", status_code=303)

@router.post("/verifications/{verification_id}/decision")
def remediation_verification_decision(
    request: Request, verification_id: str, decision: str = Form(...), decision_note: str = Form(""),
    csrf_token: str = Form(...),
):
    _require_role(request, "approver")
    _verify_csrf(request, csrf_token)
    try:
        normalized = str(decision or "").strip().upper()
        note = _bounded_text(decision_note, "decision_note", 4000)
        if normalized == "REJECT" and not note:
            raise ValueError("반려 시 사유를 입력해야 합니다.")
        updated = decide_remediation_verification_request(
            DB_PATH, verification_id, decision=normalized, decision_note=note, actor=_actor(request),
        )
        rescore_all(audit=False, actor=_actor(request))
        _queue_webhook(
            "remediation.verification_decided",
            {"verification_id": verification_id, "finding_id": updated.get("finding_id"),
             "status": updated.get("status"), "decision_note": note},
            _actor(request),
        )
    except KeyError as exc:
        raise HTTPException(404, "조치 검증 요청을 찾을 수 없습니다.") from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except ConcurrencyError as exc:
        raise HTTPException(409, str(exc)) from exc
    return RedirectResponse("/verifications?notice=verification_decided", status_code=303)

@router.get("/approvals", response_class=HTMLResponse)
def approvals_page(request: Request, status: str = "", notice: str = ""):
    _require_role(request, "operator")
    normalized = str(status or "").strip().upper()
    if normalized and normalized not in {"PENDING", "APPROVED", "REJECTED", "CANCELLED"}:
        raise HTTPException(400, "허용되지 않은 승인 상태입니다.")
    return templates.TemplateResponse(
        request=request,
        name="approvals.html",
        context={
            "requests": list_risk_approval_requests(DB_PATH, status=normalized, limit=500),
            "vex_requests": list_vex_approval_requests(str(DB_PATH), status=normalized, limit=500),
            "asset_merge_requests": list_asset_merge_requests(DB_PATH, status=normalized, limit=500),
            "asset_merge_rollback_requests": list_asset_merge_rollback_requests(DB_PATH, status=normalized, limit=500),
            "status_filter": normalized,
            "notice_message": NOTICE_MESSAGES.get(notice, ""),
        },
    )

@router.post("/approvals/{request_id}/decision")
def approval_decision(
    request: Request, request_id: str, decision: str = Form(...),
    decision_note: str = Form(""), csrf_token: str = Form(...),
):
    _require_role(request, "approver")
    _verify_csrf(request, csrf_token)
    try:
        note = _bounded_text(decision_note, "decision_note", 1500)
        if str(decision).upper() == "REJECTED" and not note:
            raise ValueError("반려 시 사유를 입력해야 합니다.")
        approval = decide_risk_approval_request(
            DB_PATH, request_id, decision=decision, decided_by=_actor(request), decision_note=note,
        )
        rescore_all(audit=False, actor=_actor(request))
        _queue_webhook(
            "risk_acceptance.decided",
            {"request_id": request_id, "finding_id": approval.get("finding_id"), "status": approval.get("status"), "decision_note": note},
            _actor(request),
        )
    except KeyError as exc:
        raise HTTPException(404, "승인 요청을 찾을 수 없습니다.") from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except ConcurrencyError as exc:
        raise HTTPException(409, str(exc)) from exc
    return RedirectResponse(url="/approvals?notice=approval_decided", status_code=303)

@router.get("/api/v1/verifications")
def api_list_remediation_verifications(request: Request, status: str = "", finding_id: str = ""):
    _require_role(request, "viewer")
    return {"items": list_remediation_verification_requests(DB_PATH, status=status, finding_id=finding_id, limit=1000)}

@router.post("/api/v1/findings/{finding_id}/verification-requests")
def api_create_remediation_verification(
    request: Request, finding_id: str, payload: ApiRemediationVerificationRequest
):
    _require_role(request, "operator")
    _require_api_token(request)
    try:
        created = create_remediation_verification_request(
            DB_PATH, finding_id, method=payload.method,
            evidence_note=_bounded_text(payload.evidence_note, "evidence_note", 4000),
            actor=_actor(request), expected_version=payload.expected_row_version,
            absence_threshold=VERIFICATION_ABSENCE_SCANS,
        )
    except KeyError as exc:
        raise HTTPException(404, "해당 취약점을 찾을 수 없습니다.") from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except ConcurrencyError as exc:
        raise HTTPException(409, str(exc)) from exc
    _queue_webhook("remediation.verification_requested", {"verification_id": created.get("verification_id"), "finding_id": finding_id}, _actor(request))
    return created

@router.get("/api/v1/verifications/{verification_id}/evidence")
def api_list_remediation_evidence(request: Request, verification_id: str):
    _require_api_token(request)
    _require_role(request, "operator")
    return {"items": list_evidence_artifacts(DB_PATH, verification_id=verification_id, limit=1000)}

@router.post("/api/v1/verifications/{verification_id}/evidence")
async def api_upload_remediation_evidence(
    request: Request, verification_id: str, file: UploadFile = File(...), notes: str = Form(""),
    source_type: str = Form("USER_UPLOAD"), source_reference: str = Form(""),
    acquisition_method: str = Form("UPLOAD"), collected_at: str = Form(""),
):
    _require_api_token(request)
    _require_role(request, "operator")
    content = await file.read(MAX_EVIDENCE_BYTES + 1)
    if len(content) > MAX_EVIDENCE_BYTES:
        raise HTTPException(413, f"증거 파일은 최대 {MAX_EVIDENCE_BYTES // (1024 * 1024)}MB입니다.")
    try:
        created = store_verification_evidence(
            DB_PATH, EVIDENCE_DIR, verification_id=verification_id, filename=file.filename or "evidence.bin",
            content=content, notes=_bounded_text(notes, "notes", 1500), actor=_actor(request),
            max_bytes=MAX_EVIDENCE_BYTES,
            source_type=_bounded_text(source_type, "source_type", 80),
            source_reference=_bounded_text(source_reference, "source_reference", 1000),
            acquisition_method=_bounded_text(acquisition_method, "acquisition_method", 80),
            collected_at=_bounded_text(collected_at, "collected_at", 64),
        )
        if EVIDENCE_SCANNER_MODE == "clamscan":
            create_background_job(
                DB_PATH, job_type="EVIDENCE_SCAN", payload={"evidence_id": created.get("evidence_id")},
                requested_by=_actor(request), priority=20, max_attempts=3,
                dedupe_key=f"evidence-scan:{created.get('evidence_id')}",
            )
        else:
            created = scan_evidence_artifact(
                DB_PATH, EVIDENCE_DIR, str(created.get("evidence_id")), mode=EVIDENCE_SCANNER_MODE,
                clamscan_path=EVIDENCE_CLAMSCAN_PATH, timeout_seconds=EVIDENCE_SCAN_TIMEOUT_SECONDS,
                actor=_actor(request),
            )
    except KeyError as exc:
        raise HTTPException(404, "조치 검증 요청을 찾을 수 없습니다.") from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    _queue_webhook(
        "remediation.evidence_uploaded",
        {"evidence_id": created.get("evidence_id"), "verification_id": verification_id,
         "finding_id": created.get("finding_id"), "sha256": created.get("sha256"),
         "scan_status": created.get("scan_status")},
        _actor(request),
    )
    return created

@router.get("/api/v1/evidence/{evidence_id}/download")
def api_download_remediation_evidence(request: Request, evidence_id: str):
    _require_api_token(request)
    _require_role(request, "operator")
    artifact = get_evidence_artifact(DB_PATH, evidence_id)
    if not artifact:
        raise HTTPException(404, "증거 파일을 찾을 수 없습니다.")
    if not verify_evidence_artifact(EVIDENCE_DIR, artifact).get("valid"):
        raise HTTPException(409, "증거 파일 무결성 검증에 실패했습니다.")
    if not evidence_download_allowed(artifact, require_clean=EVIDENCE_REQUIRE_CLEAN):
        raise HTTPException(423, f"증거 파일은 검사 완료 또는 관리자 면제 후 다운로드할 수 있습니다. 현재 상태: {artifact.get('scan_status') or 'PENDING'}")
    path = resolve_evidence_path(EVIDENCE_DIR, artifact)
    record_evidence_access(DB_PATH, evidence_id, actor=_actor(request), purpose="API download")
    return FileResponse(
        path,
        filename=str(artifact.get("original_filename") or evidence_id),
        media_type="application/octet-stream",
        headers={"X-Content-Type-Options": "nosniff", "Cache-Control": "no-store"},
    )

@router.get("/api/v1/evidence/{evidence_id}/custody")
def api_evidence_custody(request: Request, evidence_id: str):
    _require_role(request, "viewer")
    try:
        return {
            "integrity": verify_evidence_custody_chain(DB_PATH, evidence_id),
            "items": list_evidence_custody_events(DB_PATH, evidence_id, limit=1000),
        }
    except KeyError as exc:
        raise HTTPException(404, "증거 파일을 찾을 수 없습니다.") from exc

@router.post("/api/v1/evidence/{evidence_id}/custody-transfer")
def api_evidence_custody_transfer(request: Request, evidence_id: str, payload: ApiEvidenceCustodyTransfer):
    _require_api_token(request)
    _require_role(request, "operator")
    try:
        return transfer_evidence_custody(
            DB_PATH, evidence_id, actor=_actor(request),
            to_custodian=_bounded_text(payload.to_custodian, "to_custodian", 200),
            purpose=_bounded_text(payload.purpose, "purpose", 1500),
        )
    except KeyError as exc:
        raise HTTPException(404, "증거 파일을 찾을 수 없습니다.") from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc

@router.post("/api/v1/evidence/{evidence_id}/scan")
def api_scan_remediation_evidence(request: Request, evidence_id: str):
    _require_api_token(request)
    _require_role(request, "admin")
    try:
        return scan_evidence_artifact(
            DB_PATH, EVIDENCE_DIR, evidence_id, mode=EVIDENCE_SCANNER_MODE,
            clamscan_path=EVIDENCE_CLAMSCAN_PATH, timeout_seconds=EVIDENCE_SCAN_TIMEOUT_SECONDS,
            actor=_actor(request),
        )
    except KeyError as exc:
        raise HTTPException(404, "증거 파일을 찾을 수 없습니다.") from exc

@router.post("/api/v1/evidence/{evidence_id}/scan-waiver")
def api_waive_remediation_evidence_scan(request: Request, evidence_id: str, payload: ApiEvidenceScanWaiver):
    _require_api_token(request)
    _require_role(request, "admin")
    try:
        return waive_evidence_scan(
            DB_PATH, evidence_id, actor=_actor(request), reason=_bounded_text(payload.reason, "reason", 1500)
        )
    except KeyError as exc:
        raise HTTPException(404, "증거 파일을 찾을 수 없습니다.") from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc

@router.post("/api/v1/evidence/{evidence_id}/retire")
def api_retire_remediation_evidence(request: Request, evidence_id: str, payload: ApiEvidenceRetire):
    _require_api_token(request)
    _require_role(request, "operator")
    try:
        item = retire_evidence_artifact(
            DB_PATH, evidence_id, actor=_actor(request), reason=_bounded_text(payload.reason, "reason", 1500)
        )
    except KeyError as exc:
        raise HTTPException(404, "증거 파일을 찾을 수 없습니다.") from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    _queue_webhook(
        "remediation.evidence_retired",
        {"evidence_id": evidence_id, "verification_id": item.get("verification_id"),
         "finding_id": item.get("finding_id")},
        _actor(request),
    )
    return item

@router.get("/api/v1/system/evidence-integrity")
def api_evidence_integrity(request: Request):
    _require_api_token(request)
    _require_role(request, "admin")
    return verify_evidence_store(DB_PATH, EVIDENCE_DIR)

@router.post("/api/v1/verifications/{verification_id}/decision")
def api_decide_remediation_verification(
    request: Request, verification_id: str, payload: ApiRemediationVerificationDecision
):
    _require_role(request, "approver")
    _require_api_token(request)
    try:
        normalized = str(payload.decision or "").strip().upper()
        note = _bounded_text(payload.decision_note, "decision_note", 4000)
        if normalized == "REJECT" and not note:
            raise ValueError("반려 시 사유가 필요합니다.")
        updated = decide_remediation_verification_request(
            DB_PATH, verification_id, decision=normalized, decision_note=note, actor=_actor(request),
        )
        rescore_all(audit=False, actor=_actor(request))
    except KeyError as exc:
        raise HTTPException(404, "조치 검증 요청을 찾을 수 없습니다.") from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except ConcurrencyError as exc:
        raise HTTPException(409, str(exc)) from exc
    _queue_webhook("remediation.verification_decided", {"verification_id": verification_id, "finding_id": updated.get("finding_id"), "status": updated.get("status")}, _actor(request))
    return updated

@router.post("/api/v1/findings/{finding_id}/risk-acceptance-requests")
def api_request_risk_acceptance(request: Request, finding_id: str, payload: ApiRiskAcceptanceRequest):
    _require_role(request, "operator")
    _require_api_token(request)
    try:
        reason = _bounded_text(payload.reason, "reason", MAX_REASON)
        notes = _bounded_text(payload.notes, "notes", MAX_NOTES)
        expiry = _date_text(payload.exception_expiry, "exception_expiry")
        if not reason or not expiry:
            raise ValueError("위험수용 사유와 만료일이 필요합니다.")
        if parse_date(expiry) < date.today():
            raise ValueError("예외 만료일은 오늘 이후여야 합니다.")
        approval = create_risk_approval_request(
            DB_PATH, finding_id, requested_by=_actor(request), reason=reason, exception_expiry=expiry,
            notes=notes, expected_version=payload.expected_row_version,
        )
    except KeyError as exc:
        raise HTTPException(404, "해당 항목을 찾을 수 없습니다.") from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except ConcurrencyError as exc:
        raise HTTPException(409, str(exc)) from exc
    _queue_webhook(
        "risk_acceptance.requested",
        {"request_id": approval.get("request_id"), "finding_id": finding_id, "exception_expiry": expiry},
        _actor(request),
    )
    return approval

@router.post("/api/v1/approvals/{request_id}/decision")
def api_decide_approval(request: Request, request_id: str, payload: ApiApprovalDecision):
    _require_role(request, "approver")
    _require_api_token(request)
    try:
        decision = str(payload.decision or "").strip().upper()
        note = _bounded_text(payload.decision_note, "decision_note", 1500)
        if decision == "REJECTED" and not note:
            raise ValueError("반려 시 사유를 입력해야 합니다.")
        approval = decide_risk_approval_request(
            DB_PATH, request_id, decision=decision, decided_by=_actor(request), decision_note=note
        )
    except KeyError as exc:
        raise HTTPException(404, "승인 요청을 찾을 수 없습니다.") from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except ConcurrencyError as exc:
        raise HTTPException(409, str(exc)) from exc
    rescore_all(audit=False, actor=_actor(request))
    _queue_webhook(
        "risk_acceptance.decided",
        {"request_id": request_id, "finding_id": approval.get("finding_id"), "status": approval.get("status"), "decision_note": note},
        _actor(request),
    )
    return approval

@router.get("/api/v1/approvals")
def api_approvals(request: Request, status: str = "", limit: int = 200):
    _require_role(request, "operator")
    return {"items": list_risk_approval_requests(DB_PATH, status=status, limit=limit)}
