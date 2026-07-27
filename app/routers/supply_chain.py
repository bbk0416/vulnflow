from __future__ import annotations

"""Domain routes extracted from :mod:`app.main`.

The route module is intentionally dependency-injected by ``app.routers`` so the
historical compatibility surface in ``app.main`` remains available without creating
internal import cycles.
"""

from datetime import date
from pathlib import Path
from typing import Any

from fastapi import APIRouter, File, Form, Header, HTTPException, Request, UploadFile
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


ROUTE_NAMES = ('upload_sbom', 'upload_sbom_compare', 'sbom_list_page', 'sbom_detail_page', 'sbom_reconcile_ui', 'sbom_osv_scan_ui', 'osv_match_decision_ui', 'sbom_link_decision_ui', 'sbom_vex_create_ui', 'vex_request_ui', 'vex_decision_ui', 'sbom_vex_export', 'api_import_sbom', 'api_list_sboms', 'api_get_sbom', 'api_reconcile_sbom', 'api_queue_osv_scan', 'api_list_osv_scans', 'api_list_osv_matches', 'api_decide_osv_match', 'api_decide_sbom_link', 'api_create_vex', 'api_request_vex', 'api_decide_vex', 'api_export_vex')

@router.post("/upload/sbom", response_class=HTMLResponse)
async def upload_sbom(request: Request, file: UploadFile = File(...), notes: str = Form(""), csrf_token: str = Form(...)):
    _require_role(request, "operator")
    _verify_csrf(request, csrf_token)
    content = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, "파일 크기는 최대 5MB입니다.")
    try:
        parsed = parse_cyclonedx_json(io.BytesIO(content))
        result = store_cyclonedx_document(
            str(DB_PATH), parsed, source_filename=file.filename or "sbom.cdx.json",
            actor=_actor(request), notes=_bounded_text(notes, "notes", 1500),
        )
    except SbomError as exc:
        raise HTTPException(400, str(exc)) from exc
    return RedirectResponse(url=f"/sboms/{result['sbom_id']}?notice=imported", status_code=303)

@router.post("/upload/sbom-compare", response_class=HTMLResponse)
async def upload_sbom_compare(
    request: Request,
    before_file: UploadFile = File(...),
    after_file: UploadFile = File(...),
    csrf_token: str = Form(...),
):
    _require_role(request, "operator")
    _verify_csrf(request, csrf_token)
    before_content = await before_file.read(MAX_UPLOAD_BYTES + 1)
    after_content = await after_file.read(MAX_UPLOAD_BYTES + 1)
    if len(before_content) > MAX_UPLOAD_BYTES or len(after_content) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, "각 파일 크기는 최대 5MB입니다.")
    try:
        before = parse_cyclonedx_json(io.BytesIO(before_content))
        after = parse_cyclonedx_json(io.BytesIO(after_content))
        result = compare_cyclonedx(before, after)
    except SbomError as exc:
        raise HTTPException(400, str(exc)) from exc
    return templates.TemplateResponse(
        request=request,
        name="sbom_compare.html",
        context={"result": result, "before_filename": before_file.filename, "after_filename": after_file.filename},
    )

@router.get("/sboms", response_class=HTMLResponse)
def sbom_list_page(request: Request, status: str = "ACTIVE"):
    return templates.TemplateResponse(
        request=request, name="sboms.html",
        context={"sboms": list_sbom_documents(str(DB_PATH), status=status, limit=1000), "status": status},
    )

@router.get("/sboms/{sbom_id}", response_class=HTMLResponse)
def sbom_detail_page(request: Request, sbom_id: str, notice: str = ""):
    item = get_sbom_document(str(DB_PATH), sbom_id)
    if not item:
        raise HTTPException(404, "SBOM 제품 릴리스를 찾을 수 없습니다.")
    return templates.TemplateResponse(
        request=request, name="sbom_detail.html",
        context={
            "item": item, "notice": notice, "vex_states": sorted(VEX_STATES),
            "vex_justifications": sorted(v for v in VEX_JUSTIFICATIONS if v),
            "vex_responses": sorted(VEX_RESPONSES),
        },
    )

@router.post("/sboms/{sbom_id}/reconcile")
def sbom_reconcile_ui(request: Request, sbom_id: str, csrf_token: str = Form(...)):
    _require_role(request, "operator")
    _verify_csrf(request, csrf_token)
    try:
        result = reconcile_sbom_findings(str(DB_PATH), sbom_id, actor=_actor(request))
    except KeyError as exc:
        raise HTTPException(404, "SBOM 제품 릴리스를 찾을 수 없습니다.") from exc
    return RedirectResponse(url=f"/sboms/{sbom_id}?notice=linked-{result['inserted']}", status_code=303)

@router.post("/sboms/{sbom_id}/osv-scan")
def sbom_osv_scan_ui(request: Request, sbom_id: str, csrf_token: str = Form(...)):
    _require_role(request, "operator")
    _verify_csrf(request, csrf_token)
    if not get_sbom_document(str(DB_PATH), sbom_id):
        raise HTTPException(404, "SBOM 제품 릴리스를 찾을 수 없습니다.")
    job = create_background_job(
        DB_PATH, job_type="OSV_SCAN", payload={"sbom_id": sbom_id}, requested_by=_actor(request),
        priority=6, max_attempts=JOB_MAX_ATTEMPTS, dedupe_key=f"osv-scan:{sbom_id}",
    )
    return RedirectResponse(url=f"/sboms/{sbom_id}?notice=osv-job-{job['job_id']}", status_code=303)

@router.post("/osv-matches/{match_id}/decision")
def osv_match_decision_ui(
    request: Request, match_id: str, decision: str = Form(...), reason: str = Form(""),
    sbom_id: str = Form(...), csrf_token: str = Form(...),
):
    _require_role(request, "operator")
    _verify_csrf(request, csrf_token)
    try:
        item = decide_osv_match(
            str(DB_PATH), match_id, decision=decision,
            reason=_bounded_text(reason, "reason", 1500), actor=_actor(request),
        )
        if str(decision).upper() == "CONFIRM":
            rescore_all(actor=_actor(request))
        _queue_webhook("sbom.osv_candidate_decided", {
            "match_id": match_id, "sbom_id": item.get("sbom_id"), "decision": str(decision).upper(),
            "finding_id": item.get("finding_id"),
        }, _actor(request))
    except KeyError as exc:
        raise HTTPException(404, "OSV 후보를 찾을 수 없습니다.") from exc
    except SbomError as exc:
        raise HTTPException(400, str(exc)) from exc
    return RedirectResponse(url=f"/sboms/{sbom_id}?notice=osv-decided", status_code=303)

@router.post("/sbom-links/{link_id}/decision")
def sbom_link_decision_ui(
    request: Request, link_id: str, decision: str = Form(...), sbom_id: str = Form(...), csrf_token: str = Form(...),
):
    _require_role(request, "operator")
    _verify_csrf(request, csrf_token)
    try:
        decide_sbom_finding_link(str(DB_PATH), link_id, decision=decision, actor=_actor(request))
    except KeyError as exc:
        raise HTTPException(404, "SBOM finding 연결 후보를 찾을 수 없습니다.") from exc
    except SbomError as exc:
        raise HTTPException(400, str(exc)) from exc
    return RedirectResponse(url=f"/sboms/{sbom_id}?notice=link-decided", status_code=303)

@router.post("/sboms/{sbom_id}/vex")
def sbom_vex_create_ui(
    request: Request, sbom_id: str, component_id: str = Form(...), cve_id: str = Form(...),
    analysis_state: str = Form(...), justification: str = Form(""), responses: list[str] = Form([]),
    impact_statement: str = Form(""), action_statement: str = Form(""), detail: str = Form(""),
    finding_id: str = Form(""), csrf_token: str = Form(...),
):
    _require_role(request, "operator")
    _verify_csrf(request, csrf_token)
    try:
        created = create_vex_revision(
            str(DB_PATH), sbom_id=sbom_id, component_id=component_id, cve_id=cve_id,
            analysis_state=analysis_state, justification=justification, responses=responses,
            impact_statement=_bounded_text(impact_statement, "impact_statement", 4000),
            action_statement=_bounded_text(action_statement, "action_statement", 4000),
            detail=_bounded_text(detail, "detail", 4000), finding_id=finding_id or None, actor=_actor(request),
        )
    except KeyError as exc:
        raise HTTPException(404, "SBOM 구성요소를 찾을 수 없습니다.") from exc
    except SbomError as exc:
        raise HTTPException(400, str(exc)) from exc
    return RedirectResponse(url=f"/sboms/{sbom_id}?notice=vex-draft-{created['vex_id']}", status_code=303)

@router.post("/vex/{vex_id}/request")
def vex_request_ui(request: Request, vex_id: str, csrf_token: str = Form(...)):
    _require_role(request, "operator")
    _verify_csrf(request, csrf_token)
    try:
        item = request_vex_approval(str(DB_PATH), vex_id, actor=_actor(request))
    except KeyError as exc:
        raise HTTPException(404, "VEX 문장을 찾을 수 없습니다.") from exc
    except SbomError as exc:
        raise HTTPException(400, str(exc)) from exc
    return RedirectResponse(url=f"/sboms/{item['sbom_id']}?notice=vex-requested", status_code=303)

@router.post("/vex/{vex_id}/decision")
def vex_decision_ui(
    request: Request, vex_id: str, decision: str = Form(...), decision_note: str = Form(""), csrf_token: str = Form(...),
):
    _require_role(request, "approver")
    _verify_csrf(request, csrf_token)
    try:
        item = decide_vex_statement(
            str(DB_PATH), vex_id, decision=decision,
            decision_note=_bounded_text(decision_note, "decision_note", 4000), actor=_actor(request),
        )
    except KeyError as exc:
        raise HTTPException(404, "VEX 문장을 찾을 수 없습니다.") from exc
    except SbomError as exc:
        raise HTTPException(400, str(exc)) from exc
    return RedirectResponse(url=f"/sboms/{item['sbom_id']}?notice=vex-decided", status_code=303)

@router.get("/sboms/{sbom_id}/vex.cdx.json")
def sbom_vex_export(request: Request, sbom_id: str):
    _require_role(request, "viewer")
    try:
        payload = export_cyclonedx_vex(str(DB_PATH), sbom_id)
    except KeyError as exc:
        raise HTTPException(404, "SBOM 제품 릴리스를 찾을 수 없습니다.") from exc
    return JSONResponse(payload, headers={"Content-Disposition": f'attachment; filename="{sbom_id}_vex.cdx.json"'})

@router.post("/api/v1/sboms")
async def api_import_sbom(request: Request, file: UploadFile = File(...), notes: str = Form("")):
    _require_api_token(request)
    _require_role(request, "operator")
    content = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, "파일 크기는 최대 5MB입니다.")
    try:
        parsed = parse_cyclonedx_json(io.BytesIO(content))
        return store_cyclonedx_document(
            str(DB_PATH), parsed, source_filename=file.filename or "sbom.cdx.json",
            actor=_actor(request), notes=_bounded_text(notes, "notes", 1500),
        )
    except SbomError as exc:
        raise HTTPException(400, str(exc)) from exc

@router.get("/api/v1/sboms")
def api_list_sboms(request: Request, status: str = "ACTIVE"):
    _require_role(request, "viewer")
    return {"items": list_sbom_documents(str(DB_PATH), status=status, limit=1000)}

@router.get("/api/v1/sboms/{sbom_id}")
def api_get_sbom(request: Request, sbom_id: str):
    _require_role(request, "viewer")
    item = get_sbom_document(str(DB_PATH), sbom_id)
    if not item:
        raise HTTPException(404, "SBOM 제품 릴리스를 찾을 수 없습니다.")
    return item

@router.post("/api/v1/sboms/{sbom_id}/reconcile")
def api_reconcile_sbom(request: Request, sbom_id: str):
    _require_api_token(request)
    _require_role(request, "operator")
    try:
        return reconcile_sbom_findings(str(DB_PATH), sbom_id, actor=_actor(request))
    except KeyError as exc:
        raise HTTPException(404, "SBOM 제품 릴리스를 찾을 수 없습니다.") from exc

@router.post("/api/v1/sboms/{sbom_id}/osv-scan")
def api_queue_osv_scan(
    request: Request, sbom_id: str,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
):
    _require_api_token(request)
    _require_role(request, "operator")
    if not get_sbom_document(str(DB_PATH), sbom_id):
        raise HTTPException(404, "SBOM 제품 릴리스를 찾을 수 없습니다.")
    try:
        return _public_job(create_background_job(
            DB_PATH, job_type="OSV_SCAN", payload={"sbom_id": sbom_id}, requested_by=_actor(request),
            priority=6, max_attempts=JOB_MAX_ATTEMPTS, dedupe_key=f"osv-scan:{sbom_id}",
            idempotency_key=idempotency_key,
            idempotency_request={"job_type": "OSV_SCAN", "sbom_id": sbom_id},
            idempotency_retention_days=IDEMPOTENCY_RETENTION_DAYS,
        ))
    except IdempotencyConflict as exc:
        raise HTTPException(409, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc

@router.get("/api/v1/sboms/{sbom_id}/osv-scans")
def api_list_osv_scans(request: Request, sbom_id: str):
    _require_role(request, "viewer")
    return {"items": list_osv_scans(str(DB_PATH), sbom_id=sbom_id, limit=200)}

@router.get("/api/v1/sboms/{sbom_id}/osv-matches")
def api_list_osv_matches(request: Request, sbom_id: str, status: str = ""):
    _require_role(request, "viewer")
    return {"items": list_osv_matches(str(DB_PATH), sbom_id=sbom_id, status=status, limit=5000)}

@router.post("/api/v1/osv-matches/{match_id}/decision")
def api_decide_osv_match(request: Request, match_id: str, payload: ApiOsvMatchDecision):
    _require_api_token(request)
    _require_role(request, "operator")
    try:
        item = decide_osv_match(
            str(DB_PATH), match_id, decision=payload.decision,
            reason=_bounded_text(payload.reason, "reason", 1500), actor=_actor(request),
        )
        if str(payload.decision).upper() == "CONFIRM":
            rescore_all(actor=_actor(request))
        return item
    except KeyError as exc:
        raise HTTPException(404, "OSV 후보를 찾을 수 없습니다.") from exc
    except SbomError as exc:
        raise HTTPException(400, str(exc)) from exc

@router.post("/api/v1/sbom-links/{link_id}/decision")
def api_decide_sbom_link(request: Request, link_id: str, payload: ApiSbomLinkDecision):
    _require_api_token(request)
    _require_role(request, "operator")
    try:
        return decide_sbom_finding_link(str(DB_PATH), link_id, decision=payload.decision, actor=_actor(request))
    except KeyError as exc:
        raise HTTPException(404, "SBOM finding 연결 후보를 찾을 수 없습니다.") from exc
    except SbomError as exc:
        raise HTTPException(400, str(exc)) from exc

@router.post("/api/v1/sboms/{sbom_id}/vex")
def api_create_vex(request: Request, sbom_id: str, payload: ApiVexCreate):
    _require_api_token(request)
    _require_role(request, "operator")
    try:
        return create_vex_revision(
            str(DB_PATH), sbom_id=sbom_id, component_id=payload.component_id, cve_id=payload.cve_id,
            analysis_state=payload.analysis_state, justification=payload.justification, responses=payload.responses,
            impact_statement=payload.impact_statement, action_statement=payload.action_statement, detail=payload.detail,
            finding_id=payload.finding_id or None, actor=_actor(request),
        )
    except KeyError as exc:
        raise HTTPException(404, "SBOM 구성요소를 찾을 수 없습니다.") from exc
    except SbomError as exc:
        raise HTTPException(400, str(exc)) from exc

@router.post("/api/v1/vex/{vex_id}/request")
def api_request_vex(request: Request, vex_id: str):
    _require_api_token(request)
    _require_role(request, "operator")
    try:
        return request_vex_approval(str(DB_PATH), vex_id, actor=_actor(request))
    except KeyError as exc:
        raise HTTPException(404, "VEX 문장을 찾을 수 없습니다.") from exc
    except SbomError as exc:
        raise HTTPException(400, str(exc)) from exc

@router.post("/api/v1/vex/{vex_id}/decision")
def api_decide_vex(request: Request, vex_id: str, payload: ApiVexDecision):
    _require_api_token(request)
    _require_role(request, "approver")
    try:
        return decide_vex_statement(
            str(DB_PATH), vex_id, decision=payload.decision, decision_note=payload.decision_note, actor=_actor(request),
        )
    except KeyError as exc:
        raise HTTPException(404, "VEX 문장을 찾을 수 없습니다.") from exc
    except SbomError as exc:
        raise HTTPException(400, str(exc)) from exc

@router.get("/api/v1/sboms/{sbom_id}/vex")
def api_export_vex(request: Request, sbom_id: str):
    _require_role(request, "viewer")
    try:
        return export_cyclonedx_vex(str(DB_PATH), sbom_id)
    except KeyError as exc:
        raise HTTPException(404, "SBOM 제품 릴리스를 찾을 수 없습니다.") from exc
