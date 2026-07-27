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


ROUTE_NAMES = ('assets_page', 'assets_upload', 'asset_detail', 'asset_identities_page', 'asset_identifier_add_ui', 'asset_identity_merge_impact_ui', 'asset_identity_merge_request_ui', 'asset_identity_reject_ui', 'asset_merge_request_decision_ui', 'asset_merge_rollback_impact_ui', 'asset_merge_rollback_request_ui', 'asset_merge_rollback_decision_ui', 'exposure_groups_page', 'campaigns_page', 'campaigns_create', 'campaign_detail', 'campaign_members_add', 'campaign_member_remove', 'campaign_status_update', 'export_assets_csv', 'export_campaigns_csv', 'api_assets', 'api_assets_import', 'api_asset_detail', 'api_asset_identifiers', 'api_asset_identifier_add', 'api_asset_identity_candidates', 'api_asset_identity_merge_impact', 'api_asset_identity_merge_request', 'api_asset_identity_reject', 'api_asset_merge_requests', 'api_asset_merge_request_decision', 'api_asset_merge_history', 'api_asset_merge_rollback_impact', 'api_asset_merge_rollback_request', 'api_asset_merge_rollback_requests', 'api_asset_merge_rollback_decision', 'api_exposure_groups', 'api_campaigns', 'api_campaign_create', 'api_campaign_detail', 'api_campaign_members_add', 'api_campaign_member_remove', 'api_campaign_status')

@router.get("/assets", response_class=HTMLResponse)
def assets_page(request: Request, status: str = "ACTIVE", owner: str = "", query: str = "", notice: str = ""):
    assets = list_assets(DB_PATH, status=status, owner=owner, query=query, limit=1000)
    return templates.TemplateResponse(
        request=request, name="assets.html",
        context={"assets": assets, "status": status, "owner": owner, "query": query, "notice": notice},
    )

@router.post("/assets/upload")
async def assets_upload(request: Request, file: UploadFile = File(...), csrf_token: str = Form(...)):
    _require_role(request, "operator")
    _verify_csrf(request, csrf_token)
    if not (file.filename or "").lower().endswith(".csv"):
        raise HTTPException(400, "자산 인벤토리는 CSV 파일만 지원합니다.")
    content = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, "자산 CSV는 최대 5MB입니다.")
    try:
        rows = _parse_assets_csv(content)
        result = apply_asset_inventory(DB_PATH, rows, actor=_actor(request))
        rescore_all(actor=_actor(request))
        _queue_webhook("asset_inventory.imported", result, _actor(request))
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return RedirectResponse(
        f"/assets?notice=자산+{result['row_count']}건+반영,+취약점+{result['linked_findings']}건+연결", status_code=303
    )

@router.get("/asset/{asset_ref_id}", response_class=HTMLResponse)
def asset_detail(request: Request, asset_ref_id: str, notice: str = ""):
    asset = get_asset(DB_PATH, asset_ref_id)
    if not asset:
        raise HTTPException(404, "해당 자산을 찾을 수 없습니다.")
    notice_text = {
        "identifier_added": "자산 식별자를 추가했습니다.",
    }.get(notice, notice)
    return templates.TemplateResponse(
        request=request, name="asset.html", context={"asset": asset, "notice": notice_text}
    )

@router.get("/asset-identities", response_class=HTMLResponse)
def asset_identities_page(request: Request, status: str = "PENDING", notice: str = ""):
    try:
        candidates = list_asset_identity_candidates(DB_PATH, status=status, limit=1000)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return templates.TemplateResponse(
        request=request, name="asset_identities.html",
        context={
            "candidates": candidates, "status": status,
            "merge_history": list_asset_merge_history(DB_PATH, limit=200),
            "merge_requests": list_asset_merge_requests(DB_PATH, limit=200),
            "rollback_requests": list_asset_merge_rollback_requests(DB_PATH, limit=200),
            "notice": NOTICE_MESSAGES.get(notice, notice),
        },
    )

@router.post("/asset/{asset_ref_id}/identifiers")
def asset_identifier_add_ui(
    request: Request, asset_ref_id: str, identifier_type: str = Form(...), value: str = Form(...),
    scope: str = Form(""), confidence: int = Form(50), csrf_token: str = Form(...),
):
    _require_role(request, "operator")
    _verify_csrf(request, csrf_token)
    try:
        result = add_asset_identifier(
            DB_PATH, asset_ref_id, identifier_type=identifier_type, value=value, scope=scope,
            source="ui", confidence=confidence, actor=_actor(request),
        )
    except KeyError as exc:
        raise HTTPException(404, "해당 자산을 찾을 수 없습니다.") from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    if result.get("status") == "CANDIDATE":
        return RedirectResponse("/asset-identities?notice=identifier_conflict", status_code=303)
    return RedirectResponse(f"/asset/{asset_ref_id}?notice=identifier_added", status_code=303)

@router.get("/asset-identities/{candidate_id}/impact")
def asset_identity_merge_impact_ui(request: Request, candidate_id: str, target_asset_ref_id: str):
    _require_role(request, "operator")
    candidate = get_asset_identity_candidate(DB_PATH, candidate_id)
    if not candidate:
        raise HTTPException(404, "자산 식별 후보를 찾을 수 없습니다.")
    pair = {str(candidate["asset_ref_id_a"]), str(candidate["asset_ref_id_b"])}
    target = str(target_asset_ref_id or "").strip()
    if target not in pair:
        raise HTTPException(400, "대표 자산이 후보 자산 쌍에 포함되지 않습니다.")
    source = next(item for item in pair if item != target)
    try:
        return analyze_asset_merge(
            DB_PATH, source_asset_ref_id=source, target_asset_ref_id=target, candidate_id=candidate_id,
        )
    except KeyError as exc:
        raise HTTPException(404, "자산 또는 후보를 찾을 수 없습니다.") from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc

@router.post("/asset-identities/{candidate_id}/merge")
@router.post("/asset-identities/{candidate_id}/request-merge")
def asset_identity_merge_request_ui(
    request: Request, candidate_id: str, target_asset_ref_id: str = Form(...),
    reason: str = Form(...), csrf_token: str = Form(...),
):
    _require_role(request, "operator")
    _verify_csrf(request, csrf_token)
    candidate = get_asset_identity_candidate(DB_PATH, candidate_id)
    if not candidate:
        raise HTTPException(404, "자산 식별 후보를 찾을 수 없습니다.")
    pair = {str(candidate["asset_ref_id_a"]), str(candidate["asset_ref_id_b"])}
    target = str(target_asset_ref_id or "").strip()
    if target not in pair:
        raise HTTPException(400, "대표 자산이 후보 자산 쌍에 포함되지 않습니다.")
    source = next(item for item in pair if item != target)
    try:
        result = create_asset_merge_request(
            DB_PATH, source_asset_ref_id=source, target_asset_ref_id=target,
            reason=reason, requested_by=_actor(request), candidate_id=candidate_id,
        )
    except KeyError as exc:
        raise HTTPException(404, "자산 또는 후보를 찾을 수 없습니다.") from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    _queue_webhook("asset.merge_requested", {"request_id": result["request_id"]}, _actor(request))
    return RedirectResponse("/asset-identities?notice=asset_merge_requested", status_code=303)

@router.post("/asset-identities/{candidate_id}/reject")
def asset_identity_reject_ui(
    request: Request, candidate_id: str, reason: str = Form(...), csrf_token: str = Form(...),
):
    _require_role(request, "operator")
    _verify_csrf(request, csrf_token)
    try:
        result = reject_asset_identity_candidate(DB_PATH, candidate_id, reason=reason, actor=_actor(request))
    except KeyError as exc:
        raise HTTPException(404, "자산 식별 후보를 찾을 수 없습니다.") from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    _queue_webhook("asset.identity_candidate_rejected", {"candidate_id": result["candidate_id"]}, _actor(request))
    return RedirectResponse("/asset-identities?notice=candidate_rejected", status_code=303)

@router.post("/asset-merge-requests/{request_id}/decision")
def asset_merge_request_decision_ui(
    request: Request, request_id: str, decision: str = Form(...),
    decision_note: str = Form(""), csrf_token: str = Form(...),
):
    _require_role(request, "approver")
    _verify_csrf(request, csrf_token)
    action = str(decision or "").strip().upper()
    try:
        if action == "REJECTED":
            result = reject_asset_merge_request(
                DB_PATH, request_id, decided_by=_actor(request), decision_note=decision_note,
            )
        elif action == "APPROVED":
            preflight_asset_merge_request(DB_PATH, request_id)
            recovery = _create_asset_merge_recovery_bundle(request_id, _actor(request))
            result = approve_asset_merge_request(
                DB_PATH, request_id, decided_by=_actor(request), decision_note=decision_note,
                recovery_bundle_path=str(recovery["bundle_path"]),
                recovery_bundle_sha256=str(recovery["bundle_sha256"]),
            )
        else:
            raise ValueError("승인 또는 반려만 가능합니다.")
    except KeyError as exc:
        raise HTTPException(404, "자산 병합 승인 요청을 찾을 수 없습니다.") from exc
    except ConcurrencyError as exc:
        raise HTTPException(409, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    _queue_webhook(
        "asset.merge_decided", {"request_id": request_id, "status": result.get("status"),
                                "merge_id": result.get("merge_id")}, _actor(request),
    )
    return RedirectResponse("/approvals?notice=asset_merge_decided", status_code=303)

@router.get("/asset-merges/{merge_id}/rollback-impact")
def asset_merge_rollback_impact_ui(request: Request, merge_id: str):
    _require_role(request, "viewer")
    try:
        return JSONResponse(analyze_asset_merge_rollback(DB_PATH, merge_id))
    except KeyError as exc:
        raise HTTPException(404, "자산 병합 이력을 찾을 수 없습니다.") from exc

@router.post("/asset-merges/{merge_id}/request-rollback")
def asset_merge_rollback_request_ui(
    request: Request, merge_id: str, reason: str = Form(...), csrf_token: str = Form(...),
):
    _require_role(request, "operator")
    _verify_csrf(request, csrf_token)
    try:
        result = create_asset_merge_rollback_request(
            DB_PATH, merge_id=merge_id, reason=reason, requested_by=_actor(request),
        )
    except KeyError as exc:
        raise HTTPException(404, "자산 병합 이력을 찾을 수 없습니다.") from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    _queue_webhook(
        "asset.merge_rollback_requested",
        {"rollback_request_id": result.get("rollback_request_id"), "merge_id": merge_id},
        _actor(request),
    )
    return RedirectResponse("/asset-identities?notice=asset_merge_rollback_requested", status_code=303)

@router.post("/asset-merge-rollback-requests/{rollback_request_id}/decision")
def asset_merge_rollback_decision_ui(
    request: Request, rollback_request_id: str, decision: str = Form(...),
    decision_note: str = Form(""), csrf_token: str = Form(...),
):
    _require_role(request, "approver")
    _verify_csrf(request, csrf_token)
    action = str(decision or "").strip().upper()
    try:
        if action == "REJECTED":
            result = reject_asset_merge_rollback_request(
                DB_PATH, rollback_request_id, decided_by=_actor(request), decision_note=decision_note,
            )
        elif action == "APPROVED":
            result = approve_asset_merge_rollback_request(
                DB_PATH, rollback_request_id, decided_by=_actor(request), decision_note=decision_note,
            )
        else:
            raise ValueError("승인 또는 반려만 가능합니다.")
    except KeyError as exc:
        raise HTTPException(404, "자산 병합 롤백 승인 요청을 찾을 수 없습니다.") from exc
    except ConcurrencyError as exc:
        raise HTTPException(409, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    _queue_webhook(
        "asset.merge_rollback_decided",
        {"rollback_request_id": rollback_request_id, "merge_id": result.get("merge_id"),
         "status": result.get("status")},
        _actor(request),
    )
    return RedirectResponse("/approvals?notice=asset_merge_rollback_decided", status_code=303)

@router.get("/exposure-groups", response_class=HTMLResponse)
def exposure_groups_page(request: Request):
    return templates.TemplateResponse(
        request=request, name="exposure_groups.html", context={"groups": list_exposure_groups(DB_PATH, limit=1000)}
    )

@router.get("/campaigns", response_class=HTMLResponse)
def campaigns_page(request: Request, status: str = "", notice: str = ""):
    return templates.TemplateResponse(
        request=request, name="campaigns.html",
        context={"campaigns": list_campaigns(DB_PATH, status=status, limit=1000), "status": status, "notice": notice},
    )

@router.post("/campaigns")
def campaigns_create(
    request: Request, title: str = Form(...), description: str = Form(""), owner: str = Form(""),
    due_date: str = Form(""), cve_id: str = Form(""), finding_ids: str = Form(""),
    apply_workflow: bool = Form(False), csrf_token: str = Form(...),
):
    _require_role(request, "operator")
    _verify_csrf(request, csrf_token)
    title = _bounded_text(title, "title", 500)
    if not title:
        raise HTTPException(400, "캠페인 제목이 필요합니다.")
    due_date = _date_text(due_date, "due_date")
    raw_ids = re.split(r"[\s,]+", finding_ids.strip()) if finding_ids.strip() else []
    ids = _campaign_member_ids(finding_ids=raw_ids, cve_id=cve_id)
    try:
        campaign = create_campaign(
            DB_PATH, title=title, description=_bounded_text(description, "description", 4000),
            owner=_bounded_text(owner, "owner", 500), due_date=due_date, finding_ids=ids,
            actor=_actor(request), apply_workflow=apply_workflow,
        )
    except (ValueError, ConcurrencyError) as exc:
        raise HTTPException(400, str(exc)) from exc
    _queue_webhook("campaign.created", {"campaign_id": campaign["campaign_id"], "finding_count": campaign.get("finding_count", len(ids))}, _actor(request))
    return RedirectResponse(f"/campaigns/{campaign['campaign_id']}", status_code=303)

@router.get("/campaigns/{campaign_id}", response_class=HTMLResponse)
def campaign_detail(request: Request, campaign_id: str, notice: str = ""):
    campaign = get_campaign(DB_PATH, campaign_id)
    if not campaign:
        raise HTTPException(404, "해당 캠페인을 찾을 수 없습니다.")
    return templates.TemplateResponse(
        request=request, name="campaign.html", context={"campaign": campaign, "notice": notice}
    )

@router.post("/campaigns/{campaign_id}/members")
def campaign_members_add(
    request: Request, campaign_id: str, finding_ids: str = Form(""), cve_id: str = Form(""),
    csrf_token: str = Form(...),
):
    _require_role(request, "operator")
    _verify_csrf(request, csrf_token)
    raw_ids = re.split(r"[\s,]+", finding_ids.strip()) if finding_ids.strip() else []
    ids = _campaign_member_ids(finding_ids=raw_ids, cve_id=cve_id)
    try:
        added = add_campaign_findings(DB_PATH, campaign_id, ids, actor=_actor(request))
        if added:
            _queue_webhook("campaign.members_added", {"campaign_id": campaign_id, "added": added}, _actor(request))
    except KeyError as exc:
        raise HTTPException(404, "해당 캠페인을 찾을 수 없습니다.") from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return RedirectResponse(f"/campaigns/{campaign_id}?notice={added}건이+추가되었습니다", status_code=303)

@router.post("/campaigns/{campaign_id}/members/{finding_id}/remove")
def campaign_member_remove(
    request: Request, campaign_id: str, finding_id: str, csrf_token: str = Form(...),
):
    _require_role(request, "operator")
    _verify_csrf(request, csrf_token)
    try:
        removed = remove_campaign_finding(DB_PATH, campaign_id, finding_id, actor=_actor(request))
        if removed:
            _queue_webhook("campaign.member_removed", {"campaign_id": campaign_id, "finding_id": finding_id}, _actor(request))
    except KeyError as exc:
        raise HTTPException(404, "해당 캠페인을 찾을 수 없습니다.") from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    if not removed:
        raise HTTPException(404, "캠페인 구성원을 찾을 수 없습니다.")
    return RedirectResponse(f"/campaigns/{campaign_id}?notice=취약점이+제거되었습니다", status_code=303)

@router.post("/campaigns/{campaign_id}/status")
def campaign_status_update(
    request: Request, campaign_id: str, status: str = Form(...), expected_row_version: int = Form(...),
    csrf_token: str = Form(...),
):
    _require_role(request, "operator")
    _verify_csrf(request, csrf_token)
    try:
        updated_campaign = update_campaign_status(
            DB_PATH, campaign_id, status=status, actor=_actor(request), expected_version=expected_row_version
        )
        _queue_webhook("campaign.status_changed", {"campaign_id": campaign_id, "status": updated_campaign.get("status")}, _actor(request))
    except KeyError as exc:
        raise HTTPException(404, "해당 캠페인을 찾을 수 없습니다.") from exc
    except (ValueError, ConcurrencyError) as exc:
        raise HTTPException(409 if isinstance(exc, ConcurrencyError) else 400, str(exc)) from exc
    return RedirectResponse(f"/campaigns/{campaign_id}?notice=상태가+변경되었습니다", status_code=303)

@router.get("/export/assets.csv")
def export_assets_csv():
    rows = list_assets(DB_PATH, status="", limit=5000)
    output = io.StringIO()
    fields = [
        "asset_ref_id","external_asset_id","asset_name","service_name","business_unit","owner",
        "environment","criticality","data_sensitivity","internet_exposed","tags","status","source",
        "finding_count","cve_count","active_finding_count","kev_count","max_score","last_seen_at","updated_at",
    ]
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()
    for row in rows:
        writer.writerow({field: _csv_safe(row.get(field) or "") for field in fields})
    return Response(
        output.getvalue().encode("utf-8-sig"), media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=vulnflow_assets.csv"},
    )

@router.get("/export/campaigns.csv")
def export_campaigns_csv():
    rows = list_campaigns(DB_PATH, limit=5000)
    output = io.StringIO()
    fields = [
        "campaign_id","title","description","owner","due_date","status","finding_count","active_count",
        "completed_count","max_score","created_by","created_at","updated_at","completed_at",
    ]
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()
    for row in rows:
        writer.writerow({field: _csv_safe(row.get(field) or "") for field in fields})
    return Response(
        output.getvalue().encode("utf-8-sig"), media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=vulnflow_remediation_campaigns.csv"},
    )

@router.get("/api/v1/assets")
def api_assets(status: str = "", owner: str = "", query: str = "", limit: int = 500):
    items = list_assets(DB_PATH, status=status, owner=owner, query=query, limit=limit)
    return {"count": len(items), "items": items}

@router.post("/api/v1/assets")
def api_assets_import(request: Request, payload: ApiAssetImport):
    _require_role(request, "operator")
    _require_api_token(request)
    rows = [item.model_dump() for item in payload.items]
    if not rows:
        raise HTTPException(400, "가져올 자산이 없습니다.")
    try:
        result = apply_asset_inventory(DB_PATH, rows, actor=_actor(request))
        _queue_webhook("asset_inventory.imported", result, _actor(request))
        rescore_all(actor=_actor(request))
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return result

@router.get("/api/v1/assets/{asset_ref_id}")
def api_asset_detail(asset_ref_id: str):
    item = get_asset(DB_PATH, asset_ref_id)
    if not item:
        raise HTTPException(404, "해당 자산을 찾을 수 없습니다.")
    return item

@router.get("/api/v1/assets/{asset_ref_id}/identifiers")
def api_asset_identifiers(request: Request, asset_ref_id: str, include_retired: bool = False):
    _require_role(request, "viewer")
    if not get_asset(DB_PATH, asset_ref_id):
        raise HTTPException(404, "해당 자산을 찾을 수 없습니다.")
    items = list_asset_identifiers(DB_PATH, asset_ref_id, include_retired=include_retired)
    return {"count": len(items), "items": items}

@router.post("/api/v1/assets/{asset_ref_id}/identifiers")
def api_asset_identifier_add(request: Request, asset_ref_id: str, payload: ApiAssetIdentifierCreate):
    _require_role(request, "operator")
    _require_api_token(request)
    try:
        result = add_asset_identifier(
            DB_PATH, asset_ref_id, identifier_type=payload.identifier_type, value=payload.value,
            scope=payload.scope, source=payload.source, confidence=payload.confidence,
            actor=_actor(request),
        )
    except KeyError as exc:
        raise HTTPException(404, "해당 자산을 찾을 수 없습니다.") from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    if result.get("status") == "CANDIDATE":
        _queue_webhook("asset.identity_candidate_created", {
            "candidate_id": (result.get("candidate") or {}).get("candidate_id"),
            "asset_ref_id": asset_ref_id,
        }, _actor(request))
    return result

@router.get("/api/v1/asset-identities/candidates")
def api_asset_identity_candidates(request: Request, status: str = "PENDING", limit: int = 500):
    _require_role(request, "viewer")
    try:
        items = list_asset_identity_candidates(DB_PATH, status=status, limit=limit)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"count": len(items), "items": items}

@router.get("/api/v1/asset-identities/candidates/{candidate_id}/impact")
def api_asset_identity_merge_impact(
    request: Request, candidate_id: str, target_asset_ref_id: str,
):
    _require_role(request, "viewer")
    candidate = get_asset_identity_candidate(DB_PATH, candidate_id)
    if not candidate:
        raise HTTPException(404, "자산 식별 후보를 찾을 수 없습니다.")
    pair = {str(candidate["asset_ref_id_a"]), str(candidate["asset_ref_id_b"])}
    target = str(target_asset_ref_id or "").strip()
    if target not in pair:
        raise HTTPException(400, "대표 자산이 후보 자산 쌍에 포함되지 않습니다.")
    source = next(item for item in pair if item != target)
    try:
        return analyze_asset_merge(
            DB_PATH, source_asset_ref_id=source, target_asset_ref_id=target, candidate_id=candidate_id,
        )
    except KeyError as exc:
        raise HTTPException(404, "자산 또는 후보를 찾을 수 없습니다.") from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc

@router.post("/api/v1/asset-identities/candidates/{candidate_id}/merge")
@router.post("/api/v1/asset-identities/candidates/{candidate_id}/merge-requests")
def api_asset_identity_merge_request(request: Request, candidate_id: str, payload: ApiAssetIdentityMerge):
    _require_role(request, "operator")
    _require_api_token(request)
    candidate = get_asset_identity_candidate(DB_PATH, candidate_id)
    if not candidate:
        raise HTTPException(404, "자산 식별 후보를 찾을 수 없습니다.")
    pair = {str(candidate["asset_ref_id_a"]), str(candidate["asset_ref_id_b"])}
    target = str(payload.target_asset_ref_id or "").strip()
    if target not in pair:
        raise HTTPException(400, "대표 자산이 후보 자산 쌍에 포함되지 않습니다.")
    source = next(item for item in pair if item != target)
    try:
        result = create_asset_merge_request(
            DB_PATH, source_asset_ref_id=source, target_asset_ref_id=target,
            reason=payload.reason, requested_by=_actor(request), candidate_id=candidate_id,
        )
    except KeyError as exc:
        raise HTTPException(404, "자산 또는 후보를 찾을 수 없습니다.") from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    _queue_webhook("asset.merge_requested", {"request_id": result["request_id"]}, _actor(request))
    return result

@router.post("/api/v1/asset-identities/candidates/{candidate_id}/reject")
def api_asset_identity_reject(request: Request, candidate_id: str, payload: ApiAssetIdentityReject):
    _require_role(request, "operator")
    _require_api_token(request)
    try:
        result = reject_asset_identity_candidate(
            DB_PATH, candidate_id, reason=payload.reason, actor=_actor(request)
        )
    except KeyError as exc:
        raise HTTPException(404, "자산 식별 후보를 찾을 수 없습니다.") from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    _queue_webhook("asset.identity_candidate_rejected", {"candidate_id": candidate_id}, _actor(request))
    return result

@router.get("/api/v1/asset-merge-requests")
def api_asset_merge_requests(request: Request, status: str = "", limit: int = 500):
    _require_role(request, "viewer")
    try:
        items = list_asset_merge_requests(DB_PATH, status=status, limit=limit)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"count": len(items), "items": items}

@router.post("/api/v1/asset-merge-requests/{request_id}/decision")
def api_asset_merge_request_decision(
    request: Request, request_id: str, payload: ApiApprovalDecision,
):
    _require_role(request, "approver")
    _require_api_token(request)
    action = str(payload.decision or "").strip().upper()
    try:
        if action == "REJECTED":
            result = reject_asset_merge_request(
                DB_PATH, request_id, decided_by=_actor(request), decision_note=payload.decision_note,
            )
        elif action == "APPROVED":
            preflight_asset_merge_request(DB_PATH, request_id)
            recovery = _create_asset_merge_recovery_bundle(request_id, _actor(request))
            result = approve_asset_merge_request(
                DB_PATH, request_id, decided_by=_actor(request), decision_note=payload.decision_note,
                recovery_bundle_path=str(recovery["bundle_path"]),
                recovery_bundle_sha256=str(recovery["bundle_sha256"]),
            )
        else:
            raise ValueError("승인 또는 반려만 가능합니다.")
    except KeyError as exc:
        raise HTTPException(404, "자산 병합 승인 요청을 찾을 수 없습니다.") from exc
    except ConcurrencyError as exc:
        raise HTTPException(409, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    _queue_webhook(
        "asset.merge_decided", {"request_id": request_id, "status": result.get("status"),
                                "merge_id": result.get("merge_id")}, _actor(request),
    )
    return result

@router.get("/api/v1/asset-merges")
def api_asset_merge_history(request: Request, asset_ref_id: str = "", limit: int = 200):
    _require_role(request, "viewer")
    items = list_asset_merge_history(DB_PATH, asset_ref_id=asset_ref_id, limit=limit)
    return {"count": len(items), "items": items}

@router.get("/api/v1/asset-merges/{merge_id}/rollback-impact")
def api_asset_merge_rollback_impact(request: Request, merge_id: str):
    _require_role(request, "viewer")
    try:
        return analyze_asset_merge_rollback(DB_PATH, merge_id)
    except KeyError as exc:
        raise HTTPException(404, "자산 병합 이력을 찾을 수 없습니다.") from exc

@router.post("/api/v1/asset-merges/{merge_id}/rollback-requests")
def api_asset_merge_rollback_request(
    request: Request, merge_id: str, payload: ApiAssetMergeRollbackRequest,
):
    _require_role(request, "operator")
    _require_api_token(request)
    try:
        result = create_asset_merge_rollback_request(
            DB_PATH, merge_id=merge_id, reason=payload.reason, requested_by=_actor(request),
        )
    except KeyError as exc:
        raise HTTPException(404, "자산 병합 이력을 찾을 수 없습니다.") from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    _queue_webhook(
        "asset.merge_rollback_requested",
        {"rollback_request_id": result.get("rollback_request_id"), "merge_id": merge_id},
        _actor(request),
    )
    return result

@router.get("/api/v1/asset-merge-rollback-requests")
def api_asset_merge_rollback_requests(request: Request, status: str = "", limit: int = 500):
    _require_role(request, "viewer")
    try:
        items = list_asset_merge_rollback_requests(DB_PATH, status=status, limit=limit)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"count": len(items), "items": items}

@router.post("/api/v1/asset-merge-rollback-requests/{rollback_request_id}/decision")
def api_asset_merge_rollback_decision(
    request: Request, rollback_request_id: str, payload: ApiApprovalDecision,
):
    _require_role(request, "approver")
    _require_api_token(request)
    action = str(payload.decision or "").strip().upper()
    try:
        if action == "REJECTED":
            result = reject_asset_merge_rollback_request(
                DB_PATH, rollback_request_id, decided_by=_actor(request), decision_note=payload.decision_note,
            )
        elif action == "APPROVED":
            result = approve_asset_merge_rollback_request(
                DB_PATH, rollback_request_id, decided_by=_actor(request), decision_note=payload.decision_note,
            )
        else:
            raise ValueError("승인 또는 반려만 가능합니다.")
    except KeyError as exc:
        raise HTTPException(404, "자산 병합 롤백 승인 요청을 찾을 수 없습니다.") from exc
    except ConcurrencyError as exc:
        raise HTTPException(409, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    _queue_webhook(
        "asset.merge_rollback_decided",
        {"rollback_request_id": rollback_request_id, "merge_id": result.get("merge_id"),
         "status": result.get("status")},
        _actor(request),
    )
    return result

@router.get("/api/v1/exposure-groups")
def api_exposure_groups(limit: int = 500):
    items = list_exposure_groups(DB_PATH, limit=limit)
    return {"count": len(items), "items": items}

@router.get("/api/v1/campaigns")
def api_campaigns(status: str = "", limit: int = 500):
    items = list_campaigns(DB_PATH, status=status, limit=limit)
    return {"count": len(items), "items": items}

@router.post("/api/v1/campaigns")
def api_campaign_create(request: Request, payload: ApiCampaignCreate):
    _require_role(request, "operator")
    _require_api_token(request)
    title = _bounded_text(payload.title, "title", 500)
    if not title:
        raise HTTPException(400, "캠페인 제목이 필요합니다.")
    due_date = _date_text(payload.due_date, "due_date")
    ids = _campaign_member_ids(finding_ids=payload.finding_ids, cve_id=payload.cve_id)
    try:
        campaign = create_campaign(
            DB_PATH, title=title, description=_bounded_text(payload.description, "description", 4000),
            owner=_bounded_text(payload.owner, "owner", 500), due_date=due_date, finding_ids=ids,
            actor=_actor(request), apply_workflow=payload.apply_workflow,
        )
        _queue_webhook("campaign.created", {"campaign_id": campaign["campaign_id"], "finding_count": campaign.get("finding_count", len(ids))}, _actor(request))
        return campaign
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc

@router.get("/api/v1/campaigns/{campaign_id}")
def api_campaign_detail(campaign_id: str):
    campaign = get_campaign(DB_PATH, campaign_id)
    if not campaign:
        raise HTTPException(404, "해당 캠페인을 찾을 수 없습니다.")
    return campaign

@router.post("/api/v1/campaigns/{campaign_id}/members")
def api_campaign_members_add(request: Request, campaign_id: str, payload: ApiCampaignMembers):
    _require_role(request, "operator")
    _require_api_token(request)
    ids = _campaign_member_ids(finding_ids=payload.finding_ids, cve_id=payload.cve_id)
    try:
        added = add_campaign_findings(DB_PATH, campaign_id, ids, actor=_actor(request))
        if added:
            _queue_webhook("campaign.members_added", {"campaign_id": campaign_id, "added": added}, _actor(request))
        return {"added": added}
    except KeyError as exc:
        raise HTTPException(404, "해당 캠페인을 찾을 수 없습니다.") from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc

@router.delete("/api/v1/campaigns/{campaign_id}/members/{finding_id}")
def api_campaign_member_remove(request: Request, campaign_id: str, finding_id: str):
    _require_role(request, "operator")
    _require_api_token(request)
    try:
        removed = remove_campaign_finding(DB_PATH, campaign_id, finding_id, actor=_actor(request))
        if removed:
            _queue_webhook("campaign.member_removed", {"campaign_id": campaign_id, "finding_id": finding_id}, _actor(request))
    except KeyError as exc:
        raise HTTPException(404, "해당 캠페인을 찾을 수 없습니다.") from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    if not removed:
        raise HTTPException(404, "캠페인 구성원을 찾을 수 없습니다.")
    return {"removed": True}

@router.post("/api/v1/campaigns/{campaign_id}/status")
def api_campaign_status(request: Request, campaign_id: str, payload: ApiCampaignStatus):
    _require_role(request, "operator")
    _require_api_token(request)
    try:
        campaign = update_campaign_status(
            DB_PATH, campaign_id, status=payload.status, actor=_actor(request), expected_version=payload.expected_row_version
        )
        _queue_webhook("campaign.status_changed", {"campaign_id": campaign_id, "status": campaign.get("status")}, _actor(request))
        return campaign
    except KeyError as exc:
        raise HTTPException(404, "해당 캠페인을 찾을 수 없습니다.") from exc
    except ConcurrencyError as exc:
        raise HTTPException(409, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
