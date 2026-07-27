from __future__ import annotations

"""Governance routes extracted from :mod:`app.main`.

The module is dependency-injected by :mod:`app.routers` so compatibility exports
remain available while each application instance keeps isolated route globals.
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

ROUTE_NAMES = (
    "download_policy",
    "upload_policy",
    "request_policy_activation",
    "decide_policy_activation",
    "api_create_policy",
    "api_policy_detail",
    "api_policy_impact",
    "api_request_policy_activation",
    "api_decide_policy_activation",
)

@router.get("/policies/{policy_id}/download")
def download_policy(request: Request, policy_id: str):
    _require_role(request, "viewer")
    policy = get_policy_version(DB_PATH, policy_id)
    if not policy:
        raise HTTPException(404, "정책을 찾을 수 없습니다.")
    safe_version = re.sub(r"[^A-Za-z0-9._-]+", "_", str(policy.get("version") or "policy"))
    return Response(
        str(policy["content_yaml"]), media_type="application/yaml; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="vulnflow-policy-{safe_version}.yml"'},
    )

@router.post("/policies/upload")
async def upload_policy(
    request: Request, file: UploadFile = File(...), notes: str = Form(""), csrf_token: str = Form(...),
):
    _require_role(request, "admin")
    _verify_csrf(request, csrf_token)
    filename = str(file.filename or "")
    if not filename.lower().endswith((".yml", ".yaml")):
        raise HTTPException(400, "YAML 정책 파일만 지원합니다.")
    content = await file.read(MAX_POLICY_BYTES + 1)
    if len(content) > MAX_POLICY_BYTES:
        raise HTTPException(413, "정책 YAML은 최대 256KB입니다.")
    try:
        text = content.decode("utf-8-sig")
        policy, normalized_yaml, digest = parse_and_describe_policy(text)
        active = _ensure_policy_registry()
        created = create_policy_version(
            DB_PATH,
            version=str(policy["version"]),
            name=str(policy["name"]),
            content_yaml=normalized_yaml,
            content_sha256=digest,
            created_by=_actor(request),
            notes=_bounded_text(notes, "notes", 1500),
            status="DRAFT",
            supersedes_policy_id=str(active["policy_id"]),
        )
    except UnicodeDecodeError as exc:
        raise HTTPException(400, "정책 파일은 UTF-8이어야 합니다.") from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return RedirectResponse(url=f"/policies?policy_id={created['policy_id']}&notice=policy_uploaded", status_code=303)

@router.post("/policies/{policy_id}/request-activation")
def request_policy_activation(
    request: Request, policy_id: str, reason: str = Form(...), csrf_token: str = Form(...),
):
    _require_role(request, "admin")
    _verify_csrf(request, csrf_token)
    target = get_policy_version(DB_PATH, policy_id)
    if not target:
        raise HTTPException(404, "정책을 찾을 수 없습니다.")
    active = _ensure_policy_registry()
    try:
        reason_text = _bounded_text(reason, "reason", MAX_REASON)
        if not reason_text:
            raise ValueError("활성화 요청 사유가 필요합니다.")
        impact = compare_policy_impact(
            list_findings(DB_PATH),
            parse_policy_text(str(active["content_yaml"])),
            parse_policy_text(str(target["content_yaml"])),
        )
        approval = create_policy_activation_request(
            DB_PATH, policy_id=policy_id, requested_by=_actor(request),
            reason=reason_text, impact=impact,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    _queue_webhook(
        "policy.activation_requested",
        {"request_id": approval.get("request_id"), "policy_id": policy_id, "version": target.get("version"), "impact": impact},
        _actor(request),
    )
    return RedirectResponse(url=f"/policies?policy_id={policy_id}&notice=policy_requested", status_code=303)

@router.post("/policy-activation-requests/{request_id}/decision")
def decide_policy_activation(
    request: Request, request_id: str, decision: str = Form(...),
    decision_note: str = Form(""), csrf_token: str = Form(...),
):
    _require_role(request, "approver")
    _verify_csrf(request, csrf_token)
    action = str(decision or "").strip().upper()
    note = _bounded_text(decision_note, "decision_note", 1500)
    try:
        if action == "REJECTED":
            if not note:
                raise ValueError("반려 시 사유를 입력해야 합니다.")
            result = reject_policy_activation_request(
                DB_PATH, request_id, decided_by=_actor(request), decision_note=note,
            )
        elif action == "APPROVED":
            with _exclusive_operation(POLICY_ACTIVATION_LEASE_NAME, "정책 활성화"):
                approval, target, scored = _prepare_policy_activation(request_id)
                result = approve_policy_activation_request(
                    DB_PATH, request_id, scored_rows=scored,
                    decided_by=_actor(request), decision_note=note,
                )
        else:
            raise ValueError("decision은 APPROVED 또는 REJECTED여야 합니다.")
    except KeyError as exc:
        raise HTTPException(404, "정책 활성화 요청을 찾을 수 없습니다.") from exc
    except ConcurrencyError as exc:
        raise HTTPException(409, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    _queue_webhook(
        "policy.activation_decided",
        {"request_id": request_id, "policy_id": result.get("policy_id"), "status": result.get("status")},
        _actor(request),
    )
    return RedirectResponse(url="/policies?notice=policy_decided", status_code=303)


@router.post("/api/v1/policies")
def api_create_policy(request: Request, payload: ApiPolicyCreate):
    _require_role(request, "admin")
    _require_api_token(request)
    try:
        policy, normalized_yaml, digest = parse_and_describe_policy(payload.content_yaml)
        active = _ensure_policy_registry()
        created = create_policy_version(
            DB_PATH, version=str(policy["version"]), name=str(policy["name"]),
            content_yaml=normalized_yaml, content_sha256=digest,
            created_by=_actor(request), notes=_bounded_text(payload.notes, "notes", 1500),
            status="DRAFT", supersedes_policy_id=str(active["policy_id"]),
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return created

@router.get("/api/v1/policies/{policy_id}")
def api_policy_detail(request: Request, policy_id: str):
    _require_role(request, "viewer")
    policy = get_policy_version(DB_PATH, policy_id)
    if not policy:
        raise HTTPException(404, "정책을 찾을 수 없습니다.")
    return policy

@router.get("/api/v1/policies/{policy_id}/impact")
def api_policy_impact(request: Request, policy_id: str):
    _require_role(request, "viewer")
    target = get_policy_version(DB_PATH, policy_id)
    if not target:
        raise HTTPException(404, "정책을 찾을 수 없습니다.")
    active = _ensure_policy_registry()
    return compare_policy_impact(
        list_findings(DB_PATH),
        parse_policy_text(str(active["content_yaml"])),
        parse_policy_text(str(target["content_yaml"])),
    )

@router.post("/api/v1/policies/{policy_id}/activation-requests")
def api_request_policy_activation(request: Request, policy_id: str, payload: ApiPolicyActivationRequest):
    _require_role(request, "admin")
    _require_api_token(request)
    target = get_policy_version(DB_PATH, policy_id)
    if not target:
        raise HTTPException(404, "정책을 찾을 수 없습니다.")
    active = _ensure_policy_registry()
    try:
        reason = _bounded_text(payload.reason, "reason", MAX_REASON)
        if not reason:
            raise ValueError("활성화 요청 사유가 필요합니다.")
        impact = compare_policy_impact(
            list_findings(DB_PATH), parse_policy_text(str(active["content_yaml"])),
            parse_policy_text(str(target["content_yaml"])),
        )
        created = create_policy_activation_request(
            DB_PATH, policy_id=policy_id, requested_by=_actor(request), reason=reason, impact=impact,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    _queue_webhook("policy.activation_requested", {"request_id": created.get("request_id"), "policy_id": policy_id, "impact": impact}, _actor(request))
    return created

@router.post("/api/v1/policy-activation-requests/{request_id}/decision")
def api_decide_policy_activation(request: Request, request_id: str, payload: ApiPolicyDecision):
    _require_role(request, "approver")
    _require_api_token(request)
    action = str(payload.decision or "").strip().upper()
    note = _bounded_text(payload.decision_note, "decision_note", 1500)
    try:
        if action == "REJECTED":
            if not note:
                raise ValueError("반려 시 사유가 필요합니다.")
            result = reject_policy_activation_request(DB_PATH, request_id, decided_by=_actor(request), decision_note=note)
        elif action == "APPROVED":
            with _exclusive_operation(POLICY_ACTIVATION_LEASE_NAME, "정책 활성화"):
                approval, target, scored = _prepare_policy_activation(request_id)
                result = approve_policy_activation_request(
                    DB_PATH, request_id, scored_rows=scored, decided_by=_actor(request), decision_note=note,
                )
        else:
            raise ValueError("decision은 APPROVED 또는 REJECTED여야 합니다.")
    except KeyError as exc:
        raise HTTPException(404, "정책 활성화 요청을 찾을 수 없습니다.") from exc
    except ConcurrencyError as exc:
        raise HTTPException(409, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    _queue_webhook("policy.activation_decided", {"request_id": request_id, "policy_id": result.get("policy_id"), "status": result.get("status")}, _actor(request))
    return result
