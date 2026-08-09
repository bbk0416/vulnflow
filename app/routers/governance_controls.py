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
    "config_changes_page",
    "create_config_change_ui",
    "decide_config_change_ui",
    "apply_config_change_ui",
    "create_config_baseline_ui",
    "record_config_drift_ui",
    "export_config_audit",
    "export_recovery_bundle",
    "validate_recovery_bundle_ui",
    "restore_recovery_bundle_ui",
    "api_config_audit",
    "api_config_drift",
    "api_create_config_baseline",
    "api_record_config_drift",
    "api_config_changes",
    "api_create_config_change",
    "api_decide_config_change",
    "api_apply_config_change",
    "api_signing_keys",
    "api_validate_recovery_bundle",
    "api_restore_recovery_bundle",
)


def _active_project_identity(request: Request) -> tuple[str, str]:
    active = dict(getattr(request.state, "active_project", {}) or {})
    return (
        str(active.get("project_id") or "default"),
        str(active.get("name") or "기본 프로젝트"),
    )

@router.get("/config-changes", response_class=HTMLResponse)
def config_changes_page(request: Request, notice: str = ""):
    _require_role(request, "operator")
    audit = build_config_audit(db_path=DB_PATH, base_dir=BASE_DIR)
    drift = evaluate_change_control(DB_PATH, audit, evaluate_drift(DB_PATH, audit))
    return templates.TemplateResponse(
        request=request,
        name="config_changes.html",
        context={
            "audit": audit,
            "config_drift": drift,
            "change_requests": list_change_requests(DB_PATH, limit=100),
            "notice_message": NOTICE_MESSAGES.get(notice, ""),
        },
    )

@router.post("/config-changes/request")
def create_config_change_ui(
    request: Request,
    title: str = Form(...), reason: str = Form(...), rollback_plan: str = Form(...),
    window_start: str = Form(...), window_end: str = Form(...), csrf_token: str = Form(...),
):
    _require_role(request, "operator")
    _verify_csrf(request, csrf_token)
    try:
        result = create_change_request(
            DB_PATH, build_config_audit(db_path=DB_PATH, base_dir=BASE_DIR),
            actor=_actor(request), title=_bounded_text(title, "title", 200),
            reason=_bounded_text(reason, "reason", 1500),
            rollback_plan=_bounded_text(rollback_plan, "rollback_plan", 4000),
            window_start=window_start, window_end=window_end,
        )
        _queue_webhook("configuration.change.requested", {
            "request_id": result.get("request_id"), "title": result.get("title"),
            "severity": (result.get("impact") or {}).get("severity"),
            "window_start": result.get("window_start"), "window_end": result.get("window_end"),
        }, _actor(request))
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return RedirectResponse(url="/config-changes?notice=config_change_requested", status_code=303)

@router.post("/config-changes/{request_id}/decision")
def decide_config_change_ui(
    request: Request, request_id: str, decision: str = Form(...),
    decision_note: str = Form(""), csrf_token: str = Form(...),
):
    _require_role(request, "approver")
    _verify_csrf(request, csrf_token)
    try:
        result = decide_change_request(
            DB_PATH, request_id, actor=_actor(request), decision=decision,
            note=_bounded_text(decision_note, "decision_note", 1500),
        )
        _queue_webhook("configuration.change.decided", {
            "request_id": request_id, "status": result.get("status"),
            "decided_by": result.get("decided_by"),
        }, _actor(request))
    except KeyError as exc:
        raise HTTPException(404, "구성 변경 요청을 찾을 수 없습니다.") from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return RedirectResponse(url="/config-changes?notice=config_change_decided", status_code=303)

@router.post("/config-changes/{request_id}/apply")
def apply_config_change_ui(
    request: Request, request_id: str, note: str = Form(""), csrf_token: str = Form(...),
):
    _require_role(request, "approver")
    _verify_csrf(request, csrf_token)
    try:
        result = promote_change_request(
            DB_PATH, request_id, build_config_audit(db_path=DB_PATH, base_dir=BASE_DIR),
            actor=_actor(request), note=_bounded_text(note, "note", 1000),
        )
        _queue_webhook("configuration.change.applied", {
            "request_id": request_id, "status": result.get("status"),
            "applied_baseline_id": result.get("applied_baseline_id"),
        }, _actor(request))
    except KeyError as exc:
        raise HTTPException(404, "구성 변경 요청을 찾을 수 없습니다.") from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return RedirectResponse(url="/config-changes?notice=config_change_applied", status_code=303)

@router.post("/system/config-baseline")
def create_config_baseline_ui(
    request: Request, note: str = Form(""), csrf_token: str = Form(...),
):
    _require_role(request, "admin")
    _verify_csrf(request, csrf_token)
    try:
        audit = build_config_audit(db_path=DB_PATH, base_dir=BASE_DIR)
        if evaluate_drift(DB_PATH, audit)["status"] == "DRIFT":
            raise ValueError("기존 기준선 이후의 변경은 구성 변경 승인 요청을 통해 승격해야 합니다.")
        create_baseline(
            DB_PATH, audit,
            actor=_actor(request), note=_bounded_text(note, "note", 1000),
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return RedirectResponse(url="/system?notice=config_baseline_created", status_code=303)

@router.post("/system/config-drift/check")
def record_config_drift_ui(request: Request, csrf_token: str = Form(...)):
    _require_role(request, "admin")
    _verify_csrf(request, csrf_token)
    try:
        record_drift_check(
            DB_PATH, build_config_audit(db_path=DB_PATH, base_dir=BASE_DIR), actor=_actor(request),
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return RedirectResponse(url="/system?notice=config_drift_checked", status_code=303)

@router.get("/export/config-audit.json")
def export_config_audit(request: Request):
    _require_role(request, "admin")
    body = json.dumps(
        build_config_audit(db_path=DB_PATH, base_dir=BASE_DIR),
        ensure_ascii=False, indent=2, sort_keys=True,
    ).encode("utf-8")
    return Response(
        body, media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=vulnflow_config_audit.json"},
    )

@router.get("/export/recovery-bundle.zip")
def export_recovery_bundle(request: Request):
    _require_role(request, "admin")
    handle = tempfile.NamedTemporaryFile(prefix="vulnflow_recovery_", suffix=".zip", delete=False)
    handle.close()
    signing, backup_key_id, backup_key = _backup_signing()
    project_id, project_name = _active_project_identity(request)
    create_recovery_bundle(
        DB_PATH, handle.name,
        config_audit=build_config_audit(db_path=DB_PATH, base_dir=BASE_DIR),
        signing_key=backup_key, signing_key_id=backup_key_id, signing_keys=signing.keys,
        audit_signing_keys=signing.keys, created_by=_actor(request), base_dir=BASE_DIR, evidence_dir=EVIDENCE_DIR,
        project_id=project_id, project_name=project_name,
    )
    return FileResponse(
        handle.name, filename="vulnflow_recovery_bundle.zip", media_type="application/zip",
        background=BackgroundTask(lambda: os.unlink(handle.name) if os.path.exists(handle.name) else None),
    )

@router.post("/validate-recovery-bundle")
async def validate_recovery_bundle_ui(
    request: Request, file: UploadFile = File(...), csrf_token: str = Form(...),
):
    _require_role(request, "admin")
    _verify_csrf(request, csrf_token)
    content = await file.read(MAX_RECOVERY_BUNDLE_BYTES + 1)
    if len(content) > MAX_RECOVERY_BUNDLE_BYTES:
        raise HTTPException(413, f"복구 번들 크기는 최대 {MAX_RECOVERY_BUNDLE_BYTES // (1024 * 1024)}MB입니다.")
    path = ""
    try:
        handle = tempfile.NamedTemporaryFile(prefix="vulnflow_bundle_ui_validate_", suffix=".zip", delete=False)
        path = handle.name
        handle.write(content)
        handle.close()
        return JSONResponse(validate_recovery_bundle(
            path, signing_keys=_signing_config().keys, audit_signing_keys=_signing_config().keys,
            require_signature=BACKUP_REQUIRE_SIGNATURE,
            current_schema_version=CURRENT_SCHEMA_VERSION, evidence_dir=EVIDENCE_DIR,
            expected_project_id=_active_project_identity(request)[0],
        ))
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    finally:
        if path and os.path.exists(path):
            os.unlink(path)

@router.post("/restore-recovery-bundle")
async def restore_recovery_bundle_ui(
    request: Request,
    file: UploadFile = File(...),
    confirmation: str = Form(...),
    csrf_token: str = Form(...),
):
    _require_role(request, "admin")
    _verify_csrf(request, csrf_token)
    if confirmation.strip() != "RESTORE-BUNDLE":
        raise HTTPException(400, "복원 확인란에 RESTORE-BUNDLE을 입력해야 합니다.")
    if not (file.filename or "").lower().endswith(".zip"):
        raise HTTPException(400, "VulnFlow 복구 ZIP만 지원합니다.")
    content = await file.read(MAX_RECOVERY_BUNDLE_BYTES + 1)
    if len(content) > MAX_RECOVERY_BUNDLE_BYTES:
        raise HTTPException(413, f"복구 번들 크기는 최대 {MAX_RECOVERY_BUNDLE_BYTES // (1024 * 1024)}MB입니다.")
    temp_path = ""
    try:
        handle = tempfile.NamedTemporaryFile(prefix="vulnflow_bundle_restore_", suffix=".zip", delete=False)
        temp_path = handle.name
        handle.write(content)
        handle.close()
        with _exclusive_operation(RESTORE_LEASE_NAME, "복구 번들 복원"):
            if count_active_background_jobs(DB_PATH) > 0:
                raise ConcurrencyError("실행 또는 대기 중인 백그라운드 작업이 있어 복원할 수 없습니다.")
            if (
                CLUSTER_COORDINATION_ENABLED
                and count_cluster_write_activities(
                    _coordination_db_path(request.state.vulnflow_context)
                ) > 0
            ):
                raise ConcurrencyError("처리 중인 쓰기 요청이 있어 복원할 수 없습니다.")
            restore_recovery_bundle(
                DB_PATH, temp_path, actor=_actor(request), signing_keys=_signing_config().keys,
                audit_signing_keys=_signing_config().keys, require_signature=BACKUP_REQUIRE_SIGNATURE,
                current_schema_version=CURRENT_SCHEMA_VERSION, evidence_dir=EVIDENCE_DIR,
                expected_project_id=_active_project_identity(request)[0],
            )
            rescore_all(
                audit=False,
                actor=_actor(request),
                context=request.state.vulnflow_context,
            )
    except ConcurrencyError as exc:
        raise HTTPException(409, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    finally:
        if temp_path and os.path.exists(temp_path):
            os.unlink(temp_path)
    return RedirectResponse(url="/system?notice=recovery_restored", status_code=303)


@router.get("/api/v1/system/config-audit")
def api_config_audit(request: Request):
    _require_api_token(request)
    _require_role(request, "admin")
    return build_config_audit(db_path=DB_PATH, base_dir=BASE_DIR)

@router.get("/api/v1/system/config-drift")
def api_config_drift(request: Request):
    _require_api_token(request)
    _require_role(request, "admin")
    audit = build_config_audit(db_path=DB_PATH, base_dir=BASE_DIR)
    return {
        "current": evaluate_change_control(DB_PATH, audit, evaluate_drift(DB_PATH, audit)),
        "baselines": list_baselines(DB_PATH, limit=20),
        "checks": list_drift_checks(DB_PATH, limit=50),
        "change_requests": list_change_requests(DB_PATH, limit=100),
    }

@router.post("/api/v1/system/config-baseline")
def api_create_config_baseline(request: Request, payload: ApiConfigBaseline):
    _require_api_token(request)
    _require_role(request, "admin")
    try:
        audit = build_config_audit(db_path=DB_PATH, base_dir=BASE_DIR)
        if evaluate_drift(DB_PATH, audit)["status"] == "DRIFT":
            raise ValueError("기존 기준선 이후의 변경은 구성 변경 승인 요청을 통해 승격해야 합니다.")
        return create_baseline(
            DB_PATH, audit,
            actor=_actor(request), note=payload.note,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc

@router.post("/api/v1/system/config-drift/check")
def api_record_config_drift(request: Request):
    _require_api_token(request)
    _require_role(request, "admin")
    try:
        return record_drift_check(
            DB_PATH, build_config_audit(db_path=DB_PATH, base_dir=BASE_DIR), actor=_actor(request),
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc

@router.get("/api/v1/system/config-changes")
def api_config_changes(request: Request):
    _require_api_token(request)
    _require_role(request, "operator")
    audit = build_config_audit(db_path=DB_PATH, base_dir=BASE_DIR)
    return {
        "current": evaluate_change_control(DB_PATH, audit, evaluate_drift(DB_PATH, audit)),
        "requests": list_change_requests(DB_PATH, limit=200),
    }

@router.post("/api/v1/system/config-changes")
def api_create_config_change(request: Request, payload: ApiConfigChangeRequest):
    _require_api_token(request)
    _require_role(request, "operator")
    target = payload.target_snapshot or build_config_audit(db_path=DB_PATH, base_dir=BASE_DIR)
    try:
        result = create_change_request(
            DB_PATH, target, actor=_actor(request), title=payload.title, reason=payload.reason,
            rollback_plan=payload.rollback_plan, window_start=payload.window_start,
            window_end=payload.window_end,
        )
        _queue_webhook("configuration.change.requested", {
            "request_id": result.get("request_id"), "title": result.get("title"),
            "severity": (result.get("impact") or {}).get("severity"),
            "window_start": result.get("window_start"), "window_end": result.get("window_end"),
        }, _actor(request))
        return result
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc

@router.post("/api/v1/system/config-changes/{request_id}/decision")
def api_decide_config_change(request: Request, request_id: str, payload: ApiConfigChangeDecision):
    _require_api_token(request)
    _require_role(request, "approver")
    try:
        result = decide_change_request(
            DB_PATH, request_id, actor=_actor(request), decision=payload.decision,
            note=payload.decision_note,
        )
        _queue_webhook("configuration.change.decided", {
            "request_id": request_id, "status": result.get("status"),
            "decided_by": result.get("decided_by"),
        }, _actor(request))
        return result
    except KeyError as exc:
        raise HTTPException(404, "구성 변경 요청을 찾을 수 없습니다.") from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc

@router.post("/api/v1/system/config-changes/{request_id}/apply")
def api_apply_config_change(request: Request, request_id: str, payload: ApiConfigChangeApply):
    _require_api_token(request)
    _require_role(request, "approver")
    try:
        result = promote_change_request(
            DB_PATH, request_id, build_config_audit(db_path=DB_PATH, base_dir=BASE_DIR),
            actor=_actor(request), note=payload.note,
        )
        _queue_webhook("configuration.change.applied", {
            "request_id": request_id, "status": result.get("status"),
            "applied_baseline_id": result.get("applied_baseline_id"),
        }, _actor(request))
        return result
    except KeyError as exc:
        raise HTTPException(404, "구성 변경 요청을 찾을 수 없습니다.") from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc

@router.get("/api/v1/system/signing-keys")
def api_signing_keys(request: Request):
    _require_api_token(request)
    _require_role(request, "admin")
    config = _signing_config()
    proof_config = _integrity_proof_signing_config()
    return config.public_summary() | {
        "integrity_proof_public_signing": proof_config.public_summary(),
        "usage": collect_signing_key_usage(
            db_path=str(DB_PATH), recovery_dir=str(RECOVERY_DIR), export_dir=str(EXPORT_DIR), configured_key_ids=sorted(config.keys)
        )
    }

@router.post("/api/v1/recovery/validate")
async def api_validate_recovery_bundle(request: Request, file: UploadFile = File(...)):
    _require_api_token(request)
    _require_role(request, "admin")
    content = await file.read(MAX_RECOVERY_BUNDLE_BYTES + 1)
    if len(content) > MAX_RECOVERY_BUNDLE_BYTES:
        raise HTTPException(413, f"복구 번들 크기는 최대 {MAX_RECOVERY_BUNDLE_BYTES // (1024 * 1024)}MB입니다.")
    path = ""
    try:
        handle = tempfile.NamedTemporaryFile(prefix="vulnflow_bundle_validate_", suffix=".zip", delete=False)
        path = handle.name
        handle.write(content)
        handle.close()
        return validate_recovery_bundle(
            path, signing_keys=_signing_config().keys, audit_signing_keys=_signing_config().keys,
            require_signature=BACKUP_REQUIRE_SIGNATURE,
            current_schema_version=CURRENT_SCHEMA_VERSION, evidence_dir=EVIDENCE_DIR,
            expected_project_id=_active_project_identity(request)[0],
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    finally:
        if path and os.path.exists(path):
            os.unlink(path)

@router.post("/api/v1/recovery/restore")
async def api_restore_recovery_bundle(
    request: Request, file: UploadFile = File(...), confirmation: str = Form(...),
):
    _require_api_token(request)
    _require_role(request, "admin")
    if confirmation.strip() != "RESTORE-BUNDLE":
        raise HTTPException(400, "confirmation은 RESTORE-BUNDLE이어야 합니다.")
    content = await file.read(MAX_RECOVERY_BUNDLE_BYTES + 1)
    if len(content) > MAX_RECOVERY_BUNDLE_BYTES:
        raise HTTPException(413, f"복구 번들 크기는 최대 {MAX_RECOVERY_BUNDLE_BYTES // (1024 * 1024)}MB입니다.")
    path = ""
    try:
        handle = tempfile.NamedTemporaryFile(prefix="vulnflow_bundle_api_restore_", suffix=".zip", delete=False)
        path = handle.name
        handle.write(content)
        handle.close()
        with _exclusive_operation(RESTORE_LEASE_NAME, "API 복구 번들 복원"):
            if count_active_background_jobs(DB_PATH) > 0:
                raise ConcurrencyError("실행 또는 대기 중인 백그라운드 작업이 있어 복원할 수 없습니다.")
            if (
                CLUSTER_COORDINATION_ENABLED
                and count_cluster_write_activities(
                    _coordination_db_path(request.state.vulnflow_context)
                ) > 0
            ):
                raise ConcurrencyError("처리 중인 쓰기 요청이 있어 복원할 수 없습니다.")
            result = restore_recovery_bundle(
                DB_PATH, path, actor=_actor(request), signing_keys=_signing_config().keys,
                audit_signing_keys=_signing_config().keys, require_signature=BACKUP_REQUIRE_SIGNATURE,
                current_schema_version=CURRENT_SCHEMA_VERSION, evidence_dir=EVIDENCE_DIR,
                expected_project_id=_active_project_identity(request)[0],
            )
            result["rescored"] = rescore_all(
                audit=False,
                actor=_actor(request),
                context=request.state.vulnflow_context,
            )
            return result
    except ConcurrencyError as exc:
        raise HTTPException(409, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    finally:
        if path and os.path.exists(path):
            os.unlink(path)
