from __future__ import annotations

"""Project switching and administrator-managed isolated project stores."""

import time
from typing import Any
from urllib.parse import quote

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

router = APIRouter()


def install_dependencies(namespace: dict[str, Any]) -> None:
    protected = {"router", "install_dependencies", "route_exports", "ROUTE_NAMES"}
    for name, value in namespace.items():
        if not name.startswith("__") and name not in protected:
            globals()[name] = value


def route_exports() -> dict[str, Any]:
    return {name: globals()[name] for name in ROUTE_NAMES}


ROUTE_NAMES = (
    "projects_page",
    "project_switch",
    "project_create_ui",
    "project_status_ui",
    "project_membership_ui",
    "project_integrity_check_ui",
    "project_backup_ui",
    "project_recovery_drill_ui",
)


def _project_rows(request: Request, *, include_inactive: bool = False):
    admin = getattr(request.state, "role", "viewer") == "admin"
    rows = list_projects(
        CONTROL_DB_PATH,
        username=_actor(request),
        include_inactive=include_inactive,
        admin=admin,
    )
    context = getattr(request.state, "vulnflow_context", None)
    return decorate_project_rows(context, rows) if context is not None else rows


def _project_selection(project_id: str):
    return project_selection(
        CONTROL_DB_PATH,
        project_id,
        projects_dir=PROJECTS_DIR,
        default_database_path=DEFAULT_PROJECT_DB_PATH,
        default_evidence_dir=DEFAULT_EVIDENCE_DIR,
        default_export_dir=DEFAULT_EXPORT_DIR,
        default_import_preview_dir=DEFAULT_IMPORT_PREVIEW_DIR,
        default_recovery_dir=DEFAULT_RECOVERY_DIR,
    )


def _resume_lifecycle_if_needed(context) -> None:
    supervisor = context.get("LIFECYCLE_SUPERVISOR")
    if supervisor is not None and supervisor.snapshot().get("state") == "NEW":
        supervisor.start()


def _inspect_project_for_use(context, selection):
    try:
        init_db(selection.database)
    except Exception as exc:
        return mark_project_runtime_failure(context, selection, exc)
    return inspect_project_integrity(
        context, selection, signing_keys=_signing_config(context).keys
    )


@router.get("/projects", response_class=HTMLResponse)
def projects_page(request: Request, selected: str = "", notice: str = "", error: str = ""):
    projects = _project_rows(request, include_inactive=getattr(request.state, "role", "") == "admin")
    selected_id = str(selected or getattr(request.state, "active_project", {}).get("project_id") or "")
    selected_project = next((item for item in projects if item["project_id"] == selected_id), None)
    members = []
    if selected_project and getattr(request.state, "role", "") == "admin":
        members = list_project_members(CONTROL_DB_PATH, selected_id)
        context = getattr(request.state, "vulnflow_context", None)
        if context is not None and str(selected_project.get("status")) == "ACTIVE":
            selected_project["recovery"] = project_recovery_inventory(
                _project_selection(selected_id), context
            )
    notices = {
        "created": "새 프로젝트와 분리 저장소를 만들었습니다.",
        "enabled": "프로젝트를 활성화했습니다.",
        "disabled": "프로젝트를 비활성화했습니다.",
        "member_added": "사용자에게 프로젝트 접근 권한을 부여했습니다.",
        "member_removed": "사용자의 프로젝트 접근 권한을 제거했습니다.",
        "integrity_ok": "프로젝트 무결성 검사가 정상으로 완료되었습니다.",
        "integrity_degraded": "무결성 이상을 확인해 해당 프로젝트를 읽기 전용으로 격리했습니다.",
        "backup_queued": "프로젝트 복구 번들 생성 작업을 예약했습니다.",
        "drill_ok": "선택한 복구 번들로 격리 복원 리허설을 완료했습니다.",
    }
    return templates.TemplateResponse(
        request=request,
        name="projects.html",
        context={
            "projects": projects,
            "selected_project": selected_project,
            "members": members,
            "notice_message": notices.get(notice, ""),
            "error_message": str(error or ""),
        },
    )


@router.post("/projects/switch")
def project_switch(request: Request, project_id: str = Form(...), csrf_token: str = Form(...)):
    _verify_csrf(request, csrf_token)
    principal = _principal(request)
    if principal is None:
        return RedirectResponse("/login", status_code=303)
    try:
        project = resolve_project(CONTROL_DB_PATH, principal, project_id)
    except PermissionError as exc:
        return RedirectResponse(f"/projects?error={quote(str(exc))}", status_code=303)
    response = RedirectResponse("/", status_code=303)
    response.set_cookie(
        PROJECT_COOKIE,
        str(project["project_id"]),
        max_age=int(AUTH_SESSION_MINUTES) * 60,
        httponly=True,
        secure=bool(COOKIE_SECURE),
        samesite="strict",
        path="/",
    )
    return response


@router.post("/admin/projects")
async def project_create_ui(
    request: Request,
    name: str = Form(...),
    csrf_token: str = Form(...),
):
    _require_role(request, "admin")
    _verify_csrf(request, csrf_token)
    try:
        project = create_project(
            CONTROL_DB_PATH,
            name=name,
            actor=_actor(request),
            projects_dir=PROJECTS_DIR,
            default_database_path=DEFAULT_PROJECT_DB_PATH,
            default_evidence_dir=DEFAULT_EVIDENCE_DIR,
            default_export_dir=DEFAULT_EXPORT_DIR,
            default_import_preview_dir=DEFAULT_IMPORT_PREVIEW_DIR,
            default_recovery_dir=DEFAULT_RECOVERY_DIR,
            init_db_fn=init_db,
        )
        add_audit_event(
            CONTROL_DB_PATH,
            finding_id=None,
            event_type="PROJECT_CREATED",
            summary=f"프로젝트 생성: {project['name']}",
            details={"project_id": project["project_id"], "name": project["name"]},
            actor=_actor(request),
        )
        context = getattr(request.state, "vulnflow_context", None)
        if context is not None:
            mode = _inspect_project_for_use(
                context, _project_selection(str(project["project_id"]))
            )
            if not mode.get("active"):
                _resume_lifecycle_if_needed(context)
    except (ValueError, KeyError) as exc:
        return RedirectResponse(f"/projects?error={quote(str(exc))}", status_code=303)
    return RedirectResponse(
        f"/projects?selected={quote(str(project['project_id']))}&notice=created", status_code=303
    )


@router.post("/admin/projects/{project_id}/status")
async def project_status_ui(
    request: Request,
    project_id: str,
    active: str = Form("0"),
    csrf_token: str = Form(...),
):
    _require_role(request, "admin")
    _verify_csrf(request, csrf_token)
    enabled = str(active).lower() in {"1", "true", "yes", "on"}
    try:
        project = set_project_status(
            CONTROL_DB_PATH,
            project_id=project_id,
            active=enabled,
            actor=_actor(request),
        )
        add_audit_event(
            CONTROL_DB_PATH,
            finding_id=None,
            event_type="PROJECT_STATUS_CHANGED",
            summary=f"프로젝트 {'활성화' if enabled else '비활성화'}: {project['name']}",
            details={"project_id": project_id, "active": enabled},
            actor=_actor(request),
        )
        if enabled:
            context = getattr(request.state, "vulnflow_context", None)
            if context is not None:
                mode = _inspect_project_for_use(
                    context, _project_selection(project_id)
                )
                if not mode.get("active"):
                    _resume_lifecycle_if_needed(context)
    except (ValueError, KeyError) as exc:
        return RedirectResponse(f"/projects?selected={quote(project_id)}&error={quote(str(exc))}", status_code=303)
    return RedirectResponse(
        f"/projects?selected={quote(project_id)}&notice={'enabled' if enabled else 'disabled'}",
        status_code=303,
    )


@router.post("/admin/projects/{project_id}/members/{username}")
def project_membership_ui(
    request: Request,
    project_id: str,
    username: str,
    member: str = Form("0"),
    csrf_token: str = Form(...),
):
    _require_role(request, "admin")
    _verify_csrf(request, csrf_token)
    enabled = str(member).lower() in {"1", "true", "yes", "on"}
    try:
        set_project_membership(
            CONTROL_DB_PATH,
            project_id=project_id,
            username=username,
            member=enabled,
            actor=_actor(request),
        )
        add_audit_event(
            CONTROL_DB_PATH,
            finding_id=None,
            event_type="PROJECT_MEMBERSHIP_CHANGED",
            summary=f"프로젝트 사용자 {'배정' if enabled else '해제'}: {username}",
            details={"project_id": project_id, "username": username, "member": enabled},
            actor=_actor(request),
        )
    except (ValueError, KeyError) as exc:
        return RedirectResponse(f"/projects?selected={quote(project_id)}&error={quote(str(exc))}", status_code=303)
    return RedirectResponse(
        f"/projects?selected={quote(project_id)}&notice={'member_added' if enabled else 'member_removed'}",
        status_code=303,
    )


@router.post("/admin/projects/integrity-check")
async def project_integrity_check_ui(
    request: Request,
    project_id: str = Form(...),
    csrf_token: str = Form(...),
):
    _require_role(request, "admin")
    _verify_csrf(request, csrf_token)
    context = getattr(request.state, "vulnflow_context", None)
    if context is None:
        return RedirectResponse("/projects?error=애플리케이션 컨텍스트를 찾을 수 없습니다.", status_code=303)
    try:
        selection = _project_selection(project_id)
        mode = _inspect_project_for_use(context, selection)
        add_audit_event(
            CONTROL_DB_PATH,
            finding_id=None,
            event_type="PROJECT_INTEGRITY_CHECKED",
            summary=f"프로젝트 무결성 검사: {selection.name}",
            details={
                "project_id": selection.project_id,
                "status": mode.get("status"),
                "reason_count": len(mode.get("reasons") or []),
            },
            actor=_actor(request),
        )
        if not mode.get("active"):
            _resume_lifecycle_if_needed(context)
    except (ValueError, KeyError, OSError) as exc:
        return RedirectResponse(
            f"/projects?selected={quote(project_id)}&error={quote(str(exc))}", status_code=303
        )
    notice = "integrity_degraded" if mode.get("active") else "integrity_ok"
    return RedirectResponse(
        f"/projects?selected={quote(project_id)}&notice={notice}", status_code=303
    )


@router.post("/admin/projects/backup")
def project_backup_ui(
    request: Request,
    project_id: str = Form(...),
    csrf_token: str = Form(...),
):
    _require_role(request, "admin")
    _verify_csrf(request, csrf_token)
    context = getattr(request.state, "vulnflow_context", None)
    if context is None:
        return RedirectResponse("/projects?error=애플리케이션 컨텍스트를 찾을 수 없습니다.", status_code=303)
    try:
        selection = _project_selection(project_id)
        mode = project_recovery_mode(context, selection.project_id)
        if mode.get("active"):
            raise ValueError("읽기 전용으로 격리된 프로젝트는 새 복구 번들을 만들 수 없습니다.")
        if not bool(context.get("JOB_WORKER_ENABLED", False)):
            raise ValueError("백그라운드 작업자가 비활성화되어 있습니다.")
        supervisor = context.get("LIFECYCLE_SUPERVISOR")
        if supervisor is None or supervisor.snapshot().get("state") != "RUNNING":
            raise ValueError("백그라운드 작업자가 실행 중이 아닙니다. 무결성 재검사를 먼저 실행하세요.")
        job = create_background_job(
            selection.database,
            job_type="RECOVERY_BACKUP",
            payload={},
            requested_by=_actor(request),
            priority=9,
            max_attempts=int(context.get("JOB_MAX_ATTEMPTS", 3)),
            dedupe_key=f"manual-recovery:{selection.project_id}:{int(time.time() // 60)}",
        )
        add_audit_event(
            CONTROL_DB_PATH,
            finding_id=None,
            event_type="PROJECT_BACKUP_QUEUED",
            summary=f"프로젝트 복구 번들 예약: {selection.name}",
            details={"project_id": selection.project_id, "job_id": job.get("job_id")},
            actor=_actor(request),
        )
    except (ValueError, KeyError, OSError) as exc:
        return RedirectResponse(
            f"/projects?selected={quote(project_id)}&error={quote(str(exc))}", status_code=303
        )
    return RedirectResponse(
        f"/projects?selected={quote(project_id)}&notice=backup_queued", status_code=303
    )


@router.post("/admin/projects/recovery-drill")
def project_recovery_drill_ui(
    request: Request,
    project_id: str = Form(...),
    location: str = Form("local"),
    filename: str = Form(...),
    csrf_token: str = Form(...),
):
    _require_role(request, "admin")
    _verify_csrf(request, csrf_token)
    context = getattr(request.state, "vulnflow_context", None)
    if context is None:
        return RedirectResponse(
            "/projects?error=애플리케이션 컨텍스트를 찾을 수 없습니다.",
            status_code=303,
        )
    try:
        selection = _project_selection(project_id)
        bundle = resolve_stored_recovery_bundle(
            recovery_dir=selection.recovery,
            external_root=EXTERNAL_BACKUP_DIR,
            project_id=selection.project_id,
            location=location,
            filename=filename,
        )
        signing = _signing_config(context)
        report = run_recovery_drill(
            bundle,
            report_dir=selection.recovery / "drills",
            actor=_actor(request),
            project_id=selection.project_id,
            signing_keys=signing.keys,
            audit_signing_keys=signing.keys,
            require_signature=BACKUP_REQUIRE_SIGNATURE,
            current_schema_version=CURRENT_SCHEMA_VERSION,
        )
        add_audit_event(
            CONTROL_DB_PATH,
            finding_id=None,
            event_type="PROJECT_RECOVERY_DRILL_COMPLETED",
            summary=f"프로젝트 복구 리허설 완료: {selection.name}",
            details={
                "project_id": selection.project_id,
                "bundle_filename": report.get("bundle_filename"),
                "bundle_location": str(location or "local"),
                "report_filename": report.get("report_filename"),
                "duration_ms": report.get("duration_ms"),
            },
            actor=_actor(request),
        )
    except (ValueError, KeyError, OSError) as exc:
        return RedirectResponse(
            f"/projects?selected={quote(project_id)}&error={quote(str(exc))}",
            status_code=303,
        )
    return RedirectResponse(
        f"/projects?selected={quote(project_id)}&notice=drill_ok",
        status_code=303,
    )
