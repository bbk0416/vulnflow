from __future__ import annotations

"""Pilot onboarding, launch readiness, and customer-facing reporting."""

from typing import Any
from urllib.parse import quote

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from app.core.context import ApplicationContext
from app.router_dependencies import application_context

router = APIRouter()


def install_dependencies(_namespace: dict[str, Any]) -> None:
    """Compatibility no-op: this router resolves dependencies per request."""


def route_exports() -> dict[str, Any]:
    return {name: globals()[name] for name in ROUTE_NAMES}


ROUTE_NAMES = (
    "pilot_center",
    "pilot_profile_save",
    "pilot_readiness_api",
    "executive_report_export",
)


def _required(context: ApplicationContext, name: str):
    return context.require(name)


def _active_selection(request: Request, context: ApplicationContext):
    active = dict(getattr(request.state, "active_project", {}) or {})
    project_id = str(active.get("project_id") or "default")
    return _required(context, "project_selection")(
        context.get("CONTROL_DB_PATH"),
        project_id,
        projects_dir=context.get("PROJECTS_DIR"),
        default_database_path=context.get("DEFAULT_PROJECT_DB_PATH"),
        default_evidence_dir=context.get("DEFAULT_EVIDENCE_DIR"),
        default_export_dir=context.get("DEFAULT_EXPORT_DIR"),
        default_import_preview_dir=context.get("DEFAULT_IMPORT_PREVIEW_DIR"),
        default_recovery_dir=context.get("DEFAULT_RECOVERY_DIR"),
    )


def _pilot_context(request: Request, context: ApplicationContext) -> dict[str, Any]:
    selection = _active_selection(request, context)
    recovery = _required(context, "project_recovery_inventory")(selection, context)
    project_id = selection.project_id
    db_path = context.get("DB_PATH")
    members = _required(context, "list_project_members")(context.get("CONTROL_DB_PATH"), project_id)
    profile = _required(context, "get_pilot_profile")(db_path)
    readiness = _required(context, "build_pilot_readiness")(
        profile=profile,
        finding_count=_required(context, "count_findings")(db_path),
        import_count=len(_required(context, "list_import_batches")(db_path, limit=1)),
        member_count=len(members),
        integrity_status=str(getattr(request.state, "recovery_mode", {}).get("status") or "UNCHECKED"),
        backup_count=len(recovery.get("local") or []) + len(recovery.get("external") or []),
        recovery_drill_passed=str((recovery.get("latest_drill") or {}).get("status") or "").upper() == "PASSED",
        integrations=_required(context, "list_integrations")(db_path),
        cookie_secure=bool(context.get("COOKIE_SECURE", False)),
        public_base_url=str(context.get("PUBLIC_BASE_URL", "") or ""),
    )
    return {
        "profile": profile,
        "readiness": readiness,
        "project": {
            "project_id": selection.project_id,
            "name": selection.name,
            "slug": selection.slug,
        },
        "recovery": recovery,
        "members": members,
    }


@router.get("/pilot", response_class=HTMLResponse)
def pilot_center(
    request: Request,
    notice: str = "",
    error: str = "",
    context: ApplicationContext = Depends(application_context),
):
    _required(context, "_require_role")(request, "admin")
    pilot = _pilot_context(request, context)
    notices = {"profile_saved": "고객사·프로젝트 정보를 저장했습니다."}
    return context.templates.TemplateResponse(
        request=request,
        name="pilot.html",
        context={
            **pilot,
            "notice_message": notices.get(str(notice), ""),
            "error_message": str(error or ""),
        },
    )


@router.post("/pilot/profile")
def pilot_profile_save(
    request: Request,
    customer_name: str = Form(...),
    engagement_name: str = Form(...),
    contact_name: str = Form(""),
    contact_email: str = Form(""),
    scope_notes: str = Form(""),
    default_due_days: int = Form(30),
    report_footer: str = Form(""),
    csrf_token: str = Form(...),
    context: ApplicationContext = Depends(application_context),
):
    _required(context, "_require_role")(request, "admin")
    _required(context, "_verify_csrf")(request, csrf_token)
    try:
        _required(context, "save_pilot_profile")(
            context.get("DB_PATH"),
            customer_name=customer_name,
            engagement_name=engagement_name,
            contact_name=contact_name,
            contact_email=contact_email,
            scope_notes=scope_notes,
            default_due_days=default_due_days,
            report_footer=report_footer,
            actor=_required(context, "_actor")(request),
        )
    except ValueError as exc:
        return RedirectResponse(f"/pilot?error={quote(str(exc))}#profile", status_code=303)
    return RedirectResponse("/pilot?notice=profile_saved#profile", status_code=303)


@router.get("/api/v1/pilot-readiness")
def pilot_readiness_api(
    request: Request,
    context: ApplicationContext = Depends(application_context),
):
    _required(context, "_require_role")(request, "viewer")
    pilot = _pilot_context(request, context)
    return {
        "project": pilot["project"],
        "profile": pilot["profile"],
        "readiness": pilot["readiness"],
    }


@router.get("/export/executive-report.html")
def executive_report_export(
    request: Request,
    context: ApplicationContext = Depends(application_context),
):
    _required(context, "_require_role")(request, "viewer")
    db_path = context.get("DB_PATH")
    profile = _required(context, "get_pilot_profile")(db_path)
    active = dict(getattr(request.state, "active_project", {}) or {})
    project_name = str(active.get("name") or profile.get("engagement_name") or "VulnFlow 프로젝트")
    customer = str(profile.get("customer_name") or "customer").strip()
    safe_name = "".join(ch if ch.isalnum() or ch in {"-", "_"} else "_" for ch in customer)[:60] or "customer"
    download_name = f"{safe_name}_vulnerability_status.html"
    encoded_name = quote(download_name, safe="")
    return Response(
        _required(context, "generate_executive_html_report")(
            _required(context, "list_findings")(db_path),
            profile=profile,
            project_name=project_name,
        ),
        media_type="text/html; charset=utf-8",
        headers={
            "Content-Disposition": (
                'attachment; filename="vulnflow_executive_report.html"; '
                f"filename*=UTF-8''{encoded_name}"
            ),
            "Cache-Control": "no-store",
        },
    )
