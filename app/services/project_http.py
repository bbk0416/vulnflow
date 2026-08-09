from __future__ import annotations

"""HTTP project selection and per-request data-path activation."""

from collections.abc import Awaitable, Callable
from typing import Any

from fastapi import Request
from fastapi.responses import JSONResponse, Response

from app.core.auth import authenticate_request
from app.core.context import ApplicationContext
from app.core.project_scope import ProjectScopedPath, project_scope
from app.services.project_runtime import project_recovery_mode
from app.services.projects import (
    accessible_projects,
    default_project,
    project_selection,
    resolve_project,
    selection_as_public_dict,
)




def _control_database_path(context: ApplicationContext):
    current = context.get("DB_PATH")
    if not isinstance(current, ProjectScopedPath):
        return current
    return context.get("CONTROL_DB_PATH")

def _principal_for_project_scope(request: Request, context: ApplicationContext):
    session_cookie = str(context.get("AUTH_SESSION_COOKIE", "vulnflow_session"))
    demo_mode = bool(context.get("DEMO_MODE", False))
    proxy_headers_present = any(
        request.headers.get(name)
        for name in ("forwarded", "x-forwarded-for", "x-real-ip", "x-client-ip")
    )
    client_host = request.client.host if request.client is not None else ""
    return authenticate_request(
        request.headers.get("authorization", ""),
        api_tokens_json=str(context.get("AUTH_API_TOKENS_JSON", "") or ""),
        session_token=request.cookies.get(session_cookie, ""),
        db_path=_control_database_path(context),
        authenticate_session_fn=context.require("authenticate_session"),
        allow_local_fallback=(
            demo_mode
            and bool(context.get("ALLOW_LOCAL_ADMIN_FALLBACK", False))
            and not proxy_headers_present
        ),
        client_host=client_host,
        user_agent=request.headers.get("user-agent", ""),
        session_binding=str(context.get("AUTH_SESSION_BINDING", "off") or "off"),
        session_idle_minutes=int(context.get("AUTH_SESSION_IDLE_MINUTES", 0) or 0),
    )


def _selection(context: ApplicationContext, row: dict[str, Any], control_db_path):
    return project_selection(
        control_db_path,
        str(row["project_id"]),
        projects_dir=context.get("PROJECTS_DIR"),
        default_database_path=context.get("DEFAULT_PROJECT_DB_PATH"),
        default_evidence_dir=context.get("DEFAULT_EVIDENCE_DIR"),
        default_export_dir=context.get("DEFAULT_EXPORT_DIR"),
        default_import_preview_dir=context.get("DEFAULT_IMPORT_PREVIEW_DIR"),
        default_recovery_dir=context.get("DEFAULT_RECOVERY_DIR"),
    )


async def project_context_middleware(
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]],
    context: ApplicationContext,
) -> Response:
    """Resolve an authorized project before the regular security middleware."""
    principal = _principal_for_project_scope(request, context)
    control_db = _control_database_path(context)
    try:
        if principal is None:
            row = default_project(control_db)
            projects = [row]
        else:
            requested = (
                request.headers.get("X-VulnFlow-Project", "")
                if principal.auth_method == "bearer"
                else request.cookies.get(str(context.get("PROJECT_COOKIE", "vulnflow_project")), "")
            )
            projects = accessible_projects(control_db, principal)
            try:
                row = resolve_project(control_db, principal, requested)
            except PermissionError:
                if principal.auth_method == "bearer":
                    raise
                row = resolve_project(control_db, principal, "")
    except PermissionError as exc:
        return JSONResponse(
            {"detail": str(exc)},
            status_code=403,
            headers={"Cache-Control": "no-store"},
        )
    selection = _selection(context, row, control_db)
    request.state.active_project = selection_as_public_dict(selection)
    request.state.available_projects = projects
    request.state.recovery_mode = project_recovery_mode(context, selection.project_id)
    with project_scope(selection):
        response = await call_next(request)
    if principal is not None and principal.auth_method == "session":
        cookie_name = str(context.get("PROJECT_COOKIE", "vulnflow_project"))
        if request.cookies.get(cookie_name, "") != selection.project_id:
            response.set_cookie(
                cookie_name,
                selection.project_id,
                max_age=int(context.get("AUTH_SESSION_MINUTES", 480)) * 60,
                httponly=True,
                secure=bool(context.get("COOKIE_SECURE", False)),
                samesite="strict",
                path="/",
            )
    response.headers.setdefault("X-VulnFlow-Project", selection.project_id)
    return response
