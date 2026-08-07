from __future__ import annotations

"""HTTP authentication, request telemetry, write barriers, and error rendering."""

from collections.abc import Callable
import time
import uuid
from typing import Any

from fastapi import HTTPException, Request
from fastapi.exception_handlers import http_exception_handler
from fastapi.responses import JSONResponse, Response

from app.application_runtime_common import Namespace, runtime_callback
from app.core.context import ApplicationContext, RequestRuntime, get_application_context
from app.core.observability import REQUEST_ID_RE
from app.core.transactions import transaction_scope
from app.services.http_auth import unauthenticated_response
from app.services.operation_guard import WriteBarrierActive, bind_operation_guard
from app.services.recovery_mode import recovery_mode_summary, recovery_write_allowed
def _apply_security_headers(
    response: Response, *, request_id: str, recovery_active: bool = False
) -> Response:
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; style-src 'self'; img-src 'self' data:; "
        "form-action 'self'; base-uri 'self'; frame-ancestors 'none'",
    )
    response.headers.setdefault("Cache-Control", "no-store")
    response.headers["X-Request-ID"] = request_id
    if recovery_active:
        response.headers["X-VulnFlow-Recovery-Mode"] = "active"
    return response
async def local_security_scoped(
    request: Request,
    call_next: Callable[[Request], Any],
    context: ApplicationContext,
    *,
    namespace: Namespace,
):
    runtime_callback(namespace, "_refresh_router_dependencies")(context)
    request.state.vulnflow_context = context
    started = time.perf_counter()
    incoming_request_id = request.headers.get("X-Request-ID", "").strip()
    request_id = (
        incoming_request_id
        if REQUEST_ID_RE.fullmatch(incoming_request_id)
        else uuid.uuid4().hex
    )
    request.state.request_id = request_id
    open_health_paths = {"/health", "/health/live", "/health/ready"}
    open_browser_paths = {"/login"}
    is_static = request.url.path.startswith("/static/")
    if request.url.path in open_health_paths:
        actor, role, auth_method = "health-check", "viewer", "health"
    elif request.url.path in open_browser_paths or is_static:
        principal = None if is_static else runtime_callback(namespace, "_principal")(request)
        if principal is None:
            actor, role, auth_method = "anonymous", "viewer", "anonymous"
        else:
            actor, role, auth_method = principal.username, principal.role, principal.auth_method
    else:
        principal = runtime_callback(namespace, "_principal")(request)
        if principal is None:
            response = unauthenticated_response(request, context)
            _apply_security_headers(response, request_id=request_id)
            context.metrics.observe_request(
                request.method,
                request.url.path,
                401,
                time.perf_counter() - started,
            )
            return response
        actor, role, auth_method = (
            principal.username,
            principal.role,
            principal.auth_method,
        )
    request.state.actor = actor
    request.state.role = role
    request.state.auth_method = auth_method
    request.state.vulnflow_runtime = RequestRuntime(
        application=context,
        actor=actor,
        role=role,
        auth_method=auth_method,
        request_id=request_id,
    )
    recovery_mode = dict(
        getattr(request.state, "recovery_mode", None) or context.get("RECOVERY_MODE", {}) or {}
    )
    request.state.recovery_mode = recovery_mode
    csrf_cookie = str(context.get("CSRF_COOKIE", "vulnflow_csrf"))
    csrf = request.cookies.get(csrf_cookie) or runtime_callback(namespace, "_new_csrf")()
    request.state.csrf_token = csrf
    if recovery_mode.get("active") and not recovery_write_allowed(
        request.method, request.url.path
    ):
        detail = (
            "무결성 이상으로 읽기 전용 복구 모드가 활성화되어 일반 변경 요청을 차단했습니다. "
            "관리자는 시스템·복구 화면에서 백업을 내려받거나 정상 복구본을 검증·복원하세요."
        )
        headers = {
            "X-Request-ID": request_id,
            "X-VulnFlow-Recovery-Mode": "active",
            "Retry-After": "60",
        }
        recovery_summary = recovery_mode_summary(recovery_mode)
        if request.url.path.startswith("/api/") or "text/html" not in request.headers.get(
            "accept", "text/html"
        ):
            response = JSONResponse(
                {"detail": detail, "recovery_mode": recovery_summary},
                status_code=503,
                headers=headers,
            )
        else:
            response = context.templates.TemplateResponse(
                request=request,
                name="recovery_blocked.html",
                context={"detail": detail, "recovery_mode": recovery_summary},
                status_code=503,
                headers=headers,
            )
        _apply_security_headers(
            response, request_id=request_id, recovery_active=True
        )
        context.metrics.observe_request(
            request.method, request.url.path, 503, time.perf_counter() - started
        )
        context.logger.warning(
            "write blocked by read-only recovery mode",
            extra={
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "actor": actor,
                "role": role,
            },
        )
        return response
    operation_guard = bind_operation_guard(context)
    write_activity = None
    try:
        write_activity = operation_guard.begin_http_write(
            activity_id=request_id,
            actor=actor,
            method=request.method,
            path=request.url.path,
        )
    except WriteBarrierActive as exc:
        response = JSONResponse(
            {"detail": str(exc)},
            status_code=503,
            headers={"Retry-After": "5", "X-Request-ID": request_id},
        )
        context.metrics.observe_request(
            request.method,
            request.url.path,
            503,
            time.perf_counter() - started,
        )
        return response
    try:
        response = await call_next(request)
    except Exception:
        context.logger.exception(
            "request failed",
            extra={
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "actor": actor,
                "role": role,
            },
        )
        context.metrics.observe_request(
            request.method,
            request.url.path,
            500,
            time.perf_counter() - started,
        )
        raise
    finally:
        if write_activity is not None:
            try:
                operation_guard.end_http_write(write_activity)
            except Exception:
                context.logger.exception(
                    "cluster write activity cleanup failed",
                    extra={"request_id": request_id},
                )
    if (
        request.url.path not in open_health_paths
        and not is_static
        and not request.cookies.get(csrf_cookie)
    ):
        response.set_cookie(
            csrf_cookie,
            csrf,
            httponly=True,
            secure=bool(context.get("COOKIE_SECURE", False)),
            samesite="strict",
        )
    _apply_security_headers(
        response,
        request_id=request_id,
        recovery_active=bool(recovery_mode.get("active")),
    )
    route = getattr(request.scope.get("route"), "path", request.url.path)
    duration = time.perf_counter() - started
    context.metrics.observe_request(
        request.method, route, response.status_code, duration
    )
    context.logger.info(
        "request completed",
        extra={
            "request_id": request_id,
            "method": request.method,
            "path": route,
            "status": response.status_code,
            "duration_ms": round(duration * 1000, 2),
            "actor": actor,
            "role": role,
        },
    )
    return response
async def local_security(
    request: Request,
    call_next: Callable[[Request], Any],
    *,
    namespace: Namespace,
):
    context = get_application_context(request.app)
    assert context.transaction_registry is not None
    with transaction_scope(context.transaction_registry):
        return await local_security_scoped(
            request, call_next, context, namespace=namespace
        )

async def friendly_http_error(request: Request, exc: HTTPException):
    if request.url.path.startswith("/api/") or request.url.path == "/health":
        return JSONResponse(
            {"detail": exc.detail},
            status_code=exc.status_code,
            headers=exc.headers,
        )
    if "text/html" in request.headers.get("accept", "text/html"):
        context = get_application_context(request.app)
        return context.templates.TemplateResponse(
            request=request,
            name="error.html",
            context={"status_code": exc.status_code, "detail": exc.detail},
            status_code=exc.status_code,
            headers=exc.headers,
        )
    return await http_exception_handler(request, exc)
