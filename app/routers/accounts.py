from __future__ import annotations
from fastapi.responses import RedirectResponse as _UiLanguageRedirectResponse
from app.ui_i18n import UI_LANGUAGE_COOKIE, localized_template, safe_next_path

"""Browser login, logout, and administrator-managed database users."""

from typing import Any
from urllib.parse import quote, urlparse

from fastapi import APIRouter, Form, HTTPException, Request
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
    "login_page",
    "login_submit",
    "logout",
    "users_page",
    "user_create",
    "user_status",
    "user_password",
    "user_unlock",
    "user_sessions_revoke",
)


def _safe_next(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return "/"
    parsed = urlparse(text)
    if parsed.scheme or parsed.netloc or not text.startswith("/") or text.startswith("//"):
        return "/"
    return text


def _client_key(request: Request) -> str:
    return request.client.host if request.client is not None else ""


def _audit(event_type: str, summary: str, *, actor: str, details: dict[str, Any]) -> None:
    add_audit_event(
        CONTROL_DB_PATH,
        finding_id=None,
        event_type=event_type,
        summary=summary,
        details=details,
        actor=actor,
    )


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request, next: str = "", notice: str = ""):
    _ui_language = request.query_params.get("ui_language")
    if _ui_language in {"ko", "en"}:
        response = _UiLanguageRedirectResponse(
            url=safe_next_path(request.query_params.get("next") or "/login"),
            status_code=303,
        )
        response.set_cookie(
            key=UI_LANGUAGE_COOKIE,
            value=_ui_language,
            max_age=31536000,
            httponly=True,
            samesite="lax",
            path="/",
        )
        return response

    if getattr(request.state, "auth_method", "anonymous") not in {"anonymous", "health"}:
        return RedirectResponse(url=_safe_next(next), status_code=303)
    messages = {
        "logged_out": "안전하게 로그아웃했습니다.",
        "session_expired": "로그인 세션이 만료되었습니다. 다시 로그인하세요.",
        "password_changed": "비밀번호가 변경되었습니다. 새 비밀번호로 로그인하세요.",
    }
    return templates.TemplateResponse(
        request=request,
        name=localized_template(request, "login.html"),
        context={
            "next_path": _safe_next(next),
            "notice_message": messages.get(notice, ""),
            "error_message": "",
            "username": "",
        },
    )


@router.post("/login", response_class=HTMLResponse)
def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    csrf_token: str = Form(...),
    next: str = Form("/"),
):
    _verify_csrf(request, csrf_token)
    result = authenticate_user_password(
        CONTROL_DB_PATH,
        username=username,
        password=password,
        client_key=_client_key(request),
        rate_window_seconds=AUTH_RATE_WINDOW_SECONDS,
        username_client_attempts=AUTH_RATE_USERNAME_CLIENT_ATTEMPTS,
        client_attempts=AUTH_RATE_CLIENT_ATTEMPTS,
    )
    if result.status != "ok" or result.principal is None:
        # Deliberately identical for invalid, inactive, unknown, and rate-limited
        # accounts so the login endpoint does not disclose account state.
        message = "로그인 정보를 확인할 수 없습니다. 잠시 후 다시 시도하세요."
        status_code = 401
        headers = {"Cache-Control": "no-store"}
        if result.status == "rate_limited" and result.retry_after_seconds:
            headers["Retry-After"] = str(result.retry_after_seconds)
        return templates.TemplateResponse(
            request=request,
            name=localized_template(request, "login.html"),
            context={
                "next_path": _safe_next(next),
                "notice_message": "",
                "error_message": message,
                "username": str(username or ""),
            },
            status_code=status_code,
            headers=headers,
        )

    token, _expires_at = create_session(
        CONTROL_DB_PATH,
        username=result.principal.username,
        user_agent=request.headers.get("user-agent", ""),
        client_key=_client_key(request),
        lifetime_minutes=AUTH_SESSION_MINUTES,
        max_active_sessions=AUTH_MAX_ACTIVE_SESSIONS,
    )
    response = RedirectResponse(url=_safe_next(next), status_code=303)
    response.set_cookie(
        AUTH_SESSION_COOKIE,
        token,
        max_age=int(AUTH_SESSION_MINUTES) * 60,
        httponly=True,
        secure=bool(COOKIE_SECURE),
        samesite="strict",
        path="/",
    )
    return response


@router.post("/logout")
def logout(request: Request, csrf_token: str = Form(...)):
    _verify_csrf(request, csrf_token)
    token = request.cookies.get(AUTH_SESSION_COOKIE, "")
    if token:
        revoke_session(CONTROL_DB_PATH, token)
    response = RedirectResponse(url="/login?notice=logged_out", status_code=303)
    response.delete_cookie(AUTH_SESSION_COOKIE, path="/", secure=bool(COOKIE_SECURE), samesite="strict")
    response.delete_cookie(PROJECT_COOKIE, path="/", secure=bool(COOKIE_SECURE), samesite="strict")
    return response


@router.get("/admin/users", response_class=HTMLResponse)
def users_page(request: Request, notice: str = "", error: str = ""):
    _require_role(request, "admin")
    notices = {
        "created": "사용자 계정을 만들었습니다.",
        "enabled": "사용자 계정을 활성화했습니다.",
        "disabled": "사용자 계정을 비활성화하고 세션을 종료했습니다.",
        "password": "비밀번호를 변경하고 기존 세션을 종료했습니다.",
        "unlocked": "해당 사용자의 로그인 실패 기록을 초기화했습니다.",
        "sessions": "해당 사용자의 로그인 세션을 모두 종료했습니다.",
    }
    return templates.TemplateResponse(
        request=request,
        name="users.html",
        context={
            "users": list_users(CONTROL_DB_PATH),
            "roles": ("viewer", "operator", "approver", "admin"),
            "notice_message": notices.get(notice, ""),
            "error_message": str(error or ""),
        },
    )


@router.post("/admin/users")
def user_create(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    role: str = Form(...),
    csrf_token: str = Form(...),
):
    _require_role(request, "admin")
    _verify_csrf(request, csrf_token)
    try:
        user = create_user(CONTROL_DB_PATH, username=username, password=password, role=role, actor=_actor(request))
        _audit(
            "USER_CREATED",
            f"사용자 계정 생성: {user['username']}",
            actor=_actor(request),
            details={"username": user["username"], "role": user["role"]},
        )
    except ValueError as exc:
        return RedirectResponse(url=f"/admin/users?error={quote(str(exc))}", status_code=303)
    return RedirectResponse(url="/admin/users?notice=created", status_code=303)


@router.post("/admin/users/{username}/status")
def user_status(
    request: Request,
    username: str,
    active: str = Form("0"),
    csrf_token: str = Form(...),
):
    _require_role(request, "admin")
    _verify_csrf(request, csrf_token)
    enabled = str(active).lower() in {"1", "true", "yes", "on"}
    try:
        normalized = normalize_username(username)
        if not enabled and normalized == str(_actor(request)).lower():
            raise ValueError("현재 로그인한 자신의 계정은 비활성화할 수 없습니다.")
        user = set_user_active(CONTROL_DB_PATH, username=normalized, active=enabled, actor=_actor(request))
        _audit(
            "USER_STATUS_CHANGED",
            f"사용자 계정 {'활성화' if enabled else '비활성화'}: {user['username']}",
            actor=_actor(request),
            details={"username": user["username"], "active": enabled},
        )
    except (ValueError, KeyError) as exc:
        return RedirectResponse(url=f"/admin/users?error={quote(str(exc))}", status_code=303)
    return RedirectResponse(url=f"/admin/users?notice={'enabled' if enabled else 'disabled'}", status_code=303)


@router.post("/admin/users/{username}/password")
def user_password(
    request: Request,
    username: str,
    password: str = Form(...),
    csrf_token: str = Form(...),
):
    _require_role(request, "admin")
    _verify_csrf(request, csrf_token)
    try:
        user = set_user_password(CONTROL_DB_PATH, username=username, password=password, actor=_actor(request))
        _audit(
            "USER_PASSWORD_RESET",
            f"사용자 비밀번호 재설정: {user['username']}",
            actor=_actor(request),
            details={"username": user["username"]},
        )
    except (ValueError, KeyError) as exc:
        return RedirectResponse(url=f"/admin/users?error={quote(str(exc))}", status_code=303)
    if str(user["username"]).lower() == str(_actor(request)).lower():
        response = RedirectResponse(url="/login?notice=password_changed", status_code=303)
        response.delete_cookie(AUTH_SESSION_COOKIE, path="/", secure=bool(COOKIE_SECURE), samesite="strict")
        return response
    return RedirectResponse(url="/admin/users?notice=password", status_code=303)


@router.post("/admin/users/{username}/unlock")
def user_unlock(request: Request, username: str, csrf_token: str = Form(...)):
    _require_role(request, "admin")
    _verify_csrf(request, csrf_token)
    try:
        user = unlock_user(CONTROL_DB_PATH, username=username, actor=_actor(request))
        _audit(
            "USER_LOGIN_ATTEMPTS_CLEARED",
            f"사용자 로그인 실패 기록 초기화: {user['username']}",
            actor=_actor(request),
            details={"username": user["username"]},
        )
    except (ValueError, KeyError) as exc:
        return RedirectResponse(url=f"/admin/users?error={quote(str(exc))}", status_code=303)
    return RedirectResponse(url="/admin/users?notice=unlocked", status_code=303)


@router.post("/admin/users/{username}/sessions/revoke")
def user_sessions_revoke(request: Request, username: str, csrf_token: str = Form(...)):
    _require_role(request, "admin")
    _verify_csrf(request, csrf_token)
    try:
        normalized = normalize_username(username)
        count = revoke_user_sessions(CONTROL_DB_PATH, normalized)
        _audit(
            "USER_SESSIONS_REVOKED",
            f"사용자 세션 종료: {normalized}",
            actor=_actor(request),
            details={"username": normalized, "session_count": count},
        )
    except ValueError as exc:
        return RedirectResponse(url=f"/admin/users?error={quote(str(exc))}", status_code=303)
    return RedirectResponse(url="/admin/users?notice=sessions", status_code=303)
