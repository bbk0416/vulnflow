from __future__ import annotations

from typing import Any

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
    "integrations_page",
    "save_email_integration",
    "test_email_integration",
    "save_jira_integration",
    "test_jira_integration",
    "deliver_integrations_now",
    "create_finding_jira_issue",
    "api_collaboration_events",
)


def _integration_map() -> dict[str, dict[str, Any]]:
    return {str(item["channel"]): item for item in list_integrations(DB_PATH)}


def _page_context(*, notice: str = "", error: str = "", diagnostic: dict[str, Any] | None = None):
    integrations = _integration_map()
    email = integrations.get("EMAIL") or {"enabled": False, "config": {}, "secret_configured": False}
    configured_security = str((email.get("config") or {}).get("security") or "STARTTLS").upper()
    smtp_modes = ["STARTTLS", "SSL"]
    if SMTP_ALLOW_PLAIN or configured_security == "PLAIN":
        smtp_modes.append("PLAIN")
    return {
        "email": email,
        "jira": integrations.get("JIRA") or {"enabled": False, "config": {}, "secret_configured": False},
        "events": list_collaboration_events(DB_PATH, limit=100),
        "secret_key_ready": len(str(INTEGRATION_SECRET_KEY or "")) >= 32,
        "smtp_modes": smtp_modes,
        "smtp_plain_allowed": SMTP_ALLOW_PLAIN,
        "smtp_private_networks_allowed": SMTP_ALLOW_PRIVATE_NETWORKS,
        "smtp_host_allowlist": SMTP_HOST_ALLOWLIST,
        "diagnostic": diagnostic,
        "notice_message": {
            "email_saved": "이메일 알림 설정을 저장했습니다.",
            "jira_saved": "Jira 연동 설정을 저장했습니다.",
            "delivery_queued": "협업 알림 전송 작업을 예약했습니다.",
        }.get(notice, ""),
        "error_message": error,
    }


def _render_page(request: Request, *, diagnostic: dict[str, Any] | None = None, status_code: int = 200):
    return templates.TemplateResponse(
        request=request,
        name="integrations.html",
        status_code=status_code,
        context=_page_context(diagnostic=diagnostic),
    )


@router.get("/integrations", response_class=HTMLResponse)
def integrations_page(request: Request, notice: str = "", error: str = ""):
    _require_role(request, "admin")
    return templates.TemplateResponse(
        request=request,
        name="integrations.html",
        context=_page_context(notice=notice, error=error),
    )


@router.post("/integrations/email")
def save_email_integration(
    request: Request,
    enabled: bool = Form(False),
    host: str = Form(""),
    port: int = Form(587),
    security: str = Form("STARTTLS"),
    username: str = Form(""),
    password: str = Form(""),
    from_address: str = Form(""),
    recipients: str = Form(""),
    events: list[str] = Form(default=[]),
    csrf_token: str = Form(...),
):
    _require_role(request, "admin")
    _verify_csrf(request, csrf_token)
    if len(str(INTEGRATION_SECRET_KEY or "")) < 32:
        raise HTTPException(503, "VULNFLOW_INTEGRATION_SECRET_KEY를 먼저 설정하세요.")
    existing = get_integration(DB_PATH, "EMAIL") or {}
    config = {
        "host": host.strip(),
        "port": int(port),
        "security": security.strip().upper(),
        "username": username.strip(),
        "from_address": from_address.strip(),
        "recipients": [item.strip() for item in recipients.replace(";", ",").split(",") if item.strip()],
        "events": events,
    }
    try:
        normalized = validate_email_config(
            config,
            secret_configured=bool(password or existing.get("secret_configured") or not username.strip()),
            allow_plain=SMTP_ALLOW_PLAIN,
        )
        ciphertext = encrypt_secret({"password": password}, master_key=INTEGRATION_SECRET_KEY) if password else None
        save_integration(
            DB_PATH, channel="EMAIL", enabled=enabled, config=normalized,
            secret_ciphertext=ciphertext, actor=_actor(request),
        )
    except (ValueError, IntegrationSecretError) as exc:
        raise HTTPException(400, str(exc)) from exc
    return RedirectResponse("/integrations?notice=email_saved", status_code=303)


@router.post("/integrations/email/test", response_class=HTMLResponse)
def test_email_integration(request: Request, csrf_token: str = Form(...)):
    _require_role(request, "admin")
    _verify_csrf(request, csrf_token)
    if len(str(INTEGRATION_SECRET_KEY or "")) < 32:
        raise HTTPException(503, "VULNFLOW_INTEGRATION_SECRET_KEY를 먼저 설정하세요.")
    try:
        result = diagnose_saved_integration(
            DB_PATH, channel="EMAIL", master_key=INTEGRATION_SECRET_KEY,
            timeout_seconds=COLLABORATION_TIMEOUT_SECONDS,
            allow_private_networks=OUTBOUND_ALLOW_PRIVATE_NETWORKS,
            host_allowlist=OUTBOUND_HOST_ALLOWLIST,
            max_response_bytes=OUTBOUND_MAX_RESPONSE_BYTES,
            smtp_allow_private_networks=SMTP_ALLOW_PRIVATE_NETWORKS,
            smtp_host_allowlist=SMTP_HOST_ALLOWLIST,
            smtp_allow_plain=SMTP_ALLOW_PLAIN,
        )
    except IntegrationSecretError as exc:
        raise HTTPException(503, "저장된 SMTP 비밀번호를 복호화하지 못했습니다.") from exc
    return _render_page(request, diagnostic=result, status_code=200 if result["ok"] else 502)


@router.post("/integrations/jira")
def save_jira_integration(
    request: Request,
    enabled: bool = Form(False),
    base_url: str = Form(""),
    email: str = Form(""),
    api_token: str = Form(""),
    project_key: str = Form(""),
    issue_type: str = Form("Task"),
    events: list[str] = Form(default=[]),
    csrf_token: str = Form(...),
):
    _require_role(request, "admin")
    _verify_csrf(request, csrf_token)
    if len(str(INTEGRATION_SECRET_KEY or "")) < 32:
        raise HTTPException(503, "VULNFLOW_INTEGRATION_SECRET_KEY를 먼저 설정하세요.")
    existing = get_integration(DB_PATH, "JIRA") or {}
    config = {
        "base_url": base_url.strip(), "email": email.strip(),
        "project_key": project_key.strip(), "issue_type": issue_type.strip(), "events": events,
    }
    try:
        normalized = validate_jira_config(
            config, secret_configured=bool(api_token or existing.get("secret_configured")),
        )
        ciphertext = encrypt_secret({"api_token": api_token}, master_key=INTEGRATION_SECRET_KEY) if api_token else None
        save_integration(
            DB_PATH, channel="JIRA", enabled=enabled, config=normalized,
            secret_ciphertext=ciphertext, actor=_actor(request),
        )
    except (ValueError, IntegrationSecretError) as exc:
        raise HTTPException(400, str(exc)) from exc
    return RedirectResponse("/integrations?notice=jira_saved", status_code=303)


@router.post("/integrations/jira/test", response_class=HTMLResponse)
def test_jira_integration(request: Request, csrf_token: str = Form(...)):
    _require_role(request, "admin")
    _verify_csrf(request, csrf_token)
    if len(str(INTEGRATION_SECRET_KEY or "")) < 32:
        raise HTTPException(503, "VULNFLOW_INTEGRATION_SECRET_KEY를 먼저 설정하세요.")
    try:
        result = diagnose_saved_integration(
            DB_PATH, channel="JIRA", master_key=INTEGRATION_SECRET_KEY,
            timeout_seconds=COLLABORATION_TIMEOUT_SECONDS,
            allow_private_networks=OUTBOUND_ALLOW_PRIVATE_NETWORKS,
            host_allowlist=OUTBOUND_HOST_ALLOWLIST,
            max_response_bytes=OUTBOUND_MAX_RESPONSE_BYTES,
        )
    except IntegrationSecretError as exc:
        raise HTTPException(503, "저장된 Jira API 토큰을 복호화하지 못했습니다.") from exc
    return _render_page(request, diagnostic=result, status_code=200 if result["ok"] else 502)


@router.post("/integrations/deliver")
def deliver_integrations_now(request: Request, csrf_token: str = Form(...)):
    _require_role(request, "admin")
    _verify_csrf(request, csrf_token)
    create_background_job(
        DB_PATH, job_type="COLLABORATION_DELIVERY", payload={"scan_due": True},
        requested_by=_actor(request), priority=20, max_attempts=JOB_MAX_ATTEMPTS,
        dedupe_key="manual-collaboration-delivery",
    )
    return RedirectResponse("/integrations?notice=delivery_queued", status_code=303)


@router.post("/finding/{finding_id}/jira")
def create_finding_jira_issue(request: Request, finding_id: str, csrf_token: str = Form(...)):
    _require_role(request, "operator")
    _verify_csrf(request, csrf_token)
    try:
        queue_jira_issue_create(
            DB_PATH, finding_id=finding_id, actor=_actor(request),
            app_base_url=str(PUBLIC_BASE_URL or ""),
        )
        create_background_job(
            DB_PATH, job_type="COLLABORATION_DELIVERY", payload={"scan_due": False},
            requested_by=_actor(request), priority=20, max_attempts=JOB_MAX_ATTEMPTS,
            dedupe_key=f"jira-create-delivery:{finding_id}",
        )
    except KeyError as exc:
        raise HTTPException(404, "해당 취약점을 찾을 수 없습니다.") from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return RedirectResponse(f"/finding/{finding_id}?notice=jira_queued", status_code=303)


@router.get("/api/v1/collaboration-events")
def api_collaboration_events(request: Request, status: str = "", limit: int = 200):
    _require_role(request, "admin")
    return {"items": list_collaboration_events(DB_PATH, status=status, limit=limit)}
