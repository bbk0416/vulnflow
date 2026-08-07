from __future__ import annotations

"""Project-scoped email and Jira collaboration delivery."""

from dataclasses import dataclass
from datetime import date, timedelta
from email.message import EmailMessage
import json
from pathlib import Path
import smtplib
import ssl
from typing import Any
from urllib.parse import quote, urlparse

from app.core.retry import parse_retry_after, retryable_http_status
from app.repositories.collaboration import (
    claim_due_collaboration_events,
    get_finding_external_link,
    get_integration,
    queue_collaboration_event,
    record_collaboration_delivery,
    upsert_finding_external_link,
)
from app.services.collaboration_email import (
    CollaborationConfigError, DEFAULT_EMAIL_EVENTS, configured_events as _events,
    validate_email_config,
)
from app.services.integration_crypto import decrypt_secret
from app.services.outbound_smtp import connect_outbound_smtp
from app.services.outbound_http import (
    OutboundPolicyError, OutboundResolutionError, OutboundResponseTooLarge,
    OutboundTransportError, request_outbound,
)

DEFAULT_JIRA_EVENTS = frozenset({
    "finding.workflow_changed",
    "remediation.verification_requested",
    "remediation.verification_decided",
    "risk_acceptance.requested",
    "risk_acceptance.decided",
})


@dataclass(frozen=True)
class DeliveryResult:
    delivered: bool
    response_status: int | None = None
    error: str = ""
    retryable: bool = True
    retry_after_seconds: float | None = None
    external_key: str = ""
    external_url: str = ""


def validate_jira_config(config: dict[str, Any], *, secret_configured: bool) -> dict[str, Any]:
    base_url = str(config.get("base_url") or "").strip().rstrip("/")
    parsed = urlparse(base_url)
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise CollaborationConfigError("Jira Cloud 주소는 사용자정보가 없는 HTTPS URL이어야 합니다.")
    email = str(config.get("email") or "").strip()
    project_key = str(config.get("project_key") or "").strip().upper()
    issue_type = str(config.get("issue_type") or "Task").strip()
    if "@" not in email:
        raise CollaborationConfigError("Jira 계정 이메일을 입력하세요.")
    if not project_key or len(project_key) > 30 or not project_key.replace("_", "").isalnum():
        raise CollaborationConfigError("Jira 프로젝트 키가 올바르지 않습니다.")
    if not issue_type:
        raise CollaborationConfigError("Jira 이슈 유형을 입력하세요.")
    if not secret_configured:
        raise CollaborationConfigError("Jira API 토큰이 필요합니다.")
    return {
        "base_url": base_url,
        "email": email,
        "project_key": project_key,
        "issue_type": issue_type[:80],
        "events": sorted(_events(config, DEFAULT_JIRA_EVENTS)),
    }


def _finding_snapshot(db_path: str | Path, finding_id: str) -> dict[str, Any]:
    if not finding_id:
        return {}
    from app.repositories.findings import get_finding

    finding = get_finding(db_path, finding_id) or {}
    allowed = {
        "finding_id", "product", "cve_id", "asset_name", "component", "component_version",
        "status", "owner", "due_date", "target_date", "decision_label", "score", "notes",
    }
    return {key: finding.get(key) for key in allowed if key in finding}


def queue_event_for_integrations(
    db_path: str | Path,
    *,
    event_type: str,
    payload: dict[str, Any],
    actor: str,
    app_base_url: str = "",
    idempotency_key: str = "",
) -> list[str]:
    finding_id = str(payload.get("finding_id") or "").strip()
    enriched = dict(payload)
    if finding_id:
        enriched["finding"] = _finding_snapshot(db_path, finding_id)
        if app_base_url:
            enriched["finding_url"] = f"{app_base_url.rstrip('/')}/finding/{quote(finding_id, safe='')}"
    created: list[str] = []
    email = get_integration(db_path, "EMAIL")
    if email and email.get("enabled") and event_type in _events(email.get("config") or {}, DEFAULT_EMAIL_EVENTS):
        created.append(queue_collaboration_event(
            db_path,
            channel="EMAIL",
            event_type=event_type,
            finding_id=finding_id,
            payload=enriched,
            actor=actor,
            dedupe_key=f"EMAIL:{idempotency_key}" if idempotency_key else "",
        ))
    jira = get_integration(db_path, "JIRA")
    if jira and jira.get("enabled") and event_type in _events(jira.get("config") or {}, DEFAULT_JIRA_EVENTS):
        if finding_id and get_finding_external_link(db_path, finding_id, provider="JIRA"):
            created.append(queue_collaboration_event(
                db_path,
                channel="JIRA",
                event_type="jira.issue_comment",
                finding_id=finding_id,
                payload={**enriched, "source_event_type": event_type},
                actor=actor,
                dedupe_key=f"JIRA:{idempotency_key}" if idempotency_key else "",
            ))
    return created


def queue_jira_issue_create(
    db_path: str | Path,
    *,
    finding_id: str,
    actor: str,
    app_base_url: str = "",
) -> str:
    integration = get_integration(db_path, "JIRA")
    if not integration or not integration.get("enabled"):
        raise CollaborationConfigError("Jira 연동이 활성화되어 있지 않습니다.")
    existing = get_finding_external_link(db_path, finding_id, provider="JIRA")
    if existing:
        raise CollaborationConfigError(f"이미 Jira 티켓 {existing['external_key']}에 연결돼 있습니다.")
    finding = _finding_snapshot(db_path, finding_id)
    if not finding:
        raise KeyError(finding_id)
    payload = {"finding_id": finding_id, "finding": finding}
    if app_base_url:
        payload["finding_url"] = f"{app_base_url.rstrip('/')}/finding/{quote(finding_id, safe='')}"
    return queue_collaboration_event(
        db_path,
        channel="JIRA",
        event_type="jira.issue_create",
        finding_id=finding_id,
        payload=payload,
        actor=actor,
        dedupe_key=f"jira-create:{finding_id}",
        requeue_failed=True,
    )


def enqueue_due_reminders(
    db_path: str | Path,
    *,
    due_soon_days: int,
    actor: str = "system-collaboration",
) -> dict[str, int]:
    from app.core.transactions import read_connection

    today = date.today()
    soon = today + timedelta(days=max(0, int(due_soon_days)))
    with read_connection(db_path, operation="collaboration_due_reminder_scan") as conn:
        rows = conn.execute(
            """
            SELECT finding_id,due_date,target_date,status FROM findings
             WHERE record_state='ACTIVE' AND status IN ('OPEN','IN_PROGRESS','MITIGATED')
               AND COALESCE(NULLIF(due_date,''),NULLIF(target_date,'')) IS NOT NULL
            """
        ).fetchall()
    counts = {"due_soon": 0, "overdue": 0}
    email = get_integration(db_path, "EMAIL")
    if not email or not email.get("enabled"):
        return counts
    enabled_events = _events(email.get("config") or {}, DEFAULT_EMAIL_EVENTS)
    for row in rows:
        raw_due = str(row["due_date"] or row["target_date"] or "")
        try:
            due = date.fromisoformat(raw_due)
        except ValueError:
            continue
        if due < today and "finding.overdue" in enabled_events:
            event_type = "finding.overdue"
            counts["overdue"] += 1
        elif today <= due <= soon and "finding.due_soon" in enabled_events:
            event_type = "finding.due_soon"
            counts["due_soon"] += 1
        else:
            continue
        queue_collaboration_event(
            db_path,
            channel="EMAIL",
            event_type=event_type,
            finding_id=str(row["finding_id"]),
            payload={"finding_id": str(row["finding_id"]), "due_date": raw_due, "finding": _finding_snapshot(db_path, str(row["finding_id"]))},
            actor=actor,
            dedupe_key=f"{event_type}:{row['finding_id']}:{today.isoformat()}",
        )
    return counts


def _event_label(event_type: str) -> str:
    return {
        "finding.workflow_changed": "취약점 처리 상태 변경",
        "remediation.verification_requested": "조치 검증 요청",
        "remediation.verification_decided": "조치 검증 결과",
        "risk_acceptance.requested": "위험수용 승인 요청",
        "risk_acceptance.decided": "위험수용 승인 결과",
        "finding.due_soon": "조치기한 임박",
        "finding.overdue": "조치기한 초과",
        "jira.issue_create": "Jira 티켓 생성",
        "jira.issue_comment": "Jira 티켓 업데이트",
    }.get(event_type, event_type)


def _summary(payload: dict[str, Any], event_type: str) -> str:
    finding = payload.get("finding") if isinstance(payload.get("finding"), dict) else {}
    fid = str(finding.get("finding_id") or payload.get("finding_id") or "")
    product = str(finding.get("product") or "취약점")
    cve = str(finding.get("cve_id") or "")
    return f"[{_event_label(event_type)}] {fid} {product} {cve}".strip()[:255]


def _lines(payload: dict[str, Any], event_type: str) -> list[str]:
    finding = payload.get("finding") if isinstance(payload.get("finding"), dict) else {}
    lines = [_event_label(event_type)]
    fields = [
        ("관리번호", finding.get("finding_id") or payload.get("finding_id")),
        ("취약점", " ".join(str(value) for value in (finding.get("product"), finding.get("cve_id")) if value)),
        ("자산", finding.get("asset_name")),
        ("상태", finding.get("status") or payload.get("status")),
        ("담당자", finding.get("owner") or payload.get("owner")),
        ("목표일", finding.get("due_date") or finding.get("target_date") or payload.get("due_date")),
    ]
    for label, value in fields:
        if value not in {None, ""}:
            lines.append(f"{label}: {value}")
    source_event = payload.get("source_event_type")
    if source_event:
        lines.append(f"VulnFlow 이벤트: {source_event}")
    if payload.get("finding_url"):
        lines.append(f"VulnFlow: {payload['finding_url']}")
    return lines


def _adf_document(lines: list[str]) -> dict[str, Any]:
    return {
        "type": "doc",
        "version": 1,
        "content": [
            {"type": "paragraph", "content": [{"type": "text", "text": line}]}
            for line in lines if line
        ],
    }


def _deliver_email(
    config: dict[str, Any],
    secret: dict[str, str],
    event: dict[str, Any],
    *,
    timeout: int,
    allow_private_networks: bool = False,
    host_allowlist: str | tuple[str, ...] = (),
    allow_plain: bool = False,
) -> DeliveryResult:
    normalized = validate_email_config(
        config, secret_configured=bool(secret.get("password")), allow_plain=allow_plain
    )
    message = EmailMessage()
    message["Subject"] = _summary(event["payload"], str(event["event_type"]))
    message["From"] = normalized["from_address"]
    message["To"] = ", ".join(normalized["recipients"])
    message.set_content("\n".join(_lines(event["payload"], str(event["event_type"]))))
    try:
        server = connect_outbound_smtp(
            normalized["host"],
            normalized["port"],
            security=normalized["security"],
            timeout_seconds=timeout,
            allow_private_networks=allow_private_networks,
            host_allowlist=host_allowlist,
            allow_plain=allow_plain,
        )
        with server:
            if normalized["username"]:
                server.login(normalized["username"], secret.get("password", ""))
            server.send_message(message)
        return DeliveryResult(True, response_status=250)
    except smtplib.SMTPAuthenticationError as exc:
        return DeliveryResult(False, response_status=int(exc.smtp_code or 535), error="SMTP authentication failed", retryable=False)
    except OutboundPolicyError as exc:
        return DeliveryResult(False, error=f"{type(exc).__name__}: {exc}", retryable=False)
    except (OutboundResolutionError, OutboundTransportError) as exc:
        return DeliveryResult(False, error=f"{type(exc).__name__}: {exc}", retryable=True)
    except (smtplib.SMTPException, ssl.SSLError, OSError) as exc:
        return DeliveryResult(False, error=f"{type(exc).__name__}: {exc}", retryable=True)


def _jira_request(
    config: dict[str, Any], secret: dict[str, str], event: dict[str, Any], *,
    timeout: int, allow_private_networks: bool = False,
    host_allowlist: str | tuple[str, ...] = (), max_response_bytes: int = 1024 * 1024,
) -> DeliveryResult:
    normalized = validate_jira_config(config, secret_configured=bool(secret.get("api_token")))
    event_type = str(event["event_type"])
    finding_id = str(event.get("finding_id") or event["payload"].get("finding_id") or "")
    auth = (normalized["email"], secret["api_token"])
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    try:
        if event_type == "jira.issue_create":
            body = {
                "fields": {
                    "project": {"key": normalized["project_key"]},
                    "issuetype": {"name": normalized["issue_type"]},
                    "summary": _summary(event["payload"], event_type),
                    "description": _adf_document(_lines(event["payload"], event_type)),
                }
            }
            response = request_outbound(
                "POST", f"{normalized['base_url']}/rest/api/3/issue",
                basic_auth=auth, headers=headers, json_body=body,
                timeout_seconds=timeout, max_response_bytes=max_response_bytes,
                allow_private_networks=allow_private_networks, host_allowlist=host_allowlist,
            )
            payload = response.json() if response.content else {}
            key = str(payload.get("key") or "") if isinstance(payload, dict) else ""
            url = f"{normalized['base_url']}/browse/{quote(key, safe='')}" if key else ""
        else:
            link = get_finding_external_link(Path(event["db_path"]), finding_id, provider="JIRA")
            if not link:
                return DeliveryResult(True, response_status=204)
            key = str(link["external_key"])
            url = str(link["external_url"])
            response = request_outbound(
                "POST", f"{normalized['base_url']}/rest/api/3/issue/{quote(key, safe='')}/comment",
                basic_auth=auth, headers=headers,
                json_body={"body": _adf_document(_lines(event["payload"], str(event["payload"].get("source_event_type") or event_type)))},
                timeout_seconds=timeout, max_response_bytes=max_response_bytes,
                allow_private_networks=allow_private_networks, host_allowlist=host_allowlist,
            )
        if 200 <= response.status_code < 300:
            return DeliveryResult(True, response_status=response.status_code, external_key=key, external_url=url)
        retry_after = parse_retry_after(response.headers.get("Retry-After"))
        retryable = retryable_http_status(response.status_code)
        return DeliveryResult(
            False,
            response_status=response.status_code,
            error=f"Jira HTTP {response.status_code}: {response.text[:500]}",
            retryable=retryable,
            retry_after_seconds=retry_after,
        )
    except (OutboundPolicyError, OutboundResponseTooLarge) as exc:
        return DeliveryResult(False, error=f"{type(exc).__name__}: {exc}", retryable=False)
    except (OutboundResolutionError, OutboundTransportError) as exc:
        return DeliveryResult(False, error=f"{type(exc).__name__}: {exc}", retryable=True)


def deliver_collaboration_events(
    db_path: str | Path,
    *,
    master_key: str,
    timeout_seconds: int = 10,
    max_attempts: int = 5,
    due_soon_days: int = 3,
    limit: int = 50,
    allow_private_networks: bool = False,
    host_allowlist: str | tuple[str, ...] = (),
    max_response_bytes: int = 1024 * 1024,
    smtp_allow_private_networks: bool = False,
    smtp_host_allowlist: str | tuple[str, ...] = (),
    smtp_allow_plain: bool = False,
) -> dict[str, int]:
    summary = {"delivered": 0, "retry": 0, "failed": 0, "skipped": 0, "due_soon": 0, "overdue": 0}
    reminders = enqueue_due_reminders(db_path, due_soon_days=due_soon_days)
    summary.update(reminders)
    for event in claim_due_collaboration_events(db_path, limit=limit):
        integration = get_integration(db_path, str(event["channel"]), include_secret=True)
        if not integration or not integration.get("enabled"):
            outcome = record_collaboration_delivery(
                db_path,
                event_id=str(event["event_id"]),
                delivered=False,
                error="integration disabled or missing",
                max_attempts=1,
                retryable=False,
            )
            summary["failed" if outcome["status"] == "FAILED" else "retry"] += 1
            continue
        try:
            secret = decrypt_secret(str(integration.get("secret_ciphertext") or ""), master_key=master_key)
            config = dict(integration.get("config") or {})
            event["db_path"] = str(db_path)
            if str(event["channel"]) == "EMAIL":
                result = _deliver_email(
                    config,
                    secret,
                    event,
                    timeout=timeout_seconds,
                    allow_private_networks=smtp_allow_private_networks,
                    host_allowlist=smtp_host_allowlist,
                    allow_plain=smtp_allow_plain,
                )
            else:
                result = _jira_request(
                    config, secret, event, timeout=timeout_seconds,
                    allow_private_networks=allow_private_networks,
                    host_allowlist=host_allowlist,
                    max_response_bytes=max_response_bytes,
                )
        except Exception as exc:
            result = DeliveryResult(False, error=f"{type(exc).__name__}: {exc}", retryable=False)
        outcome = record_collaboration_delivery(
            db_path,
            event_id=str(event["event_id"]),
            delivered=result.delivered,
            response_status=result.response_status,
            error=result.error,
            external_key=result.external_key,
            external_url=result.external_url,
            max_attempts=max_attempts,
            retryable=result.retryable,
            retry_after_seconds=result.retry_after_seconds,
        )
        if result.delivered and str(event["event_type"]) == "jira.issue_create" and result.external_key:
            upsert_finding_external_link(
                db_path,
                finding_id=str(event["finding_id"]),
                provider="JIRA",
                external_key=result.external_key,
                external_url=result.external_url,
                actor="system-collaboration",
            )
        status = str(outcome["status"]).lower()
        summary[status if status in summary else "failed"] += 1
    return summary
