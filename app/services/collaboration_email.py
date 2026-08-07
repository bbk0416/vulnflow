from __future__ import annotations

"""Email integration configuration validation shared by UI and delivery."""

from email.headerregistry import Address
from typing import Any


DEFAULT_EMAIL_EVENTS = frozenset({
    "finding.workflow_changed",
    "remediation.verification_requested",
    "remediation.verification_decided",
    "risk_acceptance.requested",
    "risk_acceptance.decided",
    "finding.due_soon",
    "finding.overdue",
})


class CollaborationConfigError(ValueError):
    pass


def configured_events(config: dict[str, Any], defaults: frozenset[str]) -> frozenset[str]:
    raw = config.get("events")
    if not isinstance(raw, list):
        return defaults
    values = frozenset(str(item).strip() for item in raw if str(item).strip())
    return values or defaults


def _email_address(raw: Any, *, field: str) -> str:
    value = str(raw or "").strip()
    if not value or any(char in value for char in "\r\n"):
        raise CollaborationConfigError(f"{field} 이메일 주소가 올바르지 않습니다.")
    try:
        parsed = Address(addr_spec=value)
    except (TypeError, ValueError) as exc:
        raise CollaborationConfigError(f"{field} 이메일 주소가 올바르지 않습니다.") from exc
    if not parsed.username or not parsed.domain or parsed.addr_spec != value:
        raise CollaborationConfigError(f"{field} 이메일 주소가 올바르지 않습니다.")
    return value


def _recipients(raw: Any) -> list[str]:
    values = raw if isinstance(raw, list) else str(raw or "").replace(";", ",").split(",")
    output: list[str] = []
    for item in values:
        if not str(item or "").strip():
            continue
        email = _email_address(item, field="수신")
        if email not in output:
            output.append(email)
    return output


def validate_email_config(
    config: dict[str, Any], *, secret_configured: bool, allow_plain: bool = False
) -> dict[str, Any]:
    host = str(config.get("host") or "").strip()
    if not host or "://" in host or any(char.isspace() for char in host):
        raise CollaborationConfigError("SMTP 호스트 이름을 입력하세요.")
    port = int(config.get("port") or 587)
    if not 1 <= port <= 65535:
        raise CollaborationConfigError("SMTP 포트가 올바르지 않습니다.")
    security = str(config.get("security") or "STARTTLS").strip().upper()
    if security not in {"STARTTLS", "SSL", "PLAIN"}:
        raise CollaborationConfigError("SMTP 보안 방식은 STARTTLS, SSL, PLAIN 중 하나여야 합니다.")
    if security == "PLAIN" and not allow_plain:
        raise CollaborationConfigError("암호화되지 않은 SMTP는 명시적으로 허용해야 합니다.")
    sender = _email_address(config.get("from_address"), field="발신")
    recipients = _recipients(config.get("recipients"))
    if not recipients:
        raise CollaborationConfigError("수신 이메일 주소를 하나 이상 입력하세요.")
    username = str(config.get("username") or "").strip()
    if username and not secret_configured:
        raise CollaborationConfigError("SMTP 사용자명에는 비밀번호가 필요합니다.")
    return {
        "host": host,
        "port": port,
        "security": security,
        "username": username,
        "from_address": sender,
        "recipients": recipients,
        "events": sorted(configured_events(config, DEFAULT_EMAIL_EVENTS)),
    }


__all__ = [
    "CollaborationConfigError",
    "DEFAULT_EMAIL_EVENTS",
    "configured_events",
    "validate_email_config",
]
