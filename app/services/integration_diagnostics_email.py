from __future__ import annotations

import smtplib
import ssl
import time
from typing import Any

from app.services.collaboration import validate_email_config
from app.services.integration_diagnostics_common import DiagnosticResult, elapsed_ms
from app.services.outbound_http import OutboundError, OutboundPolicyError
from app.services.outbound_smtp import connect_outbound_smtp


def _smtp_error(exc: BaseException) -> tuple[str, str]:
    if isinstance(exc, smtplib.SMTPAuthenticationError):
        return "authentication", "SMTP 인증에 실패했습니다. 사용자명과 비밀번호를 확인하세요."
    if isinstance(exc, ssl.SSLCertVerificationError):
        return "tls", "SMTP 서버 인증서를 검증하지 못했습니다. 인증서 체인과 서버 이름을 확인하세요."
    if isinstance(exc, TimeoutError):
        return "connection", "SMTP 연결 시간이 초과됐습니다. 방화벽과 호스트·포트를 확인하세요."
    if isinstance(exc, OSError):
        return "connection", "SMTP 서버에 연결하지 못했습니다. DNS, 방화벽, 호스트·포트를 확인하세요."
    return "protocol", "SMTP 서버가 연결 점검 요청을 정상 처리하지 못했습니다."


def diagnose_email_connection(
    config: dict[str, Any],
    secret: dict[str, str],
    *,
    timeout_seconds: int = 10,
    allow_private_networks: bool = False,
    host_allowlist: str | tuple[str, ...] = (),
    allow_plain: bool = False,
) -> dict[str, Any]:
    started = time.monotonic()
    try:
        normalized = validate_email_config(
            config,
            secret_configured=bool(
                secret.get("password") or not str(config.get("username") or "").strip()
            ),
            allow_plain=allow_plain,
        )
    except (TypeError, ValueError) as exc:
        return DiagnosticResult(
            "EMAIL", False, "configuration", str(exc), elapsed_ms(started), {}
        ).as_dict()

    details: dict[str, Any] = {
        "host": normalized["host"],
        "port": normalized["port"],
        "security": normalized["security"],
        "authentication": bool(normalized["username"]),
        "mail_sent": False,
    }
    try:
        server = connect_outbound_smtp(
            normalized["host"],
            normalized["port"],
            security=normalized["security"],
            timeout_seconds=timeout_seconds,
            allow_private_networks=allow_private_networks,
            host_allowlist=host_allowlist,
            allow_plain=allow_plain,
        )
        with server:
            details["tls"] = normalized["security"] in {"STARTTLS", "SSL"}
            details["ehlo"] = 250
            if normalized["username"]:
                code, _ = server.login(normalized["username"], secret.get("password", ""))
                details["login"] = int(code)
        return DiagnosticResult(
            "EMAIL",
            True,
            "authenticated" if normalized["username"] else "connected",
            "SMTP 연결과 인증 점검을 통과했습니다. 테스트 메일은 보내지 않았습니다.",
            elapsed_ms(started),
            details,
        ).as_dict()
    except OutboundPolicyError:
        return DiagnosticResult(
            "EMAIL",
            False,
            "outbound_policy",
            "SMTP 주소가 외부 통신 보안 정책에 의해 차단됐습니다.",
            elapsed_ms(started),
            details,
        ).as_dict()
    except OutboundError:
        return DiagnosticResult(
            "EMAIL",
            False,
            "connection",
            "SMTP 서버에 연결하지 못했습니다. DNS, 방화벽과 TLS 설정을 확인하세요.",
            elapsed_ms(started),
            details,
        ).as_dict()
    except (smtplib.SMTPException, ssl.SSLError, OSError, TimeoutError) as exc:
        stage, message = _smtp_error(exc)
        return DiagnosticResult(
            "EMAIL", False, stage, message, elapsed_ms(started), details
        ).as_dict()
